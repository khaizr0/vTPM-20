// Must define INITGUID before including headers so DEFINE_GUID allocates storage
#define INITGUID
#include "vtpm.h"
#include "Backend.h"
#include <wdmsec.h>
#include <initguid.h>

// TPM device interface GUID – TBS uses this to discover TPM devices via PnP
// {6D5C9CB2-5A24-4FD7-B2DC-8A5C7A3C9982}
DEFINE_GUID(GUID_DEVINTERFACE_TPM,
    0x6D5C9CB2, 0x5A24, 0x4FD7,
    0xB2, 0xDC, 0x8A, 0x5C, 0x7A, 0x3C, 0x99, 0x82);

#pragma comment(lib, "wdmsec.lib")


// ── Globals ──────────────────────────────────────────────────────────────────
WDFDEVICE        g_ControlDevice   = NULL;
WDFQUEUE         g_CtrlActiveQueue = NULL; // Parallel, EvtIoDeviceControl set
WDFQUEUE         g_CtrlWaitQueue   = NULL; // Manual, parks GET_COMMAND requests
PDEVICE_CONTEXT  g_FdoContext      = NULL;

// Forward declaration
NTSTATUS CreateControlDevice(_In_ WDFDRIVER Driver);

// ── DriverEntry ───────────────────────────────────────────────────────────────
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;

    KdPrint(("vTPM: DriverEntry\n"));

    WDF_DRIVER_CONFIG_INIT(&config, EvtDriverDeviceAdd);

    status = WdfDriverCreate(DriverObject, RegistryPath,
                             WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        KdPrint(("vTPM: WdfDriverCreate failed 0x%x\n", status));
    }
    return status;
}

// ── EvtDriverDeviceAdd ────────────────────────────────────────────────────────
NTSTATUS EvtDriverDeviceAdd(
    _In_ WDFDRIVER       Driver,
    _In_ PWDFDEVICE_INIT DeviceInit)
{
    NTSTATUS status;
    WDFDEVICE device;
    PDEVICE_CONTEXT ctx;
    WDF_OBJECT_ATTRIBUTES attrs;
    WDF_IO_QUEUE_CONFIG qcfg;
    PVTPM_BACKEND backend;

    // Use the standard TPM device name so TBS can open \\.\Tpm
    DECLARE_CONST_UNICODE_STRING(devName,  L"\\Device\\Tpm");
    DECLARE_CONST_UNICODE_STRING(symLink,  L"\\DosDevices\\Tpm");

    UNREFERENCED_PARAMETER(Driver);

    KdPrint(("vTPM: EvtDriverDeviceAdd\n"));

    // ── Assign device name ────────────────────────────────────────────────
    // If \Device\Tpm already exists (e.g. duplicate PnP node), bail gracefully.
    // STATUS_OBJECT_NAME_COLLISION (0xC0000035) means a 2nd instance is loading.
    status = WdfDeviceInitAssignName(DeviceInit, &devName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("vTPM: WdfDeviceInitAssignName 0x%x – device already exists?\n", status));
        // Return a benign failure so PnP marks this device as failed-to-start
        // rather than blue-screening the machine.
        return STATUS_DEVICE_ALREADY_ATTACHED;
    }

    // ── Create FDO ────────────────────────────────────────────────────────
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs, DEVICE_CONTEXT);
    attrs.ContextSizeOverride = sizeof(DEVICE_CONTEXT) + sizeof(VTPM_BACKEND);
    attrs.ExecutionLevel = WdfExecutionLevelPassive;
    attrs.EvtCleanupCallback = EvtDeviceContextCleanup;
    status = WdfDeviceCreate(&DeviceInit, &attrs, &device);
    if (!NT_SUCCESS(status)) {
        KdPrint(("vTPM: WdfDeviceCreate 0x%x\n", status));
        return status;
    }

    // ── Initialise context ────────────────────────────────────────────────
    ctx = GetDeviceContext(device);
    RtlZeroMemory(ctx, sizeof(DEVICE_CONTEXT));
    InitializeListHead(&ctx->PendingList);
    ctx->NextRequestId = 1;
    backend = (PVTPM_BACKEND)((PUCHAR)ctx + sizeof(DEVICE_CONTEXT));
    ctx->Backend = backend;
    g_FdoContext = ctx;

    status = WdfWaitLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &ctx->BackendLock);
    if (!NT_SUCCESS(status)) {
        KdPrint(("vTPM: WdfWaitLockCreate(BackendLock) 0x%x\n", status));
        return status;
    }

    status = VtpmBackendInitialize(backend);
    if (!NT_SUCCESS(status)) {
        KdPrint(("vTPM: VtpmBackendInitialize 0x%x\n", status));
        return status;
    }

    status = WdfWaitLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &ctx->PendingListLock);
    if (!NT_SUCCESS(status)) {
        KdPrint(("vTPM: WdfWaitLockCreate(PendingListLock) 0x%x\n", status));
        return status;
    }

    // ── Symbolic link \\.\Tpm  → TBS calls CreateFile("\\\\.\\Tpm") ──────────
    status = WdfDeviceCreateSymbolicLink(device, &symLink);
    if (!NT_SUCCESS(status)) {
        // Non-fatal: symlink may already exist from a previous driver load.
        // Log but continue – the device interface (GUID) is enough for PnP discovery.
        KdPrint(("vTPM: WdfDeviceCreateSymbolicLink 0x%x (non-fatal, continuing)\n", status));
        status = STATUS_SUCCESS;
    }

    // ── Register device interface so TBS discovers us via PnP ─────────────
    status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_TPM, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("vTPM: WdfDeviceCreateDeviceInterface 0x%x\n", status));
        return status;
    }

    // ── TpmActiveQueue : default, PARALLEL, has EvtIoDeviceControl ────────
    //    (WDF calls EvtIoDeviceControlTpm automatically when a request arrives)
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&qcfg, WdfIoQueueDispatchParallel);
    qcfg.EvtIoDeviceControl = EvtIoDeviceControlTpm;

    status = WdfIoQueueCreate(device, &qcfg, WDF_NO_OBJECT_ATTRIBUTES,
                              &ctx->TpmActiveQueue);
    if (!NT_SUCCESS(status)) {
        KdPrint(("vTPM: WdfIoQueueCreate(TpmActiveQueue) 0x%x\n", status));
        return status;
    }

    // ── TpmParkQueue : secondary, MANUAL, no callbacks ────────────────────
    //    TPM requests are forwarded here when no helper is waiting.
    WDF_IO_QUEUE_CONFIG_INIT(&qcfg, WdfIoQueueDispatchManual);
    qcfg.EvtIoCanceledOnQueue = EvtIoCanceledOnQueue;

    status = WdfIoQueueCreate(device, &qcfg, WDF_NO_OBJECT_ATTRIBUTES,
                              &ctx->TpmParkQueue);
    if (!NT_SUCCESS(status)) {
        KdPrint(("vTPM: WdfIoQueueCreate(TpmParkQueue) 0x%x\n", status));
        return status;
    }

    // ── Create the singleton control device (done once) ───────────────────
    if (g_ControlDevice == NULL) {
        status = CreateControlDevice(WdfGetDriver());
        if (!NT_SUCCESS(status)) {
            KdPrint(("vTPM: CreateControlDevice 0x%x\n", status));
            return status;
        }
    }

    KdPrint(("vTPM: FDO ready – \\Device\\Tpm (symlink \\.\\Tpm) / \\Device\\VTpmControl\n"));
    return STATUS_SUCCESS;
}

VOID EvtDeviceContextCleanup(_In_ WDFOBJECT DeviceObject)
{
    WDFDEVICE device = (WDFDEVICE)DeviceObject;
    PDEVICE_CONTEXT ctx = GetDeviceContext(device);

    if (ctx->Backend != NULL) {
        VtpmBackendShutdown(ctx->Backend);
    }
    if (g_FdoContext == ctx) {
        g_FdoContext = NULL;
    }
}

// ── CreateControlDevice ───────────────────────────────────────────────────────
NTSTATUS CreateControlDevice(_In_ WDFDRIVER Driver)
{
    NTSTATUS          status;
    PWDFDEVICE_INIT   cinit = NULL;
    WDFDEVICE         cdev;
    WDF_IO_QUEUE_CONFIG qcfg;
    WDF_OBJECT_ATTRIBUTES attrs;

    DECLARE_CONST_UNICODE_STRING(cdevName, L"\\Device\\VTpmControl");
    DECLARE_CONST_UNICODE_STRING(cSymLink, L"\\DosDevices\\VTpmControl");

    cinit = WdfControlDeviceInitAllocate(Driver,
                &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RWX_RES_RWX);
    if (cinit == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    status = WdfDeviceInitAssignName(cinit, &cdevName);
    if (!NT_SUCCESS(status)) { WdfDeviceInitFree(cinit); return status; }

    // Set up file object config to capture handle close/cleanup
    WDF_FILEOBJECT_CONFIG fileConfig;
    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig,
                               WDF_NO_EVENT_CALLBACK, // Create
                               WDF_NO_EVENT_CALLBACK, // Close
                               EvtFileCleanupControl); // Cleanup
    WdfDeviceInitSetFileObjectConfig(cinit, &fileConfig, WDF_NO_OBJECT_ATTRIBUTES);

    WDF_OBJECT_ATTRIBUTES_INIT(&attrs);
    status = WdfDeviceCreate(&cinit, &attrs, &cdev);
    if (!NT_SUCCESS(status)) { WdfDeviceInitFree(cinit); return status; }

    status = WdfDeviceCreateSymbolicLink(cdev, &cSymLink);
    if (!NT_SUCCESS(status)) { WdfObjectDelete(cdev); return status; }

    // ── CtrlActiveQueue : PARALLEL, has EvtIoDeviceControl ───────────────
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&qcfg, WdfIoQueueDispatchParallel);
    qcfg.EvtIoDeviceControl = EvtIoDeviceControlControl;

    status = WdfIoQueueCreate(cdev, &qcfg, WDF_NO_OBJECT_ATTRIBUTES,
                              &g_CtrlActiveQueue);
    if (!NT_SUCCESS(status)) { WdfObjectDelete(cdev); return status; }

    // ── CtrlWaitQueue : MANUAL, no callbacks ─────────────────────────────
    //    Parks GET_COMMAND requests when no TPM command is yet available.
    WDF_IO_QUEUE_CONFIG_INIT(&qcfg, WdfIoQueueDispatchManual);

    status = WdfIoQueueCreate(cdev, &qcfg, WDF_NO_OBJECT_ATTRIBUTES,
                              &g_CtrlWaitQueue);
    if (!NT_SUCCESS(status)) { WdfObjectDelete(cdev); return status; }

    WdfControlFinishInitializing(cdev);
    g_ControlDevice = cdev;

    KdPrint(("vTPM: Control device ready – \\Device\\VTpmControl\n"));
    return STATUS_SUCCESS;
}
