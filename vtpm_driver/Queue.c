#include "vtpm.h"
#include "Backend.h"

// g_FdoContext, g_CtrlWaitQueue, g_CtrlActiveQueue defined in Driver.c

static const char*
VtpmIoctlName(_In_ ULONG IoControlCode)
{
    switch (IoControlCode) {
    case IOCTL_TPM_SUBMIT_COMMAND:
        return "IOCTL_TPM_SUBMIT_COMMAND";
    case IOCTL_TPM_SUBMIT_COMMAND2:
        return "IOCTL_TPM_SUBMIT_COMMAND2";
    case IOCTL_TPM_GET_EVENT_LOG:
        return "IOCTL_TPM_GET_EVENT_LOG";
    case IOCTL_TPM_GET_PERSISTENT_PUBLIC:
        return "IOCTL_TPM_GET_PERSISTENT_PUBLIC";
    case IOCTL_TPM_GET_DEVICE_INFO:
        return "IOCTL_TPM_GET_DEVICE_INFO";
    case IOCTL_VTPM_GET_COMMAND:
        return "IOCTL_VTPM_GET_COMMAND";
    case IOCTL_VTPM_COMPLETE_COMMAND:
        return "IOCTL_VTPM_COMPLETE_COMMAND";
    default:
        return "UNKNOWN";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
VOID VtpmCancelPendingRequest(PPENDING_REQUEST PendingReq, NTSTATUS Status)
{
    WdfRequestComplete(PendingReq->OriginalRequest, Status);
    ExFreePoolWithTag(PendingReq, VTPM_POOL_TAG);
}

// ─────────────────────────────────────────────────────────────────────────────
// EvtIoCanceledOnQueue
// Called when a request sitting in TpmParkQueue is cancelled by the caller.
// ─────────────────────────────────────────────────────────────────────────────
VOID EvtIoCanceledOnQueue(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request)
{
    PDEVICE_CONTEXT ctx;
    PLIST_ENTRY     entry;
    PPENDING_REQUEST pr = NULL;

    UNREFERENCED_PARAMETER(Queue);

    if (g_FdoContext == NULL) {
        WdfRequestComplete(Request, STATUS_CANCELLED);
        return;
    }
    ctx = g_FdoContext;

    WdfWaitLockAcquire(ctx->PendingListLock, NULL);
    for (entry = ctx->PendingList.Flink;
         entry != &ctx->PendingList;
         entry  = entry->Flink)
    {
        pr = CONTAINING_RECORD(entry, PENDING_REQUEST, ListEntry);
        if (pr->OriginalRequest == Request) {
            RemoveEntryList(&pr->ListEntry);
            break;
        }
        pr = NULL;
    }
    WdfWaitLockRelease(ctx->PendingListLock);

    if (pr != NULL) ExFreePoolWithTag(pr, VTPM_POOL_TAG);
    WdfRequestComplete(Request, STATUS_CANCELLED);
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: build a VTPM_COMMAND_HEADER into ctrlOutputBuf and complete ctrlReq
// ─────────────────────────────────────────────────────────────────────────────
static NTSTATUS
DeliverTpmCommandToHelper(
    _In_ PDEVICE_CONTEXT ctx,
    _In_ WDFREQUEST      tpmReq,   // the original TPM IOCTL (will be parked)
    _In_ WDFREQUEST      ctrlReq)  // the waiting GET_COMMAND IOCTL (will be completed)
{
    NTSTATUS  status;
    PVOID     tpmIn  = NULL; size_t tpmInLen  = 0;
    PVOID     ctrlOut = NULL; size_t ctrlOutLen = 0;
    PVTPM_COMMAND_HEADER hdr;
    PPENDING_REQUEST pr;
    WDF_REQUEST_PARAMETERS params;

    // Get TPM input buffer (the actual TPM command bytes)
    status = WdfRequestRetrieveInputBuffer(tpmReq, 0, &tpmIn, &tpmInLen);
    if (!NT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL) {
        tpmIn    = NULL;
        tpmInLen = 0;
    }

    // If input buffer is empty, Windows TBS may be using in-place I/O (bidirectional):
    // the TPM command is placed in the output buffer and the response overwrites it.
    // This is how IOCTL_TPM_SUBMIT_COMMAND2 (0x22C01C) works with TBS.
    if (tpmInLen == 0) {
        PVOID outBuf = NULL; size_t outLen = 0;
        status = WdfRequestRetrieveOutputBuffer(tpmReq, 0, &outBuf, &outLen);
        if (NT_SUCCESS(status) && outLen > 0) {
            tpmIn    = outBuf;
            tpmInLen = outLen;
            KdPrint(("vTPM: Using output buffer as TPM command source (%zu bytes)\n", tpmInLen));
        }
    }

    // Get helper's output buffer (where we write header + command bytes)
    status = WdfRequestRetrieveOutputBuffer(ctrlReq,
                 sizeof(VTPM_COMMAND_HEADER), &ctrlOut, &ctrlOutLen);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(ctrlReq, status);
        // Forward TPM request back to park queue so it isn't lost
        WdfRequestForwardToIoQueue(tpmReq, ctx->TpmParkQueue);
        return status;
    }

    if (ctrlOutLen < sizeof(VTPM_COMMAND_HEADER) + tpmInLen) {
        WdfRequestComplete(ctrlReq, STATUS_BUFFER_TOO_SMALL);
        WdfRequestForwardToIoQueue(tpmReq, ctx->TpmParkQueue);
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Allocate pending-request node
    pr = (PPENDING_REQUEST)ExAllocatePool2(POOL_FLAG_NON_PAGED,
             sizeof(PENDING_REQUEST), VTPM_POOL_TAG);
    if (pr == NULL) {
        WdfRequestComplete(ctrlReq, STATUS_INSUFFICIENT_RESOURCES);
        WdfRequestComplete(tpmReq,  STATUS_INSUFFICIENT_RESOURCES);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfWaitLockAcquire(ctx->PendingListLock, NULL);
    pr->RequestId = ctx->NextRequestId++;
    if (ctx->NextRequestId == 0) ctx->NextRequestId = 1;
    pr->OriginalRequest = tpmReq;
    InsertTailList(&ctx->PendingList, &pr->ListEntry);
    WdfWaitLockRelease(ctx->PendingListLock);

    // Fill header
    WDF_REQUEST_PARAMETERS_INIT(&params);
    WdfRequestGetParameters(tpmReq, &params);

    hdr = (PVTPM_COMMAND_HEADER)ctrlOut;
    hdr->RequestId     = pr->RequestId;
    hdr->CommandLength = (ULONG)tpmInLen;
    hdr->IoctlCode     = params.Parameters.DeviceIoControl.IoControlCode;

    if (tpmInLen > 0 && tpmIn != NULL) {
        RtlCopyMemory((PUCHAR)ctrlOut + sizeof(VTPM_COMMAND_HEADER), tpmIn, tpmInLen);
    }

    WdfRequestCompleteWithInformation(ctrlReq, STATUS_SUCCESS,
        sizeof(VTPM_COMMAND_HEADER) + tpmInLen);

    // tpmReq is now tracked in PendingList; it will be completed by COMPLETE_COMMAND
    return STATUS_SUCCESS;
}

// ─────────────────────────────────────────────────────────────────────────────
// EvtIoDeviceControlTpm
// Invoked (automatically, parallel) for every IOCTL on \\.\VirtualTpm
// ─────────────────────────────────────────────────────────────────────────────
VOID EvtIoDeviceControlTpm(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     OutputBufferLength,
    _In_ size_t     InputBufferLength,
    _In_ ULONG      IoControlCode)
{
    WDFDEVICE       device = WdfIoQueueGetDevice(Queue);
    PDEVICE_CONTEXT ctx    = GetDeviceContext(device);
    NTSTATUS        status;
    WDFREQUEST      ctrlReq;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    KdPrint(("vTPM: TPM IOCTL %s (0x%x), in=%zu, out=%zu\n",
        VtpmIoctlName(IoControlCode), IoControlCode, InputBufferLength, OutputBufferLength));

    if (VtpmBackendTryHandleIoctl(
            ctx->Backend,
            Request,
            OutputBufferLength,
            InputBufferLength,
            IoControlCode)) {
        return;
    }

    // Is there a helper already waiting with a GET_COMMAND request?
    status = WdfIoQueueRetrieveNextRequest(g_CtrlWaitQueue, &ctrlReq);
    if (NT_SUCCESS(status)) {
        // Pair immediately: deliver TPM command to the waiting helper
        DeliverTpmCommandToHelper(ctx, Request, ctrlReq);
    } else {
        // No helper waiting – park this TPM request in TpmParkQueue
        status = WdfRequestForwardToIoQueue(Request, ctx->TpmParkQueue);
        if (!NT_SUCCESS(status)) {
            KdPrint(("vTPM: Forward to TpmParkQueue failed 0x%x\n", status));
            WdfRequestComplete(Request, status);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EvtIoDeviceControlControl
// Invoked (automatically, parallel) for every IOCTL on \\.\VTpmControl
// ─────────────────────────────────────────────────────────────────────────────
VOID EvtIoDeviceControlControl(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     OutputBufferLength,
    _In_ size_t     InputBufferLength,
    _In_ ULONG      IoControlCode)
{
    PDEVICE_CONTEXT ctx = g_FdoContext;
    NTSTATUS        status;

    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (ctx == NULL) {
        WdfRequestComplete(Request, STATUS_DEVICE_NOT_READY);
        return;
    }

    if (IoControlCode == IOCTL_VTPM_GET_BACKEND_STATUS) {
        PVTPM_BACKEND_STATUS output = NULL;
        size_t outputLength = 0;
        status = WdfRequestRetrieveOutputBuffer(
            Request,
            sizeof(VTPM_BACKEND_STATUS),
            (PVOID*)&output,
            &outputLength);
        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(Request, status);
            return;
        }

        RtlZeroMemory(output, sizeof(*output));
        WdfWaitLockAcquire(ctx->BackendLock, NULL);
        output->Version = 12;
        output->Role = (ULONG)ctx->Backend->Role;
        output->Started = ctx->Backend->Started ? 1u : 0u;
        output->LastCommandCode = ctx->Backend->LastCommandCode;
        output->LastUnsupportedCommandCode =
            ctx->Backend->LastUnsupportedCommandCode;
        output->CommandCount = ctx->Backend->CommandCount;
        output->UnsupportedCommandCount =
            ctx->Backend->UnsupportedCommandCount;
        output->PcrUpdateCounter = ctx->Backend->PcrUpdateCounter;
        output->LastIoctlCode = ctx->Backend->LastIoctlCode;
        output->LastCommandLength = ctx->Backend->LastCommandLength;
        output->LastDeclaredLength = ctx->Backend->LastDeclaredLength;
        output->LastCapability = ctx->Backend->LastCapability;
        output->LastProperty = ctx->Backend->LastProperty;
        output->LastPropertyCount = ctx->Backend->LastPropertyCount;
        output->LastTpmResult = ctx->Backend->LastTpmResult;
        output->LastErrorCommandCode =
            ctx->Backend->LastErrorCommandCode;
        output->LastErrorTpmResult =
            ctx->Backend->LastErrorTpmResult;
        output->LastErrorCommandLength =
            ctx->Backend->LastErrorCommandLength;
        output->LastErrorDeclaredLength =
            ctx->Backend->LastErrorDeclaredLength;
        output->LastSizeErrorCommandCode =
            ctx->Backend->LastSizeErrorCommandCode;
        output->LastSizeErrorCommandLength =
            ctx->Backend->LastSizeErrorCommandLength;
        output->LastSizeErrorDeclaredLength =
            ctx->Backend->LastSizeErrorDeclaredLength;
        output->SizeErrorCount = ctx->Backend->SizeErrorCount;
        output->LastUnsupportedCommandLength =
            ctx->Backend->LastUnsupportedCommandLength;
        RtlCopyMemory(
            output->LastUnsupportedCommand,
            ctx->Backend->LastUnsupportedCommand,
            sizeof(output->LastUnsupportedCommand));
        output->PrimaryKeyLoaded = ctx->Backend->PrimaryKeyLoaded;
        output->PrimaryKeyPersisted = ctx->Backend->PrimaryKeyPersisted;
        output->PrimaryAvailable =
            ctx->Backend->PrimaryAvailable ? 1u : 0u;
        output->PersistentPublicIoctlCount =
            ctx->Backend->PersistentPublicIoctlCount;
        output->LastPersistentPublicStatus =
            (ULONG)ctx->Backend->LastPersistentPublicStatus;
        output->EventLogLoaded =
            ctx->Backend->EventLog != NULL ? 1u : 0u;
        output->EventLogLength = ctx->Backend->EventLogLength;
        output->EventLogReplayCount =
            ctx->Backend->EventLogReplayCount;
        output->EventLogReplayStatus =
            (ULONG)ctx->Backend->EventLogReplayStatus;
        output->EventLogIoctlCount =
            ctx->Backend->EventLogIoctlCount;
        output->LastEventLogType =
            ctx->Backend->LastEventLogType;
        output->LastEventLogOutputLength =
            ctx->Backend->LastEventLogOutputLength;
        output->LastEventLogStatus =
            (ULONG)ctx->Backend->LastEventLogStatus;
        output->LastEventLogBytesReturned =
            ctx->Backend->LastEventLogBytesReturned;
        output->EventLogPartialSuccessCount =
            ctx->Backend->EventLogPartialSuccessCount;
        WdfWaitLockRelease(ctx->BackendLock);

        WdfRequestCompleteWithInformation(
            Request,
            STATUS_SUCCESS,
            sizeof(*output));
        return;
    }

    // ── IOCTL_VTPM_GET_COMMAND ────────────────────────────────────────────
    if (IoControlCode == IOCTL_VTPM_GET_COMMAND) {
        WDFREQUEST tpmReq;

        // Is there a parked TPM command waiting?
        status = WdfIoQueueRetrieveNextRequest(ctx->TpmParkQueue, &tpmReq);
        if (NT_SUCCESS(status)) {
            // Deliver it immediately to the helper
            DeliverTpmCommandToHelper(ctx, tpmReq, Request);
        } else {
            // Nothing waiting – park this GET_COMMAND in CtrlWaitQueue
            status = WdfRequestForwardToIoQueue(Request, g_CtrlWaitQueue);
            if (!NT_SUCCESS(status)) {
                WdfRequestComplete(Request, status);
            }
        }
        return;
    }

    // ── IOCTL_VTPM_COMPLETE_COMMAND ───────────────────────────────────────
    if (IoControlCode == IOCTL_VTPM_COMPLETE_COMMAND) {
        PVOID  inBuf  = NULL; size_t inLen  = 0;
        PVOID  outBuf = NULL; size_t outLen = 0;
        PVTPM_RESPONSE_HEADER resp;
        PPENDING_REQUEST pr = NULL;
        PLIST_ENTRY      entry;

        status = WdfRequestRetrieveInputBuffer(Request,
                     sizeof(VTPM_RESPONSE_HEADER), &inBuf, &inLen);
        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(Request, status);
            return;
        }

        resp = (PVTPM_RESPONSE_HEADER)inBuf;

        WdfWaitLockAcquire(ctx->PendingListLock, NULL);
        for (entry = ctx->PendingList.Flink;
             entry != &ctx->PendingList;
             entry  = entry->Flink)
        {
            PPENDING_REQUEST item =
                CONTAINING_RECORD(entry, PENDING_REQUEST, ListEntry);
            if (item->RequestId == resp->RequestId) {
                pr = item;
                RemoveEntryList(&pr->ListEntry);
                break;
            }
        }
        WdfWaitLockRelease(ctx->PendingListLock);

        if (pr == NULL) {
            WdfRequestComplete(Request, STATUS_NOT_FOUND);
            return;
        }

        // Copy response bytes back into the original TPM caller's buffer
        status = WdfRequestRetrieveOutputBuffer(pr->OriginalRequest,
                     0, &outBuf, &outLen);
        if (NT_SUCCESS(status)) {
            ULONG copyLen = resp->ResponseLength;
            KdPrint(("vTPM: CompleteCommand ID %u, respLen=%u, outLen=%zu, status=0x%x\n",
                resp->RequestId, copyLen, outLen, resp->Status));
            if (copyLen > (ULONG)outLen) {
                KdPrint(("vTPM: [WARNING] Output buffer too small! Truncating response from %u to %zu bytes\n",
                    copyLen, outLen));
                copyLen = (ULONG)outLen;
            }
            if (copyLen > 0 &&
                inLen >= sizeof(VTPM_RESPONSE_HEADER) + copyLen) {
                RtlCopyMemory(outBuf,
                    (PUCHAR)inBuf + sizeof(VTPM_RESPONSE_HEADER), copyLen);
            }
            WdfRequestCompleteWithInformation(pr->OriginalRequest,
                (NTSTATUS)resp->Status, copyLen);
        } else {
            WdfRequestComplete(pr->OriginalRequest, status);
        }

        ExFreePoolWithTag(pr, VTPM_POOL_TAG);
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return;
    }

    // Unknown IOCTL
    WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
}

// ─────────────────────────────────────────────────────────────────────────────
// EvtFileCleanupControl
// Invoked when the user-mode helper service closes its handle to \\.\VTpmControl.
// We must cancel all pending TPM requests in the PendingList so callers do not hang.
// ─────────────────────────────────────────────────────────────────────────────
VOID EvtFileCleanupControl(_In_ WDFFILEOBJECT FileObject)
{
    UNREFERENCED_PARAMETER(FileObject);
    KdPrint(("vTPM: Control handle closed. Cleaning up pending requests...\n"));
    
    PDEVICE_CONTEXT ctx = g_FdoContext;
    if (ctx == NULL) return;

    LIST_ENTRY tempHead;
    InitializeListHead(&tempHead);

    // Drain PendingList under lock
    WdfWaitLockAcquire(ctx->PendingListLock, NULL);
    while (!IsListEmpty(&ctx->PendingList)) {
        PLIST_ENTRY entry = RemoveHeadList(&ctx->PendingList);
        InsertTailList(&tempHead, entry);
    }
    WdfWaitLockRelease(ctx->PendingListLock);

    // Complete all drained requests outside lock to avoid deadlock
    while (!IsListEmpty(&tempHead)) {
        PLIST_ENTRY entry = RemoveHeadList(&tempHead);
        PPENDING_REQUEST pr = CONTAINING_RECORD(entry, PENDING_REQUEST, ListEntry);
        
        KdPrint(("vTPM: Cancelling pending request ID %u due to control close\n", pr->RequestId));
        WdfRequestComplete(pr->OriginalRequest, STATUS_CANCELLED);
        ExFreePoolWithTag(pr, VTPM_POOL_TAG);
    }
}
