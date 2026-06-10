#pragma once

#include <ntddk.h>
#include <wdf.h>

#define FILE_DEVICE_TPM 0x22

// Standard TPM IOCTLs
#define IOCTL_TPM_SUBMIT_COMMAND CTL_CODE(FILE_DEVICE_TPM, 3, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TPM_GET_EVENT_LOG CTL_CODE(FILE_DEVICE_TPM, 5, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TPM_GET_DEVICE_INFO CTL_CODE(FILE_DEVICE_TPM, 7, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TPM_SUBMIT_COMMAND2 CTL_CODE(FILE_DEVICE_TPM, 101, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TPM_GET_PERSISTENT_PUBLIC CTL_CODE(FILE_DEVICE_TPM, 103, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

typedef struct _TPM_DEVICE_INFO {
    ULONG structVersion;
    ULONG tpmVersion;
    ULONG tpmInterfaceType;
    ULONG tpmImpRevision;
} TPM_DEVICE_INFO, *PTPM_DEVICE_INFO;

// GUID that TBS (TPM Base Services) uses to discover TPM devices via PnP
// {6D5C9CB2-5A24-4FD7-B2DC-8A5C7A3C9982}
extern const GUID GUID_DEVINTERFACE_TPM;

// Control channel IOCTLs for user-mode helper service
#define IOCTL_VTPM_GET_COMMAND      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VTPM_COMPLETE_COMMAND CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VTPM_GET_BACKEND_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define VTPM_POOL_TAG 'mTPv'

// Headers exchanged with user-mode helper
typedef struct _VTPM_COMMAND_HEADER {
    ULONG RequestId;
    ULONG CommandLength;
    ULONG IoctlCode;
} VTPM_COMMAND_HEADER, *PVTPM_COMMAND_HEADER;

typedef struct _VTPM_RESPONSE_HEADER {
    ULONG RequestId;
    ULONG ResponseLength;
    ULONG Status;
} VTPM_RESPONSE_HEADER, *PVTPM_RESPONSE_HEADER;

typedef struct _VTPM_BACKEND_STATUS {
    ULONG Version;
    ULONG Role;
    ULONG Started;
    ULONG LastCommandCode;
    ULONG LastUnsupportedCommandCode;
    ULONG CommandCount;
    ULONG UnsupportedCommandCount;
    ULONG PcrUpdateCounter;
    ULONG LastIoctlCode;
    ULONG LastCommandLength;
    ULONG LastDeclaredLength;
    ULONG LastCapability;
    ULONG LastProperty;
    ULONG LastPropertyCount;
    ULONG LastTpmResult;
    ULONG LastErrorCommandCode;
    ULONG LastErrorTpmResult;
    ULONG LastErrorCommandLength;
    ULONG LastErrorDeclaredLength;
    ULONG LastSizeErrorCommandCode;
    ULONG LastSizeErrorCommandLength;
    ULONG LastSizeErrorDeclaredLength;
    ULONG SizeErrorCount;
    ULONG LastUnsupportedCommandLength;
    UCHAR LastUnsupportedCommand[512];
    ULONG PrimaryKeyLoaded;
    ULONG PrimaryKeyPersisted;
    ULONG PrimaryAvailable;
    ULONG PersistentPublicIoctlCount;
    ULONG LastPersistentPublicStatus;
    ULONG EventLogLoaded;
    ULONG EventLogLength;
    ULONG EventLogReplayCount;
    ULONG EventLogReplayStatus;
    ULONG EventLogIoctlCount;
    ULONG LastEventLogType;
    ULONG LastEventLogOutputLength;
    ULONG LastEventLogStatus;
    ULONG LastEventLogBytesReturned;
    ULONG EventLogPartialSuccessCount;
} VTPM_BACKEND_STATUS, *PVTPM_BACKEND_STATUS;

// One entry per TPM request dispatched to user-mode
typedef struct _PENDING_REQUEST {
    LIST_ENTRY  ListEntry;
    WDFREQUEST  OriginalRequest;
    ULONG       RequestId;
} PENDING_REQUEST, *PPENDING_REQUEST;

//
// FDO device context
//
// Queue topology:
//   TpmActiveQueue  – default, Parallel  – receives TPM IOCTLs, has callback
//   TpmParkQueue    – secondary, Manual   – parks TPM requests when no helper waiting
//   CtrlWaitQueue   – global Manual       – parks GET_COMMAND requests when no TPM cmd ready
//
typedef struct _DEVICE_CONTEXT {
    WDFQUEUE    TpmActiveQueue;   // Parallel, EvtIoDeviceControl = EvtIoDeviceControlTpm
    WDFQUEUE    TpmParkQueue;     // Manual, no callbacks
    LIST_ENTRY  PendingList;      // Requests forwarded to user-mode awaiting response
    WDFWAITLOCK PendingListLock;
    WDFWAITLOCK BackendLock;
    ULONG       NextRequestId;
    struct _VTPM_BACKEND* Backend;
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, GetDeviceContext)

// Globals (defined in Driver.c)
extern WDFDEVICE       g_ControlDevice;
extern WDFQUEUE        g_CtrlActiveQueue; // Parallel queue on control device
extern WDFQUEUE        g_CtrlWaitQueue;   // Manual queue: parks waiting GET_COMMAND requests
extern PDEVICE_CONTEXT g_FdoContext;

// Driver / device callbacks
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD EvtDriverDeviceAdd;
NTSTATUS CreateControlDevice(_In_ WDFDRIVER Driver);

// IO callbacks
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControlTpm;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControlControl;
EVT_WDF_IO_QUEUE_IO_CANCELED_ON_QUEUE EvtIoCanceledOnQueue;

VOID VtpmCancelPendingRequest(PPENDING_REQUEST PendingReq, NTSTATUS Status);
EVT_WDF_FILE_CLEANUP EvtFileCleanupControl;
EVT_WDF_OBJECT_CONTEXT_CLEANUP EvtDeviceContextCleanup;
