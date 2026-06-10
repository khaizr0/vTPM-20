#include "Backend.h"
#include "KernelTpm.h"

#ifndef VTPM_ENABLE_KERNEL_BACKEND
#define VTPM_ENABLE_KERNEL_BACKEND 0
#endif

static VOID
VtpmCompleteDeviceInfo(
    _In_ WDFREQUEST Request
    )
{
    PTPM_DEVICE_INFO deviceInfo = NULL;
    size_t outputLength = 0;
    NTSTATUS status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(TPM_DEVICE_INFO),
        (PVOID*)&deviceInfo,
        &outputLength);

    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }

    RtlZeroMemory(deviceInfo, sizeof(*deviceInfo));
    deviceInfo->structVersion = 1;
    deviceInfo->tpmVersion = 2;
    deviceInfo->tpmInterfaceType = 3;
    deviceInfo->tpmImpRevision = 0;
    WdfRequestCompleteWithInformation(
        Request,
        STATUS_SUCCESS,
        sizeof(*deviceInfo));
}

NTSTATUS
VtpmBackendInitialize(
    _Out_ PVTPM_BACKEND Backend
    )
{
    RtlZeroMemory(Backend, sizeof(*Backend));
#if VTPM_ENABLE_KERNEL_BACKEND
    Backend->Role = VtpmBackendRoleKernel;
#else
    Backend->Role = VtpmBackendRoleBridge;
#endif
    Backend->Initialized = TRUE;
    if (Backend->Role == VtpmBackendRoleKernel) {
        NTSTATUS status = VtpmKernelTpmInitialize(Backend);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    KdPrint(("vTPM: Backend role=%s\n",
        Backend->Role == VtpmBackendRoleKernel ? "Kernel" : "Bridge"));
    return STATUS_SUCCESS;
}

VOID
VtpmBackendShutdown(
    _Inout_ PVTPM_BACKEND Backend
    )
{
    Backend->Initialized = FALSE;
    if (Backend->Role == VtpmBackendRoleKernel) {
        VtpmKernelTpmShutdown(Backend);
    }
}

BOOLEAN
VtpmBackendTryHandleIoctl(
    _Inout_ PVTPM_BACKEND Backend,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
{
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (!Backend->Initialized) {
        WdfRequestComplete(Request, STATUS_DEVICE_NOT_READY);
        return TRUE;
    }

    if (IoControlCode == IOCTL_TPM_GET_DEVICE_INFO) {
        VtpmCompleteDeviceInfo(Request);
        return TRUE;
    }

    if (Backend->Role == VtpmBackendRoleBridge) {
        return FALSE;
    }

    switch (IoControlCode) {
    case IOCTL_TPM_SUBMIT_COMMAND:
    case IOCTL_TPM_SUBMIT_COMMAND2: {
        PVOID input = NULL;
        PVOID output = NULL;
        size_t inputLength = 0;
        size_t outputLength = 0;
        size_t responseLength = 0;
        PUCHAR commandCopy = NULL;
        NTSTATUS status = WdfRequestRetrieveInputBuffer(
            Request, 0, &input, &inputLength);

        if (!NT_SUCCESS(status) || inputLength == 0) {
            status = WdfRequestRetrieveOutputBuffer(
                Request, 10, &output, &outputLength);
            if (NT_SUCCESS(status)) {
                input = output;
                inputLength = outputLength;
            }
        } else {
            status = WdfRequestRetrieveOutputBuffer(
                Request, 10, &output, &outputLength);
        }
        if (!NT_SUCCESS(status) || input == NULL || output == NULL) {
            WdfRequestComplete(Request, status);
            return TRUE;
        }
        if (inputLength < 10 || inputLength > 65536) {
            WdfRequestComplete(Request, STATUS_INVALID_BUFFER_SIZE);
            return TRUE;
        }

        commandCopy = (PUCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            inputLength,
            VTPM_POOL_TAG);
        if (commandCopy == NULL) {
            WdfRequestComplete(Request, STATUS_INSUFFICIENT_RESOURCES);
            return TRUE;
        }
        RtlCopyMemory(commandCopy, input, inputLength);

        WdfWaitLockAcquire(g_FdoContext->BackendLock, NULL);
        Backend->LastIoctlCode = IoControlCode;
        status = VtpmKernelTpmSubmit(
            Backend,
            commandCopy,
            inputLength,
            (UCHAR*)output,
            outputLength,
            &responseLength);
        if (NT_SUCCESS(status) && responseLength >= 10) {
            const UCHAR* responseBytes = (const UCHAR*)output;
            ULONG tpmResult =
                ((ULONG)responseBytes[6] << 24) |
                ((ULONG)responseBytes[7] << 16) |
                ((ULONG)responseBytes[8] << 8) |
                (ULONG)responseBytes[9];
            Backend->LastTpmResult = tpmResult;
            if (tpmResult != 0) {
                Backend->LastErrorCommandCode = Backend->LastCommandCode;
                Backend->LastErrorTpmResult = tpmResult;
                Backend->LastErrorCommandLength =
                    Backend->LastCommandLength;
                Backend->LastErrorDeclaredLength =
                    Backend->LastDeclaredLength;
            }
            if (tpmResult == 0x095u) {
                Backend->LastSizeErrorCommandCode =
                    Backend->LastCommandCode;
                Backend->LastSizeErrorCommandLength =
                    Backend->LastCommandLength;
                Backend->LastSizeErrorDeclaredLength =
                    Backend->LastDeclaredLength;
                ++Backend->SizeErrorCount;
            }
        }
        WdfWaitLockRelease(g_FdoContext->BackendLock);
        RtlSecureZeroMemory(commandCopy, inputLength);
        ExFreePoolWithTag(commandCopy, VTPM_POOL_TAG);
        if (NT_SUCCESS(status)) {
            WdfRequestCompleteWithInformation(
                Request, STATUS_SUCCESS, responseLength);
        } else {
            WdfRequestComplete(Request, status);
        }
        return TRUE;
    }
    case IOCTL_TPM_GET_EVENT_LOG: {
        PULONG input = NULL;
        PUCHAR output = NULL;
        size_t inputLength = 0;
        size_t outputLength = 0;
        size_t bytesToCopy = 0;
        ULONG logType;
        NTSTATUS status = WdfRequestRetrieveInputBuffer(
            Request, sizeof(ULONG), (PVOID*)&input, &inputLength);
        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(Request, status);
            return TRUE;
        }
        logType = *input;
        WdfWaitLockAcquire(g_FdoContext->BackendLock, NULL);
        ++Backend->EventLogIoctlCount;
        Backend->LastEventLogType = logType;
        Backend->LastEventLogOutputLength =
            (ULONG)min(OutputBufferLength, MAXULONG);
        /*
         * The TPM device IOCTL uses one-based log identifiers:
         * 1=SRTM current, 2=DRTM current, 3=SRTM boot,
         * 4=SRTM resume, 5=DRTM boot, 6=DRTM resume.
         */
        if ((logType != 1u && logType != 3u && logType != 4u) ||
            Backend->EventLog == NULL ||
            Backend->EventLogLength == 0) {
            Backend->LastEventLogStatus = STATUS_NOT_FOUND;
            Backend->LastEventLogBytesReturned = 0;
            WdfWaitLockRelease(g_FdoContext->BackendLock);
            WdfRequestComplete(Request, STATUS_NOT_FOUND);
            return TRUE;
        }
        if (OutputBufferLength == 0) {
            Backend->LastEventLogStatus = STATUS_BUFFER_TOO_SMALL;
            Backend->LastEventLogBytesReturned = 0;
            WdfWaitLockRelease(g_FdoContext->BackendLock);
            WdfRequestCompleteWithInformation(
                Request,
                STATUS_BUFFER_TOO_SMALL,
                Backend->EventLogLength);
            return TRUE;
        }
        bytesToCopy = min(OutputBufferLength, Backend->EventLogLength);
        WdfWaitLockRelease(g_FdoContext->BackendLock);
        status = WdfRequestRetrieveOutputBuffer(
            Request,
            bytesToCopy,
            (PVOID*)&output,
            &outputLength);
        if (!NT_SUCCESS(status)) {
            WdfWaitLockAcquire(g_FdoContext->BackendLock, NULL);
            Backend->LastEventLogStatus = status;
            Backend->LastEventLogBytesReturned = 0;
            WdfWaitLockRelease(g_FdoContext->BackendLock);
            WdfRequestComplete(Request, status);
            return TRUE;
        }
        RtlCopyMemory(
            output,
            Backend->EventLog,
            bytesToCopy);
        WdfWaitLockAcquire(g_FdoContext->BackendLock, NULL);
        Backend->LastEventLogStatus = STATUS_SUCCESS;
        Backend->LastEventLogBytesReturned = (ULONG)bytesToCopy;
        if (bytesToCopy < Backend->EventLogLength) {
            ++Backend->EventLogPartialSuccessCount;
        }
        WdfWaitLockRelease(g_FdoContext->BackendLock);
        WdfRequestCompleteWithInformation(
            Request,
            STATUS_SUCCESS,
            bytesToCopy);
        return TRUE;
    }
    case IOCTL_TPM_GET_PERSISTENT_PUBLIC: {
        PVOID input = NULL;
        PVOID output = NULL;
        size_t inputLength = 0;
        size_t outputLength = 0;
        size_t responseLength = 0;
        ULONG handle;
        NTSTATUS status = WdfRequestRetrieveInputBuffer(
            Request, sizeof(ULONG), &input, &inputLength);
        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(Request, status);
            return TRUE;
        }
        status = WdfRequestRetrieveOutputBuffer(
            Request, 1, &output, &outputLength);
        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(Request, status);
            return TRUE;
        }
        handle =
            (ULONG)((PUCHAR)input)[0] |
            ((ULONG)((PUCHAR)input)[1] << 8) |
            ((ULONG)((PUCHAR)input)[2] << 16) |
            ((ULONG)((PUCHAR)input)[3] << 24);
        WdfWaitLockAcquire(g_FdoContext->BackendLock, NULL);
        ++Backend->PersistentPublicIoctlCount;
        status = VtpmKernelTpmGetPersistentPublic(
            Backend,
            handle,
            (PUCHAR)output,
            outputLength,
            &responseLength);
        Backend->LastPersistentPublicStatus = status;
        WdfWaitLockRelease(g_FdoContext->BackendLock);
        if (NT_SUCCESS(status)) {
            WdfRequestCompleteWithInformation(
                Request,
                STATUS_SUCCESS,
                responseLength);
        } else {
            WdfRequestComplete(Request, status);
        }
        return TRUE;
    }
    default:
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
        return TRUE;
    }
}
