#pragma once

#include "vtpm.h"

typedef enum _VTPM_BACKEND_ROLE {
    VtpmBackendRoleBridge = 0,
    VtpmBackendRoleKernel = 1
} VTPM_BACKEND_ROLE;

typedef struct _VTPM_BACKEND {
    VTPM_BACKEND_ROLE Role;
    BOOLEAN Initialized;
    BOOLEAN Started;
    ULONG PcrUpdateCounter;
    ULONG LastCommandCode;
    ULONG LastUnsupportedCommandCode;
    ULONG CommandCount;
    ULONG UnsupportedCommandCount;
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
    ULONG PersistentPublicIoctlCount;
    NTSTATUS LastPersistentPublicStatus;
    PVOID EventLog;
    ULONG EventLogLength;
    ULONG EventLogReplayCount;
    NTSTATUS EventLogReplayStatus;
    ULONG EventLogIoctlCount;
    ULONG LastEventLogType;
    ULONG LastEventLogOutputLength;
    NTSTATUS LastEventLogStatus;
    ULONG LastEventLogBytesReturned;
    ULONG EventLogPartialSuccessCount;
    PVOID Sha256Algorithm;
    PVOID Sha384Algorithm;
    PVOID RsaAlgorithm;
    PVOID PrimaryKey;
    BOOLEAN PrimaryAvailable;
    USHORT PrimaryPublicSize;
    UCHAR PrimaryPublic[512];
    UCHAR PrimaryName[34];
    UCHAR PrimaryQualifiedName[34];
    ULONG Sha256ObjectLength;
    ULONG Sha384ObjectLength;
    UCHAR Sha256Pcrs[24][32];
    UCHAR Sha384Pcrs[24][48];
} VTPM_BACKEND, *PVTPM_BACKEND;

NTSTATUS
VtpmBackendInitialize(
    _Out_ PVTPM_BACKEND Backend
    );

VOID
VtpmBackendShutdown(
    _Inout_ PVTPM_BACKEND Backend
    );

BOOLEAN
VtpmBackendTryHandleIoctl(
    _Inout_ PVTPM_BACKEND Backend,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    );
