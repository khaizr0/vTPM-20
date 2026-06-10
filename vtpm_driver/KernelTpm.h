#pragma once

#include "Backend.h"

NTSTATUS
VtpmKernelTpmInitialize(
    _Inout_ PVTPM_BACKEND Backend
    );

VOID
VtpmKernelTpmShutdown(
    _Inout_ PVTPM_BACKEND Backend
    );

NTSTATUS
VtpmKernelTpmSubmit(
    _Inout_ PVTPM_BACKEND Backend,
    _In_reads_bytes_(CommandLength) const UCHAR* Command,
    _In_ size_t CommandLength,
    _Out_writes_bytes_to_(ResponseCapacity, *ResponseLength) UCHAR* Response,
    _In_ size_t ResponseCapacity,
    _Out_ size_t* ResponseLength
    );

NTSTATUS
VtpmKernelTpmGetPersistentPublic(
    _In_ PVTPM_BACKEND Backend,
    _In_ ULONG Handle,
    _Out_writes_bytes_(Capacity) UCHAR* Response,
    _In_ size_t Capacity,
    _Out_ size_t* ResponseLength
    );
