#include "KernelTpm.h"
#include <bcrypt.h>

#define TPM_ST_NO_SESSIONS          0x8001u
#define TPM_ST_SESSIONS             0x8002u
#define TBS_ST_NO_SESSIONS          0x0201u
#define TBS_ST_SESSIONS             0x0202u

#define TPM_RC_SUCCESS              0x000u
#define TPM_RC_INITIALIZE           0x100u
#define TPM_RC_COMMAND_CODE         0x143u
#define TPM_RC_SIZE                 0x095u
#define TPM_RC_VALUE                0x084u
#define TPM_RC_HASH                 0x083u
#define TPM_RC_PCR                  0x127u
#define TPM_RC_NV_HANDLE            0x18Bu

#define TPM_CC_NV_READ_PUBLIC       0x00000169u
#define TPM_CC_READ_PUBLIC          0x00000173u
#define TPM_CC_CREATE_PRIMARY       0x00000131u
#define TPM_CC_SELF_TEST            0x00000143u
#define TPM_CC_STARTUP              0x00000144u
#define TPM_CC_GET_CAPABILITY       0x0000017Au
#define TPM_CC_GET_TEST_RESULT      0x0000017Cu
#define TPM_CC_PCR_READ             0x0000017Eu
#define TPM_CC_PCR_EXTEND           0x00000182u

#define TPM_CAP_ALGS                0x00000000u
#define TPM_CAP_HANDLES             0x00000001u
#define TPM_CAP_COMMANDS            0x00000002u
#define TPM_CAP_PCRS                0x00000005u
#define TPM_CAP_TPM_PROPERTIES      0x00000006u

#define TPM_ALG_SHA256              0x000Bu
#define TPM_ALG_SHA384              0x000Cu
#define TPM_ALG_RSA                 0x0001u
#define TPM_ST_CREATION             0x8021u
#define TPM_RH_OWNER                0x40000001u
#define TPMA_ALGORITHM_HASH         0x00000004u

#define TPM_PT_FIXED                0x00000100u
#define TPM_PT_VAR                  0x00000200u

typedef struct _VTPM_PROPERTY_VALUE {
    ULONG Property;
    ULONG Value;
} VTPM_PROPERTY_VALUE;

static const VTPM_PROPERTY_VALUE g_FixedProperties[] = {
    {TPM_PT_FIXED + 0u,  0x322E3000u},
    {TPM_PT_FIXED + 1u,  0u},
    {TPM_PT_FIXED + 2u,  183u},
    {TPM_PT_FIXED + 3u,  25u},
    {TPM_PT_FIXED + 4u,  2024u},
    {TPM_PT_FIXED + 5u,  0x4D534654u},
    {TPM_PT_FIXED + 6u,  0x78434720u},
    {TPM_PT_FIXED + 7u,  0x6654504Du},
    {TPM_PT_FIXED + 8u,  0u},
    {TPM_PT_FIXED + 9u,  0u},
    {TPM_PT_FIXED + 10u, 1u},
    {TPM_PT_FIXED + 11u, 0x20240125u},
    {TPM_PT_FIXED + 12u, 0x00120000u},
    {TPM_PT_FIXED + 13u, 0x00000400u},
    {TPM_PT_FIXED + 14u, 3u},
    {TPM_PT_FIXED + 15u, 2u},
    {TPM_PT_FIXED + 16u, 3u},
    {TPM_PT_FIXED + 17u, 0x40u},
    {TPM_PT_FIXED + 18u, 24u},
    {TPM_PT_FIXED + 19u, 3u},
    {TPM_PT_FIXED + 20u, 0xFFu},
    {TPM_PT_FIXED + 22u, 0u},
    {TPM_PT_FIXED + 23u, 0x800u},
    {TPM_PT_FIXED + 24u, 6u},
    {TPM_PT_FIXED + 25u, 0x00400000u},
    {TPM_PT_FIXED + 26u, TPM_ALG_SHA384},
    {TPM_PT_FIXED + 27u, 0x00000006u},
    {TPM_PT_FIXED + 28u, 0x00000100u},
    {TPM_PT_FIXED + 29u, 0xFFu},
    {TPM_PT_FIXED + 30u, 0x00000F80u},
    {TPM_PT_FIXED + 31u, 0x00000F80u},
    {TPM_PT_FIXED + 32u, 48u},
    {TPM_PT_FIXED + 33u, 0x884u},
    {TPM_PT_FIXED + 34u, 0x144u},
    {TPM_PT_FIXED + 35u, 0u},
    {TPM_PT_FIXED + 36u, 0u},
    {TPM_PT_FIXED + 37u, 0u},
    {TPM_PT_FIXED + 38u, 0u},
    {TPM_PT_FIXED + 39u, 0u},
    {TPM_PT_FIXED + 40u, 0x80u},
    {TPM_PT_FIXED + 41u, 8u},
    {TPM_PT_FIXED + 42u, 8u},
    {TPM_PT_FIXED + 43u, 0u},
    {TPM_PT_FIXED + 44u, 0x400u},
    {TPM_PT_FIXED + 45u, 0u},
    {TPM_PT_FIXED + 46u, 0x400u},
    {TPM_PT_FIXED + 47u, 1u},
    {TPM_PT_FIXED + 48u, 1u}
};

static const VTPM_PROPERTY_VALUE g_VariableProperties[] = {
    {TPM_PT_VAR + 0u,  0x00000400u},
    {TPM_PT_VAR + 1u,  0x0000000Fu},
    {TPM_PT_VAR + 2u,  0u},
    {TPM_PT_VAR + 3u,  0u},
    {TPM_PT_VAR + 4u,  3u},
    {TPM_PT_VAR + 5u,  0u},
    {TPM_PT_VAR + 6u,  0x40u},
    {TPM_PT_VAR + 7u,  3u},
    {TPM_PT_VAR + 8u,  0u},
    {TPM_PT_VAR + 9u,  5u},
    {TPM_PT_VAR + 10u, 0u},
    {TPM_PT_VAR + 11u, 25u},
    {TPM_PT_VAR + 12u, 0xFFFFFFFFu},
    {TPM_PT_VAR + 13u, 8u},
    {TPM_PT_VAR + 14u, 0u},
    {TPM_PT_VAR + 15u, 31u},
    {TPM_PT_VAR + 16u, 600u},
    {TPM_PT_VAR + 17u, 86400u},
    {TPM_PT_VAR + 18u, 0u},
    {TPM_PT_VAR + 19u, 0u},
    {TPM_PT_VAR + 20u, 0u}
};

static const UCHAR g_EmptyCreationData[] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x20,
    0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14,
    0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
    0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C,
    0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55,
    0x08, 0x00,
    0x10, 0x00, 0x04, 0x40, 0x00, 0x00, 0x0B,
    0x00, 0x04, 0x40, 0x00, 0x00, 0x0B,
    0x00, 0x00
};

static const UCHAR g_WindowsSrkPublicTemplate[] = {
    0x00, 0x01, 0x00, 0x0B, 0x00, 0x03, 0x00, 0xB2,
    0x00, 0x20, 0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
    0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5,
    0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52,
    0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
    0x69, 0xAA, 0x00, 0x06, 0x00, 0x80, 0x00, 0x43,
    0x00, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
};

static USHORT ReadBe16(_In_reads_bytes_(2) const UCHAR* Data)
{
    return (USHORT)(((USHORT)Data[0] << 8) | Data[1]);
}

static ULONG ReadBe32(_In_reads_bytes_(4) const UCHAR* Data)
{
    return ((ULONG)Data[0] << 24) |
           ((ULONG)Data[1] << 16) |
           ((ULONG)Data[2] << 8) |
           (ULONG)Data[3];
}

static VOID WriteBe16(_Out_writes_bytes_(2) UCHAR* Data, _In_ USHORT Value)
{
    Data[0] = (UCHAR)(Value >> 8);
    Data[1] = (UCHAR)Value;
}

static VOID WriteBe32(_Out_writes_bytes_(4) UCHAR* Data, _In_ ULONG Value)
{
    Data[0] = (UCHAR)(Value >> 24);
    Data[1] = (UCHAR)(Value >> 16);
    Data[2] = (UCHAR)(Value >> 8);
    Data[3] = (UCHAR)Value;
}

static NTSTATUS WriteHeader(
    _Out_writes_bytes_(Capacity) UCHAR* Response,
    _In_ size_t Capacity,
    _In_ ULONG TpmResult,
    _In_ size_t TotalLength,
    _Out_ size_t* ResponseLength)
{
    if (TotalLength < 10 || TotalLength > MAXULONG || Capacity < TotalLength) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    WriteBe16(Response, TPM_ST_NO_SESSIONS);
    WriteBe32(Response + 2, (ULONG)TotalLength);
    WriteBe32(Response + 6, TpmResult);
    *ResponseLength = TotalLength;
    return STATUS_SUCCESS;
}

static NTSTATUS WriteResult(
    _Out_writes_bytes_(Capacity) UCHAR* Response,
    _In_ size_t Capacity,
    _In_ ULONG TpmResult,
    _Out_ size_t* ResponseLength)
{
    return WriteHeader(Response, Capacity, TpmResult, 10, ResponseLength);
}

static NTSTATUS WriteProperties(
    _In_ ULONG FirstProperty,
    _In_ ULONG RequestedCount,
    _Out_writes_bytes_(Capacity) UCHAR* Response,
    _In_ size_t Capacity,
    _Out_ size_t* ResponseLength)
{
    const VTPM_PROPERTY_VALUE* properties;
    ULONG start = 0;
    ULONG index;
    ULONG count;
    ULONG available;

    if (FirstProperty >= TPM_PT_VAR) {
        properties = g_VariableProperties;
        available = (ULONG)(
            sizeof(g_VariableProperties) /
            sizeof(g_VariableProperties[0]));
    } else {
        properties = g_FixedProperties;
        available = (ULONG)(
            sizeof(g_FixedProperties) /
            sizeof(g_FixedProperties[0]));
    }

    while (start < available &&
           properties[start].Property < FirstProperty) {
        ++start;
    }
    count = available - start;
    if (count > RequestedCount) {
        count = RequestedCount;
    }
    if (count > 32u) {
        count = 32u;
    }
    {
        NTSTATUS status = WriteHeader(
            Response, Capacity, TPM_RC_SUCCESS,
            19u + ((size_t)count * 8u), ResponseLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    Response[10] = (start + count < available) ? 1 : 0;
    WriteBe32(Response + 11, TPM_CAP_TPM_PROPERTIES);
    WriteBe32(Response + 15, count);
    for (index = 0; index < count; ++index) {
        size_t offset = 19u + ((size_t)index * 8u);
        WriteBe32(Response + offset, properties[start + index].Property);
        WriteBe32(Response + offset + 4, properties[start + index].Value);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS WritePcrs(
    _Out_writes_bytes_(Capacity) UCHAR* Response,
    _In_ size_t Capacity,
    _Out_ size_t* ResponseLength)
{
    NTSTATUS status = WriteHeader(
        Response, Capacity, TPM_RC_SUCCESS, 31, ResponseLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    Response[10] = 0;
    WriteBe32(Response + 11, TPM_CAP_PCRS);
    WriteBe32(Response + 15, 2);
    WriteBe16(Response + 19, TPM_ALG_SHA256);
    Response[21] = 3;
    RtlFillMemory(Response + 22, 3, 0xFF);
    WriteBe16(Response + 25, TPM_ALG_SHA384);
    Response[27] = 3;
    RtlFillMemory(Response + 28, 3, 0xFF);
    return STATUS_SUCCESS;
}

static NTSTATUS WriteAlgorithms(
    _Out_writes_bytes_(Capacity) UCHAR* Response,
    _In_ size_t Capacity,
    _Out_ size_t* ResponseLength)
{
    NTSTATUS status = WriteHeader(
        Response, Capacity, TPM_RC_SUCCESS, 31, ResponseLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    Response[10] = 0;
    WriteBe32(Response + 11, TPM_CAP_ALGS);
    WriteBe32(Response + 15, 2);
    WriteBe16(Response + 19, TPM_ALG_SHA256);
    WriteBe32(Response + 21, TPMA_ALGORITHM_HASH);
    WriteBe16(Response + 25, TPM_ALG_SHA384);
    WriteBe32(Response + 27, TPMA_ALGORITHM_HASH);
    return STATUS_SUCCESS;
}

static NTSTATUS WriteEmptyCapability(
    _In_ ULONG Capability,
    _Out_writes_bytes_(Capacity) UCHAR* Response,
    _In_ size_t Capacity,
    _Out_ size_t* ResponseLength)
{
    NTSTATUS status = WriteHeader(
        Response, Capacity, TPM_RC_SUCCESS, 19, ResponseLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    Response[10] = 0;
    WriteBe32(Response + 11, Capability);
    WriteBe32(Response + 15, 0);
    return STATUS_SUCCESS;
}

static NTSTATUS WriteHandles(
    _In_ PVTPM_BACKEND Backend,
    _In_ ULONG FirstHandle,
    _Out_writes_bytes_(Capacity) UCHAR* Response,
    _In_ size_t Capacity,
    _Out_ size_t* ResponseLength)
{
    ULONG count =
        Backend->PrimaryAvailable && FirstHandle <= 0x81000001u ? 1u : 0u;
    NTSTATUS status = WriteHeader(
        Response,
        Capacity,
        TPM_RC_SUCCESS,
        19u + ((size_t)count * 4u),
        ResponseLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    Response[10] = 0;
    WriteBe32(Response + 11, TPM_CAP_HANDLES);
    WriteBe32(Response + 15, count);
    if (count != 0) {
        WriteBe32(Response + 19, 0x81000001u);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS WriteReadPublicPayload(
    _In_ PVTPM_BACKEND Backend,
    _Out_writes_bytes_(Capacity) UCHAR* Response,
    _In_ size_t Capacity,
    _Out_ size_t* ResponseLength,
    _In_ BOOLEAN IncludeHeader)
{
    size_t payloadLength =
        2u + Backend->PrimaryPublicSize +
        2u + sizeof(Backend->PrimaryName) +
        2u + sizeof(Backend->PrimaryQualifiedName);
    size_t offset = IncludeHeader ? 10u : 0u;

    if (!Backend->PrimaryAvailable) {
        return IncludeHeader
            ? WriteResult(Response, Capacity, TPM_RC_NV_HANDLE, ResponseLength)
            : STATUS_NOT_FOUND;
    }
    if (Capacity < offset + payloadLength) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (IncludeHeader) {
        NTSTATUS status = WriteHeader(
            Response,
            Capacity,
            TPM_RC_SUCCESS,
            10u + payloadLength,
            ResponseLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    WriteBe16(Response + offset, Backend->PrimaryPublicSize);
    offset += 2;
    RtlCopyMemory(
        Response + offset,
        Backend->PrimaryPublic,
        Backend->PrimaryPublicSize);
    offset += Backend->PrimaryPublicSize;
    WriteBe16(Response + offset, (USHORT)sizeof(Backend->PrimaryName));
    offset += 2;
    RtlCopyMemory(
        Response + offset,
        Backend->PrimaryName,
        sizeof(Backend->PrimaryName));
    offset += sizeof(Backend->PrimaryName);
    WriteBe16(
        Response + offset,
        (USHORT)sizeof(Backend->PrimaryQualifiedName));
    offset += 2;
    RtlCopyMemory(
        Response + offset,
        Backend->PrimaryQualifiedName,
        sizeof(Backend->PrimaryQualifiedName));
    offset += sizeof(Backend->PrimaryQualifiedName);
    *ResponseLength = offset;
    return STATUS_SUCCESS;
}

NTSTATUS VtpmKernelTpmGetPersistentPublic(
    _In_ PVTPM_BACKEND Backend,
    _In_ ULONG Handle,
    _Out_writes_bytes_(Capacity) UCHAR* Response,
    _In_ size_t Capacity,
    _Out_ size_t* ResponseLength)
{
    if (Handle != 0x81000001u) {
        return STATUS_NOT_FOUND;
    }
    return WriteReadPublicPayload(
        Backend,
        Response,
        Capacity,
        ResponseLength,
        FALSE);
}

static NTSTATUS WritePcrRead(
    _In_ PVTPM_BACKEND Backend,
    _In_reads_bytes_(CommandLength) const UCHAR* Command,
    _In_ size_t CommandLength,
    _Out_writes_bytes_(Capacity) UCHAR* Response,
    _In_ size_t Capacity,
    _Out_ size_t* ResponseLength)
{
    ULONG selectionCount;
    ULONG selectionIndex;
    ULONG digestCount = 0;
    size_t commandOffset = 10;
    size_t selectionBytes = 4;
    size_t responseOffset;

    if (CommandLength < commandOffset + 4) {
        return WriteResult(
            Response, Capacity, TPM_RC_SIZE, ResponseLength);
    }
    selectionCount = ReadBe32(Command + commandOffset);
    commandOffset += 4;
    if (selectionCount == 0 || selectionCount > 2) {
        return WriteResult(
            Response, Capacity, TPM_RC_VALUE, ResponseLength);
    }

    for (selectionIndex = 0; selectionIndex < selectionCount; ++selectionIndex) {
        UCHAR selectSize;
        ULONG byteIndex;
        if (CommandLength < commandOffset + 3) {
            return WriteResult(
                Response, Capacity, TPM_RC_SIZE, ResponseLength);
        }
        selectSize = Command[commandOffset + 2];
        if (selectSize == 0 || selectSize > 3 ||
            CommandLength < commandOffset + 3u + selectSize) {
            return WriteResult(
                Response, Capacity, TPM_RC_SIZE, ResponseLength);
        }
        selectionBytes += 3u + selectSize;
        for (byteIndex = 0; byteIndex < selectSize; ++byteIndex) {
            UCHAR bits = Command[commandOffset + 3u + byteIndex];
            while (bits != 0) {
                digestCount += bits & 1u;
                bits >>= 1;
            }
        }
        commandOffset += 3u + selectSize;
    }
    if (commandOffset != CommandLength) {
        return WriteResult(
            Response, Capacity, TPM_RC_SIZE, ResponseLength);
    }

    {
        size_t digestBytes = 0;
        commandOffset = 14;
        for (selectionIndex = 0; selectionIndex < selectionCount; ++selectionIndex) {
            USHORT algorithm = ReadBe16(Command + commandOffset);
            UCHAR selectSize = Command[commandOffset + 2];
            ULONG selected = 0;
            ULONG byteIndex;
            for (byteIndex = 0; byteIndex < selectSize; ++byteIndex) {
                UCHAR bits = Command[commandOffset + 3u + byteIndex];
                while (bits != 0) {
                    selected += bits & 1u;
                    bits >>= 1;
                }
            }
            if (algorithm == TPM_ALG_SHA256) {
                digestBytes += (size_t)selected * 34u;
            } else if (algorithm == TPM_ALG_SHA384) {
                digestBytes += (size_t)selected * 50u;
            } else {
                return WriteResult(
                    Response, Capacity, TPM_RC_VALUE, ResponseLength);
            }
            commandOffset += 3u + selectSize;
        }
        if (!NT_SUCCESS(WriteHeader(
                Response,
                Capacity,
                TPM_RC_SUCCESS,
                10u + 4u + selectionBytes + 4u + digestBytes,
                ResponseLength))) {
            return STATUS_BUFFER_TOO_SMALL;
        }
    }

    WriteBe32(Response + 10, Backend->PcrUpdateCounter);
    RtlCopyMemory(Response + 14, Command + 10, selectionBytes);
    responseOffset = 14u + selectionBytes;
    WriteBe32(Response + responseOffset, digestCount);
    responseOffset += 4;

    commandOffset = 14;
    for (selectionIndex = 0; selectionIndex < selectionCount; ++selectionIndex) {
        USHORT algorithm = ReadBe16(Command + commandOffset);
        UCHAR selectSize = Command[commandOffset + 2];
        ULONG byteIndex;
        for (byteIndex = 0; byteIndex < selectSize; ++byteIndex) {
            UCHAR bits = Command[commandOffset + 3u + byteIndex];
            ULONG bitIndex;
            for (bitIndex = 0; bitIndex < 8; ++bitIndex) {
                ULONG pcrIndex = (byteIndex * 8u) + bitIndex;
                if ((bits & (1u << bitIndex)) == 0 || pcrIndex >= 24) {
                    continue;
                }
                if (algorithm == TPM_ALG_SHA256) {
                    WriteBe16(Response + responseOffset, 32);
                    responseOffset += 2;
                    RtlCopyMemory(
                        Response + responseOffset,
                        Backend->Sha256Pcrs[pcrIndex],
                        32);
                    responseOffset += 32;
                } else {
                    WriteBe16(Response + responseOffset, 48);
                    responseOffset += 2;
                    RtlCopyMemory(
                        Response + responseOffset,
                        Backend->Sha384Pcrs[pcrIndex],
                        48);
                    responseOffset += 48;
                }
            }
        }
        commandOffset += 3u + selectSize;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS OpenHashAlgorithm(
    _In_ LPCWSTR AlgorithmName,
    _Out_ PVOID* Algorithm,
    _Out_ ULONG* ObjectLength)
{
    BCRYPT_ALG_HANDLE handle = NULL;
    ULONG bytesWritten = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &handle,
        AlgorithmName,
        NULL,
        BCRYPT_PROV_DISPATCH);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = BCryptGetProperty(
        handle,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)ObjectLength,
        sizeof(*ObjectLength),
        &bytesWritten,
        0);
    if (!NT_SUCCESS(status) || bytesWritten != sizeof(*ObjectLength)) {
        BCryptCloseAlgorithmProvider(handle, 0);
        return NT_SUCCESS(status) ? STATUS_INVALID_BUFFER_SIZE : status;
    }
    *Algorithm = handle;
    return STATUS_SUCCESS;
}

static NTSTATUS HashExtendValue(
    _In_ PVOID Algorithm,
    _In_ ULONG ObjectLength,
    _In_reads_bytes_(DigestLength) const UCHAR* Current,
    _In_reads_bytes_(DigestLength) const UCHAR* EventDigest,
    _In_ ULONG DigestLength,
    _Out_writes_bytes_(DigestLength) UCHAR* Extended)
{
    BCRYPT_HASH_HANDLE hash = NULL;
    PUCHAR hashObject = NULL;
    NTSTATUS status;

    hashObject = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        ObjectLength,
        VTPM_POOL_TAG);
    if (hashObject == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = BCryptCreateHash(
        (BCRYPT_ALG_HANDLE)Algorithm,
        &hash,
        hashObject,
        ObjectLength,
        NULL,
        0,
        0);
    if (NT_SUCCESS(status)) {
        status = BCryptHashData(hash, (PUCHAR)Current, DigestLength, 0);
    }
    if (NT_SUCCESS(status)) {
        status = BCryptHashData(hash, (PUCHAR)EventDigest, DigestLength, 0);
    }
    if (NT_SUCCESS(status)) {
        status = BCryptFinishHash(hash, Extended, DigestLength, 0);
    }

    if (hash != NULL) {
        BCryptDestroyHash(hash);
    }
    RtlSecureZeroMemory(hashObject, ObjectLength);
    ExFreePoolWithTag(hashObject, VTPM_POOL_TAG);
    return status;
}

static NTSTATUS HashBuffer(
    _In_ PVOID Algorithm,
    _In_ ULONG ObjectLength,
    _In_reads_bytes_(DataLength) const UCHAR* Data,
    _In_ ULONG DataLength,
    _Out_writes_bytes_(DigestLength) UCHAR* Digest,
    _In_ ULONG DigestLength)
{
    BCRYPT_HASH_HANDLE hash = NULL;
    PUCHAR hashObject = NULL;
    NTSTATUS status;

    hashObject = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        ObjectLength,
        VTPM_POOL_TAG);
    if (hashObject == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = BCryptCreateHash(
        (BCRYPT_ALG_HANDLE)Algorithm,
        &hash,
        hashObject,
        ObjectLength,
        NULL,
        0,
        0);
    if (NT_SUCCESS(status)) {
        status = BCryptHashData(hash, (PUCHAR)Data, DataLength, 0);
    }
    if (NT_SUCCESS(status)) {
        status = BCryptFinishHash(hash, Digest, DigestLength, 0);
    }
    if (hash != NULL) {
        BCryptDestroyHash(hash);
    }
    RtlSecureZeroMemory(hashObject, ObjectLength);
    ExFreePoolWithTag(hashObject, VTPM_POOL_TAG);
    return status;
}

static NTSTATUS WritePcrExtend(
    _Inout_ PVTPM_BACKEND Backend,
    _In_ USHORT Tag,
    _In_reads_bytes_(CommandLength) const UCHAR* Command,
    _In_ size_t CommandLength,
    _Out_writes_bytes_(Capacity) UCHAR* Response,
    _In_ size_t Capacity,
    _Out_ size_t* ResponseLength)
{
    ULONG pcrIndex;
    ULONG digestCount;
    ULONG digestIndex;
    size_t offset = 14;
    BOOLEAN hasSha256 = FALSE;
    BOOLEAN hasSha384 = FALSE;
    UCHAR sha256Value[32];
    UCHAR sha384Value[48];

    if (CommandLength < 18) {
        return WriteResult(
            Response, Capacity, TPM_RC_SIZE, ResponseLength);
    }
    pcrIndex = ReadBe32(Command + 10);
    if (pcrIndex >= 24) {
        return WriteResult(
            Response, Capacity, TPM_RC_PCR, ResponseLength);
    }

    if (Tag == TPM_ST_SESSIONS || Tag == TBS_ST_SESSIONS) {
        ULONG authorizationSize = ReadBe32(Command + 14);
        if (authorizationSize > CommandLength - 18u) {
            return WriteResult(
                Response, Capacity, TPM_RC_SIZE, ResponseLength);
        }
        offset = 18u + authorizationSize;
    }
    if (CommandLength < offset + 4) {
        return WriteResult(
            Response, Capacity, TPM_RC_SIZE, ResponseLength);
    }

    digestCount = ReadBe32(Command + offset);
    offset += 4;
    if (digestCount == 0 || digestCount > 2) {
        return WriteResult(
            Response, Capacity, TPM_RC_VALUE, ResponseLength);
    }

    RtlCopyMemory(sha256Value, Backend->Sha256Pcrs[pcrIndex], 32);
    RtlCopyMemory(sha384Value, Backend->Sha384Pcrs[pcrIndex], 48);
    for (digestIndex = 0; digestIndex < digestCount; ++digestIndex) {
        USHORT algorithm;
        ULONG digestLength;
        PVOID provider;
        ULONG objectLength;
        UCHAR* stagedValue;
        NTSTATUS status;

        if (CommandLength < offset + 2) {
            return WriteResult(
                Response, Capacity, TPM_RC_SIZE, ResponseLength);
        }
        algorithm = ReadBe16(Command + offset);
        offset += 2;
        if (algorithm == TPM_ALG_SHA256 && !hasSha256) {
            digestLength = 32;
            provider = Backend->Sha256Algorithm;
            objectLength = Backend->Sha256ObjectLength;
            stagedValue = sha256Value;
            hasSha256 = TRUE;
        } else if (algorithm == TPM_ALG_SHA384 && !hasSha384) {
            digestLength = 48;
            provider = Backend->Sha384Algorithm;
            objectLength = Backend->Sha384ObjectLength;
            stagedValue = sha384Value;
            hasSha384 = TRUE;
        } else {
            return WriteResult(
                Response, Capacity, TPM_RC_HASH, ResponseLength);
        }
        if (CommandLength < offset + digestLength) {
            return WriteResult(
                Response, Capacity, TPM_RC_SIZE, ResponseLength);
        }

        status = HashExtendValue(
            provider,
            objectLength,
            stagedValue,
            Command + offset,
            digestLength,
            stagedValue);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        offset += digestLength;
    }
    if (offset != CommandLength) {
        return WriteResult(
            Response, Capacity, TPM_RC_SIZE, ResponseLength);
    }

    if (hasSha256) {
        RtlCopyMemory(Backend->Sha256Pcrs[pcrIndex], sha256Value, 32);
    }
    if (hasSha384) {
        RtlCopyMemory(Backend->Sha384Pcrs[pcrIndex], sha384Value, 48);
    }
    ++Backend->PcrUpdateCounter;
    return WriteResult(
        Response, Capacity, TPM_RC_SUCCESS, ResponseLength);
}

static USHORT ReadLe16(_In_reads_bytes_(2) const UCHAR* Data)
{
    return (USHORT)((USHORT)Data[0] | ((USHORT)Data[1] << 8));
}

static ULONG ReadLe32(_In_reads_bytes_(4) const UCHAR* Data)
{
    return (ULONG)Data[0] |
        ((ULONG)Data[1] << 8) |
        ((ULONG)Data[2] << 16) |
        ((ULONG)Data[3] << 24);
}

static NTSTATUS ReplayEventLog(_Inout_ PVTPM_BACKEND Backend)
{
    typedef struct _VTPM_WBCL_ALGORITHM {
        USHORT Id;
        USHORT Size;
    } VTPM_WBCL_ALGORITHM;
    VTPM_WBCL_ALGORITHM algorithms[64];
    const UCHAR* log = (const UCHAR*)Backend->EventLog;
    size_t length = Backend->EventLogLength;
    size_t offset = 0;
    size_t specOffset;
    size_t specEnd;
    ULONG specSize;
    ULONG algorithmCount;
    ULONG index;

    if (log == NULL || length < 32u) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    if (ReadLe32(log + 4) != 3u) {
        return STATUS_INVALID_PARAMETER;
    }
    specSize = ReadLe32(log + 28);
    specOffset = 32u;
    specEnd = specOffset + specSize;
    if (specEnd > length || specSize < 29u ||
        RtlCompareMemory(
            log + specOffset,
            "Spec ID Event03",
            15) != 15u) {
        return STATUS_INVALID_PARAMETER;
    }
    algorithmCount = ReadLe32(log + specOffset + 24u);
    offset = specOffset + 28u;
    if (algorithmCount == 0u || algorithmCount > 64u ||
        offset + algorithmCount * 4u + 1u > specEnd) {
        return STATUS_INVALID_PARAMETER;
    }
    for (index = 0; index < algorithmCount; ++index) {
        algorithms[index].Id = ReadLe16(log + offset);
        algorithms[index].Size = ReadLe16(log + offset + 2u);
        if (algorithms[index].Size == 0u ||
            algorithms[index].Size > 128u) {
            return STATUS_INVALID_PARAMETER;
        }
        offset += 4u;
    }
    if (offset + 1u + log[offset] != specEnd) {
        return STATUS_INVALID_PARAMETER;
    }

    offset = specEnd;
    while (offset < length) {
        ULONG pcrIndex;
        ULONG eventType;
        ULONG digestCount;
        ULONG digestIndex;
        ULONG eventSize;
        BOOLEAN extended = FALSE;

        if (length - offset < 12u) {
            return STATUS_INVALID_BUFFER_SIZE;
        }
        pcrIndex = ReadLe32(log + offset);
        eventType = ReadLe32(log + offset + 4u);
        digestCount = ReadLe32(log + offset + 8u);
        offset += 12u;
        if (pcrIndex >= 24u ||
            digestCount == 0u ||
            digestCount > 64u) {
            return STATUS_INVALID_PARAMETER;
        }
        for (digestIndex = 0;
             digestIndex < digestCount;
             ++digestIndex) {
            USHORT algorithmId;
            USHORT digestSize = 0;
            ULONG algorithmIndex;
            NTSTATUS status;

            if (length - offset < 2u) {
                return STATUS_INVALID_BUFFER_SIZE;
            }
            algorithmId = ReadLe16(log + offset);
            offset += 2u;
            for (algorithmIndex = 0;
                 algorithmIndex < algorithmCount;
                 ++algorithmIndex) {
                if (algorithms[algorithmIndex].Id == algorithmId) {
                    digestSize = algorithms[algorithmIndex].Size;
                    break;
                }
            }
            if (digestSize == 0u || length - offset < digestSize) {
                return STATUS_INVALID_BUFFER_SIZE;
            }
            if (eventType != 3u && algorithmId == TPM_ALG_SHA256 &&
                digestSize == 32u) {
                status = HashExtendValue(
                    Backend->Sha256Algorithm,
                    Backend->Sha256ObjectLength,
                    Backend->Sha256Pcrs[pcrIndex],
                    log + offset,
                    32u,
                    Backend->Sha256Pcrs[pcrIndex]);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                extended = TRUE;
            } else if (
                eventType != 3u &&
                algorithmId == TPM_ALG_SHA384 &&
                digestSize == 48u) {
                status = HashExtendValue(
                    Backend->Sha384Algorithm,
                    Backend->Sha384ObjectLength,
                    Backend->Sha384Pcrs[pcrIndex],
                    log + offset,
                    48u,
                    Backend->Sha384Pcrs[pcrIndex]);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                extended = TRUE;
            }
            offset += digestSize;
        }
        if (length - offset < 4u) {
            return STATUS_INVALID_BUFFER_SIZE;
        }
        eventSize = ReadLe32(log + offset);
        offset += 4u;
        if (length - offset < eventSize) {
            return STATUS_INVALID_BUFFER_SIZE;
        }
        offset += eventSize;
        if (extended) {
            ++Backend->EventLogReplayCount;
            ++Backend->PcrUpdateCounter;
        }
    }
    return STATUS_SUCCESS;
}

static NTSTATUS LoadEventLog(_Inout_ PVTPM_BACKEND Backend)
{
    DECLARE_CONST_UNICODE_STRING(valueName, L"SrtmEventLog");
    WDFKEY registryKey = NULL;
    PUCHAR log = NULL;
    ULONG logLength = 0;
    ULONG valueType = 0;
    NTSTATUS status;

    status = WdfDriverOpenParametersRegistryKey(
        WdfGetDriver(),
        KEY_READ,
        WDF_NO_OBJECT_ATTRIBUTES,
        &registryKey);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = WdfRegistryQueryValue(
        registryKey,
        &valueName,
        0,
        NULL,
        &logLength,
        &valueType);
    if ((status != STATUS_BUFFER_TOO_SMALL &&
         status != STATUS_BUFFER_OVERFLOW) ||
        valueType != REG_BINARY ||
        logLength < 32u ||
        logLength > 1024u * 1024u) {
        WdfRegistryClose(registryKey);
        return NT_SUCCESS(status) ?
            STATUS_INVALID_BUFFER_SIZE : status;
    }
    log = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        logLength,
        VTPM_POOL_TAG);
    if (log == NULL) {
        WdfRegistryClose(registryKey);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = WdfRegistryQueryValue(
        registryKey,
        &valueName,
        logLength,
        log,
        &logLength,
        &valueType);
    WdfRegistryClose(registryKey);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(log, VTPM_POOL_TAG);
        return status;
    }
    Backend->EventLog = log;
    Backend->EventLogLength = logLength;
    return STATUS_SUCCESS;
}

static NTSTATUS LoadPrimaryKey(_Inout_ PVTPM_BACKEND Backend)
{
    DECLARE_CONST_UNICODE_STRING(
        valueName,
        L"PrimaryRsaPrivateBlob");
    WDFKEY registryKey = NULL;
    PUCHAR blob = NULL;
    ULONG blobLength = 0;
    ULONG valueType = 0;
    BCRYPT_KEY_HANDLE key = NULL;
    NTSTATUS status;

    status = WdfDriverOpenParametersRegistryKey(
        WdfGetDriver(),
        KEY_READ,
        WDF_NO_OBJECT_ATTRIBUTES,
        &registryKey);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfRegistryQueryValue(
        registryKey,
        &valueName,
        0,
        NULL,
        &blobLength,
        &valueType);
    if (status != STATUS_BUFFER_TOO_SMALL &&
        status != STATUS_BUFFER_OVERFLOW) {
        WdfRegistryClose(registryKey);
        return status;
    }
    if (valueType != REG_BINARY ||
        blobLength < sizeof(BCRYPT_RSAKEY_BLOB) ||
        blobLength > 4096u) {
        WdfRegistryClose(registryKey);
        return STATUS_INVALID_BUFFER_SIZE;
    }

    blob = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        blobLength,
        VTPM_POOL_TAG);
    if (blob == NULL) {
        WdfRegistryClose(registryKey);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = WdfRegistryQueryValue(
        registryKey,
        &valueName,
        blobLength,
        blob,
        &blobLength,
        &valueType);
    WdfRegistryClose(registryKey);
    if (NT_SUCCESS(status)) {
        status = BCryptImportKeyPair(
            (BCRYPT_ALG_HANDLE)Backend->RsaAlgorithm,
            NULL,
            BCRYPT_RSAPRIVATE_BLOB,
            &key,
            blob,
            blobLength,
            0);
    }
    RtlSecureZeroMemory(blob, blobLength);
    ExFreePoolWithTag(blob, VTPM_POOL_TAG);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Backend->PrimaryKey = key;
    Backend->PrimaryKeyLoaded = 1;
    Backend->PrimaryKeyPersisted = 1;
    return STATUS_SUCCESS;
}

static NTSTATUS SavePrimaryKey(
    _Inout_ PVTPM_BACKEND Backend,
    _In_ BCRYPT_KEY_HANDLE Key)
{
    DECLARE_CONST_UNICODE_STRING(
        valueName,
        L"PrimaryRsaPrivateBlob");
    WDFKEY registryKey = NULL;
    PUCHAR blob = NULL;
    ULONG blobLength = 0;
    ULONG bytesWritten = 0;
    NTSTATUS status;

    status = BCryptExportKey(
        Key,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        NULL,
        0,
        &blobLength,
        0);
    if (!NT_SUCCESS(status) || blobLength > 4096u) {
        return NT_SUCCESS(status) ?
            STATUS_INVALID_BUFFER_SIZE : status;
    }
    blob = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        blobLength,
        VTPM_POOL_TAG);
    if (blob == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = BCryptExportKey(
        Key,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        blob,
        blobLength,
        &bytesWritten,
        0);
    if (NT_SUCCESS(status)) {
        status = WdfDriverOpenParametersRegistryKey(
            WdfGetDriver(),
            KEY_WRITE,
            WDF_NO_OBJECT_ATTRIBUTES,
            &registryKey);
    }
    if (NT_SUCCESS(status)) {
        status = WdfRegistryAssignValue(
            registryKey,
            &valueName,
            REG_BINARY,
            bytesWritten,
            blob);
    }
    if (registryKey != NULL) {
        WdfRegistryClose(registryKey);
    }
    RtlSecureZeroMemory(blob, blobLength);
    ExFreePoolWithTag(blob, VTPM_POOL_TAG);
    if (NT_SUCCESS(status)) {
        Backend->PrimaryKeyPersisted = 1;
    }
    return status;
}

static NTSTATUS WriteCreatePrimary(
    _Inout_ PVTPM_BACKEND Backend,
    _In_reads_bytes_(CommandLength) const UCHAR* Command,
    _In_ size_t CommandLength,
    _Out_writes_bytes_(Capacity) UCHAR* Response,
    _In_ size_t Capacity,
    _Out_ size_t* ResponseLength)
{
    BCRYPT_KEY_HANDLE key = NULL;
    BOOLEAN generatedKey = FALSE;
    PUCHAR publicBlob = NULL;
    ULONG publicBlobLength = 0;
    ULONG bytesWritten = 0;
    ULONG authSize;
    USHORT sensitiveSize;
    USHORT publicSize;
    USHORT outputPublicSize;
    size_t offset;
    size_t publicOffset;
    size_t uniqueSizeOffset;
    size_t uniqueOffset;
    size_t parametersLength;
    size_t responseOffset;
    UCHAR publicArea[512];
    UCHAR nameDigest[32];
    UCHAR creationHash[32];
    UCHAR qualifiedNameInput[38];
    NTSTATUS status;

    if (CommandLength < 24 || ReadBe32(Command + 10) != TPM_RH_OWNER) {
        return WriteResult(Response, Capacity, TPM_RC_VALUE, ResponseLength);
    }
    authSize = ReadBe32(Command + 14);
    if (authSize > CommandLength - 18u) {
        return WriteResult(Response, Capacity, TPM_RC_SIZE, ResponseLength);
    }
    offset = 18u + authSize;
    if (CommandLength < offset + 2) {
        return WriteResult(Response, Capacity, TPM_RC_SIZE, ResponseLength);
    }
    sensitiveSize = ReadBe16(Command + offset);
    offset += 2u + sensitiveSize;
    if (offset > CommandLength || CommandLength < offset + 2) {
        return WriteResult(Response, Capacity, TPM_RC_SIZE, ResponseLength);
    }
    publicSize = ReadBe16(Command + offset);
    publicOffset = offset + 2u;
    if (publicSize > sizeof(publicArea) - 256u ||
        CommandLength < publicOffset + publicSize ||
        publicSize < 58) {
        return WriteResult(Response, Capacity, TPM_RC_SIZE, ResponseLength);
    }
    RtlCopyMemory(publicArea, Command + publicOffset, publicSize);
    if (ReadBe16(publicArea) != TPM_ALG_RSA ||
        ReadBe16(publicArea + 2) != TPM_ALG_SHA256) {
        return WriteResult(Response, Capacity, TPM_RC_VALUE, ResponseLength);
    }

    uniqueSizeOffset = publicSize - 2u;
    uniqueOffset = publicSize;
    if (ReadBe16(publicArea + uniqueSizeOffset) != 0u) {
        return WriteResult(Response, Capacity, TPM_RC_VALUE, ResponseLength);
    }
    outputPublicSize = (USHORT)(publicSize + 256u);
    WriteBe16(publicArea + uniqueSizeOffset, 256u);

    key = (BCRYPT_KEY_HANDLE)Backend->PrimaryKey;
    status = STATUS_SUCCESS;
    if (key == NULL) {
        status = BCryptGenerateKeyPair(
            (BCRYPT_ALG_HANDLE)Backend->RsaAlgorithm,
            &key,
            2048,
            0);
        generatedKey = NT_SUCCESS(status);
        if (NT_SUCCESS(status)) {
            status = BCryptFinalizeKeyPair(key, 0);
        }
    }
    if (NT_SUCCESS(status)) {
        status = BCryptExportKey(
            key,
            NULL,
            BCRYPT_RSAPUBLIC_BLOB,
            NULL,
            0,
            &publicBlobLength,
            0);
    }
    if (NT_SUCCESS(status)) {
        publicBlob = (PUCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            publicBlobLength,
            VTPM_POOL_TAG);
        if (publicBlob == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    if (NT_SUCCESS(status)) {
        status = BCryptExportKey(
            key,
            NULL,
            BCRYPT_RSAPUBLIC_BLOB,
            publicBlob,
            publicBlobLength,
            &bytesWritten,
            0);
    }
    if (NT_SUCCESS(status)) {
        BCRYPT_RSAKEY_BLOB* rsaBlob = (BCRYPT_RSAKEY_BLOB*)publicBlob;
        PUCHAR modulus = publicBlob + sizeof(*rsaBlob) + rsaBlob->cbPublicExp;
        if (rsaBlob->Magic != BCRYPT_RSAPUBLIC_MAGIC ||
            rsaBlob->cbModulus != 256u ||
            bytesWritten < sizeof(*rsaBlob) +
                rsaBlob->cbPublicExp + rsaBlob->cbModulus) {
            status = STATUS_INVALID_BUFFER_SIZE;
        } else {
            RtlCopyMemory(publicArea + uniqueOffset, modulus, 256);
        }
    }
    if (publicBlob != NULL) {
        RtlSecureZeroMemory(publicBlob, publicBlobLength);
        ExFreePoolWithTag(publicBlob, VTPM_POOL_TAG);
    }
    if (!NT_SUCCESS(status)) {
        if (generatedKey && key != NULL) {
            BCryptDestroyKey(key);
        }
        return status;
    }

    status = HashBuffer(
        Backend->Sha256Algorithm,
        Backend->Sha256ObjectLength,
        publicArea,
        outputPublicSize,
        nameDigest,
        sizeof(nameDigest));
    if (!NT_SUCCESS(status)) {
        if (generatedKey) {
            BCryptDestroyKey(key);
        }
        return status;
    }
    WriteBe32(qualifiedNameInput, TPM_RH_OWNER);
    WriteBe16(qualifiedNameInput + 4, TPM_ALG_SHA256);
    RtlCopyMemory(qualifiedNameInput + 6, nameDigest, 32);
    status = HashBuffer(
        Backend->Sha256Algorithm,
        Backend->Sha256ObjectLength,
        qualifiedNameInput,
        sizeof(qualifiedNameInput),
        Backend->PrimaryQualifiedName + 2,
        32);
    if (!NT_SUCCESS(status)) {
        if (generatedKey) {
            BCryptDestroyKey(key);
        }
        return status;
    }
    status = HashBuffer(
        Backend->Sha256Algorithm,
        Backend->Sha256ObjectLength,
        g_EmptyCreationData,
        sizeof(g_EmptyCreationData),
        creationHash,
        sizeof(creationHash));
    if (!NT_SUCCESS(status)) {
        if (generatedKey) {
            BCryptDestroyKey(key);
        }
        return status;
    }

    parametersLength =
        2u + outputPublicSize +  /* outPublic */
        2u + sizeof(g_EmptyCreationData) +
        2u + sizeof(creationHash) +
        2u + 4u + 2u +     /* empty creationTicket */
        2u + 2u + 32u;     /* name */
    if (Capacity < 18u + parametersLength + 5u) {
        if (generatedKey) {
            BCryptDestroyKey(key);
        }
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (generatedKey) {
        status = SavePrimaryKey(Backend, key);
        if (!NT_SUCCESS(status)) {
            BCryptDestroyKey(key);
            return status;
        }
        Backend->PrimaryKey = key;
    }
    Backend->PrimaryAvailable = TRUE;
    Backend->PrimaryPublicSize = outputPublicSize;
    RtlCopyMemory(
        Backend->PrimaryPublic,
        publicArea,
        outputPublicSize);
    WriteBe16(Backend->PrimaryName, TPM_ALG_SHA256);
    RtlCopyMemory(Backend->PrimaryName + 2, nameDigest, 32);
    WriteBe16(Backend->PrimaryQualifiedName, TPM_ALG_SHA256);

    WriteBe16(Response, TPM_ST_SESSIONS);
    WriteBe32(Response + 2, (ULONG)(18u + parametersLength + 5u));
    WriteBe32(Response + 6, TPM_RC_SUCCESS);
    WriteBe32(Response + 10, 0x80000000u);
    WriteBe32(Response + 14, (ULONG)parametersLength);
    responseOffset = 18;
    WriteBe16(Response + responseOffset, outputPublicSize);
    responseOffset += 2;
    RtlCopyMemory(
        Response + responseOffset,
        publicArea,
        outputPublicSize);
    responseOffset += outputPublicSize;
    WriteBe16(
        Response + responseOffset,
        (USHORT)sizeof(g_EmptyCreationData));
    responseOffset += 2;
    RtlCopyMemory(
        Response + responseOffset,
        g_EmptyCreationData,
        sizeof(g_EmptyCreationData));
    responseOffset += sizeof(g_EmptyCreationData);
    WriteBe16(Response + responseOffset, (USHORT)sizeof(creationHash));
    responseOffset += 2;
    RtlCopyMemory(
        Response + responseOffset,
        creationHash,
        sizeof(creationHash));
    responseOffset += sizeof(creationHash);
    WriteBe16(Response + responseOffset, TPM_ST_CREATION);
    responseOffset += 2;
    WriteBe32(Response + responseOffset, TPM_RH_OWNER);
    responseOffset += 4;
    WriteBe16(Response + responseOffset, 0);
    responseOffset += 2;
    WriteBe16(Response + responseOffset, 34);
    responseOffset += 2;
    WriteBe16(Response + responseOffset, TPM_ALG_SHA256);
    responseOffset += 2;
    RtlCopyMemory(Response + responseOffset, nameDigest, 32);
    responseOffset += 32;
    WriteBe16(Response + responseOffset, 0);
    responseOffset += 2;
    Response[responseOffset++] = 1;
    WriteBe16(Response + responseOffset, 0);
    responseOffset += 2;
    *ResponseLength = responseOffset;
    return STATUS_SUCCESS;
}

static NTSTATUS EnsurePrimary(_Inout_ PVTPM_BACKEND Backend)
{
    UCHAR command[26u + sizeof(g_WindowsSrkPublicTemplate)];
    UCHAR response[1024];
    size_t responseLength = 0;

    RtlZeroMemory(command, sizeof(command));
    WriteBe16(command, TPM_ST_NO_SESSIONS);
    WriteBe32(command + 2, (ULONG)sizeof(command));
    WriteBe32(command + 6, TPM_CC_CREATE_PRIMARY);
    WriteBe32(command + 10, TPM_RH_OWNER);
    WriteBe32(command + 14, 0);
    WriteBe16(command + 18, 4);
    WriteBe16(
        command + 24,
        (USHORT)sizeof(g_WindowsSrkPublicTemplate));
    RtlCopyMemory(
        command + 26,
        g_WindowsSrkPublicTemplate,
        sizeof(g_WindowsSrkPublicTemplate));

    return WriteCreatePrimary(
        Backend,
        command,
        sizeof(command),
        response,
        sizeof(response),
        &responseLength);
}

NTSTATUS VtpmKernelTpmInitialize(_Inout_ PVTPM_BACKEND Backend)
{
    NTSTATUS status;

    Backend->Started = TRUE;
    Backend->PcrUpdateCounter = 0;
    Backend->LastCommandCode = 0;
    Backend->LastUnsupportedCommandCode = 0;
    Backend->CommandCount = 0;
    Backend->UnsupportedCommandCount = 0;
    Backend->LastIoctlCode = 0;
    Backend->LastCommandLength = 0;
    Backend->LastDeclaredLength = 0;
    Backend->LastCapability = 0;
    Backend->LastProperty = 0;
    Backend->LastPropertyCount = 0;
    Backend->LastTpmResult = 0;
    Backend->LastErrorCommandCode = 0;
    Backend->LastErrorTpmResult = 0;
    Backend->LastErrorCommandLength = 0;
    Backend->LastErrorDeclaredLength = 0;
    Backend->LastSizeErrorCommandCode = 0;
    Backend->LastSizeErrorCommandLength = 0;
    Backend->LastSizeErrorDeclaredLength = 0;
    Backend->SizeErrorCount = 0;
    Backend->LastUnsupportedCommandLength = 0;
    Backend->PrimaryKeyLoaded = 0;
    Backend->PrimaryKeyPersisted = 0;
    Backend->PersistentPublicIoctlCount = 0;
    Backend->LastPersistentPublicStatus = STATUS_NOT_FOUND;
    Backend->EventLog = NULL;
    Backend->EventLogLength = 0;
    Backend->EventLogReplayCount = 0;
    Backend->EventLogReplayStatus = STATUS_NOT_FOUND;
    Backend->EventLogIoctlCount = 0;
    Backend->LastEventLogType = 0;
    Backend->LastEventLogOutputLength = 0;
    Backend->LastEventLogStatus = STATUS_NOT_FOUND;
    Backend->LastEventLogBytesReturned = 0;
    Backend->EventLogPartialSuccessCount = 0;
    RtlZeroMemory(
        Backend->LastUnsupportedCommand,
        sizeof(Backend->LastUnsupportedCommand));
    Backend->Sha256Algorithm = NULL;
    Backend->Sha384Algorithm = NULL;
    Backend->RsaAlgorithm = NULL;
    Backend->PrimaryKey = NULL;
    Backend->PrimaryAvailable = FALSE;
    Backend->PrimaryPublicSize = 0;
    RtlZeroMemory(Backend->PrimaryPublic, sizeof(Backend->PrimaryPublic));
    RtlZeroMemory(Backend->PrimaryName, sizeof(Backend->PrimaryName));
    RtlZeroMemory(
        Backend->PrimaryQualifiedName,
        sizeof(Backend->PrimaryQualifiedName));
    Backend->Sha256ObjectLength = 0;
    Backend->Sha384ObjectLength = 0;
    RtlZeroMemory(Backend->Sha256Pcrs, sizeof(Backend->Sha256Pcrs));
    RtlZeroMemory(Backend->Sha384Pcrs, sizeof(Backend->Sha384Pcrs));

    status = OpenHashAlgorithm(
        BCRYPT_SHA256_ALGORITHM,
        &Backend->Sha256Algorithm,
        &Backend->Sha256ObjectLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = OpenHashAlgorithm(
        BCRYPT_SHA384_ALGORITHM,
        &Backend->Sha384Algorithm,
        &Backend->Sha384ObjectLength);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(
            (BCRYPT_ALG_HANDLE)Backend->Sha256Algorithm,
            0);
        Backend->Sha256Algorithm = NULL;
        return status;
    }
    status = BCryptOpenAlgorithmProvider(
        (BCRYPT_ALG_HANDLE*)&Backend->RsaAlgorithm,
        BCRYPT_RSA_ALGORITHM,
        NULL,
        BCRYPT_PROV_DISPATCH);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(
            (BCRYPT_ALG_HANDLE)Backend->Sha384Algorithm,
            0);
        BCryptCloseAlgorithmProvider(
            (BCRYPT_ALG_HANDLE)Backend->Sha256Algorithm,
            0);
        Backend->Sha384Algorithm = NULL;
        Backend->Sha256Algorithm = NULL;
        return status;
    }
    status = LoadPrimaryKey(Backend);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
        status == STATUS_NOT_FOUND) {
        status = STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(status)) {
        KdPrint((
            "vTPM: Ignoring persisted primary key load failure 0x%x\n",
            status));
        status = STATUS_SUCCESS;
    }
    status = LoadEventLog(Backend);
    Backend->EventLogReplayStatus = status;
    if (NT_SUCCESS(status)) {
        status = ReplayEventLog(Backend);
        Backend->EventLogReplayStatus = status;
        if (!NT_SUCCESS(status)) {
            KdPrint((
                "vTPM: WBCL replay disabled after parser failure 0x%x\n",
                status));
            RtlZeroMemory(
                Backend->Sha256Pcrs,
                sizeof(Backend->Sha256Pcrs));
            RtlZeroMemory(
                Backend->Sha384Pcrs,
                sizeof(Backend->Sha384Pcrs));
            Backend->EventLogReplayCount = 0;
            Backend->PcrUpdateCounter = 0;
            ExFreePoolWithTag(Backend->EventLog, VTPM_POOL_TAG);
            Backend->EventLog = NULL;
            Backend->EventLogLength = 0;
        }
    } else {
        KdPrint((
            "vTPM: WBCL unavailable during initialization 0x%x\n",
            status));
    }
    status = EnsurePrimary(Backend);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return STATUS_SUCCESS;
}

VOID VtpmKernelTpmShutdown(_Inout_ PVTPM_BACKEND Backend)
{
    if (Backend->EventLog != NULL) {
        ExFreePoolWithTag(Backend->EventLog, VTPM_POOL_TAG);
        Backend->EventLog = NULL;
        Backend->EventLogLength = 0;
    }
    if (Backend->PrimaryKey != NULL) {
        BCryptDestroyKey((BCRYPT_KEY_HANDLE)Backend->PrimaryKey);
        Backend->PrimaryKey = NULL;
    }
    if (Backend->RsaAlgorithm != NULL) {
        BCryptCloseAlgorithmProvider(
            (BCRYPT_ALG_HANDLE)Backend->RsaAlgorithm,
            0);
        Backend->RsaAlgorithm = NULL;
    }
    if (Backend->Sha384Algorithm != NULL) {
        BCryptCloseAlgorithmProvider(
            (BCRYPT_ALG_HANDLE)Backend->Sha384Algorithm,
            0);
        Backend->Sha384Algorithm = NULL;
    }
    if (Backend->Sha256Algorithm != NULL) {
        BCryptCloseAlgorithmProvider(
            (BCRYPT_ALG_HANDLE)Backend->Sha256Algorithm,
            0);
        Backend->Sha256Algorithm = NULL;
    }
    RtlSecureZeroMemory(Backend->Sha256Pcrs, sizeof(Backend->Sha256Pcrs));
    RtlSecureZeroMemory(Backend->Sha384Pcrs, sizeof(Backend->Sha384Pcrs));
}

NTSTATUS VtpmKernelTpmSubmit(
    _Inout_ PVTPM_BACKEND Backend,
    _In_reads_bytes_(CommandLength) const UCHAR* Command,
    _In_ size_t CommandLength,
    _Out_writes_bytes_to_(ResponseCapacity, *ResponseLength) UCHAR* Response,
    _In_ size_t ResponseCapacity,
    _Out_ size_t* ResponseLength)
{
    USHORT tag;
    ULONG declaredLength;
    ULONG commandCode;

    *ResponseLength = 0;
    if (Command == NULL || Response == NULL || CommandLength < 10) {
        return STATUS_INVALID_PARAMETER;
    }

    tag = ReadBe16(Command);
    declaredLength = ReadBe32(Command + 2);
    commandCode = ReadBe32(Command + 6);
    Backend->LastCommandCode = commandCode;
    Backend->LastCommandLength =
        CommandLength > MAXULONG ? MAXULONG : (ULONG)CommandLength;
    Backend->LastDeclaredLength = declaredLength;
    ++Backend->CommandCount;
    if ((tag != TPM_ST_NO_SESSIONS &&
         tag != TPM_ST_SESSIONS &&
         tag != TBS_ST_NO_SESSIONS &&
         tag != TBS_ST_SESSIONS) ||
        declaredLength < 10 ||
        declaredLength > CommandLength) {
        return WriteResult(
            Response, ResponseCapacity, TPM_RC_SIZE, ResponseLength);
    }

    switch (commandCode) {
    case TPM_CC_CREATE_PRIMARY:
        if (!Backend->Started) {
            return WriteResult(
                Response, ResponseCapacity, TPM_RC_INITIALIZE, ResponseLength);
        }
        return WriteCreatePrimary(
            Backend,
            Command,
            declaredLength,
            Response,
            ResponseCapacity,
            ResponseLength);

    case TPM_CC_READ_PUBLIC:
        if (!Backend->Started) {
            Backend->LastTpmResult = TPM_RC_INITIALIZE;
            return WriteResult(
                Response, ResponseCapacity, TPM_RC_INITIALIZE, ResponseLength);
        }
        if (declaredLength != 14) {
            Backend->LastTpmResult = TPM_RC_SIZE;
            return WriteResult(
                Response, ResponseCapacity, TPM_RC_SIZE, ResponseLength);
        }
        {
            ULONG handle = ReadBe32(Command + 10);
            if (handle != 0x80000000u && handle != 0x81000001u) {
                Backend->LastTpmResult = TPM_RC_NV_HANDLE;
                return WriteResult(
                    Response,
                    ResponseCapacity,
                    TPM_RC_NV_HANDLE,
                    ResponseLength);
            }
            return WriteReadPublicPayload(
                Backend,
                Response,
                ResponseCapacity,
                ResponseLength,
                TRUE);
        }

    case TPM_CC_NV_READ_PUBLIC:
        if (!Backend->Started) {
            return WriteResult(
                Response, ResponseCapacity, TPM_RC_INITIALIZE, ResponseLength);
        }
        if (declaredLength != 14) {
            return WriteResult(
                Response, ResponseCapacity, TPM_RC_SIZE, ResponseLength);
        }
        return WriteResult(
            Response, ResponseCapacity, TPM_RC_NV_HANDLE, ResponseLength);

    case TPM_CC_STARTUP:
        if (declaredLength != 12) {
            return WriteResult(
                Response, ResponseCapacity, TPM_RC_SIZE, ResponseLength);
        }
        Backend->Started = TRUE;
        return WriteResult(
            Response, ResponseCapacity, TPM_RC_SUCCESS, ResponseLength);

    case TPM_CC_SELF_TEST:
        return WriteResult(
            Response, ResponseCapacity,
            Backend->Started ? TPM_RC_SUCCESS : TPM_RC_INITIALIZE,
            ResponseLength);

    case TPM_CC_GET_TEST_RESULT:
        if (!Backend->Started) {
            return WriteResult(
                Response, ResponseCapacity, TPM_RC_INITIALIZE, ResponseLength);
        }
        if (ResponseCapacity < 16) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        WriteHeader(
            Response, ResponseCapacity, TPM_RC_SUCCESS, 16, ResponseLength);
        WriteBe16(Response + 10, 0);
        WriteBe32(Response + 12, TPM_RC_SUCCESS);
        return STATUS_SUCCESS;

    case TPM_CC_GET_CAPABILITY:
        if (!Backend->Started) {
            return WriteResult(
                Response, ResponseCapacity, TPM_RC_INITIALIZE, ResponseLength);
        }
        if (declaredLength != 22) {
            return WriteResult(
                Response, ResponseCapacity, TPM_RC_SIZE, ResponseLength);
        }
        {
            ULONG capability = ReadBe32(Command + 10);
            ULONG property = ReadBe32(Command + 14);
            ULONG count = ReadBe32(Command + 18);
            Backend->LastCapability = capability;
            Backend->LastProperty = property;
            Backend->LastPropertyCount = count;
            Backend->LastTpmResult = TPM_RC_SUCCESS;
            switch (capability) {
            case TPM_CAP_TPM_PROPERTIES:
                return WriteProperties(
                    property, count, Response, ResponseCapacity, ResponseLength);
            case TPM_CAP_PCRS:
                return WritePcrs(Response, ResponseCapacity, ResponseLength);
            case TPM_CAP_ALGS:
                return WriteAlgorithms(
                    Response, ResponseCapacity, ResponseLength);
            case TPM_CAP_HANDLES:
                return WriteHandles(
                    Backend,
                    property,
                    Response,
                    ResponseCapacity,
                    ResponseLength);
            case TPM_CAP_COMMANDS:
                return WriteEmptyCapability(
                    capability, Response, ResponseCapacity, ResponseLength);
            default:
                return WriteResult(
                    Response, ResponseCapacity, TPM_RC_VALUE, ResponseLength);
            }
        }

    case TPM_CC_PCR_READ:
        if (!Backend->Started) {
            return WriteResult(
                Response, ResponseCapacity, TPM_RC_INITIALIZE, ResponseLength);
        }
        return WritePcrRead(
            Backend,
            Command,
            declaredLength,
            Response,
            ResponseCapacity,
            ResponseLength);

    case TPM_CC_PCR_EXTEND:
        if (!Backend->Started) {
            return WriteResult(
                Response, ResponseCapacity, TPM_RC_INITIALIZE, ResponseLength);
        }
        return WritePcrExtend(
            Backend,
            tag,
            Command,
            declaredLength,
            Response,
            ResponseCapacity,
            ResponseLength);

    default:
        Backend->LastUnsupportedCommandCode = commandCode;
        ++Backend->UnsupportedCommandCount;
        Backend->LastUnsupportedCommandLength =
            declaredLength < sizeof(Backend->LastUnsupportedCommand)
                ? declaredLength
                : (ULONG)sizeof(Backend->LastUnsupportedCommand);
        RtlCopyMemory(
            Backend->LastUnsupportedCommand,
            Command,
            Backend->LastUnsupportedCommandLength);
        return WriteResult(
            Response, ResponseCapacity, TPM_RC_COMMAND_CODE, ResponseLength);
    }
}
