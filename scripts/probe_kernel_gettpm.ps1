# Run Windows TPM discovery and query direct-backend telemetry.

$ErrorActionPreference = "Continue"

$source = @"
using System;
using System.Runtime.InteropServices;

public static class KernelPocStatusNative {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFileW(
        string name, UInt32 access, UInt32 share, IntPtr security,
        UInt32 creation, UInt32 flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(
        IntPtr device, UInt32 code, IntPtr input, UInt32 inputLength,
        byte[] output, UInt32 outputLength, out UInt32 returned, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
}
"@

Add-Type -TypeDefinition $source -ErrorAction Stop

Write-Host "=== Get-Tpm ===" -ForegroundColor Cyan
try {
    $job = Start-Job { Get-Tpm }
    if (Wait-Job $job -Timeout 15) {
        Receive-Job $job | Format-List *
    } else {
        Write-Host "[Get-Tpm timeout after 15 seconds]" -ForegroundColor Yellow
        Stop-Job $job
    }
    Remove-Job $job -Force
} catch {
    Write-Host "[Get-Tpm error] $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== tpmtool ===" -ForegroundColor Cyan
$tpmtool = Start-Job { & tpmtool getdeviceinformation }
if (Wait-Job $tpmtool -Timeout 15) {
    Receive-Job $tpmtool
} else {
    Write-Host "[tpmtool timeout after 15 seconds]" -ForegroundColor Yellow
    Stop-Job $tpmtool
}
Remove-Job $tpmtool -Force

Write-Host ""
Write-Host "=== Kernel backend telemetry ===" -ForegroundColor Cyan
$handle = [KernelPocStatusNative]::CreateFileW(
    "\\.\VTpmControl",
    [Convert]::ToUInt32("C0000000", 16),
    [UInt32]3,
    [IntPtr]::Zero,
    [UInt32]3,
    [UInt32]0,
    [IntPtr]::Zero)
if ($handle.ToInt64() -eq -1) {
    throw "Open \\.\VTpmControl failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}

try {
    $output = New-Object byte[] 668
    $returned = [UInt32]0
    $ok = [KernelPocStatusNative]::DeviceIoControl(
        $handle,
        [UInt32]0x00222008,
        [IntPtr]::Zero,
        [UInt32]0,
        $output,
        [UInt32]$output.Length,
        [ref]$returned,
        [IntPtr]::Zero)
    if (-not $ok) {
        throw "Status IOCTL failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    $unsupportedLength = [BitConverter]::ToUInt32($output, 92)
    $unsupportedHex = ""
    if ($unsupportedLength -gt 0 -and $unsupportedLength -le 512) {
        $unsupportedHex = [BitConverter]::ToString(
            $output,
            96,
            [int]$unsupportedLength).Replace("-", " ")
        $capturePath = Join-Path $PSScriptRoot "last-unsupported-command.bin"
        try {
            $capture = New-Object byte[] $unsupportedLength
            [Array]::Copy($output, 96, $capture, 0, $unsupportedLength)
            [IO.File]::WriteAllBytes($capturePath, $capture)
            Write-Host "Captured unsupported TPM command: $capturePath"
        } catch {
            Write-Host "[Capture error] $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    [pscustomobject]@{
        Version = [BitConverter]::ToUInt32($output, 0)
        Role = [BitConverter]::ToUInt32($output, 4)
        Started = [BitConverter]::ToUInt32($output, 8)
        LastCommand = "0x{0:X8}" -f [BitConverter]::ToUInt32($output, 12)
        LastUnsupported = "0x{0:X8}" -f [BitConverter]::ToUInt32($output, 16)
        CommandCount = [BitConverter]::ToUInt32($output, 20)
        UnsupportedCount = [BitConverter]::ToUInt32($output, 24)
        PcrUpdateCounter = [BitConverter]::ToUInt32($output, 28)
        LastIoctl = "0x{0:X8}" -f [BitConverter]::ToUInt32($output, 32)
        LastCommandLength = [BitConverter]::ToUInt32($output, 36)
        LastDeclaredLength = [BitConverter]::ToUInt32($output, 40)
        LastCapability = "0x{0:X8}" -f [BitConverter]::ToUInt32($output, 44)
        LastProperty = "0x{0:X8}" -f [BitConverter]::ToUInt32($output, 48)
        LastPropertyCount = [BitConverter]::ToUInt32($output, 52)
        LastTpmResult = "0x{0:X8}" -f [BitConverter]::ToUInt32($output, 56)
        LastErrorCommand = "0x{0:X8}" -f [BitConverter]::ToUInt32($output, 60)
        LastErrorResult = "0x{0:X8}" -f [BitConverter]::ToUInt32($output, 64)
        LastErrorCommandLength = [BitConverter]::ToUInt32($output, 68)
        LastErrorDeclaredLength = [BitConverter]::ToUInt32($output, 72)
        LastSizeErrorCommand = "0x{0:X8}" -f [BitConverter]::ToUInt32($output, 76)
        LastSizeErrorCommandLength = [BitConverter]::ToUInt32($output, 80)
        LastSizeErrorDeclaredLength = [BitConverter]::ToUInt32($output, 84)
        SizeErrorCount = [BitConverter]::ToUInt32($output, 88)
        LastUnsupportedCommandLength = $unsupportedLength
        LastUnsupportedCommandHex = $unsupportedHex
        PrimaryKeyLoaded = [BitConverter]::ToUInt32($output, 608)
        PrimaryKeyPersisted = [BitConverter]::ToUInt32($output, 612)
        PrimaryAvailable = [BitConverter]::ToUInt32($output, 616)
        PersistentPublicIoctlCount = [BitConverter]::ToUInt32($output, 620)
        LastPersistentPublicStatus = "0x{0:X8}" -f [BitConverter]::ToUInt32($output, 624)
        EventLogLoaded = [BitConverter]::ToUInt32($output, 628)
        EventLogLength = [BitConverter]::ToUInt32($output, 632)
        EventLogReplayCount = [BitConverter]::ToUInt32($output, 636)
        EventLogReplayStatus = "0x{0:X8}" -f [BitConverter]::ToUInt32($output, 640)
        EventLogIoctlCount = [BitConverter]::ToUInt32($output, 644)
        LastEventLogType = [BitConverter]::ToUInt32($output, 648)
        LastEventLogOutputLength = [BitConverter]::ToUInt32($output, 652)
        LastEventLogStatus = "0x{0:X8}" -f [BitConverter]::ToUInt32($output, 656)
        LastEventLogBytesReturned = [BitConverter]::ToUInt32($output, 660)
        EventLogPartialSuccessCount = [BitConverter]::ToUInt32($output, 664)
    } | Format-List
} finally {
    [void][KernelPocStatusNative]::CloseHandle($handle)
}
