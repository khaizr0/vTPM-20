$ErrorActionPreference = "Stop"

$source = @"
using System;
using System.Runtime.InteropServices;

public static class TbsEventLogNative {
    [DllImport("tbs.dll")]
    public static extern UInt32 Tbsi_Get_TCG_Log_Ex(
        UInt32 logType,
        IntPtr output,
        ref UInt32 outputLength);
}
"@

Add-Type -TypeDefinition $source -ErrorAction Stop

$names = @(
    "SRTM_CURRENT",
    "DRTM_CURRENT",
    "SRTM_BOOT",
    "SRTM_RESUME"
)

foreach ($logType in 0..3) {
    $required = [UInt32]0
    $sizeResult = [TbsEventLogNative]::Tbsi_Get_TCG_Log_Ex(
        [UInt32]$logType,
        [IntPtr]::Zero,
        [ref]$required)
    $readResult = [UInt32]0
    $returned = [UInt32]0
    $firstBytes = ""

    if ($sizeResult -eq 0 -and $required -gt 0) {
        $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal(
            [int]$required)
        try {
            $returned = $required
            $readResult = [TbsEventLogNative]::Tbsi_Get_TCG_Log_Ex(
                [UInt32]$logType,
                $buffer,
                [ref]$returned)
            if ($readResult -eq 0 -and $returned -gt 0) {
                $previewLength = [Math]::Min(16, [int]$returned)
                $preview = New-Object byte[] $previewLength
                [Runtime.InteropServices.Marshal]::Copy(
                    $buffer,
                    $preview,
                    0,
                    $previewLength)
                $firstBytes = [BitConverter]::ToString(
                    $preview).Replace("-", " ")
            }
        } finally {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
        }
    }

    [pscustomobject]@{
        LogType = $logType
        Name = $names[$logType]
        SizeResult = "0x{0:X8}" -f $sizeResult
        Required = $required
        ReadResult = "0x{0:X8}" -f $readResult
        Returned = $returned
        FirstBytes = $firstBytes
    }
}
