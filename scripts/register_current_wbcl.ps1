$ErrorActionPreference = "Stop"

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run as Administrator."
}

$tpmPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TPM"
$integrityPath =
    "HKLM:\SYSTEM\CurrentControlSet\Control\IntegrityServices"
$backupPath = Join-Path $PSScriptRoot "WBCL.previous.bin"
$bootCount = (Get-ItemProperty -LiteralPath $tpmPath).OsBootCount
$measuredBootPath = Join-Path $env:SystemRoot "Logs\MeasuredBoot"
$bootLog = $null

if ($null -ne $bootCount) {
    $expectedName = "{0:D10}-0000000000.log" -f [UInt64]$bootCount
    $expectedPath = Join-Path $measuredBootPath $expectedName
    if (Test-Path -LiteralPath $expectedPath) {
        $bootLog = Get-Item -LiteralPath $expectedPath
    }
}

if ($null -eq $bootLog) {
    $bootLog = Get-ChildItem -LiteralPath $measuredBootPath `
        -Filter "*-0000000000.log" -File |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

if ($null -eq $bootLog) {
    throw "No SRTM boot log was found."
}

New-Item -Path $integrityPath -Force | Out-Null
$existing = Get-ItemProperty -LiteralPath $integrityPath `
    -Name WBCL -ErrorAction SilentlyContinue
if ($null -ne $existing -and $null -ne $existing.WBCL) {
    [IO.File]::WriteAllBytes($backupPath, [byte[]]$existing.WBCL)
    Write-Host "Backed up previous WBCL: $backupPath"
}

$wbcl = [IO.File]::ReadAllBytes($bootLog.FullName)
New-ItemProperty -LiteralPath $integrityPath `
    -Name WBCL `
    -PropertyType Binary `
    -Value $wbcl `
    -Force | Out-Null

Write-Host "Registered current WBCL: $($bootLog.FullName)"
Write-Host "Registered bytes: $($wbcl.Length)"

Write-Host ""
Write-Host "=== TBS current-log verification ===" -ForegroundColor Cyan
& (Join-Path $PSScriptRoot "probe_tbs_eventlog.ps1")
