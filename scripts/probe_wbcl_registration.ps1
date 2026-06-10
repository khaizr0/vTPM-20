$ErrorActionPreference = "Continue"

Write-Host "=== TPM service registry ===" -ForegroundColor Cyan
$paths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\TPM",
    "HKLM:\SYSTEM\CurrentControlSet\Services\TPM\WMI",
    "HKLM:\SYSTEM\CurrentControlSet\Services\TPM\WMI\TaskStates"
)

foreach ($path in $paths) {
    Write-Host ""
    Write-Host "--- $path ---"
    if (Test-Path -LiteralPath $path) {
        Get-ItemProperty -LiteralPath $path |
            Format-List *
    } else {
        Write-Host "Not found"
    }
}

Write-Host ""
Write-Host "=== MeasuredBoot files ===" -ForegroundColor Cyan
Get-ChildItem -LiteralPath "$env:SystemRoot\Logs\MeasuredBoot" -Force `
    -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object Name, Length, CreationTime, LastWriteTime |
    Format-Table -AutoSize

Write-Host ""
Write-Host "=== WMI log files ===" -ForegroundColor Cyan
Get-ChildItem -LiteralPath "$env:SystemRoot\System32\LogFiles\WMI" -Force `
    -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -match "SRTM|DRTM|TPM"
    } |
    Sort-Object LastWriteTime -Descending |
    Select-Object Name, Length, CreationTime, LastWriteTime |
    Format-Table -AutoSize
