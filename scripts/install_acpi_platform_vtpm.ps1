$ErrorActionPreference = "Stop"

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run as Administrator."
}

$package = $PSScriptRoot
$acpiDevice = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
    Where-Object { $_.InstanceId -like "ACPI\VTPM0001*" } |
    Select-Object -First 1

if ($null -eq $acpiDevice) {
    throw "ACPI\VTPM0001 is not present. Configure the host SSDT and cold boot the VM."
}

$certificate = Join-Path $package "vtpm.cer"
Import-Certificate -FilePath $certificate `
    -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
Import-Certificate -FilePath $certificate `
    -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null

sc.exe stop vtpm 2>&1 | Out-Null

Get-PnpDevice -ErrorAction SilentlyContinue |
    Where-Object { $_.InstanceId -like "ROOT\VTPM*" } |
    ForEach-Object {
        pnputil.exe /remove-device $_.InstanceId
        if ($LASTEXITCODE -notin 0, 3010) {
            throw "Failed to remove stale device $($_.InstanceId), exit code $LASTEXITCODE."
        }
    }

pnputil.exe /add-driver (Join-Path $package "vtpm.inf") /install
$installExit = $LASTEXITCODE
if ($installExit -notin 0, 3010) {
    throw "pnputil failed with exit code $LASTEXITCODE."
}
if ($installExit -eq 3010) {
    Write-Host "Driver installed; Windows requires a reboot." `
        -ForegroundColor Yellow
}

pnputil.exe /scan-devices
if ($LASTEXITCODE -ne 0) {
    throw "pnputil device scan failed with exit code $LASTEXITCODE."
}
Start-Sleep -Seconds 5

Write-Host ""
Write-Host "=== ACPI vTPM device ===" -ForegroundColor Cyan
Get-PnpDevice -PresentOnly |
    Where-Object { $_.InstanceId -like "ACPI\VTPM0001*" } |
    Format-List Status, Class, FriendlyName, InstanceId, Problem,
        ProblemStatus

Write-Host ""
Write-Host "Restart Windows, then run:"
Write-Host "  tpmtool getdeviceinformation"
Write-Host "  Get-Tpm"
