$ErrorActionPreference = "Continue"

Write-Host "=== ACPI TPM device ===" -ForegroundColor Cyan
Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
    Where-Object { $_.InstanceId -like "ACPI\VTPM0001*" } |
    Format-List Status, Class, FriendlyName, InstanceId, Problem,
        ProblemStatus

Write-Host ""
Write-Host "=== ACPI TPM2 static table ===" -ForegroundColor Cyan
$firmwareTable = Get-CimInstance -Namespace root\wmi `
    -ClassName MSSmBios_RawSMBiosTables -ErrorAction SilentlyContinue

$asl = "C:\Program Files (x86)\Windows Kits\10\Tools\10.0.22621.0\x64\ACPIVerify\asl.exe"
if (Test-Path -LiteralPath $asl) {
    & $asl /nologo /tab=TPM2 /c
} else {
    Write-Host "ASL tool is not installed in the guest."
}

Write-Host ""
Write-Host "=== TPM status ===" -ForegroundColor Cyan
Get-Tpm | Format-List TpmPresent, TpmReady, TpmEnabled, TpmActivated,
    PpiVersion, ManufacturerIdTxt, ManufacturerVersionFull20
& "$env:SystemRoot\System32\tpmtool.exe" getdeviceinformation
