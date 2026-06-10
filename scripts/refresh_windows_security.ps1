$ErrorActionPreference = "Continue"
$output = Join-Path $PSScriptRoot "windows_security_refresh.log"

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run as Administrator."
}

function Write-TpmState {
    param([string]$Title)

    Write-Host ""
    Write-Host "=== $Title ===" -ForegroundColor Cyan

    Write-Host ""
    Write-Host "--- Get-Tpm ---"
    try {
        Get-Tpm -ErrorAction Stop | Format-List *
    } catch {
        Write-Host "[Get-Tpm error] $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "--- tpmtool getdeviceinformation ---"
    & "$env:SystemRoot\System32\tpmtool.exe" getdeviceinformation

    Write-Host ""
    Write-Host "--- TPM WMI task state ---"
    $wmiPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TPM\WMI"
    if (Test-Path -LiteralPath $wmiPath) {
        Get-ItemProperty -LiteralPath $wmiPath |
            Select-Object TaskReadyForAttestation, TaskReadyForStorage,
                TaskInformationFlags, MaintenanceTaskComplete,
                AIKEnrollmentErrorCode |
            Format-List
    } else {
        Write-Host "TPM WMI registry state was not found."
    }
}

Remove-Item -LiteralPath $output -Force -ErrorAction SilentlyContinue
Start-Transcript -Path $output -Force | Out-Null

try {
    Write-TpmState "Before refresh"

    Write-Host ""
    Write-Host "=== Platform security state ===" -ForegroundColor Cyan
    try {
        "SecureBoot: $(Confirm-SecureBootUEFI -ErrorAction Stop)"
    } catch {
        "SecureBoot: unavailable or disabled ($($_.Exception.Message))"
    }

    & bcdedit.exe /enum "{current}" |
        Select-String -Pattern "testsigning|nointegritychecks|hypervisorlaunchtype"

    try {
        Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard `
            -ClassName Win32_DeviceGuard -ErrorAction Stop |
            Format-List *
    } catch {
        Write-Host "[DeviceGuard query error] $($_.Exception.Message)" `
            -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "=== Register current WBCL ===" -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot "register_current_wbcl.ps1")

    Write-Host ""
    Write-Host "=== Run TPM maintenance tasks ===" -ForegroundColor Cyan
    $taskNames = @(
        "Tpm-Maintenance",
        "Tpm-PreAttestationHealthCheck",
        "Tpm-HASCertRetr"
    )
    foreach ($taskName in $taskNames) {
        try {
            Start-ScheduledTask -TaskPath "\Microsoft\Windows\TPM\" `
                -TaskName $taskName -ErrorAction Stop
            Write-Host "Started: $taskName"
        } catch {
            Write-Host "[$taskName] $($_.Exception.Message)" `
                -ForegroundColor Yellow
        }
    }

    Start-Sleep -Seconds 20

    Write-Host ""
    Write-Host "=== Refresh Windows Security UI ===" -ForegroundColor Cyan
    Get-Process -Name SecHealthUI -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue

    try {
        $packages = Get-AppxPackage -AllUsers -Name Microsoft.SecHealthUI `
            -ErrorAction Stop
        foreach ($package in $packages) {
            $manifest = Join-Path $package.InstallLocation "AppXManifest.xml"
            Add-AppxPackage -DisableDevelopmentMode -Register $manifest `
                -ErrorAction Stop
            Write-Host "Re-registered: $manifest"
        }
    } catch {
        Write-Host "[SecHealthUI registration error] $($_.Exception.Message)" `
            -ForegroundColor Yellow
    }

    foreach ($serviceName in @("SecurityHealthService", "wscsvc")) {
        try {
            Restart-Service -Name $serviceName -Force -ErrorAction Stop
            Write-Host "Restarted service: $serviceName"
        } catch {
            Write-Host "[$serviceName restart] $($_.Exception.Message)" `
                -ForegroundColor Yellow
        }
    }

    Start-Sleep -Seconds 10
    Write-TpmState "After refresh"

    Write-Host ""
    Write-Host "=== Windows Security services ===" -ForegroundColor Cyan
    Get-Service SecurityHealthService, wscsvc, WinDefend, tbs `
        -ErrorAction SilentlyContinue |
        Select-Object Name, Status, StartType |
        Format-Table -AutoSize

    Start-Process "windowsdefender://devicesecurity" -ErrorAction SilentlyContinue
} finally {
    Stop-Transcript | Out-Null
}

Write-Host "Saved: $output" -ForegroundColor Green
