$ErrorActionPreference = "Continue"

$stateRoot = Join-Path $env:ProgramData "vTPM"
$logPath = Join-Path $stateRoot "boot-state.log"
$tpmPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TPM"
$integrityPath = "HKLM:\SYSTEM\CurrentControlSet\Control\IntegrityServices"
$measuredBootPath = Join-Path $env:SystemRoot "Logs\MeasuredBoot"

New-Item -ItemType Directory -Path $stateRoot -Force | Out-Null
Start-Transcript -Path $logPath -Append | Out-Null

try {
    Write-Host ""
    Write-Host "=== vTPM boot-state refresh $(Get-Date -Format o) ==="

    $bootLog = $null
    $bootCount = (Get-ItemProperty -LiteralPath $tpmPath `
        -ErrorAction SilentlyContinue).OsBootCount

    if ($null -ne $bootCount) {
        $expectedName = "{0:D10}-0000000000.log" -f [UInt64]$bootCount
        $expectedPath = Join-Path $measuredBootPath $expectedName
        if (Test-Path -LiteralPath $expectedPath) {
            $bootLog = Get-Item -LiteralPath $expectedPath
        }
    }

    if ($null -eq $bootLog) {
        $bootLog = Get-ChildItem -LiteralPath $measuredBootPath `
            -Filter "*-0000000000.log" -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
    }

    if ($null -eq $bootLog) {
        throw "No measured-boot event log was found."
    }

    $wbcl = [IO.File]::ReadAllBytes($bootLog.FullName)
    New-Item -Path $integrityPath -Force | Out-Null
    New-ItemProperty -LiteralPath $integrityPath `
        -Name WBCL `
        -PropertyType Binary `
        -Value $wbcl `
        -Force | Out-Null

    Write-Host "Registered WBCL: $($bootLog.FullName)"
    Write-Host "Registered bytes: $($wbcl.Length)"

    foreach ($taskName in @(
            "Tpm-Maintenance",
            "Tpm-PreAttestationHealthCheck",
            "Tpm-HASCertRetr")) {
        try {
            Start-ScheduledTask -TaskPath "\Microsoft\Windows\TPM\" `
                -TaskName $taskName -ErrorAction Stop
            Write-Host "Started TPM task: $taskName"
        } catch {
            Write-Host "[$taskName] $($_.Exception.Message)"
        }
    }

    try {
        Start-Service -Name wscsvc -ErrorAction Stop
        Write-Host "Security Center service is running."
    } catch {
        Write-Host "[wscsvc] $($_.Exception.Message)"
    }

    Start-Sleep -Seconds 20

    Write-Host ""
    & "$env:SystemRoot\System32\tpmtool.exe" getdeviceinformation
    Get-Service wscsvc, SecurityHealthService -ErrorAction SilentlyContinue |
        Format-Table Status, Name, StartType -AutoSize
} catch {
    Write-Host "[boot-state refresh error] $($_.Exception.Message)"
} finally {
    Stop-Transcript | Out-Null
}
