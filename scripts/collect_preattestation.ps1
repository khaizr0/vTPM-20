$ErrorActionPreference = "Continue"
$output = Join-Path $PSScriptRoot "preattestation.log"
$measuredBoot = Join-Path $env:SystemRoot "Logs\MeasuredBoot"

Remove-Item -LiteralPath $output -Force -ErrorAction SilentlyContinue
Start-Transcript -Path $output -Force | Out-Null

try {
    Write-Host "=== Available TPM event logs ===" -ForegroundColor Cyan
    $tpmLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
        Where-Object {
            $_.LogName -match "TPM|TBS|Attestation"
        } |
        Sort-Object LogName

    $tpmLogs |
        Select-Object LogName, IsEnabled, RecordCount, LastWriteTime |
        Format-Table -AutoSize

    Write-Host ""
    Write-Host "=== Trigger pre-attestation task ===" -ForegroundColor Cyan
    try {
        Start-ScheduledTask `
            -TaskPath "\Microsoft\Windows\TPM\" `
            -TaskName "Tpm-PreAttestationHealthCheck" `
            -ErrorAction Stop
        Start-Sleep -Seconds 15
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "=== TPM-WMI events 1038 and 1040 ===" -ForegroundColor Cyan
    $matchingEvents = foreach ($log in $tpmLogs) {
        Get-WinEvent -FilterHashtable @{
            LogName = $log.LogName
            Id = 1038, 1040
        } -MaxEvents 10 -ErrorAction SilentlyContinue
    }

    if ($matchingEvents) {
        $matchingEvents |
            Sort-Object TimeCreated -Descending |
            Select-Object -First 20 TimeCreated, LogName, ProviderName,
                Id, LevelDisplayName, Message |
            Format-List
    } else {
        Write-Host "No event 1038/1040 was found."
    }

    Write-Host ""
    Write-Host "=== Recent TPM/TBS events ===" -ForegroundColor Cyan
    $recentEvents = foreach ($log in $tpmLogs) {
        Get-WinEvent -LogName $log.LogName -MaxEvents 30 `
            -ErrorAction SilentlyContinue
    }

    $recentEvents |
        Sort-Object TimeCreated -Descending |
        Select-Object -First 80 TimeCreated, LogName, ProviderName,
            Id, LevelDisplayName, Message |
        Format-List

    Write-Host ""
    Write-Host "=== System TPM/TBS events ===" -ForegroundColor Cyan
    Get-WinEvent -LogName System -MaxEvents 1000 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.ProviderName -match "TPM|TBS|Attestation|Kernel-Boot"
        } |
        Select-Object -First 100 TimeCreated, LogName, ProviderName,
            Id, LevelDisplayName, Message |
        Format-List

    Write-Host ""
    Write-Host "=== MeasuredBoot pre-attestation JSON ===" -ForegroundColor Cyan
    if (Test-Path -LiteralPath $measuredBoot) {
        $jsonFiles = Get-ChildItem -LiteralPath $measuredBoot -Filter *.json |
            Sort-Object LastWriteTime -Descending

        $jsonFiles |
            Select-Object -First 20 Name, Length, LastWriteTime |
            Format-Table -AutoSize

        foreach ($file in ($jsonFiles | Select-Object -First 5)) {
            Write-Host ""
            Write-Host "--- $($file.FullName) ---"
            $bytes = [IO.File]::ReadAllBytes($file.FullName)
            if ($bytes.Length -ge 2 -and
                $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
                [Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
            } elseif ($bytes.Length -ge 2 -and
                $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
                [Text.Encoding]::BigEndianUnicode.GetString(
                    $bytes, 2, $bytes.Length - 2)
            } elseif ($bytes.Length -ge 4 -and
                $bytes[1] -eq 0 -and $bytes[3] -eq 0) {
                [Text.Encoding]::Unicode.GetString($bytes)
            } else {
                [Text.Encoding]::UTF8.GetString($bytes)
            }
        }
    } else {
        Write-Host "MeasuredBoot directory not found: $measuredBoot"
    }

    Write-Host ""
    Write-Host "=== Current TPM summary ===" -ForegroundColor Cyan
    try {
        Get-Tpm -ErrorAction Stop | Format-List *
    } catch {
        Write-Host "[Get-Tpm error] $($_.Exception.Message)"
    }
    tpmtool getdeviceinformation

    Write-Host ""
    Write-Host "=== TBS event-log probe ===" -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot "probe_tbs_eventlog.ps1")

    Write-Host ""
    Write-Host "=== WBCL registration probe ===" -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot "probe_wbcl_registration.ps1")

    Write-Host ""
    Write-Host "=== Kernel backend probe ===" -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot "probe_kernel_gettpm.ps1")
} finally {
    Stop-Transcript | Out-Null
}

Write-Host "Saved: $output" -ForegroundColor Green
