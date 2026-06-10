$ErrorActionPreference = "Stop"

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run as Administrator."
}

$stateRoot = Join-Path $env:ProgramData "vTPM"
$scriptPath = Join-Path $stateRoot "refresh_tpm_boot_state.ps1"
$taskName = "vTPM Windows Security Integration"

New-Item -ItemType Directory -Path $stateRoot -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot `
        "refresh_tpm_boot_state.ps1") `
    -Destination $scriptPath `
    -Force

$action = New-ScheduledTaskAction `
    -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""

$startupTrigger = New-ScheduledTaskTrigger -AtStartup
$startupTrigger.Delay = "PT20S"
$logonTrigger = New-ScheduledTaskTrigger -AtLogOn
$logonTrigger.Delay = "PT5S"

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger @($startupTrigger, $logonTrigger) `
    -Principal $principal `
    -Settings $settings `
    -Force | Out-Null

try {
    Start-Service -Name wscsvc -ErrorAction Stop
    Write-Host "Security Center service started."
} catch {
    Write-Host "wscsvc is protected; the SYSTEM task will start it."
}

Start-ScheduledTask -TaskName $taskName
Write-Host "Installed scheduled task: $taskName"
Write-Host "Runtime script: $scriptPath"
Write-Host "Runtime log: $(Join-Path $stateRoot 'boot-state.log')"
