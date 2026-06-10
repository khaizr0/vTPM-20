$ErrorActionPreference = "Stop"

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run as Administrator."
}

$integrityPath =
    "HKLM:\SYSTEM\CurrentControlSet\Control\IntegrityServices"
$backupPath = Join-Path $PSScriptRoot "WBCL.previous.bin"

if (Test-Path -LiteralPath $backupPath) {
    $wbcl = [IO.File]::ReadAllBytes($backupPath)
    New-Item -Path $integrityPath -Force | Out-Null
    New-ItemProperty -LiteralPath $integrityPath `
        -Name WBCL `
        -PropertyType Binary `
        -Value $wbcl `
        -Force | Out-Null
    Write-Host "Restored previous WBCL value."
} elseif (Test-Path -LiteralPath $integrityPath) {
    Remove-ItemProperty -LiteralPath $integrityPath `
        -Name WBCL -ErrorAction SilentlyContinue
    Write-Host "Removed synthetic WBCL value."
}
