$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$source = Join-Path $root "build\driver-kernel-poc"
$package = Join-Path $root "release-kernel-poc"
$scripts = Join-Path $root "scripts"
$cert = Join-Path $root "cert\vtpm.cer"
$inf2cat = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x86\Inf2Cat.exe"
$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
$certificateSubject = "CN=vTPM2 Development"

$processPath = [Environment]::GetEnvironmentVariable("Path", "Process")
[Environment]::SetEnvironmentVariable("PATH", $null, "Process")
[Environment]::SetEnvironmentVariable("Path", $processPath, "Process")

if (-not (Test-Path (Join-Path $source "vtpm.sys"))) {
    throw "Build kernel-poc first with build_driver_variants.ps1."
}
if (-not (Test-Path -LiteralPath $scripts)) {
    throw "Guest scripts directory is missing: $scripts"
}
New-Item -ItemType Directory -Path (Split-Path $cert -Parent) -Force |
    Out-Null
$signingCertificate = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object {
        $_.Subject -eq $certificateSubject -and
        $_.HasPrivateKey -and
        $_.NotAfter -gt (Get-Date).AddDays(1)
    } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1
if (!$signingCertificate) {
    $signingCertificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $certificateSubject `
        -CertStoreLocation Cert:\CurrentUser\My `
        -HashAlgorithm SHA256 `
        -KeyLength 2048 `
        -KeyExportPolicy Exportable `
        -NotAfter (Get-Date).AddYears(3)
}
Export-Certificate -Cert $signingCertificate -FilePath $cert -Force |
    Out-Null
$thumbprint = $signingCertificate.Thumbprint

New-Item -ItemType Directory -Path $package -Force | Out-Null
Get-ChildItem -LiteralPath $package -Force -ErrorAction SilentlyContinue |
    Remove-Item -Force -Recurse
Copy-Item -LiteralPath (Join-Path $source "vtpm.sys") -Destination $package
Copy-Item -LiteralPath (Join-Path $source "vtpm.inf") -Destination $package
Copy-Item -LiteralPath $cert -Destination $package
foreach ($name in @(
        "collect_preattestation.ps1",
        "install_acpi_platform_vtpm.ps1",
        "install_windows_security_integration.ps1",
        "probe_acpi_tpm_platform.ps1",
        "probe_kernel_gettpm.ps1",
        "probe_tbs_eventlog.ps1",
        "probe_wbcl_registration.ps1",
        "refresh_tpm_boot_state.ps1",
        "refresh_windows_security.ps1",
        "register_current_wbcl.ps1",
        "unregister_current_wbcl.ps1")) {
    Copy-Item -LiteralPath (Join-Path $scripts $name) `
        -Destination $package
}
Copy-Item -LiteralPath (Join-Path $root "acpi\vtpm_ssdt.asl") -Destination $package

$infPath = Join-Path $package "vtpm.inf"
$utcDriverDate = [DateTime]::UtcNow.ToString("MM/dd/yyyy")
$infContent = Get-Content -LiteralPath $infPath
$infContent = $infContent -replace `
    "^DriverVer\s*=.*$", `
    "DriverVer = $utcDriverDate,13.0.0.0"
$infContent | Set-Content -LiteralPath $infPath -Encoding ASCII

& $signtool sign `
    /v `
    /fd SHA256 `
    /s My `
    /sha1 $thumbprint `
    (Join-Path $package "vtpm.sys")
if ($LASTEXITCODE -ne 0) {
    throw "Embedded driver signing failed."
}

& $inf2cat /driver:$package /os:10_X64
if ($LASTEXITCODE -ne 0) {
    throw "Inf2Cat failed."
}

& $signtool sign /v /fd SHA256 /s My /sha1 $thumbprint `
    (Join-Path $package "vtpm.cat")
if ($LASTEXITCODE -ne 0) {
    throw "Catalog signing failed."
}

Get-ChildItem -LiteralPath $package -File |
    Sort-Object Name |
    ForEach-Object {
        $hash = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
        "{0}  {1}" -f $hash.Hash, $_.Name
    } |
    Set-Content -LiteralPath (Join-Path $package "SHA256SUMS.txt") -Encoding ASCII

Write-Host "Kernel PoC package: $package"
Get-AuthenticodeSignature (Join-Path $package "vtpm.cat") |
    Format-List Status,StatusMessage,SignerCertificate
