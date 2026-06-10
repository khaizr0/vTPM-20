$ErrorActionPreference = "Continue"

$root = $PSScriptRoot
$project = Join-Path $root "vtpm_driver\vtpm.vcxproj"
$msbuild = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe"

# Some hosted shells expose both Path and PATH. MSBuild treats its child
# environment as case-insensitive and fails before invoking cl.exe.
$processPath = [Environment]::GetEnvironmentVariable("Path", "Process")
[Environment]::SetEnvironmentVariable("PATH", $null, "Process")
[Environment]::SetEnvironmentVariable("Path", $processPath, "Process")

if (-not (Test-Path -LiteralPath $msbuild)) {
    throw "MSBuild not found: $msbuild"
}

function Build-KernelBackend {
    param(
        [Parameter(Mandatory=$true)][string]$Name
    )

    $outDir = Join-Path $root "build\driver-$Name"

    $arguments = @(
        $project,
        "/t:Rebuild",
        "/p:Configuration=Release",
        "/p:Platform=x64",
        "/p:SpectreMitigation=false",
        "/p:UseSpectreMitigation=false",
        "/p:VtpmKernelBackend=true"
    )
    Write-Host "Building $Name..."
    Remove-Item `
        -LiteralPath (Join-Path $root "vtpm_driver\x64\Release\vc143.pdb") `
        -Force `
        -ErrorAction SilentlyContinue
    $log = Join-Path $root "build\driver-$Name-msbuild.log"
    New-Item -ItemType Directory -Path (Split-Path $log -Parent) -Force |
        Out-Null
    Remove-Item -LiteralPath $log -Force -ErrorAction SilentlyContinue
    $output = & $msbuild @arguments 2>&1
    $exitCode = $LASTEXITCODE
    $output | Set-Content -LiteralPath $log -Encoding UTF8
    $output | ForEach-Object { Write-Host $_ }

    if ($exitCode -ne 0) {
        throw "Driver build failed: $Name"
    }

    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    Copy-Item `
        -LiteralPath (Join-Path $root "vtpm_driver\x64\Release\vtpm.sys") `
        -Destination (Join-Path $outDir "vtpm.sys") `
        -Force
    Copy-Item `
        -LiteralPath (Join-Path $root "vtpm_driver\x64\Release\vtpm.inf") `
        -Destination (Join-Path $outDir "vtpm.inf") `
        -Force

    $driver = Join-Path $outDir "vtpm.sys"
    $hash = Get-FileHash -LiteralPath $driver -Algorithm SHA256
    [pscustomobject]@{
        Variant = $Name
        KernelBackend = $true
        Driver = $driver
        Length = (Get-Item -LiteralPath $driver).Length
        SHA256 = $hash.Hash
    }
}

Build-KernelBackend -Name "kernel-poc" | Format-Table -AutoSize
