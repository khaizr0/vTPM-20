param(
    [string]$VmName = "win11"
)

$ErrorActionPreference = "Stop"

$vboxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$asl = "C:\Program Files (x86)\Windows Kits\10\Tools\10.0.22621.0\x64\ACPIVerify\asl.exe"
$source = Join-Path $PSScriptRoot "acpi\vtpm_ssdt.asl"
$aml = Join-Path $PSScriptRoot "acpi\vtpm_ssdt.aml"
$tpm2Table = Join-Path $PSScriptRoot "acpi\vtpm_tpm2.bin"
$ssdtKey = "VBoxInternal/Devices/acpi/0/Config/CustomTable0"
$tpm2Key = "VBoxInternal/Devices/acpi/0/Config/CustomTable1"

function Write-UInt16Le {
    param([IO.BinaryWriter]$Writer, [UInt16]$Value)
    $Writer.Write($Value)
}

function Write-UInt32Le {
    param([IO.BinaryWriter]$Writer, [UInt32]$Value)
    $Writer.Write($Value)
}

function Write-UInt64Le {
    param([IO.BinaryWriter]$Writer, [UInt64]$Value)
    $Writer.Write($Value)
}

function Write-FixedAscii {
    param(
        [IO.BinaryWriter]$Writer,
        [string]$Value,
        [int]$Length
    )
    $bytes = [Text.Encoding]::ASCII.GetBytes($Value)
    if ($bytes.Length -ne $Length) {
        throw "ASCII field '$Value' must be exactly $Length bytes."
    }
    $Writer.Write($bytes)
}

function New-Tpm2AcpiTable {
    param([string]$Path)

    $stream = New-Object IO.MemoryStream
    $writer = New-Object IO.BinaryWriter($stream)
    try {
        Write-FixedAscii $writer "TPM2" 4
        Write-UInt32Le $writer 52
        $writer.Write([byte]4)
        $writer.Write([byte]0)
        Write-FixedAscii $writer "VTPM2 " 6
        Write-FixedAscii $writer "VTPMTPM2" 8
        Write-UInt32Le $writer 1
        Write-FixedAscii $writer "VTPM" 4
        Write-UInt32Le $writer 1
        Write-UInt16Le $writer 0
        Write-UInt16Le $writer 0
        Write-UInt64Le $writer 0
        Write-UInt32Le $writer 1

        $bytes = $stream.ToArray()
        $sum = 0
        foreach ($byte in $bytes) {
            $sum = ($sum + $byte) -band 0xFF
        }
        $bytes[9] = [byte]((-1 * $sum) -band 0xFF)
        [IO.File]::WriteAllBytes($Path, $bytes)
    } finally {
        $writer.Dispose()
        $stream.Dispose()
    }
}

if (!(Test-Path -LiteralPath $vboxManage)) {
    throw "VBoxManage was not found."
}
if (!(Test-Path -LiteralPath $asl)) {
    throw "Microsoft ASL compiler was not found."
}

$stateLine = & $vboxManage showvminfo $VmName --machinereadable |
    Where-Object { $_ -like "VMState=*" }
if ($stateLine -notmatch 'VMState="poweroff"') {
    throw "Power off VM '$VmName' completely before configuring ACPI."
}

Remove-Item -LiteralPath $aml -Force -ErrorAction SilentlyContinue
& $asl /nologo "/Fo=$aml" $source
if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $aml)) {
    throw "ACPI SSDT compilation failed."
}

New-Tpm2AcpiTable -Path $tpm2Table

& $vboxManage setextradata $VmName $ssdtKey $aml
if ($LASTEXITCODE -ne 0) {
    throw "VirtualBox SSDT configuration failed."
}
& $vboxManage setextradata $VmName $tpm2Key $tpm2Table
if ($LASTEXITCODE -ne 0) {
    throw "VirtualBox TPM2 table configuration failed."
}

Write-Host "Configured VM: $VmName"
Write-Host "Custom SSDT: $aml"
Write-Host "Static TPM2 table: $tpm2Table"
Write-Host "VirtualBox keys: $ssdtKey, $tpm2Key"
Write-Host "Start the VM and install the ACPI platform driver package."
