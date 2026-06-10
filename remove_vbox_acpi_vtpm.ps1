param(
    [string]$VmName = "win11"
)

$ErrorActionPreference = "Stop"
$vboxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$keys = @(
    "VBoxInternal/Devices/acpi/0/Config/CustomTable0",
    "VBoxInternal/Devices/acpi/0/Config/CustomTable1"
)

$stateLine = & $vboxManage showvminfo $VmName --machinereadable |
    Where-Object { $_ -like "VMState=*" }
if ($stateLine -notmatch 'VMState="poweroff"') {
    throw "Power off VM '$VmName' completely before removing ACPI."
}

foreach ($key in $keys) {
    & $vboxManage setextradata $VmName $key
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to remove VirtualBox custom ACPI key: $key"
    }
}

Write-Host "Removed custom vTPM ACPI table from VM: $VmName"
