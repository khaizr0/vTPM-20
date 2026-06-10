DefinitionBlock ("", "SSDT", 2, "VTPM2 ", "VTPMENUM", 0x00000001)
{
    Scope (\_SB)
    {
        Device (VTP0)
        {
            Name (_HID, "VTPM0001")
            Name (_CID, "MSFT0101")
            Name (_UID, Zero)
            Name (_STA, 0x0F)
        }
    }
}
