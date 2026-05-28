rule UPX_Packed
{
    meta:
        description = "UPX packer detected"
        severity    = "medium"
        author      = "Quarantine"
    strings:
        $a = "UPX0" ascii
        $b = "UPX1" ascii
        $c = "UPX!" ascii
    condition:
        2 of them
}

rule MPRESS_Packed
{
    meta:
        description = "MPRESS packer detected"
        severity    = "medium"
        author      = "Quarantine"
    strings:
        $a = ".MPRESS1" ascii
        $b = ".MPRESS2" ascii
    condition:
        any of them
}

rule ASPack_Packed
{
    meta:
        description = "ASPack packer detected"
        severity    = "medium"
        author      = "Quarantine"
    strings:
        $a = ".aspack" ascii nocase
        $b = "ASPack" ascii
    condition:
        any of them
}

rule PECompact_Packed
{
    meta:
        description = "PECompact packer detected"
        severity    = "medium"
        author      = "Quarantine"
    strings:
        $a = "PEC2" ascii
        $b = "PECompact2" ascii
    condition:
        any of them
}
