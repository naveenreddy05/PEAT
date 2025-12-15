rule Gafgyt_Bashlite
{
    meta:
        description = "Detects Gafgyt/Bashlite IoT botnet"
        severity = "CRITICAL"
        family = "Gafgyt"

    strings:
        $s1 = "PING" ascii
        $s2 = "PONG" ascii
        $s3 = "STD" ascii
        $s4 = "HOLD" ascii
        $s5 = "JUNK" ascii
        $s6 = "TCP" ascii
        $s7 = "UDP" ascii
        $s8 = "CNC" ascii

        $cmd1 = "SCANNER" ascii
        $cmd2 = "LDSERVER" ascii
        $cmd3 = "HTTPFLOOD" ascii
        $cmd4 = "LOLNOGTFO" ascii

    condition:
        uint32(0) == 0x464c457f and
        (
            4 of ($s*) or
            2 of ($cmd*)
        )
}

rule Gafgyt_Variant_Qbot
{
    meta:
        description = "Detects Qbot (Gafgyt variant)"
        severity = "CRITICAL"
        family = "Qbot"

    strings:
        $s1 = "QWERTY" ascii
        $s2 = "HACK" ascii
        $s3 = "LOLNOGTFO" ascii
        $s4 = "STD" ascii
        $s5 = "COMBO" ascii

    condition:
        uint32(0) == 0x464c457f and 3 of ($s*)
}
