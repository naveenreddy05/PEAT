rule Mirai_Botnet
{
    meta:
        description = "Detects Mirai IoT botnet malware"
        author = "PEAT Analysis Engine"
        severity = "CRITICAL"
        family = "Mirai"

    strings:
        $s1 = "/bin/busybox" ascii wide
        $s2 = "MIRAI" ascii wide nocase
        $s3 = "ECCHI" ascii wide
        $s4 = "JOSHO" ascii wide
        $s5 = "HTTPSUCK" ascii wide
        $s6 = "killer" ascii wide
        $s7 = "DDoS" ascii wide nocase
        $s8 = "TSource Engine Query" ascii wide

        $cmd1 = "ps -x" ascii
        $cmd2 = "killall -9" ascii
        $cmd3 = "watchdog" ascii
        $cmd4 = "/dev/watchdog" ascii

        $net1 = "zTdl7rXgSpyJZ92FbeAj8B6Q" ascii
        $net2 = "CNC_OP" ascii
        $net3 = "DyoNRT" ascii

    condition:
        uint32(0) == 0x464c457f and  // ELF magic
        (
            3 of ($s*) or
            2 of ($cmd*) or
            any of ($net*)
        )
}

rule Mirai_Variant
{
    meta:
        description = "Detects Mirai variants and forks"
        severity = "CRITICAL"
        family = "Mirai_Variant"

    strings:
        $hex1 = { 22 54 00 53 00 68 00 69 00 62 00 61 }
        $hex2 = { 50 4f 53 54 20 2f }

        $str1 = "POST /" ascii
        $str2 = "User-Agent:" ascii
        $str3 = "/bin/sh" ascii
        $str4 = "nproc" ascii
        $str5 = "/proc/" ascii
        $str6 = "iptables" ascii

    condition:
        uint32(0) == 0x464c457f and
        (
            any of ($hex*) and 2 of ($str*)
        )
}
