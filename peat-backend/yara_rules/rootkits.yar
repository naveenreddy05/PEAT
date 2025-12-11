rule Linux_Rootkit
{
    meta:
        description = "Detects Linux rootkit indicators"
        severity = "CRITICAL"
        family = "Rootkit"

    strings:
        $s1 = "rootkit" ascii nocase
        $s2 = "hide_file" ascii
        $s3 = "hide_process" ascii
        $s4 = "hide_module" ascii
        $s5 = "/proc/" ascii
        $s6 = "kernel" ascii
        $s7 = "insmod" ascii
        $s8 = "rmmod" ascii
        $s9 = "module_hide" ascii

        $sys1 = "sys_call_table" ascii
        $sys2 = "sys_read" ascii
        $sys3 = "sys_write" ascii

    condition:
        uint32(0) == 0x464c457f and
        (
            3 of ($s*) or
            any of ($sys*)
        )
}

rule Kernel_Module_Rootkit
{
    meta:
        description = "Detects malicious kernel modules"
        severity = "CRITICAL"
        family = "Kernel_Rootkit"

    strings:
        $s1 = "module_init" ascii
        $s2 = "module_exit" ascii
        $s3 = "MODULE_LICENSE" ascii
        $s4 = "hide" ascii nocase
        $s5 = "/proc" ascii

        $mal1 = "keylogger" ascii nocase
        $mal2 = "packet_sniffer" ascii nocase

    condition:
        uint32(0) == 0x464c457f and
        (
            all of ($s1, $s2, $s3) and
            (any of ($s4, $s5) or any of ($mal*))
        )
}
