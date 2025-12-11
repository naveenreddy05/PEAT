rule Generic_Backdoor
{
    meta:
        description = "Detects generic backdoor indicators"
        severity = "CRITICAL"
        family = "Backdoor"

    strings:
        $s1 = "backdoor" ascii nocase
        $s2 = "reverse_shell" ascii nocase
        $s3 = "/bin/sh" ascii
        $s4 = "bash -i" ascii
        $s5 = "nc -" ascii
        $s6 = "netcat" ascii nocase
        $s7 = "/dev/tcp/" ascii
        $s8 = "mkfifo" ascii

        $cmd1 = "exec" ascii
        $cmd2 = "system" ascii
        $cmd3 = "popen" ascii

    condition:
        uint32(0) == 0x464c457f and
        (
            2 of ($s*) or
            (any of ($s*) and any of ($cmd*))
        )
}

rule Reverse_Shell
{
    meta:
        description = "Reverse shell implementation"
        severity = "CRITICAL"
        family = "Reverse_Shell"

    strings:
        $s1 = "connect" ascii
        $s2 = "socket" ascii
        $s3 = "/bin/sh" ascii
        $s4 = "dup2" ascii
        $s5 = "execve" ascii

        $hex1 = { 2f 62 69 6e 2f 73 68 }  // /bin/sh

    condition:
        uint32(0) == 0x464c457f and
        (
            all of ($s*) or
            ($hex1 and 3 of ($s*))
        )
}
