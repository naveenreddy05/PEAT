rule Cryptominer_XMRig
{
    meta:
        description = "Detects XMRig cryptocurrency miner"
        severity = "HIGH"
        family = "Cryptominer"

    strings:
        $s1 = "xmrig" ascii nocase
        $s2 = "monero" ascii nocase
        $s3 = "stratum+tcp" ascii
        $s4 = "pool" ascii
        $s5 = "donate-level" ascii
        $s6 = "randomx" ascii nocase
        $s7 = "cpu-priority" ascii

        $net1 = "stratum" ascii
        $net2 = "mining.pool" ascii
        $net3 = "donate.v2.xmrig.com" ascii

    condition:
        uint32(0) == 0x464c457f and
        (
            3 of ($s*) or
            any of ($net*)
        )
}

rule Generic_Cryptominer
{
    meta:
        description = "Generic cryptocurrency mining indicators"
        severity = "HIGH"
        family = "Cryptominer"

    strings:
        $s1 = "minerd" ascii
        $s2 = "cpuminer" ascii
        $s3 = "ethminer" ascii
        $s4 = "cryptonight" ascii nocase
        $s5 = "keccak" ascii
        $s6 = "hashrate" ascii nocase
        $s7 = "pool" ascii
        $s8 = "worker" ascii

    condition:
        uint32(0) == 0x464c457f and 3 of ($s*)
}
