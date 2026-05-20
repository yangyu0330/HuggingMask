rule malicious_pickle_execution_opcodes
{
    meta:
        description = "Detect execution-capable Python pickle opcodes by byte value"
        scope = "prefilter only; Path A pickletools whitelist is authoritative"

    strings:
        $global       = { 63 }      // GLOBAL 'c'
        $stack_global = { 93 }      // STACK_GLOBAL
        $reduce       = { 52 }      // REDUCE 'R'
        $build        = { 62 }      // BUILD 'b'
        $inst         = { 69 }      // INST 'i'
        $obj          = { 6F }      // OBJ 'o'
        $newobj       = { 81 }      // NEWOBJ
        $newobj_ex    = { 92 }      // NEWOBJ_EX
        $ext1         = { 82 }      // EXT1
        $ext2         = { 83 }      // EXT2
        $ext4         = { 84 }      // EXT4
        $persid       = { 50 }      // PERSID 'P'
        $binpersid    = { 51 }      // BINPERSID 'Q'

    condition:
        uint8(0) == 0x80 and any of them
}