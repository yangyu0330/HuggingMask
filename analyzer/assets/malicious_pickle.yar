rule malicious_pickle
{
    strings:
        $a = "REDUCE"
        $b = "GLOBAL"
        $c = "STACK_GLOBAL"

    condition:
        any of them
}