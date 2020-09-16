rule troj_osx_evilquest {
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        description = "EvilQuest / ThiefQuest."
        date = "23JUL2020"
        hash = "bcdb0ca7c51e9de4cf6c5c346fd28a4ed28e692319177c8a94c86dc676ee8e48"
        reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/updates-on-thiefquest-the-quickly-evolving-macos-malware/"
        
    strings:
        $http_01 = "GET /%s HTTP/1.0" ascii wide
        $http_02 = "Host: %s" ascii wide
        
        $log_01 = "This application has to be run by root" ascii wide
        $log_02 = "Cannot create thread!" ascii wide
        $log_03 = "ERROR1: %s" ascii wide
        $log_04 = "ERROR2: %s" ascii wide
        $log_05 = "ERROR3: %s" ascii wide
        $log_06 = "ERROR4: %s" ascii wide
        $log_07 = "ERROR5: %s" ascii wide
        
        $func_01 = "_react_exec" ascii wide
        $func_02 = "_react_start" ascii wide
        $func_03 = "_react_save" ascii wide
        $func_04 = "_react_keys" ascii wide
        $func_05 = "_react_ping" ascii wide
        $func_06 = "_react_host" ascii wide
        $func_07 = "_react_scmd" ascii wide
        $func_08 = "ei_rootgainer_elevate" ascii wide
        $func_09 = "run_payload" ascii wide
        $func_10 = "sxorxorkey_s" ascii wide

    condition:
        3 of ($func_*)
            and
        all of ($log_*)
            and
        all of ($http_*)
}
