rule troj_win_oldgremlin : lnk
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "30SEP2020"
        hash01 = "7d7a7f85fc83d65a133b05b0356a98fd2fd6fb946e3014460f3bf96ffc5d213d"
        hash01 = "827773bd4558521678608e84f27c5f0eebc6761aa40892b6b0bef67109b751c5"
        hash02 = "091d86659caa0dda54dd302c3752b3cd54339c34a56fd7bb22857e43fdf88dc5"
        hash03 = "c5c54b49ca536cbdb193f1f614aac813e6586bd8e52215b008494b610461765d"
        hash04 = "35bc847e8a2ac7ccb75850cf69db5a47c245ed2a4dc5e98283dfd8f7f9df59e1"
        hash05 = "dc9cbd484395367158c5819882ac811ee8464a62b018ffa51d3d476003643e54"
        hash06 = "7171c68237e2c2054686cb31c92904b38862a06e14990aee5b5c23fd00cd7029"
        hash07 = "769ad49c1d893c2965e25f180288e649d42b89a0b7588f63ad7c4bdba1105537"
        hash08 = "71f351c47a4cd1d9836b39da8454d1dc20df51950fe1c25aa3192f0d60a0643f"
        hash09 = "bfa9d5cc0d139f2d8bb16d0fc8e8d661c554e77523b4b1f6c0a48a5172e45b93"
        hash10 = "5c9cf2e4f2392a60cb7fe1d3ca94bda99968c7ee73f908dfc627a6b6d3dc404a"
        description = "Detects OldGremlin LNK 1st Stage File." 
        reference = "https://www.group-ib.com/blog/oldgremlin"

    strings:
        // Part of command executed via LNK
        $cmd_01 = "Windows\\System32\\cmd.exe" ascii
        $cmd_02 = "comspec" wide
        
        // Part of embedded JS
        $jscript_01 = "script type=\"text/javascript" ascii
        $jscript_02  = "fromCharCode" ascii
        
        // LNK Header and CLSID
        $LNKStruct = { 4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
        
    condition:
        filesize > 15KB 
            and
        all of ($cmd_*) 
            and
        all of ($jscript_*) 
            and
        $LNKStruct at 0
}
