rule troj_win_originlogger
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "07JUL2022"
        hash1 = "adcc4844f7b5f6cee020243af9e7fb069a6bb69f4c02d987a1a520d182f2d6f9"
        hash2 = "0973965b16b2083ffc7dac9051549a9bf76a987d697f01ae82c8b647768c2f13"
        hash3 = "7a5949e13f3b0922c13f58942102f9ea6eb6cc08d985210bda9f8972e1b14dc9"
        description = "Detects OriginLogger keylogger."
	
    strings:
        $xorLoop = {
            7E ?? ?? ?? ??  // ldsfld   uint8[]
            06              // ldloc.0
            7E ?? ?? ?? ??  // ldsfld   uint8[]
            06              // ldloc.0
            91              // ldelem.u1
            06              // ldloc.0
            61              // xor
            20 ?? ?? ?? ??  // ldc.i4   [0xAA]
            61              // xor
            D2              // conv.u1
            9C              // stelem.i1
        }

        $indexZero = {
            7E ?? ?? ?? ??  // ldsfld
            16              // ldc.i4.0
            9A              // ldelem.ref
            25              // dup
            2D ??           // brtrue.s
            26              // pop
            16              // ldc.i4.0
            16              // ldc.i4.0
            16              // ldc.i4.0
            28 ?? ?? ?? ??  // call
            2A              // ret
        }

        $meth_01 = "FtpWebRequest" ascii
        $meth_02 = "HttpWebRequest" ascii
        $meth_03 = "RegOpenKeyEx" ascii
        $meth_04 = "Regex" ascii
        $meth_05 = "CreateDirectory" ascii

        $str_01 = "HTTP/1.1" wide
        $str_02 = "credential" wide
        $str_03 = "logins" wide

    condition:
        uint16(0) == 0x5A4D 
            and 
        $xorLoop
            and 
        $indexZero 
            and 
        all of ($meth_*) 
            and 
        all of ($str_*) 
}
