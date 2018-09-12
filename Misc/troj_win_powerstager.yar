rule troj_win_powerstager
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "02JAN2018"
        hash1 = "758097319d61e2744fb6b297f0bff957c6aab299278c1f56a90fba197795a0fa" //x86
        hash2 = "83e714e72d9f3c500cad610c4772eae6152a232965191f0125c1c6f97004b7b5" //x64
        description = "Detects PowerStager Windows executable, both x86 and x64."
	
    strings:
        // META
        $filename = /%s\\[a-zA-Z0-9]{12}/
        $pathname = "TEMP" wide ascii
        $filedesc = "Lorem ipsum dolor sit amet, consecteteur adipiscing elit" wide ascii

        // API Calls
        $apicall_01 = "memset"
        $apicall_02 = "getenv"
        $apicall_03 = "fopen"
        $apicall_04 = "memcpy"
        $apicall_05 = "fwrite"
        $apicall_06 = "fclose"
        $apicall_07 = "CreateProcessA"

        // Decoding Function x86 / x64
        $decoder_x86_01 = { 8D 95 [4] 8B 45 ?? 01 D0 0F B6 18 8B 4D ?? }
        $decoder_x86_02 = { 89 C8 0F B6 84 05 [4] 31 C3 89 D9 8D 95 [4] 8B 45 ?? 01 D0 88 08 83 45 [2] 8B 45 ?? 3D }
        $decoder_x64_01 = { 8B 85 [4] 48 98 44 0F [7] 8B 85 [4] 48 63 C8 48 }
        $decoder_x64_02 = { 48 89 ?? 0F B6 [3-6] 44 89 C2 31 C2 8B 85 [4] 48 98 }

    condition:
        uint16be(0) == 0x4D5A
          and
        all of ($apicall_*)
          and
        $filename
          and
        $pathname
          and
        $filedesc
          and
        (all of ($decoder_x86*) or all of ($decoder_x64*))
}
