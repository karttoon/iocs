rule ransomware_win_antefrigus
{
    meta:
	author = "Jeff White (karttoon@gmail.com) @noottrak"
        description = "AnteFrigus Unpacked Ransomware"
        date = "22NOV2019"
        hash = "ce9a66ed66ee29ca27678e02f2a900a7d810ecdf58b28f1815be8a49f1a59991"
        reference = "https://www.bleepingcomputer.com/news/security/strange-antefrigus-ransomware-only-targets-specific-drives/"

    strings:
        $cpp_str01 = "G:\\sever\\Scan\\crypro\\rijndael_simd.cpp" wide ascii
        $cpp_str02 = "G:\\sever\\Scan\\crypro\\sha_simd.cpp" wide ascii
        $cpp_str03 = "G:\\sever\\Scan\\crypro\\sse_simd.cpp" wide ascii
        
        $path_str01 = "C:/qweasd/test.txt" wide ascii
        $path_str02 = "-readme.txt" wide ascii
        $path_str03 = "C:/qweasd/news.html" wide ascii
        
        $pdb = "C:\\Users\\Nikolas\\source\\repos\\shicpefinaly\\Release\\shicpefinaly.pdb" wide ascii

    condition:
	    all of ($cpp_str*) or 2 of ($path_str*) or $pdb
}

