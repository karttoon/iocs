rule troj_win_headertip
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "06APR2022"
	hash01 = "1b3c16fb7fb368272dfcf8c8f07acc41606affce2f49eaed5c5b43802fa947fb"
	hash02 = "8dbb7fad51d75bdf43e1070777c7fd10e03a55e167dc715b109791e2a553d986"
	hash03 = "e0f1d23d9e0a302b5e4e7080305e9849e73dc3f15e4eeeecda8a3a625c24a49f"
        description = "Detects HeaderTip DLL"

    strings:
        $ = "HttpsInit" ascii
        $ = "POST" wide
        $ = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko" wide
        $ = "%016I64x%08x" wide

    condition:
        all of them
}

