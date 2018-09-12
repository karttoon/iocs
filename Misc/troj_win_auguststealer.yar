rule troj_win_auguststealer
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "23JUL2017"
        hash1 = "dc0b12d7708e0091b3ea2c530a214ccb10ea152134a61a21a9be40f1322950de"
        description = "Detects August Stealer information stealer."

    strings:
        // August.exe
        $string_originalname = { 41 75 67 75 73 74 2E 65 78 65 }

        // MD5CryptoServiceProvider
        $string_md5crypto = { 4D 44 35 43 72 79 70 74 6F 53 65 72 76 69 63 65 50 72 6F 76 69 64 65 72 }

        // CreateDecryptor
        $string_createdecrypt = { 43 72 65 61 74 65 44 65 63 72 79 70 74 6F 72 }

        // Firefox
        $string_firefox = { 46 69 72 65 66 6F 78 }

        // Password
        $string_password = { 50 61 73 73 77 6F 72 64 }

        // Fiddler
        $string_fiddler = { 46 00 69 00 64 00 64 00 6C 00 65 00 72 }

        // Wireshark
        $string_wireshark = { 57 00 69 00 72 00 65 00 73 00 68 00 61 00 72 00 6B }

        // SELECT * FROM Win32_OperatingSystem
        $string_win32os = { 53 00 45 00 4C 00 45 00 43 00 54 00 20 00 2A 00 20 00 46 00 52 00 4F 00 4D 00 20 00 57 00 69 00 6E 00 33 00 32 00 5F 00 4F 00 70 00 65 00 72 00 61 00 74 00 69 00 6E 00 67 00 53 00 79 00 73 00 74 00 65 00 6D }

        // Opera
        $string_opera = { 4F 00 70 00 65 00 72 00 61 }

        // Chrome
        $string_chrome = { 43 68 72 6F 6D 65 }

        // recentservers.xml|sitemanager.xml
        $string_servers = { 72 00 65 00 63 00 65 00 6E 00 74 00 73 00 65 00 72 00 76 00 65 00 72 00 73 00 2E 00 78 00 6D 00 6C 00 7C 00 73 00 69 00 74 00 65 00 6D 00 61 00 6E 00 61 00 67 00 65 00 72 00 2E 00 78 00 6D 00 6C }

        // POST
        $string_post = { 50 00 4F 00 53 00 54 00 }

        // .bat
        $string_bat = { 2E 00 62 00 61 00 74 00 }

        // *.rdp
        $string_rdp = { 2A 00 2E 00 72 00 64 00 70 00 }

        // August_
        $string_augustdll = { 41 75 67 75 73 74 5F }

        // August@
        $string_augustprod = { 41 75 67 75 73 74 40 }

    condition:
        13 of ($string_*)
}
