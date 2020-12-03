rule troj_win_plugx_loader_go
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        description = "PlugX DLL Loader - Golang (also catches the self-extracting RARs containing the DLL)"
        date = "02DEC2020"
        hash01 = "d9332581f77427ec9f57e68d290a9f69ecadf5e35d519e782a785f4b8f3a1ac1"
        hash02 = "4d1eb28ad0b9c6d505b0a3c46695a9393bd65ee17929e8d42c9b16620caf0fd8"
        hash03 = "1102d23c62929f49980af8bdb34c4bca777ae938220749676d7fc27208cde293"
        hash04 = "bc6c2fda18f8ee36930b469f6500e28096eb6795e5fd17c44273c67bc9fa6a6d"
        reference = "https://www.proofpoint.com/us/blog/threat-insight/ta416-goes-ground-and-returns-golang-plugx-malware-loader"
 
    strings:
        $ = { 68 65 78 2E 64 6C 6C 00 43 45 46 50 72 6F 63 65 73 73 46 6F 72 6B 48 61 6E 64 6C 65 72 45 78 00 } // hex.dll\x00CEFProcessForkHandlerEx\x00 
    
    condition:
        all of them
}
