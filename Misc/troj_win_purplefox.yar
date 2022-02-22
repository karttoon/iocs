rule troj_win_purplefox
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        description = "Detects PurpleFox malware."
        date = "01FEB2022"
        hash01 = "BE5434982BE1F4E910BC16B44BDFD929A9257816533D376963710CCB7CB978B7"
        hash02 = "BAE1270981C0A2D595677A7A1FEFE8087B07FFEA061571D97B5CD4C0E3EDB6E0"
        hash03 = "272919BCB4ACC9330A112301D33BEA2789EE1B273F7406E75B3A2FFD11CCFDE0"
        reference = "https://blog.minerva-labs.com/malicious-telegram-installer-drops-purple-fox-rootkit"

    strings:
        $ = ":7456/%c?=%d" ascii wide nocase
        $ = "\\1.rar" ascii wide nocase
        $ = "\\7zz.exe" ascii wide nocase
        $ = "\\ojbk.exe" ascii wide nocase
        $ = ":7456/77" ascii wide nocase
        $ = "C:\\ProgramData\\360.dll" ascii wide nocase
        $ = "C:\\ProgramData\\rundll3222.exe" ascii wide nocase
        $ = "C:\\ProgramData\\svchost.txt" ascii wide nocase
    
    condition:
        all of them

}
