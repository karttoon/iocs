rule troj_win_blackstar
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "18MAY2017"
        hash1 = "afb93727e0a9f7fd472c3e7337ab0e71b4bcd32a29561588eeb3c652aaa1debd" // V1.0
        hash2 = "ff6b4f9f5d6ee9d39477a64a5bc870061950c25af153cd0c01e031fc8db624cc" // V1.5
        hash3 = "445cb87e0daaec2b24ac52d62adf1e7ddf43717cfe0818268260b44fdfdf24b5" // V2.9
        hash4 = "f9085dd195af5b6c5e04908bdd6993167c1d2e08f5f28ff4066510ce32e641d0" // V3.0
        description = "Detects Blakstar malware family"
        
    strings:
        // Identifying Strings

        // V1.0
        $int_01 = "KeyTrap was successfully executed" wide nocase ascii
        $int_02 = "BlakStar: KeyTrap" wide nocase ascii
        $int_03 = "BlakStar KeyTrap" wide nocase ascii

        // V1.5
        $int_04 = "c:\\users\\public\\Microsoft\\blakstar\\" wide nocase ascii
        $int_05 = "BlakStar client successfully installed" wide nocase ascii
        $int_06 = "BlakStar installer executed on" wide nocase ascii
        $int_07 = "BlakStar Client error" wide nocase ascii

        // Encryption Keys

        // V1.0
        $key_01 = "VWEBRXYWVERYFVWEUFRVwebtgobroebrvboBYOBVOYEBRYOBVWOYEB" wide nocase ascii

        // V1.5
        $key_02 = "XSBBDEYSJ3473BUdfjtuE3574347XVEVCOreyuuhwehfbvruyvcZCYXBEVYEVKK" wide nocase ascii

        // V3.0
        $key_03 = "KVDKYEhavelowYSJ3473BUdfjtuE3574347XVEV" wide nocase ascii

        // IRC Commands

        // V1.0
        $irc_01 = "USER Capricorn 8 * :Capricorn v1.0" wide nocase ascii
        $irc_02 = "PRIVMSG {0} : The computer has been idle for {1}" wide nocase ascii
        $irc_03 = "PRIVMSG {0} :Fail to get user's idle time" wide nocase ascii
        $irc_04 = "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms" wide nocase ascii
        $irc_05 = "PRIVMSG {0} : {1} was downloaded successfully" wide nocase ascii
        $irc_06 = "PRIVMSG {0} : {1} was opened successfully" wide nocase ascii
        $irc_07 = "PRIVMSG {0} : Screen image uploaded successfully." wide nocase ascii

        // C2 Commands

        // V1.0
        $cmd_01 = "$get <url> <destination> - download a remote file from a url" wide nocase ascii
        $cmd_02 = "$delete <filepath> - delete a single file" wide nocase ascii
        $cmd_03 = "$image - capture and upload screen image" wide nocase ascii
        $cmd_04 = "$open <file_path> - open a file or directory" wide nocase ascii
        $cmd_05 = "$stop <process_name> - stop running process" wide nocase ascii
        $cmd_06 = "$dir <folder_path> - stop running process" wide nocase ascii
        $cmd_07 = "$user - return logged in user" wide nocase ascii
        $cmd_08 = "$idle time - return the user's idle time'" wide nocase ascii

        // POST

        // V1.0
        $web_01 = "Machine={0}&User={1}&OS={2}&Time={3}&Version={4}&APP={5}" wide nocase ascii
        $web_02 = "Machine={0}&User={1}&OS={2}&Time={3}&Version={4}" wide nocase ascii

        // Config Call-out

        // V1.0
        $web_03 = /http:\/\/[a-zA-Z0-9.-]+\/Settings\/Configuration\/Config\.ini/
        $web_04 = "Settings/Configuration/Config.ini" wide nocase ascii

        // V1.5
        $web_05 = /http:\/\/[a-zA-Z0-9.-]+\/settings\/config\.ini/
        $web_06 = "settings/config.ini" wide nocase ascii

        // V3.0
        $web_07 = "Settings/Configuration/Update.txt" wide nocase ascii

    condition:
        (uint16be(0) == 0x4D5A and filesize < 1MB)
          and
        1 of ($int*)
          or
        1 of ($key*)
          or
        2 of ($irc*)
          or
        2 of ($cmd*)
          or
        2 of ($web*)
}
