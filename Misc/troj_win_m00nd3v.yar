rule win_troj_m00nd3v {
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        description = "Detects M00nD3v Stub." 
        date = "20JUL2020"
        hash1 = "c23b33ddb4e0cfa52b9242648f5cb7a6ee916b4ba1e6f547d8d5ef543dccbb9d"
        reference = "https://www.zscaler.com/blogs/research/deep-dive-m00nd3v-logger"
        
    strings:
        $pop_01 = "POP3 User Name" ascii wide
        $pop_02 = "POP3 Server" ascii wide
        $pop_03 = "POP3 Password" ascii wide
        $pop_04 = "POP3 Port" ascii wide
        
        $imap_01 = "IMAP User Name" ascii wide
        $imap_02 = "IMAP Server" ascii wide
        $imap_03 = "IMAP Password" ascii wide
        $imap_04 = "IMAP Port" ascii wide
        
        $httpmail_01 = "HTTPMail User Name" ascii wide
        $httpmail_02 = "HTTPMail Server" ascii wide
        $httpmail_03 = "HTTPMail Password" ascii wide
        $httpmail_04 = "HTTPMail Port" ascii wide
        
        $smtp_01 = "SMTP Server" ascii wide
        $smtp_02 = "SMTP Password" ascii wide
        $smtp_03 = "SMTP USer Name" ascii wide // Note the incorrect capitalization
        $smtp_04 = "SMTP Port" ascii wide
        
        $moondev_01 = "M00nD3v Stub.exe" ascii wide
        $moondev_02 = "https://m00nd3v.com/M00nD3v/Decryption/BouncyCastle.Crypto.dll" ascii wide
        
        $ip_01 = "http://bot.whatismyipaddress.com/" ascii wide
        $ip_02 = "http://dyn.com/dns/" ascii wide

    condition:
        any of ($moondev_*)
        or
        all of ($pop_*) and all of ($ip_*)
        or
        all of ($imap_*) and all of ($ip_*)
        or
        all of ($httpmail_*) and all of ($ip_*)
        or
        all of ($smtp_*) and all of ($ip_*)
}
