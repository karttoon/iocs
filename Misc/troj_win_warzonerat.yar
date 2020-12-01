rule troj_win_warzonerat
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "12NOV2020"
        hash_01 = "531d967b9204291e70e3aab161a5b7f1001339311ece4f2eed8e52e91559c755"
        hash_02 = "B3E18B33CDB21C77E0C3070489C05E12F629EC2C6A4B1AF1D39FAC2FDCDF5D46"
        hash_03 = "628F41216961F41DBDE420016512DCE8ADD4CA90B100BD2D4E2F12D82458A335"
        description = "Detects WarzoneRAT."
        reference = "https://research.checkpoint.com/2020/warzone-behind-the-enemy-lines/"

    strings:
        $avemaria_01 = "AVE_MARIA" ascii
        $avemaria_02 = "WM_DSP" wide
        $avemaria_03 = "WM_DISP" wide
        $avemaria_04 = "%u.%u.%u.%u" ascii
        $avemaria_05 = "Hey I'm Admin" wide
        
        $keylog_01 = "POP3 Password" wide
        $keylog_02 = "SMTP Password" wide
        $keylog_03 = "HTTP Password" wide
        $keylog_04 = "IMAP Password" wide
        
        $warzone = /warzone\d+/ // network RC4 enc key usually warzone160 (1.6.0+)

    condition:
        all of ($avemaria_*)
        	and
        (all of ($keylog_*)
        	or
         $warzone)
}
