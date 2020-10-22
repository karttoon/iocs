rule troj_apk_gravityrat_a
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        description = "APK variant of GravityRAT."
        hash_01 = "b2cd09952bae1ec439cebfc0d60cdcc1454ef306140d6ed46eb4542d19b5a9e7"
        hash_02 = "da567018471eb780f3706ad63e07ea14ca366639e0616b5ced12d27c9fb268ea"
        hash_03 = "cf6edfc2c92d85033556d1a2c683f3bd738e4b43c86b9b75faa2747507716e67"
        date = "22OCT2020"
        reference = "https://securelist.com/gravityrat-the-spy-returns/99097/"

    strings:
        $c2_01 = "http://n2.nortonupdates.online:64443" ascii
        $c2_02 = "http://n4.nortonupdates.online:64443" ascii
        
        $log_01 = "hi back restarting!! :D" ascii
        
        $path_01 = "/WHISKY/$@D.php" ascii
        $path_02 = "/WHISKY/upload.php?imei=" ascii
        $path_03 = "/WHISKY/write.php" ascii
        $path_04 = "/WHISKY/register.php" ascii
    
    condition:
        1 of ($c2_*)
            or
        1 of ($log_*)
            or
        2 of ($path_*)
}

