rule loader_win_unknown001 : PennyWise
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "14JUL2022"
        hash01 = "48115B0E7007C7BF3065F8A3860FDF067A28F5E5BA3D5F44EBFDEF8B0B1019A0"
        hash02 = "7D5F29FB2248E2A4AF57EAC1BBF81AD4AEC0F2126EF0D6CA69090C52E18A1243"
        hash03 = "575AC614BA1148D06120215D2F81962EDD54DB2F4C9810F61F7614B3B726DDC8"
        description = "Detects a malware loader which uses process hollowing on AppLaunch.exe"
        reference = "https://blog.cyble.com/2022/06/30/infostealer/"
	
    strings:
        // Cluster 1
        $str_01 = "673846405357007579878821619813876310959816507" ascii
        $str_02 = "o6hXqahcz1nyTmEWmN99uMqckr9mqkXOJmltGCYhtZuc8AXyMCRuTLs2Qhf4fiCUWt6hABhWklV9jr9FOJh8bfQcyh" ascii
        // Cluster 2
        $str_03 = "495571907783603845594622781396864775526388194" ascii
        $str_04 = "ssMyQc4aW68diVpooAdKIkblZUxw0G777TgFt1ggaq38la4oWdFxNTtJqZYD1pQblKpU1Kadx8sB0hIbWl7" ascii
        // Injects into AppLaunch.exe 
        $app_01 = "\x00rk\\v4.0.30319\\AppLaunch.exe\x00" ascii
        $app_02 = "\x00C:\\Windows\\Microsoft.NET\\Framewo\x00" ascii
    
    condition:
        uint16(0) == 0x5A4D 
            and
        2 of ($str_*)
            and 
        all of ($app_*)
}
