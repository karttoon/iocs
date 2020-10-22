rule apt_win_ismagent_vba : OilRig
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "26JUN2018"
        hash1 = "d7130e42663e95d23c547d57e55099c239fa249ce3f6537b7f2a8033f3aa73de"
        description = "Identify the VBA macro used by ISMAgent"

    strings:
        $vba_01 = "ActiveDocument.Sections(intSection).Headers(1).Range" ascii wide
        $vba_02 = "CreateObject" ascii wide
        $vba_03 = "CreateTextFile" ascii wide
        $vba_04 = "StrReverse" ascii wide
        $vba_05 = /objShell.ShellExecute "powershell.exe", " -exec bypass -File C:\\programdata\\[a-zA-Z0-9_]+\.ps1", "C:\\ProgramData/

    condition:
        @vba_01[1] < @vba_02[1]
          and
        @vba_02[1] < @vba_03[1]
          and
        @vba_03[1] < @vba_04[1]
          and
        @vba_04[1] < @vba_05[1]
}

rule apt_win_ismagent_ps1 : Oilrig
{
    meta:
        author = "Jeff White [karttoon@gmail.com] @noottrak"
        date = "26JUN2018"
        hash1 = "d7130e42663e95d23c547d57e55099c239fa249ce3f6537b7f2a8033f3aa73de"
        description = "Identify the PS1 dropped by ISMAgent"

    strings:
        $ = "function DB64" ascii wide
        $ = "function EB64" ascii wide
        $ = "function DAES" ascii wide
        $ = "function MA" ascii wide
        $ = "function WebReq" ascii wide
        $ = "function Query" ascii wide
        $ = "function get-res" ascii wide
        $ = "function DNS-Con" ascii wide

    condition:
        all of them
}
