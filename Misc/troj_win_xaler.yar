rule troj_win_xaler
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "17DEC2019"
        hash1 = "e973e776621cc2286329d16a5d707816ebb7a498b72d42745e1781249804bfa3"
        description = "Detects Xaler Macro Virus."

    strings:
        $ = "GOODSub"
        $ = "RELAX2"
        $ = "C:\\temp.tmp"

    condition:
        all of them
}
