rule troj_win_bitrat
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "03MAR2022"
        hash01 = "5f732fc3a715db12115ca5fe9564ce894b4dc96598837426e3a11ac119bf437c"
        hash02 = "342a5102bc7eedb62d5192f7142ccc7413dc825a3703e818cf32094638ebd17a"
        description = "Detects BitRAT downloader"
        reference = "https://www.fortinet.com/blog/threat-research/nft-lure-used-to-distribute-bitrat"

    strings:
        $ = "https://cdn.discordapp.com/attachments/" ascii wide // Ending for observed URL: '923858595353874472/927279369183973407/NFTEXE.png'
        $ = "-enc aQBwAGMAbwBuAGYAaQBnACAALwByAGUAbABlAGEAcwBlAA==" ascii wide // ipconfig /release
        $ = "-enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMgAwAA==" ascii wide // Start-Sleep -s 20
        $ = "-enc aQBwAGMAbwBuAGYAaQBnACAALwByAGUAbgBlAHcA" ascii wide // ipconfig //renew

    condition:
        all of them
}

