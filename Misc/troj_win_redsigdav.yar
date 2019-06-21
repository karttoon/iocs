rule troj_win_redsigdav {
meta:
    author = "Jeff White (karttoon@gmail.com) @noottrak"
    date = "21FEB2019"
    hash01 = "3f15b6376019755ae9faf5a01b202410c6548a0e3717176a36fcbd88d7df635e"
    hash02 = "e530e16d5756cdc2862b4c9411ac3bb3b113bc87344139b4bfa2c35cd816e518"
    hash03 = "6b3d2cef39e75c627e8e36b6a0047ace4557b71c907083fd5de32f2e6b3cde0a"
    description = "Identifies IIS 6 WebDav exploit tool utilizing CVE-2017-7269 used in Operation Red Signature"
    reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/supply-chain-attack-operation-red-signature-targets-south-korean-organizations/"

strings:
    // Long header request for CVE-2017-7269
    $exploit_01 = "If: <http://%s/%s> (Not <locktoken:IIS>)"
    $exploit_02 = "If: <https://%s/%s> (Not <locktoken:IIS>)"
    $exploit_03 = "If: <http://%s/%s> (Not <locktoken:IIS>)"
    $exploit_04 = "If: <https://%s/%s> (Not <locktoken:IIS>)"
    $exploit_05 = "If: <http://%s/images> (Not <locktoken:IIS>)"
    $exploit_06 = "If: <https://%s/images> (Not <locktoken:IIS>)"

    // Required for PROPFIND request
    $prop = "PROPFIND"

    // Command help
    $cmdhelp_01 = "iisexit                            -close connection"
    $cmdhelp_02 = "iisget <remotefile> <localfile>    -get remote file to local"
    $cmdhelp_03 = "iisput <localfile> <remotefile>    -put local file to remote"
    $cmdhelp_04 = "iiscmd <program>                   -run program"
    $cmdhelp_05 = "iishelp                            -show help info"

    // Included commands
    $cmd_01 = "iisexit"
    $cmd_02 = "iisget"
    $cmd_03 = "iisput"
    $cmd_04 = "iiscmd"
    $cmd_05 = "iishelp"

    // Print outs
    $outmsg_01 = "[-] SafeSendRecv Parameter Error: %d !"
    $outmsg_02 = "[-] IISData Error!"
    $outmsg_03 = "[-] Shell Start Error!"
    $outmsg_04 = "[-] Get Encode Key for Tunnel Failed!"
    $outmsg_05 = "[-] Over Ret : %d, Status = %d"
    $outmsg_06 = "[-] Install Shell Failed!"
    $outmsg_07 = "[+] Guessed URI Length : %d"
    $outmsg_08 = "[-] Guess Error : 0"
    $outmsg_09 = "[*] IIS 6 WEBDAV Memory Corrupt Exploit @ 2017-03-17"
    $outmsg_10 = "[*] Guessed Return = %d, HTTP Status = %d"
    $outmsg_11 = "Close Server,byby!"

condition:
    (1 of ($exploit_*) and $prop) or all of ($cmd_*) or 1 of ($cmdhelp_*) or 2 of ($outmsg_*)
}