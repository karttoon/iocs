rule troj_win_pennywise_stealer.yar
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "14JUL2022"
        hash01 = "7DE9DB22A3CF2C481F953D3D4D3F88FB85088A6F1CAF7CBD5DAD83540F4ECD34"
        hash02 = "E9CAB3A18F4E6324D8C722110A250C57A1B250429F73092CBD88435DBA0F35DE"
        hash03 = "0501597D29626DF172C5F40D5B04366C94188CF620694E96CE394EACD5E4E920"
        description = "Detects PennyWise Stealer malware"
        reference = "https://blog.cyble.com/2022/06/30/infostealer/"
	
    strings:
        $ = "PennyWise"
        $ = "StringBuilder"
        $ = "StackTrace"
        $ = "StackFrame"
        $ = "BCryptDecrypt"
        $ = "GetProcAddress"
        $ = "GetFileName"
        $ = "CreateHttp"

    condition:
        all of them
}
