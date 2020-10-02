rule troj_android_vamp_a
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "02OCT2020"
        description = "the Vamp malware family." // public facing description following convention
        hash01 = "54f2aa690954ddfcd72e0915147378dd9a7228954b05c54da3605611b2d5a55e"
        hash02 = "7a8be888e55a602500639d5b07cf7380b1fa9d639cd7fe728939af8e0285a9cd"
        hash03 = "c0517197b58ee5dfab94a8fa1436b27d781fe019e3af02ace507f7dd676ba216"
        hash04 = "6c525037272d506db73f68264e6b9682447c48b254fb49709278aba450a0f2c4"
        hash05 = "6271efb198a719672176a802eeba96a6102d93ef516e5c8489ee0dcf104a2e74"
        description = "Detects APT-C-23 / Vamp APK malware variant" 
        reference = "https://www.welivesecurity.com/2020/09/30/aptc23-group-evolves-its-android-spyware/"

    strings:
        // net/axel/app/utils/k$b0.class
        // C2 params
        $ = "device_name" ascii
        $ = "market_name" ascii
        $ = "package_name" ascii
        $ = "version" ascii
        $ = "connection_type" ascii
        $ = "api_ver" ascii
        $ = "s_token" ascii
        $ = "clock" ascii
        $ = "lang" ascii
        $ = "perms" ascii
        $ = "battery" ascii
        // net/axel/app/utils/k$e2.class
        $ = "/version/" ascii

    condition:
        all of them
}

