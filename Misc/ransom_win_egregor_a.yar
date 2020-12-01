rule ransom_win_egregor_a
    {
        meta:
            author = "Jeff White (karttoon@gmail.com) @noottrak"
            description = "Autogenerated by Binsequencer v.1.1.0 - Egregor Ransomware DLL Common Byte Pattern"
            date = "01DEC2020"
            hash01 = "a5989c480ec6506247325652a1f3cb415934675de3877270ae0f65edd9b14d13"
            hash02 = "6ad7b3e0873c9ff122c32006fdc3675706a03c4778287085a020d839b74cd780"
            hash03 = "9c900078cc6061fb7ba038ee5c065a45112665f214361d433fc3906bf288e0eb"
            hash04 = "6dbe1d2de299359036520f15490834a6ac40b665cf5cd249379d65242af00b44"
 
 
        strings:
            $ = { CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC558B??568B????578B????8B??83????74??8B????03??33????E8????????8B????8B????03??33????5F5E5DE9????????CCCCCCCCCCCCCCCCCCCCCCCCCCCC558B??83????53568B????57C6??????C7????????????8B????8D????33??????????505389????89????E8????????8B????57E8????????8B????83????F6??????0F85????????89????8D????89????8B????89????83????0F84????????8D????8D????8B??????8D????8B??89????85??74??8D????E8????????B1??88????85??78??7E??8B????81??????????75??83????????????74??68????????E8????????83????85??74??8B??????????8B??6A??FF????E8????????FF??8B????83????8B????8B??8B??E8????????39????74??EB??8A????8B??83????74??8B????E9????????8B????C7????????????EB??84??74??8B????EB??83??????74??68????????8D????BA????????508B??E8????????FF????53E8????????83????8B????5F5E5B8B??5DC368????????8D????8B??508B??E8????????89????8D????53FF????E8????????8B????83????8B??8B????E8????????CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCE8????????E8????????E8????????84??75??32??C3E8????????84??75??E8????????EB??B0??C3CCCCCCCCCCCCCCCCCCCCE8????????85??0F95??C3CCCC6A??E8????????59B0??C3CCCC558B??80??????75??E8????????E8????????6A??E8????????59B0??5DC3CCCCCCCCCCCCCCE8????????B0??C3CCCCC3E9????????558B??5DE9????????CCCC558B??FF????E8????????595DC2????CCCCCCCC558B??FF????E8????????595DC2????CCCCCCCC558B??8B????8B????8B????F00FB1??5DC3CCCCCCCC558B??8B????8B????8B????F00FB1??5DC3CCCCCCCC558B??8B????33??33??F00FB1??5DC3CCCCCCCC558B??8B????89??8B??5DC2????CCCCCC558B??8B????89??8B??5DC2????CCCCCC568B??FF??E8????????83????595EC3CCCCCCCC568B??FF??E8????????83????595EC3CCCCCCCCB8????????C3B8????????C383????0F95??C383????0F95??C3558B??FF????E8????????595DC2????CCCCCCCC558B??FF????E8????????595DC2????CCCCCCCC8B??83????C38B??C38B??C383????0F95??C383????0F95??C3568B??FF??E8????????83????595EC3CCCCCCCC568B??FF??E8????????83????595EC3CCCCCCCC558B??8B????8B????3B??75??33??5DC383????83????8A??3A??75??84??74??8A????3A????75??83????83????84??75??EB??1B??83????5DC3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC558B??FF????FF??????????85??74??568B??50E8????????8B??5985??75??5E5DC3CCCCCCCCCCCCCCCC558B??8B????BA????????8D????EB??0FB6??33??69??????????418A??84??75??8B??5DC3CCCCCCCCCCCCCCCCCC558B??83????33??33??538B????F00FB1??85??0F85????????5668????????68????????68????????508D????89????5150E8????????8B??83????85??74??8B??8D????8A??4184??75??2B??74??80????????75??C6????????83????75??8D????89????83????5750E8????????8B??5985??74??83????8D????56FF????89????5089????E8????????8B????83????33??F00FB1??85??75??FF????33??FF????FF??????????8B????5789????E8????????595F56E8????????8B????595E5B8B??5DC3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC8B??????0FB6??????8B??8B??????85??0F84????????69??????????83????0F8E????????81??????????0F8C????????0FBA????????????73??F3AA8B??????8B??C30FBA????????????0F83????????660F6E??660F70????03??0F11??83????83????2B??81??????????7E??8D????????????8D????????????90660F7F??660F7F????660F7F????660F7F????660F7F????660F7F????660F7F????660F7F????8D??????????81??????????F7??????????75??EB??0FBA????????????73??660F6E??660F70????83????72??F30F????F30F??????83????83????83????73??F7??????????74??8D??????F30F????F30F??????8B??????8B??C3F7??????????74??88??4783????F7??????????75??F7??????????74??89??83????83????F7??????????74??8D????????????8D??????????89??89????83????83????F7??????????75??8B??????8B??C3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC558B??FF????E8????????595DC2????CCCCCCCC558B??8B????89??8B??5DC2????CCCCCC568B??FF??E8????????83????595EC3CCCCCCCC83????0F95??C38B??83????C38B??C383????0F95??C3568B??FF??E8????????83????595EC3CCCCCCCC558B??578B????80??????74??8B??85??74??8D????8A??4184??75??2B??53568D????53E8????????8B??5985??74??FF??5356E8????????8B????8B??83????33??89??C6??????56E8????????595E5BEB??8B????8B??89??C6??????5F5DC3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC558B??568B????80??????74??FF??E8????????5983????C6??????5E5DC3CCCCCCCCCCCCCC558B??83????538B????56576A??59BE????????8D????F3A58B????85??74??F6????74??8B??83????518B??8B????8B??8B????E8????????FF??89????89????85??74??F6????74??C7????????????8D????50FF????FF????FF????FF??????????5F5E5B8B??5DC2????CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC5356578B??????8B??????8B??????555250515168????????64????????????A1????????33??89??????64????????????8B??????8B????8B??????33??8B????83????74??8B??????83????74??3B??76??8D????8D??????8B??89????83??????75??68????????8B????E8????????B9????????8B????E8????????EB??64????????????83????5F5E5BC38B??????F7????????????B8????????74??8B??????8B????33??E8????????558B????FF????FF????FF????E8????????83????5D8B??????8B??????89??B8????????C355FF??????E8????????83????8B??????8B??FF????FF????FF????E8????????83????5DC2????555657538B??33??33??33??33??33??FF??5B5F5E5DC38B??8B??8B??6A??E8????????33??33??33??33??33??FF??558B??5356576A??5268????????51E8????????5F5E5B5DC3558B??????5251FF??????E8????????83????5DC2????CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC3C3558B??FF????E8????????595DC2????CCCCCCCC558B??8B????89?? }
 
        condition:
            all of them
}