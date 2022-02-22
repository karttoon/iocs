rule Godzilla_Webshells_303
{ 

    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "30NOV2021"
        hash1 = "758097319d61e2744fb6b297f0bff957c6aab299278c1f56a90fba197795a0fa" //x86
        hash2 = "83e714e72d9f3c500cad610c4772eae6152a232965191f0125c1c6f97004b7b5" //x64
        description = "Detects various builds of Godzilla Webshell."
	reference = "https://unit42.paloaltonetworks.com/manageengine-godzilla-nglite-kdcsponge/"

  strings:

    $303_php_xorb64_1 = "$pass" ascii wide nocase
    $303_php_xorb64_2 = "$payloadName" ascii wide nocase
    $303_php_xorb64_3 = "$key" ascii wide nocase
    $303_php_xorb64_4 = "$payload=encode" ascii wide nocase
    $303_php_xorb64_5 = "$_SESSION[$payloadName]" ascii wide nocase

    $303_csharp_aesraw_ashx_1 = "Class=\"Handler1\"" ascii wide nocase
    $303_csharp_aesraw_ashx_2 = "{string key" ascii wide nocase
    $303_csharp_aesraw_ashx_3 = "Context.Session[\"payload\"]" ascii wide nocase

    $303_csharp_aesraw_asmx_1 = "Class=\"WebService1\"" ascii wide nocase
    $303_csharp_aesraw_asmx_2 = "{string key" ascii wide nocase
    $303_csharp_aesraw_asmx_3 = "Context.Session[\"payload\"]" ascii wide nocase

    $303_csharp_aesraw_aspx_1 = "{string key" ascii wide nocase
    $303_csharp_aesraw_aspx_2 = "Context.Session[\"payload\"]" ascii wide nocase
    $303_csharp_aesraw_aspx_3 = "CreateInstance(\"LY\")" ascii wide nocase

    $303_csharp_aesb64_ashx_1 = "Class=\"Handler1\"" ascii wide nocase
    $303_csharp_aesb64_ashx_2 = "{string key" ascii wide nocase
    $303_csharp_aesb64_ashx_3 = "string pass" ascii wide nocase
    $303_csharp_aesb64_ashx_4 = "string md5" ascii wide nocase

    $303_csharp_aesb64_asmx_1 = "Class=\"WebService1\"" ascii wide nocase
    $303_csharp_aesb64_asmx_2 = "{string key" ascii wide nocase
    $303_csharp_aesb64_asmx_3 = "string pass" ascii wide nocase
    $303_csharp_aesb64_asmx_4 = "string md5" ascii wide nocase

    $303_csharp_aesb64_aspx_1 = "{string key" ascii wide nocase
    $303_csharp_aesb64_aspx_2 = "string pass" ascii wide nocase
    $303_csharp_aesb64_aspx_3 = "string md5" ascii wide nocase
    $303_csharp_aesb64_aspx_4 = "Context.Session[\"payload\"]" ascii wide nocase

    // Also covers 303_java_aesraw_jsp
    $303_java_aesraw_jspx_1 = "String xc" ascii wide nocase
    $303_java_aesraw_jspx_2 = "class X extends" ascii wide nocase
    $303_java_aesraw_jspx_3 = "request.setAttribute(\"parameters\"" ascii wide nocase

    // Also covers 303_java_aesb64_jsp
    $303_java_aesb64_jspx_1 = "String xc" ascii wide nocase
    $303_java_aesb64_jspx_2 = "String pass" ascii wide nocase
    $303_java_aesb64_jspx_3 = "String md5" ascii wide nocase
    $303_java_aesb64_jspx_4 = "class X extends" ascii wide nocase

  condition:

    all of ($303_php_xorb64_*) or
    all of ($303_csharp_aesraw_ashx_*) or
    all of ($303_csharp_aesraw_asmx_*) or
    all of ($303_csharp_aesraw_aspx_*) or
    all of ($303_csharp_aesb64_ashx_*) or
    all of ($303_csharp_aesb64_asmx_*) or
    all of ($303_csharp_aesb64_aspx_*) or
    all of ($303_java_aesraw_jspx_*) or
    all of ($303_java_aesb64_jspx_*)

}
