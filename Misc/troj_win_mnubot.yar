rule troj_win_mnubot
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "15JUN2018"
        hash1 = "a1ad4ce17f2c9e5585d7687ef628fab63dac3f022b66bade372b559c9674e483"
        hash2 = "b6bc057005c8db5bbbab720990f36c1ba6e16f7e98fca570b2cfd4d8e66091d9"
        description = "Detects Delphi-based Mnubot Trojan."

    strings:
        $ = "This program must be run under Win32" ascii wide
        $ = "Boolean" ascii wide
        $ = "System" ascii wide
        $ = "ShortInt" ascii wide
        $ = "Pointer" ascii wide
        $ = "Variant" ascii wide
        $ = "HRESULT" ascii wide
        $ = "Create" ascii wide
        $ = "Address" ascii wide
        $ = "Message" ascii wide
        $ = "Flags" ascii wide
        $ = "t!Ht:" ascii wide
        $ = "~]x[[)" ascii wide
        $ = "BkU'9" ascii wide
        $ = "_^[YY]" ascii wide
        $ = "_^[Y]" ascii wide
        $ = "PPRTj" ascii wide
        $ = "az-Latn-AZ" ascii wide
        $ = "HACCEL" ascii wide
        $ = "Count" ascii wide
        $ = "Ident" ascii wide
        $ = "Close" ascii wide
        $ = "Value" ascii wide
        $ = "Index" ascii wide
        $ = "Remove" ascii wide
        $ = "cp819" ascii wide
        $ = "johab" ascii wide
        $ = "^[YY]" ascii wide
        $ = "t,HtYH" ascii wide
        $ = "scode" ascii wide
        $ = "@Qm6t" ascii wide
        $ = "t?Htb" ascii wide
        $ = "r!t2Ht[" ascii wide
        $ = "GetProc" ascii wide
        $ = "Classes" ascii wide
        $ = "Buffer" ascii wide
        $ = "Write" ascii wide
        $ = "IWICBitmap" ascii wide
        $ = "TEvent" ascii wide
        $ = "Enter" ascii wide
        $ = "TArray" ascii wide
        $ = "CloseKey" ascii wide
        $ = "ReadBool" ascii wide
        $ = "Bitmap" ascii wide
        $ = "Empty" ascii wide
        $ = "wifBmp" ascii wide
        $ = "C ;C$s" ascii wide
        $ = "PFNLVCOMPARE" ascii wide
        $ = "igZoom" ascii wide
        $ = "Point" ascii wide
        $ = "8]_^[" ascii wide
        $ = "Image" ascii wide
        $ = "Popup" ascii wide
        $ = "Driver" ascii wide
        $ = "Printer" ascii wide
        $ = "Ctl3D" ascii wide
        $ = ";S(t%" ascii wide
        $ = "Dummy" ascii wide
        $ = "Range" ascii wide
        $ = "Print" ascii wide
        $ = "T;s$|" ascii wide
        $ = "cbrUSEDEF" ascii wide
        $ = "Event" ascii wide
        $ = "IsEmpty" ascii wide
        $ = "ToOem" ascii wide
        $ = "Connection" ascii wide
        $ = "Query" ascii wide
        $ = "GetItem" ascii wide
        $ = "Notify" ascii wide
        $ = "TList" ascii wide
        $ = "Thumb" ascii wide
        $ = "Connect" ascii wide
        $ = "GetBoolean" ascii wide
        $ = "MSHTML" ascii wide
        $ = "Wz6@E" ascii wide
        $ = "version" ascii wide
        $ = "DEBUG" ascii wide
        $ = "DEFAULT_CHAR" ascii wide
        $ = "CHARS" ascii wide
        $ = "oleaut32.dll" ascii wide
        $ = "advapi32.dll" ascii wide
        $ = "RegCloseKey" ascii wide
        $ = "user32.dll" ascii wide
        $ = "LoadLibraryA" ascii wide
        $ = "GetProcAddress" ascii wide
        $ = "ExitProcess" ascii wide
        $ = "GetDC" ascii wide
        $ = "gdi32.dll" ascii wide
        $ = "version.dll" ascii wide
        $ = "VerQueryValueW" ascii wide
        $ = "ole32.dll" ascii wide
        $ = "OleDraw" ascii wide
        $ = "VariantCopy" ascii wide
        $ = "comctl32.dll" ascii wide
        $ = "ImageList_Add" ascii wide
        $ = "winspool.drv" ascii wide
        $ = "OpenPrinterW" ascii wide
        $ = "wininet.dll" ascii wide
        $ = "InternetCheckConnectionW" ascii wide
        $ = "DEFAULT_CHARSET" ascii wide

    condition:
	    all of them
}
