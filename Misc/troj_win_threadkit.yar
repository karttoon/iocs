rule troj_win_threadkit_rtf
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date   = "28MAR2018"
        description = "Detects RTF document created by ThreadKit dropper."

    strings:
	    // DeL %tMp%\Block.TxT
	    $ = "44654C2025744D70255C426C6F636B2E547854" nocase

	    // DeL %tMp%\Inteldriverupd1.ScT
	    $ = "44654C2025744D70255C496E74656C647269766572757064312E536354" nocase

	    // ObjShell.Run "cMd /C %tEmP%\tAsK.bAt",0,True
	    $ = "4F626A5368656C6C2E52756E2022634D64202F43202574456D50255C7441734B2E624174222C302C54727565" nocase

    condition:
        all of them
}
