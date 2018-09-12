rule informational_win_ole_protected
{
	meta:
		author = "Jeff White (karttoon@gmail.com) @noottrak"
		date = "07SEP2016"
		description = "Identify OLE Project protection within documents." // Documents with protection removed leave these artifacts as well

	strings:
	    // \r\nCMG="
		$ole_cmg = { 0D 0A 43 4D 47 3D 22 }

		// \r\nDPB="
		$ole_dpb = { 0D 0A 44 50 42 3D 22 }

		// \r\nGC="
		$ole_gc  = { 0D 0A 47 43 3D 22 }

		$ole_vba = "VBA_PROJECT" wide ascii

	condition:
		uint32be(0) == 0xD0CF11E0
		  and
		@ole_cmg[1] < @ole_dpb[1]
		  and
		@ole_dpb[1] < @ole_gc[1]
		  and
		$ole_vba
}

rule informational_win_ole_exist
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "27JUL2018"
        description = "Identify OLE Packages embedded in Office 97-2K3 Doc Files."

    strings:
        // OLE Package header
        $ = { 4F 4C 45 20 50 61 63 6B 61 67 65 00 00 00 00 00 08 00 00 00 50 61 63 6B 61 67 65 00 }

    condition:
        all of them
}
