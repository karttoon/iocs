rule troj_win_mbrkiller_unpacked
{
	meta:
		author = "Jeff White (karttoon@gmail.com) @noottrak"
		date = "20JUN2018"
        hash01 = "1a09b182c63207aa6988b064ec0ee811c173724c33cf6dfe36437427a5c23446"
        description = "Identifies the NSIS MBR Killer malware after being unpacked by VMProtect"
        reference = "https://www.flashpoint-intel.com/blog/banco-de-chile-mbr-killler-reveals-hidden-nexus-buhtrap/"

	strings:
	    // \\.\PHYSICALDRIVE%d
		$ = { 5C 5C 2E 5C 50 48 59 53 49 43 41 4C 44 52 49 56 45 25 64 }

		// Kernel32::CreateFile(t, i, i, i, i, i, i)
		$ = { 4B 65 72 6E 65 6C 33 32 3A 3A 43 72 65 61 74 65 46 69 6C 65 28 74 2C 20 69 2C 20 69 2C 20 69 2C 20 69 2C 20 69 2C 20 69 29 }

		// MBR Killer Setup: Installing
		$ = { 4D 42 52 20 4B 69 6C 6C 65 72 20 53 65 74 75 70 3A 20 49 6E 73 74 61 6C 6C 69 6E 67 }

		// $$\wininit.ini
		$ = { 24 24 5C 77 69 6E 69 6E 69 74 2E 69 6E 69 }

		// System.dll
		$ = { 53 79 73 74 65 6D 2E 64 6C 6C }

	condition:
		all of them
}
