rule troj_win_macrosafe_vba
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "21JUL2017"
        hash1 = "36fa53bb90ea70ac11c2fe1de8ed7db6721e4d8b840628e7920835562d9ec6da"
        description = "Detects macro_safe generated VBA that executes compressed PowerShell (scriplet SCT) files - seen in wild using plaintext and base64 variants."

    strings:
        // powershell.exe -NoP -NonI -W Hidden -Command "Invoke-
        $ps_string  = { 70 6F 77 65 72 73 68 65 6C 6C 2E 65 78 65 20 2D 4E 6F 50 20 2D 4E 6F 6E 49 20 2D 57 20 48 69 64 64 65 6E 20 2D 43 6F 6D 6D 61 6E 64 20 22 49 6E 76 6F 6B 65 2D }

        // cG93ZXJzaGVsbC5leGUgLU5vUCAtTm9uSSAtVyBIaWRkZW4gLUNvbW1hbmQgIiJJbnZva2Ut
        $ps_b64 = { 63 47 39 33 5A 58 4A 7A 61 47 56 73 62 43 35 6C 65 47 55 67 4C 55 35 76 55 43 41 74 54 6D 39 75 53 53 41 74 56 79 42 49 61 57 52 6B 5A 57 34 67 4C 55 4E 76 62 57 31 68 62 6D 51 67 49 69 4A 4A 62 6E 5A 76 61 32 55 74 }

        // Expression $(New-Object IO.StreamReader ($(New-O
        $xp_string = { 45 78 70 72 65 73 73 69 6F 6E 20 24 28 4E 65 77 2D 4F 62 6A 65 63 74 20 49 4F 2E 53 74 72 65 61 6D 52 65 61 64 65 72 20 28 24 28 4E 65 77 2D 4F }

        // RXhwcmVzc2lvbiAkKE5ldy1PYmplY3QgSU8uU3RyZWFtUmVhZGVyICgkKE5ldy1P
        $xp_b64 = { 52 58 68 77 63 6D 56 7A 63 32 6C 76 62 69 41 6B 4B 45 35 6C 64 79 31 50 59 6D 70 6C 59 33 51 67 53 55 38 75 55 33 52 79 5A 57 46 74 55 6D 56 68 5A 47 56 79 49 43 67 6B 4B 45 35 6C 64 79 31 50 }

        // bject IO.Compression.DeflateStream ($(New-Object
        $obj_string  = { 62 6A 65 63 74 20 49 4F 2E 43 6F 6D 70 72 65 73 73 69 6F 6E 2E 44 65 66 6C 61 74 65 53 74 72 65 61 6D 20 28 24 28 4E 65 77 2D 4F 62 6A 65 63 74 }

        // YmplY3QgSU8uQ29tcHJlc3Npb24uRGVmbGF0ZVN0cmVhbSAoJChOZXctT2JqZWN0
        $obj_b64     = { 59 6D 70 6C 59 33 51 67 53 55 38 75 51 32 39 74 63 48 4A 6C 63 33 4E 70 62 32 34 75 52 47 56 6D 62 47 46 30 5A 56 4E 30 63 6D 56 68 62 53 41 6F 4A 43 68 4F 5A 58 63 74 54 32 4A 71 5A 57 4E 30 }

        // IO.MemoryStream (,$([Convert]::FromBase64String
        $io_string   = { 49 4F 2E 4D 65 6D 6F 72 79 53 74 72 65 61 6D 20 28 2C 24 28 5B 43 6F 6E 76 65 72 74 5D 3A 3A 46 72 6F 6D 42 61 73 65 36 34 53 74 72 69 6E 67 }

        // IElPLk1lbW9yeVN0cmVhbSAoLCQoW0NvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5n
        $io_b64      = { 49 45 6C 50 4C 6B 31 6C 62 57 39 79 65 56 4E 30 63 6D 56 68 62 53 41 6F 4C 43 51 6F 57 30 4E 76 62 6E 5A 6C 63 6E 52 64 4F 6A 70 47 63 6D 39 74 51 6D 46 7A 5A 54 59 30 55 33 52 79 61 57 35 6E }

        // )))), [IO.Compression.Compr
        $comp_string = { 29 29 29 29 2C 20 5B 49 4F 2E 43 6F 6D 70 72 65 73 73 69 6F 6E 2E 43 6F 6D 70 72 }

        // KFwiIiAiICYgc3RyICYgIiBcIiIgKSkpKSwgW0lPLkNvbXByZXNzaW9uLkNvbXBy
        $comp_b64    = { 4B 46 77 69 49 69 41 69 49 43 59 67 63 33 52 79 49 43 59 67 49 69 42 63 49 69 49 67 4B 53 6B 70 4B 53 77 67 57 30 6C 50 4C 6B 4E 76 62 58 42 79 5A 58 4E 7A 61 57 39 75 4C 6B 4E 76 62 58 42 79 }

        // essionMode]::Decompress)), [Text.Encoding]::ASCI
        $enc_string  = { 65 73 73 69 6F 6E 4D 6F 64 65 5D 3A 3A 44 65 63 6F 6D 70 72 65 73 73 29 29 2C 20 5B 54 65 78 74 2E 45 6E 63 6F 64 69 6E 67 5D 3A 3A 41 53 43 49 }

        // ZXNzaW9uTW9kZV06OkRlY29tcHJlc3MpKSwgW1RleHQuRW5jb2RpbmddOjpBU0NJ
        $enc_b64     = { 5A 58 4E 7A 61 57 39 75 54 57 39 6B 5A 56 30 36 4F 6B 52 6C 59 32 39 74 63 48 4A 6C 63 33 4D 70 4B 53 77 67 57 31 52 6C 65 48 51 75 52 57 35 6A 62 32 52 70 62 6D 64 64 4F 6A 70 42 55 30 4E 4A }

        // I)).ReadToEnd();"
        $end_string  = { 49 29 29 2E 52 65 61 64 54 6F 45 6E 64 28 29 3B 22 }

        // SSkpLlJlYWRUb0VuZCgpOyIi
        $end_b64     = { 53 53 6B 70 4C 6C 4A 6C 59 57 52 55 62 30 56 75 5A 43 67 70 4F 79 49 69 }

    condition:
        1 of ($ps_*)
          and
        1 of ($xp_*)
          and
        1 of ($obj_*)
          and
        1 of ($io_*)
          and
        1 of ($comp_*)
          and
        1 of ($enc_*)
          and
        1 of ($end_*)
}
