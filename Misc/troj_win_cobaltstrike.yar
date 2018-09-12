rule troj_win_cobaltstrike_memoryinject
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "21JUL2017"
        hash1 = "8637026ae5bec1198fca7085db07b75343331af1644df6c411413c0f315a3216"
        description = "Detects Cobalt Strike payload typically loaded into memory via PowerShell."

    strings:
        // beacon.dll
        $ = { 62 65 61 63 6F 6E 2E 64 6C 6C }

        // HTTP/1.1 200 OK
        $ = { 48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B }

        // char c = (i & 0xFF);
        $ = { 63 68 61 72 20 63 20 3D 20 28 69 20 26 20 30 78 46 46 29 3B }

        // could not spawn %s (token): %d
        $ = { 63 6F 75 6C 64 20 6E 6F 74 20 73 70 61 77 6E 20 25 73 20 28 74 6F 6B 65 6E 29 3A 20 25 64 }

        // could not run %s as %s\%s: %d
        $ = { 63 6F 75 6C 64 20 6E 6F 74 20 72 75 6E 20 25 73 20 61 73 20 25 73 5C 25 73 3A 20 25 64 }

        // %d is an x64 process (can't inject x86 content)
        $ = { 25 64 20 69 73 20 61 6E 20 78 36 34 20 70 72 6F 63 65 73 73 20 28 63 61 6E 27 74 20 69 6E 6A 65 63 74 20 78 38 36 20 63 6F 6E 74 65 6E 74 29 }

        // %d is an x86 process (can't inject x64 content)
        $ = { 25 64 20 69 73 20 61 6E 20 78 38 36 20 70 72 6F 63 65 73 73 20 28 63 61 6E 27 74 20 69 6E 6A 65 63 74 20 78 36 34 20 63 6F 6E 74 65 6E 74 29 }

        // ppid %d is in a different desktop session (spawned jobs may fail). Use 'ppid' to reset.
        $ = { 70 70 69 64 20 25 64 20 69 73 20 69 6E 20 61 20 64 69 66 66 65 72 65 6E 74 20 64 65 73 6B 74 6F 70 20 73 65 73 73 69 6F 6E 20 28 73 70 61 77 6E 65 64 20 6A 6F 62 73 20 6D 61 79 20 66 61 69 6C 29 2E 20 55 73 65 20 27 70 70 69 64 27 20 74 6F 20 72 65 73 65 74 2E }

        // kerberos ticket purge failed: %08x
        $ = { 6B 65 72 62 65 72 6F 73 20 74 69 63 6B 65 74 20 70 75 72 67 65 20 66 61 69 6C 65 64 3A 20 25 30 38 78 }

        // IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')
        $ = { 49 45 58 20 28 4E 65 77 2D 4F 62 6A 65 63 74 20 4E 65 74 2E 57 65 62 63 6C 69 65 6E 74 29 2E 44 6F 77 6E 6C 6F 61 64 53 74 72 69 6E 67 28 27 68 74 74 70 3A 2F 2F 31 32 37 2E 30 2E 30 2E 31 3A 25 75 2F 27 29 }

        // powershell -nop -exec bypass -EncodedCommand
        $ = { 70 6F 77 65 72 73 68 65 6C 6C 20 2D 6E 6F 70 20 2D 65 78 65 63 20 62 79 70 61 73 73 20 2D 45 6E 63 6F 64 65 64 43 6F 6D 6D 61 6E 64 }

        // I'm already in SMB mode
        $ = { 49 27 6D 20 61 6C 72 65 61 64 79 20 69 6E 20 53 4D 42 20 6D 6F 64 65 }

        // Failed to impersonate logged on user %d (%u)
        $ = { 46 61 69 6C 65 64 20 74 6F 20 69 6D 70 65 72 73 6F 6E 61 74 65 20 6C 6F 67 67 65 64 20 6F 6E 20 75 73 65 72 20 25 64 20 28 25 75 29 }

    condition:
        all of them
}
