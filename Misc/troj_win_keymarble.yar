rule troj_win_keymarble {

    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "25FEB2019"
        hash1 = "1c4745c82fdcb9d05e210eff346d7bee2f087357b17bfcf7c2038c854f0dee61"
        description = "Detections parts of functions in the KEYMARBLE backdoor."
        reference = "https://research.checkpoint.com/north-korea-turns-against-russian-targets/"

    strings:
        // Leading bytes for case statement
        $case = { 55 8B EC 83 E4 F8 81 C2 AA BA DC FE 83 FA 22 }

        // Part of function for drive scanning
        $drive_01 = "CD Drive" wide
        $drive_02 = "Local Disk" wide
        $drive_03 = "%c:" wide
        $drive_04 = { 83 C4 0C 8D 45 F4 0F 57 C0 66 0F D6 45 F4 53 68 }

        // Part of function to profile system
        $scan = { 66 8B 85 E8 F7 FF FF 83 C4 0C 66 89 85 D0 F7 FF FF 8D 85 90 F7 FF FF C7 85 A0 F7 FF FF 44 00 00 00 C7 85 CC F7 FF FF 01 00 00 00 50 8D 85 A0 F7 FF FF 50 6A 00 6A 00 6A 00 6A 00 6A 00 6A 00 6A 00 8D }

    condition:
        (all of ($drive_*) or $scan) and $case
}

