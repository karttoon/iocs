rule packer_win_spoonvm
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "11DEC2018"
        hash1 = "78d5f6594091eb763d6b2a970c766b76662584a826a7712d319f9a3d27f2b2f5"
        hash2 = "f8053b54fae5c60c50c27f1bb9c1731a7a9d05bc2377222e66bbd8ffe748c74b"
        description = "Detects SpoonVM"

    strings:
        $spoonvm = "Spoon Virtual Machine" wide
        $pdb1 = "C:\\bamboo-home\\xml-data\\build-dir\\SPOONVM-VM-JOB1\\vm\\Build\\Output\\x86\\StubExe.pdb" ascii
        $pdb2 = "C:\\bamboo-home\\xml-data\\build-dir\\SPOONVM-VM3-JOB1\\vm\\Build\\Output\\x86\\StubExe.pdb" ascii
        // May need to tweak this regex but captures variants on the above currently
        $pdb3 = /SPOONVM-VM[a-zA-Z0-9\/\\-]+\.pdb/

    condition:
        $spoonvm
          and
        1 of ($pdb*)
}
