rule troj_win_mehcrypter : mehstager
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "25SEP2020"
        hash0 = "c06fa3ea675ce17fd8d53590c80f7d523d8ba2078fcb91addba233c892710df2"
        hash1 = "4f54c21b0c64098df8386927b4e6a163bc80cba73026fc339bb508e6d3aaba55"
        hash2 = "e307bd08edf3370bc79b5443af5c514459239a938cc4136ec3d32921beb81fa9"
        hash3 = "657ea4bf4e591d48ee4aaa2233e870eb99a17435968652e31fc9f33bbb2fe282"
        hash4 = "49bc1b3ace1da04f90fd1dd0dcda42ef6766cc8baa3d6a83e2c451ece3ab5db6"
        hash5 = "5e71c1b9d8537176e6acccd8a45db9871c365c0a737f6f29453880b176161756"
        hash6 = "3a257667dbfc9dd90415160e2b02b021d5c289b1d62799b1f4f29ffe98f4a986"
        description = "Detects MegStager of the MehCrypter malware family"
        reference = "https://decoded.avast.io/janrubin/complex-obfuscation-meh/"

    strings:
        $ = "pe.bin" ascii // pe.bin is the encoded file with payload and key necessary to make the stager work
        $ = "bin 404" ascii
        $ = "SOFTWARE\\Borland\\Delphi\\RTL" ascii

    condition:
        all of them
}
