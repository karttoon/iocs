rule ransom_win_lyposit
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "18SEP2018"
        hash1 = "7a2001287331890f2fbf1b1b4875e4146d983d1f5647ec105d332cd7e03cd02d"
        hash2 = "fea80a08eac00f6389edbae6c58fe985ba914e790c7cd7580fdc39ab5fa931fd"
        description = "Detects Lyposit ransomware which masquerades as MacOS app."

    strings:
        $ = "C:\\af32d3b0\\b662ef49.exe"

    condition:
        all of them
}
