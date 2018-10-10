rule troj_win_vbkryjetor
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "20SEP2018"
        hash1 = "1ac53bc8373d5ffad51f8805cf0bf6cb28f7374f56b29813c8be05f338da416d"
        hash2 = "615d69508c11dc977abae1c91464ff8e4cc9c0dd4ba994452a8ae623993a7dc9"
        description = "Detects VBKryjetor trojan."

    strings:
        $ = "C:\\Users\\World\\Desktop\\duck\\Zbw138ht2aeja2.pdb"

    condition:
        all of them
}
