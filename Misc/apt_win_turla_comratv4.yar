rule apt_win_turla_comratv4
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "29OCT2020"
        hash1 = "44d6d67b5328a4d73f72d8a0f9d39fe4bb6539609f90f169483936a8b3b88316"
        description = "Detects a ComRATv4 variant used by Turla." 
        reference = "https://us-cert.cisa.gov/ncas/analysis-reports/ar20-303a"

    strings:
        $ = "C:\\Projects\\chinch_4_0\\projects\\chinch4\\Build\\x64\\Release\\x64_Release.pdb" ascii wide

    condition:
        all of them
}
