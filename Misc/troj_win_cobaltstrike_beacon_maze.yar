import "pe"
rule trojan_win_cobaltstrike_beacon_maze
{
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        description = "Maze Dropper using CobaltStrike v4 Beacon" 
        date = "25AUG2020"
        hash1 = "81a9ced421d01a2f9a7bf1335d227eee19606fe220a50ecf96a78abca6cc816b"
        reference = "https://labs.sentinelone.com/case-study-catching-a-human-operated-maze-ransomware-attack-in-action/"

    strings:
        $ = "VirtualAllocExNuma" ascii wide
        $ = "IsDebuggerPresent" ascii wide
        $ = "Sleep" ascii wide

    condition:
        all of them
            and
        (pe.signatures[0].subject contains "Clubessential, LLC")
}

