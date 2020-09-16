rule troj_win_negasteal
{
    meta:
        author  = "Jeff White (karttoon@gmail.com) @noottrak"
        date    = "15APR2020"
        comment = "All hashes in block comment for each change"
        hash01 = "d81ba465fe59e7d600f7ab0e8161246a5badd8ae2c3084f76442fb49f6585e95"
        description = "Detects an observed Negastealer campaign payload"

    strings:
	$ = "Mozilla/5.0 (Windows NT 5.2) AppleWebKit/534.30 (KHTML, like Gecko) Chrome/12.0.742.122 Safari/534.30"
	$ = "news.php"
	$ = "http://%s/%s"
	$ = "type=0"
	$ = "time=%s"
    condition:
	all of them
}
