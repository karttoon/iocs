rule troj_elf_cetus_a
{
    meta:
	author = "Jeff White (karttoon@gmail.com) @noottrak"
        description = "Detects Cetus Linux Malware."
        date = "2020-07-07"
        hash = "b49a3f3cb4c70014e2c35c880d47bc475584b87b7dfcfa6d7341d42a16ebe443"
    strings:
        $ = "timeout %d docker -H %d.%d.%d.%d exec %s apt-get -yq update" ascii wide
        $ = "timeout %d docker -H %d.%d.%d.%d exec %s apt-get -yq install masscan docker.io" ascii wide
        $ = "timeout %d docker -H %d.%d.%d.%d cp -L /usr/bin/docker-cache %s:/usr/bin/" ascii wide
        $ = "timeout %d docker -H %d.%d.%d.%d cp -L /usr/bin/portainer %s:/usr/bin/" ascii wide
        $ = "timeout %d docker -H %d.%d.%d.%d exec %s bash --norc -c 'echo \"/usr/bin/portainer %s >/dev/null" ascii wide
        $ = "timeout %d docker -H %d.%d.%d.%d restart %s" ascii wide
        $ = "timeout %d docker -H %d.%d.%d.%d run -dt --name %s --restart always ubuntu:18.04 /bin/bash" ascii wide
        $ = "timeout %d docker -H %d.%d.%d.%d ps -a --no-trunc" ascii wide
        $ = "masscan %d.%d.%d.%d/%d -p 2375 -oL - --max-rate 360 2>/dev/null" ascii wide
    condition:
        any of them
}

