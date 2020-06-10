---
title:     "Hack The Box - Nibbles"
tags: [linux,easy,sudo]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nibbles/1.png)

We are going to pwn Nibbles from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/121>


Like always begin with our Nmap Scan.

## Nmap Scan Results

```bash
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http


PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.2 - 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.4 (95%), Linux 3.16 (95%), Linux 3.18 (95%), Linux 4.2 (95%), Linux 4.8 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Lets start from HTTP 
It Looks simple 

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nibbles/2.png)

But the source code gives us some new directory<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nibbles/3.png)

We run Gobuster on this directory

## Gobuster Results
```bash
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.75/nibbleblog/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/12/07 17:48:22 Starting gobuster
===============================================================
/admin (Status: 301)
/admin.php (Status: 200)
/content (Status: 301)
/index.php (Status: 200)
/languages (Status: 301)
/plugins (Status: 301)
/README (Status: 200)
/themes (Status: 301)
===============================================================
2019/12/07 17:50:49 Finished
===============================================================
```

While checking other pages from gobuster result ``/README`` shows the version of it.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nibbles/4.png)

> Nibbleblog is an open source blog system which has been widely used. 

There is login page too ``/admin.php``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nibbles/5.png)

So I just tried some random passwords and I tried ``nibbles`` (Box name) and logged with ``admin:nibbles``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nibbles/6.png)

Since we know the version of it, Lets search them in searchsploit<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nibbles/7.png)

## Getting Shell

Lets fire up the metasploit 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nibbles/8.png)

It worked!!

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nibbles/9.png)

## Privilege Escalation

Lets start with ``sudo -l``

```bash

$ sudo -l
sudo: unable to resolve host Nibbles: Connection timed out
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh

```
It looks we can run this script as root without password

And We have the write permission on that file So I created a reverse shell payload on my machine and copied that!!
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nibbles/10.png)

``echo`` that to the ``monitor.sh`` and run that with ``sudo``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nibbles/11.png)

Listening on my machine<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nibbles/12.png)

I'm Root !!!
