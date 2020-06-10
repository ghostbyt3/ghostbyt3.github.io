---
title:     "Hack The Box - Blocky"
tags: [linux,easy,sudo]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-blocky/1.png)

We are going to pwn Blocky from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/48>


Like always begin with our Nmap Scan.

## Nmap Scan Results
```bash
PORT      STATE  SERVICE
21/tcp    open   ftp
22/tcp    open   ssh
80/tcp    open   http
8192/tcp  closed sophos
25565/tcp open   minecraft

PORT      STATE  SERVICE   VERSION
21/tcp    open   ftp       ProFTPD 1.3.5a
22/tcp    open   ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp    open   http      Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.8
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: BlockyCraft &#8211; Under Construction!
8192/tcp  closed sophos
25565/tcp open   minecraft Minecraft 1.11.2 (Protocol: 127, Message: A Minecraft Server, Users: 0/20)
Device type: general purpose|WAP|specialized|storage-misc|broadband router|printer
Running (JUST GUESSING): Linux 3.X|4.X|2.6.X (94%), Asus embedded (90%), Crestron 2-Series (89%), HP embedded (89%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel cpe:/h:asus:rt-ac66u cpe:/o:crestron:2_series cpe:/h:hp:p2000_g3 cpe:/o:linux:linux_kernel:3.4 cpe:/o:linux:linux_kernel:2.6.22
Aggressive OS guesses: Linux 3.10 - 4.11 (94%), Linux 3.13 or 4.2 (94%), Linux 4.4 (94%), Linux 3.13 (93%), Linux 4.2 (93%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.12 (91%), Linux 3.2 - 4.9 (91%), Linux 3.8 - 3.11 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
While checking the webpage I cant find anything useful<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-blocky/2.png)

So start our Gobuster and see what are the directories available.

## Gobuster Scan Results
```bash
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.37
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/12/04 17:27:04 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/index.php (Status: 301)
/javascript (Status: 301)
/phpmyadmin (Status: 301)
/plugins (Status: 301)
/server-status (Status: 403)
/wiki (Status: 301)
/wp-admin (Status: 301)
/wp-content (Status: 301)
/wp-includes (Status: 301)
===============================================================
2019/12/04 17:29:31 Finished
===============================================================
```

It is an Wordpress site so we can use ``wpscan`` to find any plugins or username that we make use of it.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-blocky/3.png)

Found an user ``notch``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-blocky/4.png)


While looking at the directories found some plugins in ``/plugins``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-blocky/5.png)

So I downloaded it and to see whats inside!!<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-blocky/6.png)

Found some ``mysql`` creds we know there is ``/phpmyadmin`` from Gobuster results.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-blocky/7.png)
 
``root:8YsqfCTnvxAUeduzjNSXe22``

## Getting Shell

I logged in and Can't find anything useful!<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-blocky/8.png)

So later I tried login with ``ssh`` using the creds we found, with ``notch`` user.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-blocky/9.png)

## Privilege Escalation

I tried ``sudo -l`` Looks like we can run any command with ``sudo`` without password xD
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-blocky/10.png)

So I did

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-blocky/11.png)

I'm Root Now!
