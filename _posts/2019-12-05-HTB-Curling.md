---
title:     "Hack The Box - Curling"
tags: [linux,easy,joomla]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-curling/1.png)

We are going to pwn Curling from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/160>


Like always begin with our Nmap Scan.

## Nmap Scan Results:

```bash
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http


PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8a:d1:69:b4:90:20:3e:a7:b6:54:01:eb:68:30:3a:ca (RSA)
|   256 9f:0b:c2:b2:0b:ad:8f:a1:4e:0b:f6:33:79:ef:fb:43 (ECDSA)
|_  256 c1:2a:35:44:30:0c:5b:56:6a:3f:a5:cc:64:66:d9:a9 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Joomla! - Open Source Content Management
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Home
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.18 (95%), Linux 3.2 - 4.9 (95%), Linux 3.16 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.1 (93%), Linux 3.2 (93%), Linux 3.10 - 4.11 (93%), Oracle VM Server 3.4.2 (Linux 4.1) (93%), Linux 3.12 (93%), Linux 3.13 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Lets start with HTTP 

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-curling/2.png)<br/>
It looks like ``JoomlaCMS`` from the icon!

So start our Gobuster 

## Gobuster Results:

```bash
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.150
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/12/10 15:38:24 Starting gobuster
===============================================================
/images (Status: 301)
/media (Status: 301)
/templates (Status: 301)
/modules (Status: 301)
/bin (Status: 301)
/plugins (Status: 301)
/includes (Status: 301)
/language (Status: 301)
/components (Status: 301)
/cache (Status: 301)
/libraries (Status: 301)
/tmp (Status: 301)
/layouts (Status: 301)
/administrator (Status: 301)
/cli (Status: 301)
/server-status (Status: 403)
===============================================================
2019/12/10 17:33:37 Finished
===============================================================
```

While checking the webpage found ``floris`` may be an user.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-curling/3.png)

And like always check the source code
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-curling/4.png)

Found ``/secret.txt`` may contain anything useful

Looks like base64. Lets try decode it <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-curling/5.png)

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-curling/6.png)
It gives us ``Curling2018!`` may be a password!

So we can try login in the webpage using ``Floris:Curling2018!`` in ``/administrator``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-curling/7.png)
We logged in succesfully!
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-curling/8.png)

## Getting Shell

Now its time to get reverse shell
Found Templates which means we can edit that to get reverse shell

`` Templates ->  Beez3 details and files -> ``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-curling/9.png)
Upload it and click template preview

Started my nc listener<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-curling/10.png)<br/>
I got the shell

While checking the home directories found ``password_backup``
I cant see ``user.txt`` but I can see whats inside ``password_backup``
It is hex so we can reverse them
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-curling/11.png)
I Copied that to my machine 

## Getting User Floris

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-curling/12.png)<br/>
First I did ``xxd -r`` which reverse the hex dump.
I checked what file it is , it is a ``bzip2`` so I renamed it ,to extract.
And the output is ``gzip`` file,
After some extraction I got ``password.txt``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-curling/13.png)

May be ``floris`` ssh password

Lets try login in ``ssh``
``floris:5d<wdCbdZu)|hChXll ``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-curling/14.png)

## Privilege Escalation:

I found it is an ``Ubuntu`` box so I checked ``snap`` version.

>Snap (also known as Snappy) is a software deployment and package management system built by Canonical. The packages, are usually called 'snaps' and the tool for using them is called 'snapd',

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-curling/15.png)

I found some exploits from searchsploit<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-curling/16.png)

><https://www.exploit-db.com/exploits/46362>

Uploaded on the machine and it worked<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-curling/17.png)

I got root!



