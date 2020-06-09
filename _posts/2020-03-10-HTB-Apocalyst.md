---
title:     "Hack The Box - Apocalyst"
tags: [linux,medium,wordpress]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-apocalyst/1.png)

We are going to pwn Apocalyst from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/57>


Lets Begin with our Initial Nmap Scan.

## Nmap Scan Results:
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fd:ab:0f:c9:22:d5:f4:8f:7a:0a:29:11:b4:04:da:c9 (RSA)
|   256 76:92:39:0a:57:bd:f0:03:26:78:c7:db:1a:66:a5:bc (ECDSA)
|_  256 12:12:cf:f1:7f:be:43:1f:d5:e6:6d:90:84:25:c8:bd (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.8
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apocalypse Preparation Blog
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.16 (95%), Linux 3.2 - 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.8 (95%), Linux 4.4 (95%), Linux 4.9 (95%), Linux 3.18 (95%), Linux 4.2 (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## HTTP :

Added ``apocalyst.htb`` on ``/etc/hosts`` because its not rendering correctly with IP.

Its a Wordpress site.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-apocalyst/2.png)

So I Started ``Wpscan`` and found and an user.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-apocalyst/3.png)

Started my Gobuster to bruteforce the directories but everything leads to same image, So I used a tool called ``cewl`` to create a wordlist using the webpage and started my Gobuster again with new wordlist and some extra parameters.

> cewl - custom word list generator

Why I did this? Because every directory leads to same image file and I can't check each page so by doing this method we can find something different.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-apocalyst/4.png)

```
-f, --addslash                      Apped / to each request
-l, --includelength                 Include the length of the body in the output
```
From the scan result only ``/Rightiousness/`` has different length when compare to others,
```
/glorification/ (Status: 200) [Size: 157]
/given/ (Status: 200) [Size: 157]
/Rightiousness/ (Status: 200) [Size: 175]
/Job/ (Status: 200) [Size: 157]
/Psalms/ (Status: 200) [Size: 157]
```
Downloaded the image to my machine.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-apocalyst/5.png)

Used [Steghide](https://github.com/StefanoDeVuono/steghide) to extract the files in the image.

>steghide - a steganography program

It is a wordlists. So we can brute force the user password with ``list.txt``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-apocalyst/6.png)

``wpscan -U falaraki -P ~/CTF/HTB/Boxes/Apocalyst/list.txt --url http://apocalyst.htb/``

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-apocalyst/7.png)
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-apocalyst/8.png)

We got the password for the user.
``Username: falaraki, Password: Transclisiation``

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-apocalyst/9.png)

Once Logged in, I searched for anyway to get reverse shell and found we can edit the pages in ``Appearance --> Editor``.
I selected one of the page from the templates on the right side of the page.
Changed that to [PHP Reverse Shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)(Don't forgot to change the IP).
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-apocalyst/10.png)

After Uploaded the file, Open the page in new tab and Started my Listener.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-apocalyst/11.png)

I look at the home directory and found ``.secret`` which looks like base64 encoded.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-apocalyst/12.png)

There is an online tool called [Base64Decode](https://www.base64decode.org/) to decode and it gives us me a password.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-apocalyst/13.png)

Logged in with ``SSH`` with `` falaraki : Y0uAINtG37TiNgTH!sUzersP4ss ``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-apocalyst/14.png)

## Privilege Escalation :

Uploaded my Enumeration Script and found this.
```
[!] fst160 Can we write to critical files?................................. yes!
---
/etc/passwd
---
```

Since we have write permission, I created a password using ``openssl`` to create a new user with root permission.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-apocalyst/15.png)

Added ``wolf:46Xd.1NlqFBp.:0:0:root:/root:/bin/bash`` at the bottom.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-apocalyst/16.png)

I'm Root now <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-apocalyst/17.png)


