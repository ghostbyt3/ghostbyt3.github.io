---
title:     "Hack The Box - Writeup"
tags: [linux,easy,cron,path]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-writeup/1.png)

We are going to pwn WriteUp from Hack The Box.

Link : https://www.hackthebox.eu/home/machines/profile/192


Like always begin with our Nmap Scan.

## Nmap Scan Results:

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http


PORT   STATE    SERVICE VERSION
22/tcp open     ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 dd:53:10:70:0b:d0:47:0a:e2:7e:4a:b6:42:98:23:c7 (RSA)
|   256 37:2e:14:68:ae:b9:c2:34:2b:6e:d9:92:bc:bf:bd:28 (ECDSA)
|_  256 93:ea:a8:40:42:c1:a8:33:85:b3:56:00:62:1c:a0:ab (ED25519)
80/tcp filtered http
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.2 - 4.9 (92%), Linux 4.2 (92%), Linux 4.4 (92%), Linux 4.8 (92%), Linux 4.9 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Like always start from webpage.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-writeup/2.png)

It seems like there is ``fail2ban`` running which bans IP's If we try to bruteforce webpages.

>Fail2Ban is an intrusion prevention software framework that protects computer servers from brute-force attacks.

Since we cant bruteforce lets try some common directories.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-writeup/3.png)

We got a hint , there is another directory ``/writeup``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-writeup/4.png)

While checking the source code found its running as ``CMS Made Simple``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-writeup/5.png)

There is quite a lot of vulnerabilites since we dont know its version I started with ``sql injection`` because some are ``Authenticated``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-writeup/6.png)

Copied the Script to my directory.After reading the instructions of how to use the exploit ,I started it
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-writeup/7.png)

After sometime it gives us ``user and password`` lets login with them in ssh.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-writeup/8.png)

We Successfully Logged in<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-writeup/9.png)

## Privilege Escalation:

While checking its ``id``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-writeup/10.png)

There is an uncommon ``staff``

> staff: Allows users to add local modifications to the system (/usr/local) without needing root privileges (note that executables in /usr/local/bin are in the PATH variable of any user, and they may "override" the executables in /bin and /usr/bin with the same name). Compare with group "adm", which is more related to monitoring/security.

So Immediately I checked the path

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-writeup/11.png)

Later I uploaded ``pspy`` so check for ``cronjob``

>pspy is a command line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute. Great for enumeration of Linux systems in CTFs. Also great to demonstrate your colleagues why passing secrets as arguments on the command line is a bad idea.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-writeup/12.png)

While its started I did another ssh connection. When doing that ,there is something called ``run-parts`` running.
From the ``$PATH`` I came to know it first checks in ``usr/local/bin`` and the file not available it moves to ``usr/bin``
If the path is not specified fully we can hijack it. In our case path is not fully specified.
Since the ``PATH`` first searches in ``usr/local/bin`` we can create a file ``run-parts`` and get root.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-writeup/13.png)

I created one with ``perl`` reverse shell because there is already ``.pl`` file running.

>https://github.com/pentestmonkey/perl-reverse-shell/blob/master/perl-reverse-shell.pl

Started listener on one terminal and started login in another machine our ``run-parts``(reverse shell) gets executed.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-writeup/14.png)

Got Root!!

