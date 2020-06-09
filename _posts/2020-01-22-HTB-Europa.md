---
title:     "Hack The Box - Europa"
tags: [linux,medium,cron]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-europa/1.png)

We are going to pwn Europa from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/27>


Lets Begin with our Initial Nmap Scan.

## Nmap Scan Results:

```
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https


PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6b:55:42:0a:f7:06:8c:67:c0:e2:5c:05:db:09:fb:78 (RSA)
|   256 b1:ea:5e:c4:1c:0a:96:9e:93:db:1d:ad:22:50:74:75 (ECDSA)
|_  256 33:1f:16:8d:c0:24:78:5f:5b:f5:6d:7f:f7:b4:f2:e5 (ED25519)
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| ssl-cert: Subject: commonName=europacorp.htb/organizationName=EuropaCorp Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.europacorp.htb, DNS:admin-portal.europacorp.htb
| Not valid before: 2017-04-19T09:06:22
|_Not valid after:  2027-04-17T09:06:22
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%), Linux 4.4 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## HTTP & HTTPS:
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-europa/2.png)<br/>
Only default page of apache2 in both 80 and 443 

But our nmap shows there is a domain 
> admin-portal.europacorp.htb

So I added them in ``/etc/hosts``

Its a login page.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-europa/3.png)

While checking its certificate found an ``issuer`` with id ``admin@europacorp.htb``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-europa/4.png)

Back to the login page, I tried some normal sql injection commands

> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-europa/5.png)<br/>
Found a redirection, If we ``Follow redirection`` we will be logged in.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-europa/6.png)

While enumerating the webpages I found something going on ``Tools``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-europa/7.png)

I send it to burp <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-europa/8.png)<br/>
While seeing that I came to know whatever we type in ``ipaddress=`` it changes the same in the response of ``remote-address``.
This looks like regular expression because ``/ip_address/`` replace with whatever we give.

>A regular expression, regex or regexp is a sequence of characters that define a search pattern. Usually such patterns are used by string searching algorithms for "find" or "find and replace" operations on strings, or for input validation. 

While searching for any exploit available to inject, Found this 

>https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-europa/9.png)<br/>
This explains how it works so all we need to do is to add ``/e `` <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-europa/9.1.png)<br/>
It works. So now we can try to get the reverse shell now. I tried some reverse shell commands non worked so I hosted a python server with php reverse sehll on my machine and I tried with ``curl``.

Started my listerer and got the shell.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-europa/10.png)

## Privilege Escalation:

I uploaded my Linux Enumeration script but there is nothing useful,
So I uploaded ``pspy``

>pspy is a command line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute. Great for enumeration of Linux systems in CTFs. Also great to demonstrate your colleagues why passing secrets as arguments on the command line is a bad idea.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-europa/11.png)<br/>
There is something runs in ``/var/www/cronjobs/``
While checking ``clearlogs``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-europa/12.png)

It executes a script located in ``/var/www/cmd/logcleared.sh``<br/>
But the script is missing in the  directory but we have writable permission on it, so I created the ``logcleared.sh`` with reverse shell to give us root.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-europa/13.png)

Started the listener in my machine<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-europa/14.png)

I'm Root Now!! 