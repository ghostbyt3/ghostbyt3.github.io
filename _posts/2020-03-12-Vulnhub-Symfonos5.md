---
title:     "Vulnhub - Symfonos 5"
tags: [medium,ldap,lfi,sudo]
---

Today, We are going to pwn Symfonos 5 by Zayotic from Vulnhub

## Description:

```
Beginner real life based machine designed to teach people the importance of understanding from the interior.
```
Download Link : <https://www.vulnhub.com/entry/symfonos-52,415/>

Lets Begin with our Initial Scan

Nmap Scan Results:
```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 16:70:13:77:22:f9:68:78:40:0d:21:76:c1:50:54:23 (RSA)
|   256 a8:06:23:d0:93:18:7d:7a:6b:05:77:8d:8b:c9:ec:02 (ECDSA)
|_  256 52:c0:83:18:f4:c7:38:65:5a:ce:97:66:f3:75:68:4c (ED25519)
80/tcp  open  http     Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
389/tcp open  ldap     OpenLDAP 2.2.X - 2.3.X
636/tcp open  ldapssl?
```

## HTTP:

Normal Webpage with an Image like always.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos5/1.png)

Started My Gobuster to find any useful directories.

Gobuster Results:
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.1.101
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,html
[+] Timeout:        10s
===============================================================
2020/03/12 22:11:24 Starting gobuster
===============================================================
/index.html (Status: 200)
/static (Status: 301)
/home.php (Status: 302)
/admin.php (Status: 200)
/logout.php (Status: 302)
/portraits.php (Status: 200)
/server-status (Status: 403)
===============================================================
2020/03/12 22:13:28 Finished
===============================================================
```
When I visit ``/home.php`` it redirects to ``/admin.php`` Lets capture the request in burp.

``302 Found`` which is redirection, We can stop a redirection using burp.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos5/2.png)

All we need to do is change ``302 Found`` to ``200 Ok`` For that open ``Proxy -> Options -> Match and Replace``.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos5/3.png)

Now we can visit ``/home.php``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos5/4.png)

When checking those tabs this looks Local FIle Inclusion 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos5/5.png)

I checked that in Burp and yeah its a LFI
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos5/6.png)

I tried to read ``admin.php`` using LFI
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos5/7.png)
Its looks like a password : ``qMDdyZh3cT6eeAWD`` for ldap

We can use ``ldapsearch`` tool since we got password.

Reference : 
> - https://docs.oracle.com/cd/E19450-01/820-6169/ldapsearch-examples.html
> - https://access.redhat.com/documentation/en-US/Red_Hat_Directory_Server/8.2/html/Administration_Guide/Examples-of-common-ldapsearches.html

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos5/8.png)

```
-b searchbase	Use searchbase as the starting point for the search instead of the default.

-x     		  	Use simple authentication instead of SASL.

-D binddn 		Use the Distinguished Name binddn to bind to the LDAP directory.  For SASL binds, the server is expected to ignore this value.

-w password 	Use passwd as the password for simple authentication

```

We got User ``zeus`` Password which is base64 encoded.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos5/9.png)<br/>
``zeus  :  cetkKf4wCuHC9FET ``

I tried login with this in SSH<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos5/10.png)

## Privilege Escalation:

Like always I started with ``sudo -l``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos5/11.png)<br/>
We can run ``dpkg`` as root without password.

Searched that in [GTFOBins](https://gtfobins.github.io/gtfobins/dpkg/)<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos5/12.png)<br/>
The machine doesn't have fpm so I created that payload in my machine and uploaded here.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos5/13.png)

Proof:

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos5/14.png)
