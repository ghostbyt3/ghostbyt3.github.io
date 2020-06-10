---
title:     "Hack The Box - Valentine"
tags: [linux,easy,heartbleed,kernel_exploit]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-valentine/1.png)

We are going to pwn Valentine from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/127>


Like always begin with our Nmap Scan.

## Nmap Scan Results

```bash
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_ssl-date: 2019-12-07T15:32:32+00:00; +19s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.0 (95%), Linux 2.6.32 - 3.5 (95%), Nokia N9 phone (Linux 2.6.32) (95%), Linux 2.6.38 - 3.0 (94%), Linux 3.2 (94%), Linux 2.6.38 - 2.6.39 (94%), Linux 2.6.39 (94%), Linux 3.5 (93%), Linux 2.6.32 - 3.10 (93%), Linux 2.6.32 - 3.9 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Start from Webpage like always

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-valentine/2.png)<br/>
This image looks like heartbleed it may be ``heartbleed vulnerability``

## Gobuster Results

```bash
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.79
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/12/07 19:25:22 Starting gobuster
===============================================================
/index (Status: 200)
/dev (Status: 301)
/encode (Status: 200)
/decode (Status: 200)
/omg (Status: 200)
/server-status (Status: 403)
===============================================================
2019/12/07 21:11:06 Finished
===============================================================
```

To know about what is ``heartbleed`` this will be very helpful

>https://xkcd.com/1354/

To confirm that , we can use nmap scripts

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-valentine/3.png)

Yes it is confirmed, so I searched for exploits 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-valentine/4.png)

This one might work
>https://www.exploit-db.com/exploits/32745

when the script runs and it grabs some memory for us<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-valentine/5.png)

While its running on background I looked for directories 
There is ``/decode.php``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-valentine/5.1.png)

And ``/encode.php``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-valentine/5.2.png)<br/>
I tried some commands to get anything useful but none worked!

And the script found some base64 lets try decode them for that I used ``/decode.php`` 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-valentine/6.png)

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-valentine/7.png)

It may be password for something 

## Getting User Shell

While checking other directories found ``hype_key`` from ``/dev``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-valentine/9.png)

It is in hex , so we can decode them and see what we got
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-valentine/8.png)

> xxd - make a hexdump or do the reverse.

```
-r reverse
-p plain
```

We got an ``ssh private key``

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-valentine/10.png)

We can try login with them with ``hype`` since we got it as ``hype_key``

It's asking for passphrase may be the one we got from heartbleed exploit

``hype:heartbleedbelievethehype``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-valentine/11.png)

We are successfully logged in as ``hype``

## Privilege Escalation

While checking the kernel it looks old one <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-valentine/12.png)

Yes it is we can use ``Dirty Cow`` for Priv Escalation
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-valentine/13.png)
>https://www.exploit-db.com/exploits/40839

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-valentine/14.png)

I uploaded the Script into the machine and from the given instruction I run that<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-valentine/15.png)

Yes it worked it created new user as ``root``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-valentine/16.png)


