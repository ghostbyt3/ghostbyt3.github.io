---
title:     "Hack The Box - Postman"
tags: [linux,easy,redis,john]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-postman/1.png)

We are going to pwn Postman by TheCyberGeek from Hack The Box. I enjoyed the way to get user shell.

Link : <https://www.hackthebox.eu/home/machines/profile/215>


Lets Begin with our Initial Nmap Scan.

Nmap Scan Results:

```
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
6379/tcp  open  redis
10000/tcp open  snet-sensor-mgmt


PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-server-header: MiniServ/1.910
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.2 - 4.9 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 3.16 (93%), Linux 3.18 (93%), ASUS RT-N56U WAP (Linux 3.4) (93%), Oracle VM Server 3.4.2 (Linux 4.1) (93%), Android 4.1.1 (93%), Adtran 424RG FTTH gateway (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Begin with HTTP:

The site looks to be under construction.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-postman/2.png)
The Only thing I got from webpage is email address at the bottom.

Gobuster Results:
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.160
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/12/05 00:41:42 Starting gobuster
===============================================================
/css (Status: 301)
/fonts (Status: 301)
/images (Status: 301)
/index.html (Status: 200)
/js (Status: 301)
/server-status (Status: 403)
/upload (Status: 301)
===============================================================
2019/12/05 00:43:54 Finished
===============================================================
```
And Gobuster results doesn't reveal any useful directories.

So I started checking other ports.

Found that port ``6379`` - ``redis`` looks suspecious. I started searching for any vulnerabilities.
Found this!

> https://medium.com/@Victor.Z.Zhu/redis-unauthorized-access-vulnerability-simulation-victor-zhu-ac7a71b2e419

>Redis, is an open source, widely popular data structure tool that can be used as an in-memory distributed database, message broker or cache. Since it is designed to be accessed inside trusted environments, it should not be exposed on the Internet. However, some Redis’ are bind to public interface and even has no password authentication protection.

So from the above statement we need to check whether redis has no password authentication. We can do that with ``telnet``

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-postman/3.png)<br/>
Yeah! It works it doesn't ask for any authentication. Now I can continue with the article.

So First we need to create a ``ssh`` keys so I can enter the machine.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-postman/4.png)<br/>
And I generated a pair of keys.<br/>
We know that ``.pub`` must be inside the box so only we can connect it with our private key. And I changed that ``keys.pub`` to ``foo.txt`` with two blank lines before and after the public key.

We can use ``redis-cli`` to get command line interface. We can install it with ``apt install redis-tools``.

> redis-cli - Command-line client to redis-server

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-postman/5.png)

```
-h Redis-Server which we need to connect 

-x is saying that we are setting the key in redis named s-key with our pub key (foo.txt).
```

Yeah We send our pub key(foo.txt) successfully. Now its time to configure.
We can connect the server using same ``redis-cli -h IP``.

Now What we want to do here is to store ``s-key`` (SSH public key) in the ``.ssh`` folder so that we can remote SSH login to the target machine.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-postman/6.png)

So I created ``.ssh`` inside ``/var/lib/redis`` which we have permission.
And Changed the name to ``authorized_keys`` and ``save``.

Now Our key is in ``/redis/.ssh`` so we can login as ``redis`` now with our private key.

And we can now log in to the box with SSH
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-postman/7.png)

So I searched for any interesting files in the box and got ``id_rsa.bak``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-postman/8.png)

We can crack the RSA Private Key using ``john``
For that we need to use ``ssh2john`` first.
If you don't have , you can get it from [here](https://github.com/koboi137/john/blob/bionic/ssh2john.py).
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-postman/9.png)

I copied the result and saved it as ``pass`` .Now we can use this to crack with ``john``

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-postman/10.png)

We got the password ``computer2008`` I saw the user from home dir. I tried SSH login with the password but I can't. Using ``su`` from the redis shell I can log in as ``Matt``.

``matt : computer2008``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-postman/11.png)

## Privilege Escalation:

We know port ``10000`` running ``Webmin 1.910``, which is an old version.
There is an exploit, 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-postman/12.png)

> https://www.exploit-db.com/exploits/46984

I fired up my metasploit and searched for the exploit and 
Its asking for the ``USER`` and ``PASSWORD`` so I used the Matt user.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-postman/13.png)

It worked <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-postman/14.png)

I got Root!!















