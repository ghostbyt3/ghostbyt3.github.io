---
title:     "Hack The Box - Friendzone"
tags: [linux,easy,cron,domain,lfi,smb]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/1.png)

We are going to pwn FriendZone from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/173>


Like always begin with our Nmap Scan.

## Nmap Scan Results:

```
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
53/tcp  open  domain
80/tcp  open  http
139/tcp open  netbios-ssn
443/tcp open  https
445/tcp open  microsoft-ds


PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
|_  256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.2 - 4.9 (95%), Linux 3.16 (95%), Linux 3.18 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.1 (93%), Linux 3.2 (93%), Linux 3.10 - 4.11 (93%), Oracle VM Server 3.4.2 (Linux 4.1) (93%), Linux 3.12 (93%), Linux 3.13 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Hosts: FRIENDZONE, 127.0.0.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -39m33s, deviation: 1h09m15s, median: 25s
|_nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2019-12-22T19:36:53+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-12-22T17:36:54
|_  start_date: N/A

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   596.08 ms 10.10.14.1
2   596.22 ms 10.10.10.123

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.63 seconds
```

Lets Begin with HTTP 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/2.png)
This is Simple Page but there is a domain name at the bottom ``friendzoneportal.red``

So I started with ``SMB`` to see if there is any file available

> smbmap - SMB enumeration tool

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/3.png)

```
-H HOST
              IP of host
```
Found there is an file called ``creds.txt`` in ``general``

We can use ``smbclient`` to login, we know the location of the file.

>smbclient - ftp-like client to access SMB/CIFS resources on servers

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/4.png)<br/>
I logged in ``without password`` and downloaded the file.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/5.png)<br/>
We got some creds `` admin : WORKWORKHhallelujah@# ``

I tried login with them in ``ftp`` and ``ssh`` but failed!

We know there is Port 53 open which is ``domain`` may be we can do a zone transfer for that domain.
I added ``friedzone.red`` and ``friendzoneportal.red`` in ``/etc/hosts``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/6.png)

> dig - DNS lookup utility

By using this we can find other domains available for the webpage.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/7.png)<br/>
Found some new domains , I added those new entries to ``/etc/hosts``

I started with ``https://administrator1.friendzone.red``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/8.png)<br/>
and Logged with the creds we found from smb `` admin : WORKWORKHhallelujah@# ``

Once Logged in, It told me to visit ``/dashboard.php``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/9.png)

The dashboard seems to be deal with images with some paramaters.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/10.png)

So I started testing one from the displayed one.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/11.png)<br/>
Look at the parameters, may be we can do ``LFI``.
I tested with ``php wrapper``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/12.png)<br/>
Its working and ``Timestamp`` is the page and ``.php`` suffix is added automatically.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/13.png)

>https://highon.coffee/blog/lfi-cheat-sheet/

## Getting a reverse shell

The ``development`` share, we saw from ``smbmap`` has writable permission by the guest so why dont we upload a reverse shell there and try to access from this page.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/14.png)

We know the location of it from ``smbmap``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/15.png)

Listening on my machine<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/16.png)

## Privilege Escalation:

Once I get into the box I started checking for any ``.conf`` files available.

Got an user and password ``  friend : Agpyu12!0.213$ ``
Now I logged in as ``friend``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/18.png)

Found some writable files from my Enumeration script<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/17.png)

Later I uploaded ``pspy``

>pspy is a command line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute. Great for enumeration of Linux systems in CTFs. Also great to demonstrate your colleagues why passing secrets as arguments on the command line is a bad idea.

My guess is correct<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/19.png)<br/>
So I started checking ``reporter.py`` <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/20.png)<br/>
Can't find anything but ``import os`` which is also a writeable file so we edit it.
Since it is python I added python script to get shell
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/21.png)

Open my terminal and started listening and we need to wait sometime since it is ``cronjob``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-friendzone/22.png)

I got Root!!





