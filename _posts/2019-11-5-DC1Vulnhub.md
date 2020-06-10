---
title:     "Vulnhub - DC 1"
tags: [drupal,easy]
categories: Vulnhub
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/1.1.png)
Today, We are going to pwn DC 1 by DCAU7 from Vulnhub

## Description

> DC-1 is a purposely built vulnerable lab for the purpose of gaining experience in the world of penetration testing.
It was designed to be a challenge for beginners, but just how easy it  is will depend on your skills and knowledge, and your ability to learn.
To successfully complete this challenge, you will require Linux  skills, familiarity with the Linux command line and experience with  basic penetration testing tools, such as the tools that can be found on  Kali Linux, or Parrot Security OS.
There are multiple ways of gaining root, however, I have included some flags which contain clues for beginners.
There are five flags in total, but the ultimate goal is to find and  read the flag in root's home directory. You don't even need to be root  to do this, however, you will require root privileges.
Depending on your skill level, you may be able to skip finding most of these flags and go straight for root.
Beginners may encounter challenges that they have never come across  previously, but a Google search should be all that is required to obtain  the information required to complete this challenge.

Download Link : <https://www.vulnhub.com/entry/dc-1,292/>


Lets Begin with our Initial Scan

## Nmap Scan Results
```
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
33699/tcp open  unknown
```

```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.0p1 Debian 4+deb7u7 (protocol 2.0)
| ssh-hostkey: 
|   1024 c4:d6:59:e6:77:4c:22:7a:96:16:60:67:8b:42:48:8f (DSA)
|   2048 11:82:fe:53:4e:dc:5b:32:7f:44:64:82:75:7d:d0:a0 (RSA)
|_  256 3d:aa:98:5c:87:af:ea:84:b8:23:68:8d:b9:05:5f:d8 (ECDSA)
80/tcp    open  http    Apache httpd 2.2.22 ((Debian))
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.2.22 (Debian)
|_http-title: Welcome to Drupal Site | Drupal Site
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          33699/tcp   status
|   100024  1          34071/udp6  status
|   100024  1          37756/tcp6  status
|_  100024  1          57057/udp   status
33699/tcp open  status  1 (RPC #100024)
MAC Address: 08:00:27:85:58:A6 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.2 - 3.16
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Since there is a HTTP port open , Lets start our Gobuster

## Gobuster Results

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/1.png)
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/2.png)

While checking the webpage it is a ``Drupal CMS`` which is one of the well know CMS.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/3.png)

It is drupal site so we can use [droopescan](https://github.com/droope/droopescan)

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/4.png)

It show us some possible versions, Lets search for any exploits available for them

## Method 1 (Metasploit)

While searching in metasploit , there are more than 5 exploits so i started testing them one by one!
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/5.png)
And finally this one works

> unix/webapp/drupal_drupalgeddon2

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/6.png)

We got a shell

## Method 2 

Searchsploit give us some exploits too
We know the version will be between 7.2x - 7.2x
So I randomly chose one and started testing it
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/7.png)

while reading the description of it, we can create our own admin account

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/8.png)

```
-u for username
-p for password
-t for url 
```

And I created a new admin user lets try login

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/9.png)

Successfully Logged in

To get a reverse shell we can add a module which help us to get the shell
>https://www.drupal.org/project/shell

We need to do is go to the module section

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/10.png)

Add New Module

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/11.png)
Once installed go the module and click the shell


![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/12.png)

Now we can get reverse shell by using netcat 

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/13.png)

```Flag 1 ```

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/14.png)

While checking for any default cred in /var/www , found ```Flag 2```

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/15.png)

```Flag 3 ```

Found it on the website 

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/16.png)

Got ``` Flag 4``` From /home

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/17.png)

## Privilege Escalation

Now we need to Privilege Escalation, I uploaded my Linux Enumeration Script
And found an SUID binary
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/18.png)

[GTFOBins](https://gtfobins.github.io/gtfobins/find/) Helps to get root

>sudo find . -exec /bin/sh \; -quit

```Flag 5 ```

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/dc1/19.png)

We got the ROOT!!



