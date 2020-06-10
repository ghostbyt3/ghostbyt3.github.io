---
title:     "Hack The Box - Popcorn"
tags: [linux,medium,file-upload-vuln,kernel_exploit]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-popcorn/1.png)

We are going to pwn Popcorn from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/4>


Like always begin with our Nmap Scan.

## Nmap Scan Results:

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
|_  2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
80/tcp open  http    Apache httpd 2.2.12 ((Ubuntu))
|_http-server-header: Apache/2.2.12 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.17 - 2.6.36 (95%), Linux 2.6.30 (95%), Linux 2.6.32 (95%), Linux 2.6.35 (95%), Linux 2.4.20 (Red Hat 7.2) (95%), Linux 2.6.17 (95%), Android 2.3.5 (Linux 2.6) (95%), AVM FRITZ!Box FON WLAN 7240 WAP (94%), Canon imageRUNNER ADVANCE C3320i or C3325 copier (94%), Epson WF-2660 printer (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### HTTP:

Looks like an normal webpage, Lets do Gobuster and see if anything interesting.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-popcorn/2.png)

GoBuster Results:
```
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.6
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/01/12 09:38:15 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/cgi-bin/ (Status: 403)
/index (Status: 200)
/index.html (Status: 200)
/test (Status: 200)
/torrent (Status: 301)
===============================================================
2020/01/12 09:40:05 Finished
===============================================================
```


``/torrent`` Looks Interesting
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-popcorn/3.png)

I searched for any exploits available and got this one<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-popcorn/4.png)

> https://www.exploit-db.com/exploits/11746

So it is an file upload vulnerability

So First we need to create an account <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-popcorn/5.png)

Account Successfully created and I started searching for any uploads available.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-popcorn/6.png)

And found this , So I uploaded random ``.torrent`` file to see what we can do with it.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-popcorn/7.png)

Once uploaded it shows me this page with an option for ``Edit this Torrent`` which is interesting.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-popcorn/8.png)

There is an option to upload a picture as Screenshot. So we can try creating a image with reverse shell inside it.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-popcorn/9.png)

I created a Payload with ``GIF89`` which makes the file to look like gif image and saved it as ``shell.php.gif``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-popcorn/10.png)

While uploading I captured the intercept via burp and removed that ``.gif`` and Forwarded.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-popcorn/11.png)

File Uploaded<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-popcorn/12.png)

Once uploaded I tried to view the image inorder to start our payload, by clicking on the image it opened. <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-popcorn/13.png)

Started my nc listener<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-popcorn/14.png)

## Privilege Escalation

Its is an old kernel version.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-popcorn/15.png)

Searched for the exploit available for this version and got ``Dirty Cow`` exploit.<br/>
> https://www.exploit-db.com/exploits/40839

Uploaded it to the box and Followed the instruction.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-popcorn/16.png)

New Account created as ``root``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-popcorn/17.png)

Got Root Flag.
 

