---
title:     "Hack The Box - Teacher"
tags: [linux,easy,cron,rce,intruder]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/1.png)

We are going to pwn Teacher from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/165>


Like always begin with our Nmap Scan.

## Nmap Scan Results:

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Blackhat highschool
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.16 (95%), Linux 3.18 (95%), Linux 3.2 - 4.9 (95%), Linux 4.2 (95%), Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.8 - 3.11 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 4.4 (95%), Linux 4.8 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
```
Lets begin our enumeration from webpage
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/2.png)
Looks like an normal webpage

While looking at each pages I found something on ``/gallery`` source code.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/3.png)

If I click the image link it shows me some error.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/4.png)

So I downloaded it into my machine and I used ``strings``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/5.png)<br/>
It gives me some message along with ``user:giovanni`` and ``password:Th4C00lTheacha(Missing Char)``

Which means there must be a login page so I started my Gobuster

## Gobuster Results:

```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.153
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/12/11 19:07:47 Starting gobuster
===============================================================
/css (Status: 301)
/fonts (Status: 301)
/images (Status: 301)
/index.html (Status: 200)
/javascript (Status: 301)
/js (Status: 301)
/manual (Status: 301)
/moodle (Status: 301)
/phpmyadmin (Status: 403)
/server-status (Status: 403)
===============================================================
2019/12/11 19:10:25 Finished
===============================================================
```
While checking them found some new page ``/moodle``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/6.png)<br/>
So I bruteforce this directory

## Gobuster Results of ``/moodle``:

```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.153/moodle/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/12/13 17:47:47 Starting gobuster
===============================================================
/admin (Status: 301)
/analytics (Status: 301)
/auth (Status: 301)
/backup (Status: 301)
/blocks (Status: 301)
/blog (Status: 301)
/cache (Status: 301)
/calendar (Status: 301)
/comment (Status: 301)
/course (Status: 301)
/error (Status: 301)
/files (Status: 301)
/filter (Status: 301)
/group (Status: 301)
/index.php (Status: 200)
/install (Status: 301)
/lang (Status: 301)
/lib (Status: 301)
/local (Status: 301)
/login (Status: 301)
/media (Status: 301)
/message (Status: 301)
/mod (Status: 301)
/my (Status: 301)
/notes (Status: 301)
/pix (Status: 301)
/portfolio (Status: 301)
/question (Status: 301)
/rating (Status: 301)
/report (Status: 301)
/repository (Status: 301)
/rss (Status: 301)
/search (Status: 301)
/tag (Status: 301)
/theme (Status: 301)
/user (Status: 301)
/webservice (Status: 301)
===============================================================
2019/12/13 17:50:22 Finished
===============================================================
```
Its quite a lot

Finally I found a login page ``/moodle/login/index.php``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/7.png)<br/>
We already have a user and password along with a missing character
So we need to bruteforce the character

I started my burp and capture the login intercept and send that to intruder
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/8.png)

I created my wordlist we need to find the last character or letter so<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/9.png)

I added ``` !@#$%^&*() ``` manually and my wordlist is ready

I uploaded them into the payload section<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/10.png)

Started the attack and this one length is different that other , it might be the correct passsword
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/11.png)

Yes I logged in 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/12.png)
``` giovanni:Th4C00lTheacha# ```

Now we need to get a reverse shell and I found this

>https://blog.ripstech.com/2018/moodle-remote-code-execution/

I did the same process from the blog
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/13.png)

Added the code <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/13.1.png)

From the code I came to know we need to call ``hack`` for any command execution.

Then I send that request to burp and it worked I got reverse shell.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/14.png)

Immediately I started searching for ``conf`` files and I got this<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/15.png)

> mysql -u root -D moodle -p

```
-u db user
-D db name
-p password
```

Once we entered it will ask for password by entering them I logged in.

`` SHOW DATABASES; ``
Will show all the databases

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/16.png)

And then I use ``moodle`` by using ``USE moodle;``

``SHOW TABLES;``
Will show all the tables on the particular database.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/17.png)

From there I chosed ``mdl_user`` and got some hashes<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/18.png)

I cracked ``giovanni``'s hash using [Crack Station](https://crackstation.net/)
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/19.png)

`` giovanni:expelled ``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/20.png)

Im giovanni now 

## Privilege Escalation:

I tried running Linux Enumeration script , Nothing usefull
So I uploaded ``pspy``

>pspy is a command line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute. Great for enumeration of Linux systems in CTFs. Also great to demonstrate your colleagues why passing secrets as arguments on the command line is a bad idea.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-teacher/21.png)

There is a ``cronjob`` running on the background.

While checking the script I came to know it going to ``/giovanni/work`` and compress all files in ``/courses`` and then it moving to ``/tmp`` and extract them and giving them permission recursively.
![](https://ra