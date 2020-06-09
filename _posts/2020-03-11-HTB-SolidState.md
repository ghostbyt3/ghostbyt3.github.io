---
title:     "Hack The Box - SolidState"
tags: [linux,medium,mail,pop3,rbash]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-solidstate/1.png)

We are going to pwn SolidState from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/85>


Lets Begin with our Initial Nmap Scan.

## Nmap Scan Results:
```
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp        JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.22 [10.10.14.22]), 
80/tcp   open  http        Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3        JAMES pop3d 2.3.2
119/tcp  open  nntp        JAMES nntpd (posting ok)
4555/tcp open  james-admin JAMES Remote Admin 2.3.2
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.16 (95%), Linux 3.18 (95%), Linux 3.2 - 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.8 (95%), Linux 4.4 (95%), Linux 4.2 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## HTTP:

The Webpage looks useless, Nothing Special.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-solidstate/2.png)

## MAIL:

Nmap Scan reveales James which is an mail server.

>Apache James, a.k.a. Java Apache Mail Enterprise Server or some variation thereof, is an open source SMTP and POP3 mail transfer agent and NNTP news server written entirely in Java. 

I searched for any exploits available in Searchsploit.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-solidstate/3.png)

>https://www.exploit-db.com/exploits/35513

The Exploit revealed Default credentials of Port 4555

```
# credentials to James Remote Administration Tool (Default - root/root)
user = 'root'
pwd = 'root'
```

So I logged in with these credentials<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-solidstate/4.png)

HELP command reveals we can see the list of users and we can even change the mail password. I changed ``mindy`` mail password.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-solidstate/5.png)

So Password is reset for user ``mindy``.

We Changed User's mail password and POP3 is Open, So we can view the mails received by user ``mindy`` using ``telnet``
>Post Office Protocol is an application-layer Internet standard protocol used by e-mail clients to retrieve e-mail from a mail server. POP version 3 is the version in common use.

This Article helps me to use POP3 in command line.
>https://www.vircom.com/blog/quick-guide-of-pop3-command-line-to-type-in-telnet/

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-solidstate/6.png)

First Message doesn't have anything useful but Second messange give me SSH password for ``mindy``.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-solidstate/7.png)

## SSH:

``mindy : P@55W0rd1!2@``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-solidstate/8.png)

Got User Flag!!.

We can see that we have rbash which is Restricted Bash so we are restricted to use some commands. So I googled about how to escape rbash and found [this](https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells?slide=9). We can also use ``bash –noprofile`` in ssh.

``
--noprofile
              Do  not  read either the system-wide startup file /etc/profile or any of the personal initialization files ~/.bash_profile, ~/.bash_lo‐
              gin, or ~/.profile.  By default, bash reads these files when it is invoked as a login shell.
``

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-solidstate/9.png)

## Another Method:

We already found an [exploit](https://www.exploit-db.com/exploits/35513) which runs the payload if someone logs in.

I changed the payload to give us reverse shell.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-solidstate/10.png)

Run the exploit and started my nc listener on another terminal and Logged in SSH.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-solidstate/11.png)

Now we have normal bash shell.

## Privilege Escalation:

My Enumeration Script revealed there is a file with writeable permission in ``/opt/tmp.py`` which is running as root. Maybe its a cronjob.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-solidstate/12.png)

I changed the script and gave SETUID to ``/bin/sh`` 

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-solidstate/13.png)

SETUID make the executable ``/bin/sh`` to run as root because the script is running as root.

So When I use run ``sh`` I will get root shell

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-solidstate/14.png)

I'm Root!!

## Extra:

Instead of using ``telnet`` command line for ``pop3``, We can use Thunderbird Mail Client.

All we need to do is, Open ThunderBird -> Add Email -> Login
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-solidstate/55.png)

Now we can view the mail in better GUI
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-solidstate/56.png)