---
title:     "Hack The Box - Grandpa"
tags: [windows,easy,isi]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-grandpa/1.png)

We are going to pwn Grandpa from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/13>


Lets Begin with our Initial Nmap Scan.

## Nmap Scan Results:

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Server Type: Microsoft-IIS/6.0
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Server Date: Fri, 06 Mar 2020 16:37:45 GMT
|_  WebDAV type: Unknown
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2003|2008|XP|2000 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_server_2008::sp2 cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_2000::sp4
Aggressive OS guesses: Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows Server 2008 Enterprise SP2 (90%), Microsoft Windows Server 2003 SP2 (90%), Microsoft Windows XP SP3 (90%), Microsoft Windows 2003 SP2 (89%), Microsoft Windows XP (87%), Microsoft Windows Server 2003 SP1 - SP2 (86%), Microsoft Windows 2000 SP4 (85%), Microsoft Windows XP SP2 or Windows Server 2003 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## HTTP:

Doesn't look like anything useful but we know the webpage is running as ``ISI 6.0`` from Nmap results.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-grandpa/2.png)

So I started searching for exploits available for it. 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-grandpa/3.png)

Later I found this 

> https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl

So I opened my ``metasploit`` and tried that exploit.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-grandpa/4.png)<br/>
And I checked whether its vulnerable or not and yeah its vulnerable.

I got the shell<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-grandpa/5.png)

## Privilege Escalation:

Background the Session and Lets try ``local_exploit_suggester``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-grandpa/6.png)<br/>
Seems like lot of exploits. Before doing that we need to ``migrate`` process inorder to make it stable. So I won't face any errors while using any exploit.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-grandpa/7.png)

Now we can try the exploits, I selected randomly, Started from lastone.

> exploit/windows/local/ppr_flatten_rec

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-grandpa/8.png)

It worked!! We got Authority\System<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-grandpa/9.png)