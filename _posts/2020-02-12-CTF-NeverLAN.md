---
title:     "NeverLAN CTF 2020"
tags: [ctf]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/0.png)


NeverLAN CTF is a beginner friendly CTF . Me any my friend [D4mianWayne](https://twitter.com/d4mianwayne) did this together, it's really fun and we enjoyed it. In this post I write a walkthrough for the CTF.

# Web

## Cookie Monster
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/1.1.png)
The Webpage:

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/1.png)
    
The title of the challenge is ``Cookie Monster``

> - Google search "cookie monster favorite guy red"
> - It's a character named Elmo

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/2.png)

Got the Flag!

## Stop the Bot
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/3.png)

The Webpage:
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/4.png)

It says bot everywhere so I looked at ``robots.txt``

>The robots exclusion standard, also known as the robots exclusion protocol or simply robots.txt, is a standard used by websites to communicate with web crawlers and other web robots. The standard specifies how to inform the web robot about which areas of the website should not be processed or scanned.

It shows the files or directories in the webpage.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/5.png)

It shows ``flag.txt``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/6.png)


## SQL Breaker
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/7.1.png)

The Webpage:
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/7.png)

Found a Login page
 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/8.png)

Since it is an SQL Breaker I tried some normal sql injection

> Source : https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection

```admin'-- - : admin```

It Worked!!
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/9.png)


## SQL Breaker 2
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/10.png)

The Webpage:
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/11.png)

Another login page

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/12.png)

Like Before I tried some normal SQLi

``` ' or 1=1 limit 1 -- -+ ```

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/13.png)

It says only admin user can see the flag, Since the normal sqli works, So adding an offset to the payload (offset 1) will make me select the next from the list.Implicit offset is 0.
The 1 in the limit states, show me 1 line of output so if you do LIMIT 1 OFFSET 1.
It will give you one line, specifically the second line in the output

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/14.png)

``` ' or 1=1 limit 1 offset 1-- -+ ```

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/15.png)

## Follow Me!
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/16.png)

It looks like the page keeps on redirecting ,If a website returns 302 redirect page, browser don't bother loading the page. So normally we won't see that data. If we prevent following of redirects, we'll be able to view the page.
I captured the request in burp and started Follow Redirecion, at a particular domain I got Flag.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/17.png)

## Browser Bias
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/18.png)

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/19.png)

The Webpage shows us a message that the site is only optimized for browsers that run on commodo 64.
So I googled which browser do that.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/20.png)

Its ``Hyperlink 2.5e``

So I capture the request in burp and changed the User Agent to Hyperlink 2.5e from Firefox.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/21.png)


# PCAP

## Unsecured Login
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/22.png)

HTTP requires data to be transferred from one point to another over the network. The transfer of resources happens using TCP 
So I searched directly as ``tcp contains flag``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/23.png)

## Unsecured Login2
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/24.png)

Did the same thing as I did on the first challenge 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/25.png)

This time flag is in url so I opened it to get the flag
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/26.png)

## FTP
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/27.png)

Since its FTP, I tried searching as FTP and checked each packet in ftp. 
Found the flag in FTP-DATA Protocol.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/28.png)

## Teletype Network
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/29.png)

The file name give me the hint so I searched for ``telnet contains flag``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/30.png)

## Hidden ctf on my network
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/62.png)

So from the given hint : When a new machine connect to an network , DHCP first assign IP for the machine.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/63.png)

## Note 

We can even use ``strings`` to get flag , because everything in plain text, thats why it works.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/64.png)

# RECON

## Front Page of the Internet
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/31.png)

I googled ``Front Page of the Internet`` and found it is ``reddit``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/32.png)

Since the creator of this challenge is ``ZestyFE`` I searched for his account in reddit.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/33.png)


## The Big Stage
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/34.png)

>Hint : One time we keynoted @SaintCon... I think I remember hiding a flag in our pres

So I started googling about the conference and found a YT link
> https://www.youtube.com/watch?v=1wthauUWsGI

Did some fastforwarding at 1:49:40 found an example of a CTF flag.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/35.png)


## The Link
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/36.png)

> Hint : NeverLAN's secret Track 2

Track represents Music maybe , when I register for CTF I saw ``Music`` category in the main page. 

>https://neverlanctf.com/

So I opened that and found ``Track1`` ``Track2`` ``Track3`` (If its not displayed reload the page.)
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/37.png)

We know Track2 is what we want, Its an youtube video so I opened link directly to YT and found the flag in comments.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/38.png)

## Thats just Phreaky
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/39.png)

Hint : The first of many stories that have been told. 01 September 2017 | 14:01

From the given hints I googled and opened the first link which relates everything with the hint
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/40.png)

Looks like some story.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/41.png)

I searched the flag in source code of the page.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/42.png)

# Forensic

## OpenBackPack
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/70.png)

I started with ``strings`` and ``steghide`` not good results then I tried ``binwalk``.

>binwalk  - tool for searching binary images for embedded files and executable code

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/71.png)
It extracted the files.

```
-e, --extract
              Automatically extract known file types
```

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/72.png)


## Look into the past
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/43.png)

I downloaded the file to my machine and extracted and started searching whats there.

```
root@w0lf:~/CTF/CTFTIME/NeverLAN /2020/Forensic/look_into_the_past/home/User# ls -la
total 52
drwxr-xr-x 9 1000 rvm 4096 Feb  8 21:54 .
drwxr-xr-x 3 1000 rvm 4096 Feb  8 21:54 ..
-rw-r--r-- 1 1000 rvm  349 Feb  7 00:03 .bash_history
-rw-r--r-- 1 1000 rvm  864 Feb  7 00:04 .bashrc
drwxr-xr-x 2 1000 rvm 4096 Feb  8 21:54 Desktop
drwxr-xr-x 2 1000 rvm 4096 Feb  8 22:22 Documents
drwxr-xr-x 2 1000 rvm 4096 Feb  8 21:54 Downloads
drwxr-xr-x 2 1000 rvm 4096 Feb  8 21:54 Music
drwxr-xr-x 2 1000 rvm 4096 Feb  8 21:54 Pictures
-rw-r--r-- 1 1000 rvm  672 Feb  7 00:04 .profile
drwxr-xr-x 2 1000 rvm 4096 Feb  8 21:54 Public
drwxr-xr-x 2 1000 rvm 4096 Feb  8 21:54 Videos
-rw-r--r-- 1 1000 rvm   37 Feb  7 00:03 .vimrc
```

Found ``.bash_history`` 

> In computing, various shells maintain a record of the commands issued by the user during the current session. The history command works with the command history list. 

Found some commands history.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/44.png)

I looks like 3 passwords we created and decoded the ``flag.txt`` file to ``flag.txt.enc`` and the 3 passwords are split into 3 places

> - Embeded pass1 in a image using Steghide.<br>
> - Created an user with ``pass2``.<br>
> - pass3 Added in sqlite database.<br>

So I started from ``pass1``
```
steghide embed -cf doggo.jpeg -ef $pass1 
mv doggo.jpeg ~/Pictures
```
Its embeded in an image and its located in ``/Pictures``

```
root@w0lf:~/CTF/CTFTIME/NeverLAN /2020/Forensic/look_into_the_past/home/User/Pictures# steghide extract -sf doggo.jpeg 
Enter passphrase: 
wrote extracted data to "steganopayload213658.txt".

root@w0lf:~/CTF/CTFTIME/NeverLAN /2020/Forensic/look_into_the_past/home/User/Pictures# ls
doggo.jpeg  steganopayload213658.txt

root@w0lf:~/CTF/CTFTIME/NeverLAN /2020/Forensic/look_into_the_past/home/User/Pictures# cat steganopayload213658.txt 
JXrTLzijLb
``` 
They didnt used any password so I left the passphrase empty.

``pass2``

```
useradd -p '$pass2'  user
```

New user added with the name of ``user`` and ``pass2``, basically passwords will be in ``/etc/shadows``

I did ``cat /etc/shadows``
```
user:KI6VWx09JJ:18011:0:99999:7:::
```

``pass3``

```
sqlite3 /opt/table.db "INSERT INTO passwords values ('1', $pass3)"
tar -zcf /opt/table.db.tar.gz /opt/table.db
```
A Sqlite Database created and ``pass3`` inserted into ``passwords`` and its in ``/opt`` directory.

```
root@w0lf:~/CTF/CTFTIME/NeverLAN /2020/Forensic/look_into_the_past/opt# ls
table.db.tar

root@w0lf:~/CTF/CTFTIME/NeverLAN /2020/Forensic/look_into_the_past/opt# file table.db.tar 
table.db.tar: POSIX tar archive

root@w0lf:~/CTF/CTFTIME/NeverLAN /2020/Forensic/look_into_the_past/opt# tar -xvf table.db.tar 
table.db
```
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/45.png)

Got 3 pass now 

We know they encrypted with openssl with these command
```
openssl enc -aes-256-cbc -salt -in flag.txt -out flag.txt.enc -k $(cat $pass1)$pass2$pass3
```

Now we can decrypt the ``flag.txt.enc`` to ``flag.txt`` with the passwords we found.

I combined all 3 passwords

```
openssl enc -d -aes-256-cbc -salt -in flag.txt.enc -out flag.txt -k JXrTLzijLbKI6VWx09JJnBNfDKbP5n
```

> -d for decode 

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/46.png)


# Chicken Little

## Chicken Little 1 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/47.png)

I logged in with the given credentials
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/48.png)

They Provide the password in ``Welcome.txt``

## Chicken Little 2
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/49.png)

Hint : Password is hidden

We can view all files even hidden files using ``ls -la``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/50.png)

## Chicken Little 3
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/51.png)

If I cat the ``BAWKBAWK.txt`` it keeps on printing ``BAWK`` and We know that on every password has ``level`` before the password. 
So I used ``grep`` that level 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/52.png)

## Chicken Little 4
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/53.png)

Its a binary file so we can use ``strings`` to see printable characters in the file.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/54.png)

## Chicken Little 5
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/55.png)

This is an gzip file but I cant decompress it because the extension is missing, I added them and tried extracting.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/56.png)


> gzip -d the_sky_is_falling.gz

> -d = decompress

## Chicken Little 6
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/57.png)

The Hint is we need to download the image file to our machine and see it
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/57.1.png)

> Reference : https://linuxize.com/post/how-to-use-scp-command-to-securely-transfer-files/

>SCP (secure copy) is a command-line utility that allows you to securely copy files and directories between two locations. With scp , you can copy a file or directory: From your local system to a remote system

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/58.png)

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/59.png)

## Chicken Little 7
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/60.png)

The Hint is we can get level7 password in normal hash location which is ``/etc/shadow`` and crack them using hashcat.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/61.png)

I copied the hashes to my machines and named it as hash
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/61.1.png)
```
-m 1800  = sha512crypt
-a 3     =  attack mode
```
How do you find its sha512crypt? I used ``john`` before that and it shows me what hash it is?

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/61.2.png)

# Trivia

## Milk Please
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/65.png)

>Cookies were designed to be a reliable mechanism for websites to remember stateful information.

Flag:Cookies

## Professional guessing
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/66.png)

Flag:Password Cracking

## Base 2^6
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/67.png)

Flag:Base64

## AAAAAAAAAAAAAA! I hate CVEs
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/68.png)

With the give hint I googled the exploit 

>https://www.exploit-db.com/exploits/47995

This is because of ``pwfeedback``

Flag:pwfeedback

## Rick Rolled by the NSA???
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/69.png)

I googled with the hint

>https://arstechnica.com/information-technology/2020/01/researcher-develops-working-exploit-for-critical-windows-10-vulnerability/

Flag: CVE-2020-0601


We managed to get into the position of 136 out of 1121
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/neverlanctf/final.png)