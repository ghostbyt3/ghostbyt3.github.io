---
title:     "Hack The Box - Haystack"
tags: [linux,easy,cron,port_forward]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/1.png)

We are going to pwn Haystack from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/195>


Like always begin with our Nmap Scan.

## Nmap Scan Results:

```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9200/tcp open  wap-wsp

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 2a:8d:e2:92:8b:14:b6:3f:e4:2f:3a:47:43:23:8b:2b (RSA)
|   256 e7:5a:3a:97:8e:8e:72:87:69:a3:0d:d1:00:bc:1f:09 (ECDSA)
|_  256 01:d2:59:b2:66:0a:97:49:20:5f:1c:84:eb:81:ed:95 (ED25519)
80/tcp   open  http    nginx 1.12.2
|_http-server-header: nginx/1.12.2
|_http-title: Site doesn't have a title (text/html).
9200/tcp open  http    nginx 1.12.2
| http-methods: 
|_  Potentially risky methods: DELETE
|_http-server-header: nginx/1.12.2
|_http-title: Site doesn't have a title (application/json; charset=UTF-8).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.2 - 4.9 (92%), Linux 3.18 (90%), Crestron XPanel control system (90%), Linux 3.16 (89%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
```
Lets begin our enumeration from HTTP<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/2.png)

Only one image it look suspecious, So I downloaded it to my machine.

I used ``strings`` on the image.

>strings - print the sequences of printable characters in files

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/3.png)<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/4.png)<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/5.png)<br/>
It gives me some base64 code so I decoded it.

It looks like spanish so we translate and see.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/6.png)

It gives us some hint or message. `` the needle in the haystack is 'key' ``

While checking ``9200`` port I came to know It is a ``elasticsearch``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/7.png)<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/8.png)

It is a searchengine so we can search for ``clave`` because it is the ``key``(Guess)
I dont know how to search so I googled.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/9.png)

I did the same and I got 2 spanish words again so I decoded it <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/10.png)
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/11.png)
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/12.png)

Got ``user`` and ``password``and I logged in with ``ssh`` as ``security : spanish.is.key``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/13.png)

## Privilege Escalation:

I uploaded ``pspy`` to check is there any cronjob
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/14.png)
I noticed that ``logstash`` was running as root.

> Logstash is an open source tool for collecting, parsing, and storing logs for future use. Kibana 3 is a web interface that can be used to search and view the logs that Logstash has indexed. Both of these tools are based on Elasticsearch. 


So I went to the location and see whats in there.
```
[security@haystack tmp]$ cd /etc/logstash/conf.d/
[security@haystack conf.d]$ ls -al
total 12
drwxrwxr-x. 2 root kibana  62 Jun 24 08:12 .
drwxr-xr-x. 3 root root   183 Jun 18 22:15 ..
-rw-r-----. 1 root kibana 131 Jun 20 10:59 filter.conf
-rw-r-----. 1 root kibana 186 Jun 24 08:12 input.conf
-rw-r-----. 1 root kibana 109 Jun 24 08:12 output.conf
[security@haystack conf.d]$ cat input.conf 
cat: input.conf: Permission denied
[security@haystack conf.d]$ cat filter.conf 
cat: filter.conf: Permission denied
[security@haystack conf.d]$ cat output.conf 
cat: output.conf: Permission denied
[security@haystack conf.d]$ 
```
I dont have read and write permissions on the files.The user ``kibana`` can read them, so we need to be ``kibana``

My Linux Enumeration script shows a port listening on the localhost.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/15.png)

So I curl that to see what it is 

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/16.png)<br/>
It is confirmed as ``kibana``

> Kibana is an open source data visualization dashboard for Elasticsearch. It provides visualization capabilities on top of the content indexed on an Elasticsearch cluster. 

Lets check its version first, I googled that<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/17.png)

I tried them in the machine<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/18.png)

Its ``6.4.2``, We can do port forwarding to see whats running on the box.
We need to ``` ~C ``` will open ssh interactive shell and then ``` -L 5602:127.0.0.1:5601 ``` Which port forward 5601 to 5602.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/19.png)

Now we can see them on our browser from the port ``5602``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/20.png)

We already know the version of it , so I searched for any exploits available and found this one from github.

>https://github.com/mpgn/CVE-2018-17246

I uploaded them into the machine.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/21.png)

I got the shell as ``kibana``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/22.png)

Now we can check what's in ``logstash``

There are 3 conf files<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/23.png)

Input check in the path ``/opt/kibana`` for the file ``logstash_*``

Next it filter some commands if its not matching the ``message``

Then it executes.

So all we need to do is create a file with name ``logstash_anything`` and create a command which match the ``message`` and put in the folder ``/opt/kibana`` 
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haystack/24.png)

I got Root!!
