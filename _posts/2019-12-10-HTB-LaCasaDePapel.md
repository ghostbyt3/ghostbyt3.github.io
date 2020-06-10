---
title:     "Hack The Box - LaCasaDePapel"
tags: [linux,easy,cron,php]
---

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/1.png)

We are going to pwn LaCasaDePapel from Hack The Box.

Link : <https://www.hackthebox.eu/home/machines/profile/181>


Like always begin with our Nmap Scan.

## Nmap Scan Results:

```
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
6200/tcp open  lm-x


21/tcp  open  ftp      vsftpd 2.3.4
22/tcp  open  ssh      OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 03:e1:c2:c9:79:1c:a6:6b:51:34:8d:7a:c3:c7:c8:50 (RSA)
|   256 41:e4:95:a3:39:0b:25:f9:da:de:be:6a:dc:59:48:6d (ECDSA)
|_  256 30:0b:c6:66:2b:8f:5e:4f:26:28:75:0e:f5:b1:71:e4 (ED25519)
80/tcp  open  http     Node.js (Express middleware)
|_http-title: La Casa De Papel
443/tcp open  ssl/http Node.js Express framework
| ssl-cert: Subject: commonName=lacasadepapel.htb/organizationName=La Casa De Papel
| Not valid before: 2019-01-27T08:35:30
|_Not valid after:  2029-01-24T08:35:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|   http/1.1
|_  http/1.0
6200/tcp open  lm-x?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, NULL, RPCCheck: 
|     [34mPsy Shell v0.9.9 (PHP 7.2.10 
|     cli) by Justin Hileman
|     [39m
|   GetRequest: 
|     [34mPsy Shell v0.9.9 (PHP 7.2.10 
|     cli) by Justin Hileman
|     [39m
|     [30;43mPHP Warning: Use of undefined constant GET - assumed 'GET' (this will throw an Error in a future version of PHP) in phar://eval()'d code on line 1
|     [39;49m
|   HTTPOptions, RTSPRequest: 
|     [34mPsy Shell v0.9.9 (PHP 7.2.10 
|     cli) by Justin Hileman
|     [39m
|     [30;43mPHP Warning: Use of undefined constant OPTIONS - assumed 'OPTIONS' (this will throw an Error in a future version of PHP) in phar://eval()'d code on line 1
|     [39;49m
|   Help: 
|     [34mPsy Shell v0.9.9 (PHP 7.2.10 
|     cli) by Justin Hileman
|     [39m
|     [30;43mPHP Warning: Use of undefined constant HELP - assumed 'HELP' (this will throw an Error in a future version of PHP) in phar://eval()'d code on line 1
|_    [39;49m
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port6200-TCP:V=7.80%I=7%D=12/26%Time=5E04A453%P=x86_64-pc-linux-gnu%r(N
SF:ULL,42,"\x1b\[34mPsy\x20Shell\x20v0\.9\.9\x20\(PHP\x207\.2\.10\x20\xe2\
SF:x80\x94\x20cli\)\x20by\x20Justin\x20Hileman\x1b\[39m\n")%r(GenericLines
SF:,42,"\x1b\[34mPsy\x20Shell\x20v0\.9\.9\x20\(PHP\x207\.2\.10\x20\xe2\x80
SF:\x94\x20cli\)\x20by\x20Justin\x20Hileman\x1b\[39m\n")%r(GetRequest,E6,"
SF:\x1b\[34mPsy\x20Shell\x20v0\.9\.9\x20\(PHP\x207\.2\.10\x20\xe2\x80\x94\
SF:x20cli\)\x20by\x20Justin\x20Hileman\x1b\[39m\n\x1b\[30;43mPHP\x20Warnin
SF:g:\x20\x20Use\x20of\x20undefined\x20constant\x20GET\x20-\x20assumed\x20
SF:'GET'\x20\(this\x20will\x20throw\x20an\x20Error\x20in\x20a\x20future\x2
SF:0version\x20of\x20PHP\)\x20in\x20phar://eval\(\)'d\x20code\x20on\x20lin
SF:e\x201\x1b\[39;49m\n")%r(HTTPOptions,EE,"\x1b\[34mPsy\x20Shell\x20v0\.9
SF:\.9\x20\(PHP\x207\.2\.10\x20\xe2\x80\x94\x20cli\)\x20by\x20Justin\x20Hi
SF:leman\x1b\[39m\n\x1b\[30;43mPHP\x20Warning:\x20\x20Use\x20of\x20undefin
SF:ed\x20constant\x20OPTIONS\x20-\x20assumed\x20'OPTIONS'\x20\(this\x20wil
SF:l\x20throw\x20an\x20Error\x20in\x20a\x20future\x20version\x20of\x20PHP\
SF:)\x20in\x20phar://eval\(\)'d\x20code\x20on\x20line\x201\x1b\[39;49m\n")
SF:%r(RTSPRequest,EE,"\x1b\[34mPsy\x20Shell\x20v0\.9\.9\x20\(PHP\x207\.2\.
SF:10\x20\xe2\x80\x94\x20cli\)\x20by\x20Justin\x20Hileman\x1b\[39m\n\x1b\[
SF:30;43mPHP\x20Warning:\x20\x20Use\x20of\x20undefined\x20constant\x20OPTI
SF:ONS\x20-\x20assumed\x20'OPTIONS'\x20\(this\x20will\x20throw\x20an\x20Er
SF:ror\x20in\x20a\x20future\x20version\x20of\x20PHP\)\x20in\x20phar://eval
SF:\(\)'d\x20code\x20on\x20line\x201\x1b\[39;49m\n")%r(RPCCheck,42,"\x1b\[
SF:34mPsy\x20Shell\x20v0\.9\.9\x20\(PHP\x207\.2\.10\x20\xe2\x80\x94\x20cli
SF:\)\x20by\x20Justin\x20Hileman\x1b\[39m\n")%r(DNSVersionBindReqTCP,42,"\
SF:x1b\[34mPsy\x20Shell\x20v0\.9\.9\x20\(PHP\x207\.2\.10\x20\xe2\x80\x94\x
SF:20cli\)\x20by\x20Justin\x20Hileman\x1b\[39m\n")%r(DNSStatusRequestTCP,4
SF:2,"\x1b\[34mPsy\x20Shell\x20v0\.9\.9\x20\(PHP\x207\.2\.10\x20\xe2\x80\x
SF:94\x20cli\)\x20by\x20Justin\x20Hileman\x1b\[39m\n")%r(Help,E8,"\x1b\[34
SF:mPsy\x20Shell\x20v0\.9\.9\x20\(PHP\x207\.2\.10\x20\xe2\x80\x94\x20cli\)
SF:\x20by\x20Justin\x20Hileman\x1b\[39m\n\x1b\[30;43mPHP\x20Warning:\x20\x
SF:20Use\x20of\x20undefined\x20constant\x20HELP\x20-\x20assumed\x20'HELP'\
SF:x20\(this\x20will\x20throw\x20an\x20Error\x20in\x20a\x20future\x20versi
SF:on\x20of\x20PHP\)\x20in\x20phar://eval\(\)'d\x20code\x20on\x20line\x201
SF:\x1b\[39;49m\n");


Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.2 - 4.9 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 3.18 (94%), Linux 3.16 (93%), ASUS RT-N56U WAP (Linux 3.4) (93%), Oracle VM Server 3.4.2 (Linux 4.1) (93%), Android 4.1.1 (93%), Adtran 424RG FTTH gateway (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Unix
```

## HTTP:

The Webpage contains login form asking for an OTP token<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/2.png)

## HTTPS:

It shows some certification error<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/22.png)

## FTP:

I checked the version ``vsftpd 2.3.4``, I found some exploit<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/3.png)

Its not working , may be they patched it
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/4.png)<br/>
But it looks like something running on port ``6200`` that stops us getting shell.

So I checked whats there using ``nc``
It shows ``psy shell`` I cant run any system commands.
Then I googled about it and found this 

>https://psysh.org/

we can use it to execute php commands 
So I tried with ```scandir(".")```<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/5.png)

```
ls
Variables: $tokyo
```

```
show $tokyo
  > 2| class Tokyo {
    3|  private function sign($caCert,$userCsr) {
    4|          $caKey = file_get_contents('/home/nairobi/ca.key');
    5|          $userCert = openssl_csr_sign($userCsr, $caCert, $caKey, 365, ['digest_alg'=>'sha256']);
    6|          openssl_x509_export($userCert, $userCertOut);
    7|          return $userCertOut;
    8|  }
    9| }
```
Its look like creating some certificate.

I used same `` file_get_contents`` to view the file<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/6.png)

Got ``ca.key`` in ``nairobi`` directory.
We know ``HTTPS`` have some certification error. So we can use that.

## Cerificate Generation:

First we need to Generate a CSR for an Existing Private Key<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/7.png)
> openssl req -new -key ca.key -out server.csr

Then Generate a Self-Signed Certificate from an Existing Private Key and CSR
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/8.png)
> openssl x509 -req -days 365 -in server.csr -signkey ca.key -out server.crt

Firefox wont import this file so we need to convert to pkcs12
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/9.png)
>openssl pkcs12 -export -in server.crt -inkey ca.key -out server.p12

> ###Reference : https://phoenixnap.com/kb/openssl-tutorial-ssl-certificates-private-keys-csrs

I added the certificate to my browser<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/10.png)

Once added Just refresh the webpage<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/11.png)<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/12.png)

On url it represents some path so I changed that <br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/13.png)

I opened ``.ssh`` dir but can't see get the private flags

![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/14.png)

I opened ``SEASON1`` and clicked ``01.avi``

It give new url ``https://lacasadepapel.htb/file/U0VBU09OLTEvMDEuYXZp``
I copied that and decoded to base64.<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/15.png)

Its directly downloading the file, so we encode the ``id_rsa`` and pass that to url we can download that!<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/16.png)<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/17.png)

Got the private key lets try login in ``ssh``
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/18.png)

## Privilege Escalation:

There is a file ``memcached.ini``<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/19.png)

It executes the ``memcached.js`` in the directory.
So I edited that to get shell (we have writable permission)<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/20.png)

I started listening on my machine<br/>
![](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-lacasadepapel/21.png)






