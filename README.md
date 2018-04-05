# Metasploit module for RCE in iTop <= 2.4.0

Installation:
------

```bash
mkdir -p ~/.msf4/modules/exploits/itop/
wget https://raw.githubusercontent.com/attackercan/itop-2.4.0-rce/master/itop_rce.rb \
-O ~/.msf4/modules/exploits/itop/itop_rce.rb
msfconsole
use exploit/itop/itop_rce
```

Blogpost:
------
https://httpsonly.blogspot.com/2018/04/pentest-0day-in-itop-240-gave-me-domain.html


Author:
------
Vladimir Ivanov https://twitter.com/httpsonly


Usage example:
------
![msf](https://user-images.githubusercontent.com/17142772/38373739-934bf824-38fa-11e8-94fb-044a8147583c.png)
