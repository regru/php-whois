# php-whois

PHP class to retrieve WHOIS information.

## Example of usage

```php

<?php

$sld = 'reg.ru';

$domain = new Phois\Whois\Whois($sld);

$whois_answer = $domain->info();

echo $whois_answer;

if ($domain->isAvailable()) {
    echo "Domain is available\n";
} else {
    echo "Domain is registered\n";
}

```

A more complete example:

```php

<?php
require_once __DIR__.'/../vendor/autoload.php';

$sld = 'nabi.ir';

try {
	$domain = new Phois\Whois\Whois($sld);
} catch (InvalidArgumentException $e) {
	die($e->getMessage()."\n");
}

if ($domain->isAvailable()) {
	echo "Domain is available\n";
} else {
	echo "Domain is registered\n";
}

```
