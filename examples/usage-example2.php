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
