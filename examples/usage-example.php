<?php

include '../src/Phois/Whois/Whois.php';
include '../src/Phois/Whois/WhoisServers.php';
include '../src/Phois/Whois/WhoisException.php';

$slds = ['ero-massaj.com', 'cerus-group.com', 'test.com', 'google.com', 'vk.com', 'habr.com', 'montessori.place'];

foreach ($slds as $sld) {
	echo $sld, PHP_EOL, PHP_EOL;
	$domain = new Phois\Whois\Whois($sld);

	$whois_answer = $domain->info();
	echo $whois_answer;

	if ($domain->isAvailable()) {
		echo "Domain is available\n";
	} else {
		echo "Domain is registered\n";
	}
}
