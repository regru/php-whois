<?php

require_once '../src/Phois/Whois/Whois.php';

$sld = 'reg.ru';
//$sld = 'com.sk'; // Not found. The Domain cannot be registered

$domain = new Phois\Whois\Whois($sld);

$whois_answer = $domain->info();

echo $whois_answer;

if ($domain->isAvailable()) {
    echo "Domain is available\n";
} else {
    echo "Domain is registered\n";
}
