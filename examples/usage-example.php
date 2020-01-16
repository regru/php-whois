<?php

include '../src/Phois/Whois/Whois.php';
include '../src/Phois/Whois/WhoisServers.php';
include '../src/Phois/Whois/WhoisException.php';

$sld = 'test.saarland';

$domain = new Phois\Whois\Whois($sld);

$whois_answer = $domain->info();

echo $whois_answer;

if ($domain->isAvailable()) {
    echo "Domain is available\n";
} else {
    echo "Domain is registered\n";
}
