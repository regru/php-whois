<?php

include('whois.class.php');

$domain_name = 'reg.ru';

$domain = new whois( $domain_name );
$whois_answer = $domain->info();

echo $whois_answer;

if ($domain->is_available()) {
    echo "Domain is available\n";
} else {
    echo "Domain is registered\n";
}

