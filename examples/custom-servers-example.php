<?php

include __DIR__.'/../src/Phois/Whois/Whois.php';

$sld = 'anlo.ng';

Phois\Whois\Whois::setServers([
    'ng' => [
        'whois.nic.net.ng',
        'Domain Status: No Object Found',
    ],
    'work' => [
        'whois.nic.work',
        'not been registered',
    ],
]);

Phois\Whois\Whois::setServers('path-to-your-servers.json');

$domain = new Phois\Whois\Whois($sld);

$whois_answer = $domain->info();

echo $whois_answer;

if ($domain->isAvailable()) {
    echo "Domain is available\n";
} else {
    echo "Domain is registered\n";
}
