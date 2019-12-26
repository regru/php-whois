<?php

include '../src/Phois/Whois/Whois.php';
include '../src/Phois/Whois/WhoisServers.php';
include '../src/Phois/Whois/WhoisException.php';

$servers = json_decode(file_get_contents(__DIR__. '/../src/Phois/Whois/whois.servers.json'), true);

foreach ($servers as $domain => $server) {
	try {
		$whois = new Phois\Whois\Whois('test.' . $domain);
	} catch (Exception $e) {
		echo "\033[31m Error: {$e->getMessage()} \e[0m";
		continue;
	}

	echo PHP_EOL;
	echo "Checking domain {$domain} :";

	try {
		$whois_answer = $whois->info();
	} catch (Phois\Whois\WhoisException $e) {

		echo "\033[33m WHOIS EXCEPTION for domain {$domain}:  {$e->getMessage()} \e[0m";
		echo PHP_EOL;

		$agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36';
		$c = curl_init("https://www.iana.org/domains/root/db/{$domain}.html");
		curl_setopt($c, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($c, CURLOPT_USERAGENT, $agent);

		$result = curl_exec($c);
		if (curl_errno($c) === 0) {
			$whoisText = strpos($result, '<b>WHOIS Server:</b>');
			if ($whoisText > 0) {
				$whoisServerText = substr($result, $whoisText + 20);
				$whoisServer = trim(substr($whoisServerText, 0, strpos($whoisServerText, '</p>')));
				if (preg_match('/^[a-zA-Z0-9-]*((-|\.)?[a-zA-Z0-9-])*\.([a-zA-Z-]{2,})$/i', $whoisServer)) {
					$servers[$domain] = [ $whoisServer, "not found"];
					file_put_contents(
						__DIR__. '/whois.servers-updated.json',
						json_encode($servers, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE |JSON_NUMERIC_CHECK | JSON_PRETTY_PRINT )
					);
					echo "\033[32m Founded new whois server for domain {$domain}:  {$whoisServer} . Changes saved in whois.servers-updated.json \e[0m";
				}
			}
		} else {
			var_dump(curl_error($c));
			echo "\033[31m Trying to find whois server failed \e[0m";
			echo $result;
		}

		curl_close($c);
		echo PHP_EOL;
		echo PHP_EOL;
		continue;
	}

	echo $whois_answer ? " OK" : "\e[31m fail\e[0m";
}
