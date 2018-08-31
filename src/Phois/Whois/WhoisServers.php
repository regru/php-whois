<?php

namespace Phois\Whois;

class WhoisServers {
	private $list;
	private static $instance;
	public static function getInstance() {
		if (!is_null(self::$instance)) {
			return self::$instance;
		}
		return new self(__DIR__. '/whois.servers.json');
	}
	protected function __construct($configPath) {
		$this->list = json_decode(file_get_contents($configPath), true);
	}
	public function exists($tld) {
		$exists =  array_key_exists($tld, $this->list) &&
			array_key_exists(0, $this->list[$tld]) &&
			strlen($this->list[$tld][0]) > 6
		;
		return $exists;
	}
	public function getServer($tld) {
		return $this->list[$tld][0];
	}
	public function getNotFoundString($tld) {
		if (array_key_exists(1, $this->list[$tld])) {
			return $this->list[$tld][1];
		}
		return false;
	}

}
