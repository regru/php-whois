<?php

namespace Phois\Whois;

class Whois {
	private $domain;

	private $TLDs;

	private $subDomain;

	private $servers;
	
	private $info;

	const CONNECT_TIMEOUT = 30;
	const TIMEOUT = 30;

	/**
	 * @param string $domain full domain name (without trailing dot)
	 * @throws \InvalidArgumentException
	 */
	public function __construct($domain) {
		$this->domain = $domain;
		// check $domain syntax and split full domain name on subdomain and TLDs
		if (preg_match('/^([\p{L}\d\-]+)\.((?:[\p{L}\-]+\.?)+)$/ui', $this->domain, $matches) ||
			preg_match('/^(xn\-\-[\p{L}\d\-]+)\.(xn\-\-(?:[a-z\d-]+\.?1?)+)$/ui', $this->domain, $matches)
		) {
			$this->subDomain = $matches[1];
			$this->TLDs = $matches[2];
		} else {
			throw new \InvalidArgumentException("Invalid $domain syntax");
		}
		// setup whois servers array from json file
		$this->servers = WhoisServers::getInstance();
	}

	/**
	 * @return string
	 * @throws WhoisException
	 */
	public function info() {
		if (!is_null($this->info)) {
			return $this->info;
		}
		if (!$this->isValid()) {
			throw new WhoisException("Domain name isn't valid!");
		}

		$whoisServer = $this->servers->getServer($this->TLDs);

		// if whois server serve replay over HTTP protocol instead of WHOIS protocol
		if (preg_match('/^https?:\/\//i', $whoisServer)) {
			// curl session to get whois reposnse
			$string = $this->getWithCurl($whoisServer);
		} else {
			$string = $this->getWithSocket($whoisServer);
		}

		$string_encoding = mb_detect_encoding($string, 'UTF-8, ISO-8859-1, ISO-8859-15', true);
		$string_utf8 = mb_convert_encoding($string, 'UTF-8', $string_encoding);

		$this->info = htmlspecialchars($string_utf8, ENT_COMPAT, 'UTF-8', true);
		return $this->info;
	}
	/**
	 * @param $whoisServer
	 * @return string
	 * @throws WhoisException
	 */
	private function getWithCurl($whoisServer) {
		$ch = curl_init();
		$url = "$whoisServer{$this->subDomain}.{$this->TLDs}";
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
		curl_setopt($ch, CURLOPT_TIMEOUT, self::TIMEOUT);
		curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, self::CONNECT_TIMEOUT);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);

		$data = curl_exec($ch);
		$error = curl_error($ch);
		curl_close($ch);

		if ($error !== '') {
			throw new WhoisException( "Connection error: $error");
		}
		
		return strip_tags($data);
	}

	/**
	 * @param $whoisServer
	 * @return string
	 * @throws WhoisException
	 */
	private function getWithSocket($whoisServer){
		if (false === gethostbynamel($whoisServer)) {
			throw new WhoisException( "Host is unreachable: $whoisServer");
		}

		$handle = fsockopen($whoisServer, 43, $errno, $errstr, self::CONNECT_TIMEOUT);

		if (!$handle || $errno !== 0) {
			throw new WhoisException( "Connection error: $errstr");
		}

		stream_set_timeout($handle, self::TIMEOUT);

		$dom = "{$this->subDomain}.{$this->TLDs}";
		if (false === fwrite($handle, "$dom\r\n")) {
			throw new WhoisException('Can not write query!');
		};
		
		$string = '';
		$this->checkTimeout($handle);
		while (!feof($handle)) {
			$this->checkStream($handle);
			$raw = fread($handle,  8192);
			$this->checkTimeout($handle);
			if (false === $raw) {
				throw new WhoisException('Response chunk cannot be read');
			}
			$string .= $raw;
		}
		fclose($handle);
		foreach (preg_split("/\r\n|\n|\r/", $string) as $line) {
			$lineArr = explode(':', trim($line));
			if (count($lineArr) !== 2) continue;
			if (false === strpos(strtolower($lineArr[0]),  'whois server')) continue;
			$newServer = trim($lineArr[1]);
			if (strlen($newServer) > 0 && $newServer !== $whoisServer) {
				return $this->getWithSocket($newServer);
			}
		}
		return $string;
	}

	/**
	 * @param resource $handle
	 * @throws WhoisException
	 */
	private function checkTimeout($handle) {
		if (stream_get_meta_data($handle)['timed_out']) {
			throw new WhoisException('Connection timeout');
		};
	}

	/**
	 * @param resource $handle
	 * @throws WhoisException
	 */
	private function checkStream($handle) {
		$stR = [$handle];
		$stW = null;
		if (false === stream_select($stR, $stW, $stW, self::TIMEOUT)) {
			throw new WhoisException('Connection stream select timeout');
		};
	}
	
	/**
	 * @return string
	 * @throws WhoisException
	 */
	public function htmlInfo() {
		return nl2br($this->info());
	}

	/**
	 * @return string full domain name
	 */
	public function getDomain() {
		return $this->domain;
	}

	/**
	 * @return string top level domains separated by dot
	 */
	public function getTLDs() {
		return $this->TLDs;
	}

	/**
	 * @return string return subdomain (low level domain)
	 */
	public function getSubDomain() {
		return $this->subDomain;
	}

	/**
	 * @return bool
	 * @throws WhoisException
	 */
	public function isAvailable() {
		$notFoundString = $this->servers->getNotFoundString($this->TLDs);
		if (false === $notFoundString) {
			throw new WhoisException("Availability check is not implemented for {$this->TLDs}");
		}
		$whoisInfo = $this->info();
		$array = explode(':', $notFoundString);
		
		if ('MAXCHARS' === $array[0]) {
			$domainQuoted = preg_quote($this->domain, '/');
			$whoisInfoWithoutDomain = preg_replace("/$domainQuoted/", '', $whoisInfo);
			$maxLen = intval(trim($array[1]));
			return strlen($whoisInfoWithoutDomain) <= $maxLen;
		} 
		
		$notFoundStringQuoted = preg_quote($notFoundString, '/');
		$whoisInfo = preg_replace('/\s+/', ' ', $whoisInfo);
		if (preg_match("/$notFoundStringQuoted/i", $whoisInfo)) {
			return true;
		}
		return false;
	}

	public function isValid() {
		if (!$this->servers->exists($this->TLDs)) {
			return false;
		}
		$tmp_domain = strtolower($this->subDomain);
		if (!preg_match('/^[a-z0-9\-]{2,}$/', $tmp_domain)) {
			return false;
		}
		
		if (preg_match('/^-|-$/', $tmp_domain)) {
			return false;
		}

		return true;
	}
}
