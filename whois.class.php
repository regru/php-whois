<?php

class whois {
    var $domain;
    var $tldname;
    var $domainname;

    var $servers;

    function whois ($domain_name) {
        $this->domain = $domain_name;
        $this->get_tld();
        $this->get_domain();
        // setup whois servers array from json file
        $this->servers = json_decode(file_get_contents( __DIR__.'/whois.servers.json' ),TRUE);
    }

    function info() {
        if ($this->is_valid()) {
            $whois_server = $this->servers[$this->tldname][0];

            // If tldname have been found
            if ($whois_server != '') {
				
				// if whois server serve replay over HTTP protocol instead of WHOIS protocol
				if(preg_match("/^https?:\/\//i", $whois_server)){
				
					// curl session to get whois reposnse
					$ch = curl_init();
					$url = $whois_server . $this->domainname . '.' . $this->tldname;
					curl_setopt($ch, CURLOPT_URL, $url);
					curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
					curl_setopt($ch, CURLOPT_TIMEOUT, 60);
					curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
					curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
					curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
					
					$data = curl_exec($ch);

					if (curl_error($ch)){
						return "Connection error!";
					}else {
						$string = strip_tags($data);
					}
					curl_close($ch);

				}else{
					
					// Getting whois information
					$fp = fsockopen($whois_server, 43);
					if (!$fp) {
						return "Connection error!";
					}

					$dom = $this->domainname . '.' . $this->tldname;
					fputs($fp, "$dom\r\n");

					// Getting string
					$string = '';

					// Checking whois server for .com and .net
					if ($this->tldname == 'com' || $this->tldname == 'net') {
						while (!feof($fp)) {
							$line = trim(fgets($fp, 128));

							$string .= $line;

							$lineArr = split(":", $line);

							if (strtolower($lineArr[0]) == 'whois server') {
								$whois_server = trim($lineArr[1]);
							}
						}
						// Getting whois information
						$fp = fsockopen($whois_server, 43);
						if (!$fp) {
							return "Connection error!";
						}


						$dom = $this->domainname . '.' . $this->tldname;
						fputs($fp, "$dom\r\n");

						// Getting string
						$string = '';

						while (!feof($fp)) {
							$string .= fgets($fp, 128);
						}

						// Checking for other tld's
					} else {
						while (!feof($fp)) {
							$string .= fgets($fp, 128);
						}
					}
					fclose($fp);
				}

                return htmlspecialchars($string);
            } else {
                return "No whois server for this tld in list!";
            }
        } else {
            return "Domainname isn't valid!";
        }
    }

    function html_info() {
        return nl2br($this->info());
    }

    function get_tld() {
        $domain = split("\.", $this->domain);
        if (count($domain) > 2) {
            for ($i = 1; $i < count($domain); $i++) {
                if ($i == 1) {
                    $this->tldname = $domain[$i];
                } else {
                    $this->tldname .= '.' . $domain[$i];
                }
            }
        } else {
            $this->tldname = $domain[1];
        }
    }

    function get_domain() {
        $domain = split("\.", $this->domain);
        $this->domainname = $domain[0];
    }

    function is_available() {
        $whois_string = $this->info();
        $not_found_string = '';
        if (isset($this->servers[$this->tldname][1])) {
           $not_found_string = $this->servers[$this->tldname][1];
        }

        $whois_string2 = @ereg_replace($this->domain, '', $whois_string);
        $whois_string = @preg_replace("/\s+/", ' ', $whois_string);

        $array = split(":", $not_found_string);
        if ($array[0] == "MAXCHARS") {
            if (strlen($whois_string2) <= $array[1]) {
                return true;
            } else {
                return false;
            }
        } else {
            if (preg_match("/" . $not_found_string . "/i", $whois_string)) {
                return true;
            } else {
                return false;
            }
        }
    }

    function is_valid() {
        if (
            isset($this->servers[$this->tldname][0]) 
            && strlen($this->servers[$this->tldname][0]) > 6
        ) {
            $tmp_domain = strtolower($this->domainname);
            if (
                ereg("^[a-z0-9\-]{3,}$", $tmp_domain) 
                && !ereg("^-|-$", $tmp_domain) //&& !preg_match("/--/", $tmp_domain)
            ) {
                return true;
            }
        }
        return false;
    }
}
