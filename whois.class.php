<?php

class whois {
    var $domain;
    var $tldname;
    var $domainname;

    var $servers = array(
        'ru' => array('whois.ripn.net', 'No entries found'),
        'su' => array('whois.ripn.net', 'No entries found'),
        'com' => array('whois.crsnic.net', 'No match'),
        'net' => array('whois.crsnic.net', 'No match'),
        'org' => array('whois.pir.org', 'NOT FOUND'),
        'biz' => array('whois.biz', 'Not found'),
        'info' => array('whois.afilias.info', 'Not found'),
        'mobi' => array('whois.dotmobiregistry.net', 'NOT FOUND'),
        'name' => array('whois.nic.name', 'No match'),
        'tv' => array('whois.nic.tv', 'No match'),
        'cn' => array('whois.cnnic.net.cn', 'No entries found'),
        //.vn
        'tw' => array('whois.twnic.net', 'NO MATCH TIP'),
        'in' => array('whois.inregistry.in', 'NOT FOUND'),
        'mn' => array('whois.nic.mn', 'Domain not found'),
        'cc' => array('whois.nic.cc', 'No match'),
        'ws' => array('whois.worldsite.ws', 'No match for'),
        'asia' => array('whois.nic.asia', 'NOT FOUND'),
        'ir' => array('whois.nic.ir', 'no entries found')
        //.bz
    );


    function whois ($domain_name) {
        $this->domain = $domain_name;
        $this->get_tld();
        $this->get_domain();
    }

    function info() {
        if ($this->is_valid()) {
            $whois_server = $this->servers[$this->tldname][0];

            // If tldname have been found
            if ($whois_server != '') {
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
                && !ereg("^-|-$", $tmp_domain) && !preg_match("/--/", $tmp_domain)
            ) {
                return true;
            }
        }
        return false;
    }
}
