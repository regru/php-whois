<?php

namespace Phois\Whois;

class Whois
{
    private $domain;

    private $TLDs;

    private $subDomain;

    private $servers;

    /**
     * @param string $domain full domain name (without trailing dot)
     */
    public function __construct($domain)
    {
        $this->domain = $domain;
        // check $domain syntax and split full domain name on subdomain and TLDs
        if (
            preg_match('/^([\p{L}\d\-]+)\.((?:[\p{L}\d\-]+\.?)+)$/ui', $this->domain, $matches)
            || preg_match('/^(xn\-\-[\p{L}\d\-]+)\.(xn\-\-(?:[a-z\d-]+\.?1?)+)$/ui', $this->domain, $matches)
        ) {
            $this->subDomain = $matches[1];
            $this->TLDs = $matches[2];
        } else
            throw new \InvalidArgumentException("Invalid $domain syntax");
        // setup whois servers array from json file
        $this->servers = json_decode(file_get_contents( __DIR__.'/whois.servers.json' ), true);
    }

    public function info()
    {
        if ($this->isValid()) {
            $whois_server = $this->servers[$this->TLDs][0];

            // If TLDs have been found
            if ($whois_server != '') {

                // if whois server serve replay over HTTP protocol instead of WHOIS protocol
                if (preg_match("/^https?:\/\//i", $whois_server)) {

                    // curl session to get whois reposnse
                    $ch = curl_init();
                    $url = $whois_server . $this->subDomain . '.' . $this->TLDs;
                    curl_setopt($ch, CURLOPT_URL, $url);
                    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
                    curl_setopt($ch, CURLOPT_TIMEOUT, 60);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
                    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);

                    $data = curl_exec($ch);

                    if (curl_error($ch)) {
                        return "Connection error!";
                    } else {
                        $string = strip_tags($data);
                    }
                    curl_close($ch);

                } else {

                    // Getting whois information
                    $fp = fsockopen($whois_server, 43);
                    if (!$fp) {
                        return "Connection error!";
                    }

                    $dom = $this->subDomain . '.' . $this->TLDs;
                    fputs($fp, "$dom\r\n");

                    // Getting string
                    $string = '';

                    // Checking whois server for .com and .net
                    if ($this->TLDs == 'com' || $this->TLDs == 'net') {
                        while (!feof($fp)) {
                            $line = trim(fgets($fp, 128));

                            $string .= $line;

                            $lineArr = explode (":", $line);

                            if (strtolower($lineArr[0]) == 'whois server') {
                                $whois_server = trim($lineArr[1]);
                            }
                        }
                        // Getting whois information
                        $fp = fsockopen($whois_server, 43);
                        if (!$fp) {
                            return "Connection error!";
                        }

                        $dom = $this->subDomain . '.' . $this->TLDs;
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

                $string_encoding = mb_detect_encoding($string, "UTF-8, ISO-8859-1, ISO-8859-15", true);
                $string_utf8 = mb_convert_encoding($string, "UTF-8", $string_encoding);

                return htmlspecialchars($string_utf8, ENT_COMPAT, "UTF-8", true);
            } else {
                return "No whois server for this tld in list!";
            }
        } else {
            return "Domain name isn't valid!";
        }
    }

    public function htmlInfo()
    {
        return nl2br($this->info());
    }

    /**
     * @return string full domain name
     */
    public function getDomain()
    {
        return $this->domain;
    }

    /**
     * @return string top level domains separated by dot
     */
    public function getTLDs()
    {
        return $this->TLDs;
    }

    /**
     * @return string return subdomain (low level domain)
     */
    public function getSubDomain()
    {
        return $this->subDomain;
    }

    public function isAvailable()
    {
        $whois_string = $this->info();
        $not_found_string = '';
        if (isset($this->servers[$this->TLDs][1])) {
           $not_found_string = $this->servers[$this->TLDs][1];
        }

        $whois_string2 = @preg_replace('/' . $this->domain . '/', '', $whois_string);
        $whois_string = @preg_replace("/\s+/", ' ', $whois_string);

        $array = explode (":", $not_found_string);
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

    public function isValid()
    {
        if (
            isset($this->servers[$this->TLDs][0])
            && strlen($this->servers[$this->TLDs][0]) > 6
        ) {
            $tmp_domain = strtolower($this->subDomain);
            if (
                preg_match("/^[a-z0-9\-]{3,}$/", $tmp_domain)
                && !preg_match("/^-|-$/", $tmp_domain) //&& !preg_match("/--/", $tmp_domain)
            ) {
                return true;
            }
        }

        return false;
    }
}
