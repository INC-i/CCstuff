<?php

class IP
{

    protected static $V4MAX = 4294967295;
    protected static $V6MAX = "340282366920938463463374607431768211455";
    protected static $REGEX = array();

    public function __construct()
    {
        
        $SEG4 = "(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])";
        $SEG6 = "[0-9a-fA-F]{1,4}";
        self::$REGEX['ipv4'] = "/^(($SEG4\.){3}$SEG4)$/";
        self::$REGEX['ipv6'] = "/^(" .
                              "($SEG6:){7}$SEG6|" .
                              "($SEG6:){1,7}:|" .
                              "($SEG6:){1,6}:$SEG6|" .
                              "($SEG6:){1,5}(:$SEG6){1,2}|" .
                              "($SEG6:){1,4}(:$SEG6){1,3}|" .
                              "($SEG6:){1,3}(:$SEG6){1,4}|" .
                              "($SEG6:){1,2}(:$SEG6){1,5}|" .
                              "$SEG6:((:$SEG6){1,6})|" .
                              ":((:$SEG6){1,7}|:)|" .
                              "fe80:(:$SEG6){0,4}%[0-9a-zA-Z]{1,}|" .
                              "::(ffff(:0{1,4}){0,1}:){0,1}$SEG4|" .
                              "($SEG6:){1,4}:$SEG4" .
                              ")$/";
                              
    }

    public function is_ipv4($addr)
    {
        if (preg_match(self::$REGEX['ipv4'], $addr)) {
            return True;
        } else {
            return False;
        }
    }

    public function is_ipv6($addr)
    {
        if (preg_match(self::$REGEX['ipv6'], $addr)) {
            return True;
        } else {
            return False;
        }
    }

    public function is_cidr($cidr)
    {
        if (strpos($cidr, "/") === false) {
            return False;
        }

        list($ip, $mask) = explode("/", $cidr);
        if ($this->is_ipv4($ip) && preg_match("/^\d+$/", $mask)) {
            $min = $this->ipv4ton($ip);
            if ($mask < 0 || $mask > 32) {
                return False;
            }
            $max = $min + pow(2, 32-$mask) -1;
            if ($max > self::$V4MAX) {
                return False;
            }
            return True;
        } else if ($this->is_ipv6($ip) && preg_match("/^\d+$/", $mask)) {
            $min = gmp_init($this->ipv6ton($ip));
            if ($mask < 0 || $mask > 128) {
                return False;
            }
            $max = gmp_sub(gmp_add($min, gmp_pow(2, 128-$mask)), 1);
            if (gmp_cmp($max, self::$V6MAX) > 0) {
                return False;
            }
            return True;
        }
    }
    
    public function ipv4ton($addr)
    {
        if (!$this->is_ipv4($addr)) {
            trigger_error(sprintf("%s is not IPv4 Address.", $addr), E_USER_NOTICE);
        }
        $nip = 0;
        foreach (explode(".", $addr) as $k => $e) {
            $nip |= $e << (32 - 8*($k+1));
        }
        return $nip;
    }
    
    public function ipv6ton($addr)
    {
        $addr = $this->fullformedipv6($addr);
        $n = gmp_init(0);
        foreach (explode(':', $addr) as $k => $e) {
            $n = gmp_init(
                gmp_strval(
                    gmp_or(
                        $n, gmp_mul(
                            gmp_init(hexdec($e)),gmp_pow(2, 128-16*($k+1))
                            )
                    )
                )
            );
        }
        return gmp_strval($n);
    }

    public function fullformedipv6($addr)
    {
        if (!$this->is_ipv6($addr)) {
            trigger_error(sprintf("%s is not IPv6 Address.", $addr), E_USER_NOTICE);
        }
        $parts = explode('::', $addr);
        if (count($parts) == 2) {
            $prefix = $suffix = '';
            list($fpart, $bpart) = array(explode(':', $parts[0]), explode(':', $parts[1]));
            list($ffcnt, $bfcnt) = array(count($fpart), count($bpart));
            if ($ffcnt == 1 && $fpart[0] == '') {
                $ffcnt = 0;
            }else{
                $prefix = ':';
            }
            if ($bfcnt == 1 && $bpart[0] == '') {
                $bfcnt = 0;
            }else {
                $suffix = ':';
            }
            $fcnt = $ffcnt + $bfcnt;
            $abbrv_part = implode(':', array_fill(0, 8-$fcnt, "0000"));
            $addr = $parts[0] . $prefix . $abbrv_part . $suffix . $parts[1];
        }
        return $addr;
    }

    public function ntoipv4($n)
    {
        if (!preg_match('/^\d+$/', $n)) {
            trigger_error(sprintf("%s is not integer.", $n), E_USER_NOTICE);
        }else if((int)$n < 0 || (int)$n > self::$V4MAX) {
            trigger_error(sprintf("%s is over ipv4 range.", $n), E_USER_NOTICE);
        }
        $ary = array();
        for ($i=1;$i<5;$i++) {
            $ary[$i-1] = $n >> (32 - 8*$i) & 0xFF;
        }
        return implode('.', $ary);
    }
    
    public function ntoipv6($n)
    {
        //引数はstr型、intやlongだと指数表示されてしまう場合があるため
        if (!is_string($n)) {
            trigger_error(sprintf("%s is not string type.", (string)$n), E_USER_NOTICE);
        }else if (!preg_match('/^\d+$/', $n)) {
            trigger_error(sprintf("%s is not integer.", (string)$n), E_USER_NOTICE);
        }else if (gmp_cmp($n, 0) < 0 || gmp_cmp($n, self::$V6MAX) > 0) {
            trigger_error(sprintf("%s is over ipv6 range.", $n), E_USER_NOTICE);
        }
        $ary = array();
        for ($i=1;$i<9;$i++) {
            //gmpで2除算
            $ary[$i-1] = sprintf('%04s', dechex(gmp_strval(gmp_and(gmp_div_q($n, gmp_pow(2, 128-16*$i)), 0xFFFF))));
        }
        return implode(':', $ary);
    }


    public function contain($cidr, $ip)
    {
        if (strpos($cidr, "/") === false) {
            trigger_error("$cidr is not IP/CIDR.", E_USER_NOTICE);
        }
        
        list($sip, $mask) = explode("/", $cidr);
        if ($this->is_ipv4($sip) && preg_match("/^\d+$/", $mask)) {
            if (!$this->is_ipv4($ip)) {
                trigger_error("$ip is not ipv4 address.", E_USER_NOTICE);
            }
            $min = $this->ipv4ton($sip);
            if (0 <= $mask && $mask <= 32) {
                $max = $min + pow(2, 32 - $mask) - 1;
            } else {
                trigger_error("/$mask is not cidr.", E_USER_NOTICE);
            }
            if ($max <= self::$V4MAX) {
                $tval = $this->ipv4ton($ip);
                if ($min <= $tval && $tval <= $max) {
                    return True;
                } else {
                    return False;
                }
            } else {
                trigger_error("$cidr is invalid ip range.", E_USER_NOTICE);
            }
        } else if ($this->is_ipv6($sip) && preg_match("/^\d+$/", $mask)) {
            if (!$this->is_ipv6($ip)) {
                trigger_error("$ip is not ipv6 address.", E_USER_NOTICE);
            }
            $min = $this->ipv6ton($sip);
            if (0 <= $mask && $mask <= 128) {
                $max = gmp_sub(gmp_add($min, gmp_pow(2, 128 - $mask)), 1);
            } else {
                trigger_error("/$mask is not cidr.", E_USER_NOTICE);
            }
            if (gmp_cmp($max, self::$V6MAX) <= 0 ) {
                $tval = $this->ipv6ton($ip);
                if (gmp_cmp($min, $tval) <= 0 && gmp_cmp($tval, $max) <= 0) {
                    return True;
                } else {
                    return False;
                }
            } else {
                trigger_error("$cidr is invalid ip range.", E_USER_NOTICE);
            }
        } else {
            trigger_error("$sip/$mask is not IP/CIDR.", E_USER_NOTICE);
        }
    }

    public function getiprangebycidr($cidr)
    {
        if (!$this->is_cidr($cidr)) {
            trigger_error(sprintf("%s is not cidr.", $cidr), E_USER_NOTICE);
        }
        list($sip, $mask) = explode('/', $cidr);
        $ips = array();
        if ($this->is_ipv4($sip)) {
            $min = $this->ipv4ton($sip);
            $ips[0] = $this->ntoipv4($min);
            $ips[1] = $this->ntoipv4($min + pow(2, 32-$mask)-1);
        } elseif ($this->is_ipv6($sip)) {
            $min = $this->ipv6ton($sip);
            $ips[0] = $this->ntoipv6($min);
            $ips[1] = $this->ntoipv6(gmp_strval(gmp_sub(gmp_add($min, gmp_pow(2, 128-$mask)), 1)));
        }
        return $ips;
    }

    public function getcidrsbyiprange($sip, $eip)
    {
        $cidrlist = null;
        if ($this->is_ipv4($sip) && $this->is_ipv4($eip)) {
            $minIP = $this->ipv4ton($sip);
            $maxIP = $this->ipv4ton($eip);
            if ($minIP > $maxIP) {
                trigger_error(sprintf("Minimum IP(%s) is larger than Maximum IP(%s).", $sip, $eip), E_USER_NOTICE);
            }
            $cidrlist = $this->tocidrv4($minIP, $maxIP - $minIP + 1);
        } elseif ($this->is_ipv6($sip) && $this->is_ipv6($eip)) {
            $minIP = $this->ipv6ton($sip);
            $maxIP = $this->ipv6ton($eip);
            if ($minIP > $maxIP) {
                trigger_error(sprintf("Minimum IP(%s) is larger than Maximum IP(%s).", $sip, $eip), E_USER_NOTICE);
            }
            $cidrlist = $this->tocidrv6(
                $minIP, 
                gmp_strval(gmp_add(gmp_sub(gmp_init($maxIP), gmp_init($minIP)), 1))
            );
        } else {
            trigger_error(sprintf("%s or %s is not IPRange.", $sip, $eip), E_USER_NOTICE);
        }
        return $cidrlist;
    }
    
    protected function tocidrv4($sip, $n, $cidrlist = array())
    {
        if ($n == 0) {
            return $cidrlist;
        }
        $pw = (int)log($n, 2);
        array_push($cidrlist, sprintf('%s/%s', $this->ntoipv4($sip), 32-$pw));
        $sip += pow(2, $pw);
        return $this->tocidrv4($sip, $n-pow(2, $pw), $cidrlist);
    }
    
    protected function tocidrv6($sip, $n, $cidrlist = array())
    {
        if ($n == '0') {
            return $cidrlist;
        }
        $pw = $this->_gmp_log_retr_int($n, 2);
        array_push($cidrlist, sprintf('%s/%s', $this->ntoipv6($sip), 128-$pw));
        $cnt = gmp_pow(2, $pw);
        $sip = gmp_strval(gmp_add($sip, $cnt));
        return $this->tocidrv6($sip, gmp_strval(gmp_sub($n, $cnt)), $cidrlist);
    }

    private function _gmp_log_retr_int($n, $b, $pw = 0)
    {
        $n = gmp_strval(gmp_div_q(gmp_init($n), gmp_init($b)));
        if ($n == '0') {
            return $pw;
        }
        ++$pw;
        return $this->_gmp_log_retr_int($n, $b, $pw);
    }
}

class RIR extends IP
{
    private static $_SELECTSQL = null;
    private static $_DEFAULTDBNAME = "/rirdb";
    private static $_SQLDIR = '/sql';
    private $_v6list = null;
    private $_c = null;

    public function __construct($dbpath = null)
    {
        parent::__construct();
        self::$REGEX['cc'] = "/^[a-zA-Z]{2}$/"; 
        if (is_null($dbpath)) {
            $dbpath = dirname(__FILE__) . self::$_DEFAULTDBNAME;
        }
        if (file_exists($dbpath)) {
            $this->_c = new SQLite3($dbpath);
        } else {
            trigger_error(sprintf('DB(%s) is not found.', $dbpath), E_USER_ERROR);
        }
    }

    private function _sqlreader($fpath)
    {
        $key = $buf = null;
        $sqllist = array();
        if ($fh = fopen($fpath, 'r')) {
            while (!feof($fh)) {
                $line = rtrim(fgets($fh));
                if (!preg_match("/^\s*$|^#|^;/", $line)) {
                    //空白、コメント行は無視
                    if (preg_match("/^\s*'(\S*)'\s*:(\S*)$/", $line, $m)) {
                        if (!is_null($key)) {
                            $sqllist[$key] = preg_replace("/^\s*/", '', preg_replace("/\s{2,}/", ' ', $buf));
                        }
                        list($key, $buf) = array($m[1], $m[2]);
                    } else {
                        $buf .= $line . ' ';
                    }
                }
            }
            fclose($fh);
            $sqllist[$key] = preg_replace("/^\s*/", '', preg_replace("/\s{2,}/", ' ', $buf));
            return $sqllist;
        } else {
            trigger_error(sprintf("%s is not found.", $fpath), E_USER_ERROR);
        }
    }

    private function _getdata($name, $arg1 = null, $arg2 = null)
    {
        if (is_null(self::$_SELECTSQL)) {
            self::$_SELECTSQL = $this->_sqlreader(dirname(__FILE__) . self::$_SQLDIR . '/select.sql');
        }
        if (is_null($this->_c)) {
            trigger_error("DB connection is not found.", E_USER_ERROR);
        } else if (!array_key_exists($name, self::$_SELECTSQL)) {
            trigger_error(sprintf("\'%s\' identifier is not defined in the file(%s/select.sql).", 
                          $name, dirname(__FILE__) . self::$_SQLDIR), E_USER_ERROR);
        }
        $query = preg_replace('/\{1\}/', $arg2, preg_replace('/\{0\}/', $arg1, self::$_SELECTSQL[$name]));
        $result = $this->_c->query($query);

        $rows = array();
        while ($res = $result->fetchArray(SQLITE3_NUM)) {
            array_push($rows, $res);
        }

        if ($rows == array()) {
            $result = False;
        }else {
            $rows_cnt = count($rows, 0);
            $cols_cnt = count($rows, 1)/count($rows, 0) - 1;
            if ($rows_cnt === 1 && $cols_cnt === 1) {
            //[[0]]
                $result = $rows[0][0];
            }else if ($rows_cnt === 1 && $cols_cnt > 1) {
            //[[0,1,2・・・]]
                $result = $rows[0];
            }else{
                $result = $rows;
            }
        }
        return $result;
    }

    public function is_asn($num)
    {
       if (preg_match('/^\d+$/', $num) && $this->_getdata('asn_exist', $num) > 0) {
            return True;
       } else {
            return False;
       }
    }

    public function is_cc($cc)
    {
        if (preg_match(self::$REGEX['cc'], $cc) && $this->_getdata('cc_exist', $cc) > 0) {
            return True;
        } else {
            return False;
        }
    }

    public function getririnfo($arg)
    {
         if ($this->is_ipv4($arg)) {
            return $this->_getdata('ipv4_to_all', $this->ipv4ton($arg));
         } else if ($this->is_ipv6($arg)) {
            $res = $this->_binsearch($this->ipv6ton($arg));
            return $this->_getdata('ipv6_to_all', $res[0], $res[1]);
         } else if ($this->is_asn($arg)) {
            return $this->_getdata('asn_to_all', $arg);
         } else {
            trigger_error(sprintf("%s is not both IPv4,6 Address and ASN.", $arg), E_USER_NOTICE);
         }
    }

    public function ipv4tocc($addr)
    {
        return $this->_getdata('ipv4_to_cc', $this->ipv4ton($addr));
    }

    public function ipv6tocc($addr)
    {
        $res = $this->_binsearch($this->ipv6ton($addr));
        return $res[2];
    }

    private function _binsearch($val)
    {
        $res = False;
        if (!is_string($val)) {
            trigger_error(sprintf("%s is not string type.", (string)$n), E_USER_NOTICE);
        } elseif (!preg_match('/^\d+$/', $val)) {
            trigger_error(sprintf("%s is not integer.", (string)$n), E_USER_NOTICE);
        }
        $val = gmp_init($val);
        if ($this->_v6list == null) {
            $this->_v6list = $this->_getdata('get_ipv6ranges');
        }
        list($min, $max) = array(0, count($this->_v6list) - 1);
        while ($min <= $max) {
            $i = floor(($min + $max) / 2);
            $first = gmp_init($this->_v6list[$i][0]);
            $last = gmp_init($this->_v6list[$i][1]);
            if (gmp_cmp($val, $first) >= 0 && gmp_cmp($val, $last) <= 0) {
                $res = $this->_v6list[$i];
                break;
            } else if (gmp_cmp($val, $first) < 0) {
                $max = $i - 1;
            } else if (gmp_cmp($val, $last) > 0) {
                $min = $i + 1;
            }
        }
        return $res;
    }

    public function asntocc($asn)
    {
        if (!$this->is_asn($asn)) {
            trigger_error(sprintf("%s is not ASN.", $asn), E_USER_NOTICE);
        }
        return $this->_getdata('asn_to_cc', $asn);
    }

    public function cctoasns($cc)
    {
        if (!$this->is_cc($cc)) {
            trigger_error(sprintf("%s is not country code.", $cc), E_USER_NOTICE);
        }
        $asnlist = array();
        foreach($this->_getdata('cc_to_asns', $cc) as $e){
            if ($e[0] === $e[1]) {
                array_push($asnlist, $e[0]);
            }else{
                for ($i=$e[0];$i<=$e[1];$i++) {
                    array_push($asnlist, $i);
                }
            }
        }
        return $asnlist;
    }

    public function cctoipv4s($cc)
    {
        $cidrlist = array();
        if (!$this->is_cc($cc)) {
            trigger_error(sprintf("%s is not country code.", $cc), E_USER_NOTICE);
        }
        foreach ($this->_getdata('cc_to_ipv4s', $cc) as $e) {
            $cidrs = $this->tocidrv4((int)$e[0], (int)($e[1] - $e[0] + 1));
            foreach ($cidrs as $cidr) {
                array_push($cidrlist, $cidr);
            }
        }
        return $cidrlist;
    }
    
    public function cctoipv6s($cc)
    {
        $cidrlist = array();
        if (!$this->is_cc($cc)) {
            trigger_error(sprintf("%s is not country code.", $cc), E_USER_NOTICE);
        }
        foreach ($this->_getdata('cc_to_ipv6s', $cc) as $e) {
            $cidrs = $this->tocidrv6($e[0], gmp_strval(gmp_add(gmp_sub($e[1], $e[0]), "1")));
            foreach($cidrs as $cidr) {
                array_push($cidrlist, $cidr);
            }
        }
        return $cidrlist;
    }

    public function cctoname($cc)
    {
        if (!$this->is_cc($cc)) {
            trigger_error(sprintf("%s is not country code.", $cc), E_USER_NOTICE);
        }
        return $this->_getdata('cc_to_name', $cc);
    }

    public function nametocc($name)
    {
        if (!preg_match('/[A-Za-z]*/', $name)) {
            trigger_error(sprintf("%s is not English name.", $name), E_USER_NOTICE);
        }
        return $this->_getdata('name_to_cc', $name);
    }

}

?>
