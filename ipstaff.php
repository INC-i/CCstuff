<?php
//namespace ipstaff; 最後にディレクトリをわけ、ファイルもわける。

class CoreException extends Exception
{

    private $_errmsg = null;

    public function __construct($errmsg)
    {
        parent::__construct();
        $this->_errmsg = $errmsg;
    }

    public function __toString()
    {
        return $this->_errmsg;
    }
}

class IP
{

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
    
    public function ipv4ton($addr)
    {
        if (!$this->is_ipv4($addr)) {
            throw new CoreException(sprintf("%s is not IPv4 Address.", $addr));
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
            throw new CoreException(sprintf("%s is not IPv6 Address.", $addr));
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
        if (!is_int($n)) {
            throw new CoreException(sprintf("%s is not integer.", $n));
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
            throw new CoreException(sprintf("%s is not string type.", (string)$n));
        } elseif (!preg_match('/^\d+$/', $n)) {
            throw new CoreException(sprintf("%s is not integer.", (string)$n));
        }
        $ary = array();
        for ($i=1;$i<9;$i++) {
            //gmpで2除算
            $ary[$i-1] = sprintf('%04s', dechex(gmp_strval(gmp_and(gmp_div_q($n, gmp_pow(2, 128-16*$i)), 0xFFFF))));
        }
        return implode(':', $ary);
    }
    
    public function getiprangebycidr($cidr)
    {
        if (!preg_match('/^.*\/[0-9]+$/', $cidr)) {
            throw new CoreException(sprintf("%s is not cidr.", $cidr));
        }
        list($sip, $mask) = explode('/', $cidr);
        $ips = array();
        if ($this->is_ipv4($sip) && $mask >=0 && $mask <=32) {
            $max = pow(2, 32-$mask)-1;
            $ips[0] = $this->ntoipv4($this->ipv4ton($sip));
            $ips[1] = $this->ntoipv4($this->ipv4ton($sip) + $max);
        } elseif ($this->is_ipv6($sip) && $mask >=0 && $mask <=128) {
            $max = gmp_sub(gmp_pow(2, 128-$mask), 1);
            $ips[0] = $this->ntoipv6(gmp_strval(gmp_add(gmp_init($this->ipv6ton($sip)), 0)));
            $ips[1] = $this->ntoipv6(gmp_strval(gmp_add(gmp_init($this->ipv6ton($sip)), $max)));
        } else {
            throw new CoreException(sprintf("%s is not cidr.", $cidr));
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
                throw new CoreException(sprintf("Minimum IP(%s) is larger than Maximum IP(%s).", $sip, $eip));
            }
            $cidrlist = $this->tocidrv4($minIP, $maxIP - $minIP + 1);
        } elseif ($this->is_ipv6($sip) && $this->is_ipv6($eip)) {
            $minIP = $this->ipv6ton($sip);
            $maxIP = $this->ipv6ton($eip);
            if ($minIP > $maxIP) {
                throw new CoreException(sprintf("Minimum IP(%s) is larger than Maximum IP(%s).", $sip, $eip));
            }
            $cidrlist = $this->tocidrv6(
                $minIP, 
                gmp_strval(gmp_add(gmp_sub(gmp_init($maxIP), gmp_init($minIP)), 1))
            );
        } else {
            throw new CoreException(sprintf("%s or %s is not IPRange.", $sip, $eip));
        }
        return $cidrlist;
    }
    
    protected function tocidrv4($sip, $n, $cidrlist = array())
    {
        if ($n == 0) {
            return $cidrlist;
        }
        $pw = (int)log($n, 2);
        $cidrlist[count($cidrlist)] = sprintf('%s/%s', $this->ntoipv4($sip), 32-$pw);
        $sip += pow(2, $pw);
        return $this->tocidrv4($sip, $n-pow(2, $pw), $cidrlist);
    }
    
    protected function tocidrv6($sip, $n, $cidrlist = array())
    {
        if ($n == '0') {
            return $cidrlist;
        }
        $pw = $this->_gmp_log_retr_int($n, 2);
        $cidrlist[count($cidrlist)] = sprintf('%s/%s', $this->ntoipv6($sip), 128-$pw);
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
    private static $_DEFAULTDBNAME = "rirdb";
    private static $_SQLDIR = './sql';
    private $_v6list = null;
    private $_c = null;

    public function __construct($dbpath = null)
    {
        parent::__construct();
        self::$REGEX['cc'] = "/^[a-zA-Z]{2}$/"; 
        if (is_null($dbpath)) {
            $dbpath = self::$_DEFAULTDBNAME;
        }
        if (file_exists($dbpath)) {
            $this->_c = new SQLite3($dbpath);
        } else {
            throw new CoreException(sprintf('DB(%s) is not found.', $dbpath));
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
            throw new CoreException(sprintf("%s is not found.", $fpath));
        }
    }

    private function _getdata($name, $arg1 = null, $arg2 = null)
    {
        if (is_null(self::$_SELECTSQL)) {
            self::$_SELECTSQL = $this->_sqlreader(self::$_SQLDIR . '/select.sql');
        }
        if (is_null($this->_c)) {
            throw new CoreException("DB connection is not found.");
        } else if (!array_key_exists($name, self::$_SELECTSQL)) {
            throw new CoreException(sprintf("\'%s\' identifier is not defined in the file(%s/select.sql).", $name, self::$_SQLDIR));
        }
        $query = preg_replace('/\{1\}/', $arg2, preg_replace('/\{0\}/', $arg1, self::$_SELECTSQL[$name]));
        $result = $this->_c->query($query);

        $rows = array();
        while ($res = $result->fetchArray(SQLITE3_NUM)) {
            $rows[count($rows)] = $res;
        }

        if ($rows == array()) {
            $result = False;
        }else {
            $rcnt = count($rows);
            $ccnt = count($rows[0]);
            if ($rcnt == 1 && $ccnt == 1) {
                $result = $rows[0][0];
            } else {
                $result = $rows;
            }
        }
        return $result;
    }

    public function is_asn($num)
    {
       if (is_int($num) && $this->_getdata('asn_exist', $num) > 0) {
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
            throw new CoreException(sprintf("%s is not both IPv4,6 Address and ASN.", $arg));
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
            throw new CoreException(sprintf("%s is not string type.", (string)$n));
        } elseif (!preg_match('/^\d+$/', $val)) {
            throw new CoreException(sprintf("%s is not integer.", (string)$n));
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
            throw new CoreException(sprintf("%s is not ASN.", $asn));
        }
        return $this->_getdata('asn_to_cc', $asn);
    }

    public function cctoasns($cc)
    {
        if (!$this->is_cc($cc)) {
            throw new CoreException(sprintf("%s is not country code.", $cc));
        }
        return $this->_getdata('cc_to_asns', $cc);
    }

    public function cctoipv4s($cc)
    {
        $cidrlist = array();
        if (!$this->is_cc($cc)) {
            throw new CoreException(sprintf("%s is not country code.", $cc));
        }
        foreach ($this->_getdata('cc_to_ipv4s', $cc) as $e) {
            $cidrlist[count($cidrlist)] = $this->tocidrv4((int)$e[0], (int)($e[1] - $e[0] + 1));
        }
        return $cidrlist;
    }
    
    public function cctoipv6s($cc)
    {
        $cidrlist = array();
        if (!$this->is_cc($cc)) {
            throw new CoreException(sprintf("%s is not country code.", $cc));
        }
        foreach ($this->_getdata('cc_to_ipv6s', $cc) as $e) {
            $cidrlist[count($cidrlist)] = $this->tocidrv6($e[0], gmp_strval(gmp_add(gmp_sub($e[1], $e[0]), "1")));
        }
        return $cidrlist;
    }

    public function cctoname($cc)
    {
        if (!$this->is_cc($cc)) {
            throw new CoreException(sprintf("%s is not country code.", $cc));
        }
        return $this->_getdata('cc_to_name', $cc);
    }

    public function nametocc($name)
    {
        if (!preg_match('/[A-Za-z]*/', $name)) {
            throw new CoreException(sprintf("%s is not English name.", $name));
        }
        return $this->_getdata('name_to_cc', $name);
    }

}

?>
