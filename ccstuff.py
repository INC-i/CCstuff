#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
import math
import sqlite3
import os

class ip():

    v4max = 4294967295
    v6max = 340282366920938463463374607431768211455
    re_int = re.compile('^\d+$')
    regex = {}
    
    def __init__(self):
        ipv4seg = '(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
        ipv6seg = '[0-9a-fA-F]{1,4}'
        ip.regex['ipv4'] = re.compile(r'^((SEG4\.){3}SEG4)$'.replace('SEG4', ipv4seg))
        ip.regex['ipv6'] = re.compile(r'^(' \
                                       '(SEG6:){7}SEG6|' \
                                       '(SEG6:){1,7}:|' \
                                       '(SEG6:){1,6}:SEG6|' \
                                       '(SEG6:){1,5}(:SEG6){1,2}|' \
                                       '(SEG6:){1,4}(:SEG6){1,3}|' \
                                       '(SEG6:){1,3}(:SEG6){1,4}|' \
                                       '(SEG6:){1,2}(:SEG6){1,5}|' \
                                       'SEG6:((:SEG6){1,6})|' \
                                       ':((:SEG6){1,7}|:)|' \
                                       'fe80:(:SEG6){0,4}%[0-9a-zA-Z]{1,}|' \
                                       '::(ffff(:0{1,4}){0,1}:){0,1}SEG4|' \
                                       '(SEG6:){1,4}:SEG4' \
                                       ')$'.replace('SEG6', ipv6seg).replace('SEG4', ipv4seg))

    def is_int(self, num):
        if self.re_int.match(num):
            return True
        else:
            return False

    def is_ipv4(self, addr):
        if type(addr) is str and ip.regex['ipv4'].match(addr):
            return True
        else:
            return False

    def is_ipv6(self, addr):
        if type(addr) is str and ip.regex['ipv6'].match(addr):
            return True
        else:
            return False

    def is_cidr(self, cidr):
        if not "/" in cidr:
            return False

        ip, mask = cidr.split("/")
        if not self.is_int(mask):
           raise False

        mask = int(mask)
        if self.is_ipv4(ip) and mask >= 0 and mask <= 32:
            min = self.ipv4ton(ip)
            max = min + 2 ** (32 - mask) - 1
            if max > self.v4max:
                return False
        elif self.is_ipv6(ip) and mask >= 0 and mask <= 128:
            min = self.ipv6ton(ip)
            max = min + 2 ** (128 - mask) - 1
            if max > self.v6max:
                return False
        else:
            return False

        return True
            

    def contain(self, cidr, ip):
        if not "/" in cidr:
            raise ValueError("%s is not cidr." % cidr)

        sip, mask = cidr.split("/")
        
        if not self.is_int(mask):
           raise ValueError("%s is not cidr." % cidr)

        mask = int(mask)
        min, max, tval = 0, 0, 0

        if self.is_ipv4(sip) and mask >= 0 and mask <= 32:
            if not self.is_ipv4(ip):
                raise ValueError("%s is not ipv4 address." % ip)
            min = self.ipv4ton(sip)
            max = min + 2 ** (32 - mask) - 1
            if max > self.v4max:
                raise ValueError("%s is not cidr." % cidr)
            tval = self.ipv4ton(ip)
        elif self.is_ipv6(sip) and mask >= 0 and mask <= 128:
            if not self.is_ipv6(ip):
                raise ValueError("%s is not ipv6 address." % ip)
            min = self.ipv6ton(sip)
            max = min + 2 ** (128 - mask) - 1
            if max > self.v6max:
                raise ValueError("%s is not cidr." % cidr)
            tval = self.ipv6ton(ip)
        else:
            raise ValueError("%s is not cidr." % cidr)

        if (tval < min or tval > max):
            return False

        return True
        


    def ipv4ton(self, addr):
        if not self.is_ipv4(addr): 
            raise ValueError('{0} is not IPv4 Address.'.format(addr))
        numip = 0
        ipparts = addr.split('.')
        for i in range(1, 5):
            numip |= int(ipparts[i-1]) << (32 - 8*i)
        return numip
       
    def ipv6ton(self, addr):
        addr = self.fullformedipv6(addr)
        numip = 0
        ipparts = addr.split(':')
        for i in range(1,9):
            numip |= int(ipparts[i-1], 16) << (128 - 16*i)
        return numip
    
    def fullformedipv6(self, addr):
        if not type(addr) is str:
            raise ValueError('{0} is not str type.'.format(addr))
        if not self.is_ipv6(addr):
            raise ValueError('{0} is not IPv6 Address.'.format(addr))
        parts = addr.split('::')
        if len(parts) == 2:
            prefix, suffix = '', ''
            f_part, b_part = parts[0].split(':'), parts[1].split(':')
            ffcnt, bfcnt = len(f_part), len(b_part)
            # ::で分割した部分のそれぞれが、空のときは、部分の個数を0にする
            if ffcnt == 1 and f_part[0] == '':
                ffcnt = 0
            else:
                prefix = ':'
            if bfcnt == 1 and b_part[0] == '':
                bfcnt = 0
            else:
                suffix = ':'
            fcnt = ffcnt + bfcnt
            abbrv_part = ':'.join(['0000' for i in range(8-fcnt)])
            addr = parts[0] + prefix + abbrv_part + suffix + parts[1]
        return addr

    def ntoipv4(self, num):
        if not type(num) is int:
            raise ValueError('%s is not int type.' % num)
        return '.'.join([str(num >> (32 - 8*i) & 0xFF) for i in range(1,5)])

    def ntoipv6(self, num):
        if not type(num) in (int, long):
            raise ValueError('%s is not int type.' % num)
        return ':'.join(['{0:0>4}'.format(format(num >> (128 - 16*i) & 0xFFFF, 'x')) for i in range(1,9)])
   
    def getiprangebycidr(self, cidr, re_cidr=re.compile('.*/\d+$')):
        if not type(cidr) is str:
            raise ValueError('{0} is not str type.'.format(cidr))
        if not re_cidr.match(cidr):
            raise ValueError('{0} is not Cidr.'.format(cidr))
        cidr_splited = cidr.split('/')
        sip, mask= cidr_splited[0], int(cidr_splited[1])
        ips = None
        if self.is_ipv4(sip) and mask >= 0 and mask <= 32:
            ips = [self.ntoipv4(self.ipv4ton(sip)), self.ntoipv4(self.ipv4ton(sip) + 2 ** (32 - mask) - 1)]
        elif self.is_ipv6(sip) and mask >= 0 and mask <= 128:
            ips = [self.ntoipv6(self.ipv6ton(sip)), self.ntoipv6(self.ipv6ton(sip) + 2 ** (128 - mask) - 1)]
        else:
            raise ValueError('{0} is not Cidr.'.format(cidr))
        return ips

    def getcidrsbyiprange(self, sip, eip):
        cidrlist = None
        if self.is_ipv4(sip) and self.is_ipv4(eip):
            minIP = self.ipv4ton(sip)
            maxIP = self.ipv4ton(eip)
            if minIP > maxIP:
                raise ValueError('Minimum IP({0}) is larger than Maximum IP({1}).'.format(sip, eip))
            cidrlist = self._tocidrv4(minIP, maxIP - minIP +1)
        elif self.is_ipv6(sip) and self.is_ipv6(eip):
            minIP = self.ipv6ton(sip)
            maxIP = self.ipv6ton(eip)
            if minIP > maxIP:
                raise ValueError('Minimum IP({0}) is larger than Maximum IP({1}).'.format(sip, eip))
            cidrlist = self._tocidrv6(minIP, maxIP - minIP +1)
        else: 
            raise ValueError('{0} or {1} is not IPRange.'.format(sip, eip))
        return cidrlist

    def _tocidrv4(self, sip, num, cidrlist=None):
        if num == 0:return cidrlist
        if cidrlist is None:
            cidrlist = []
        pw = int(math.log(num, 2))
        cidrlist.append('{ip}/{cidr}'.format(ip=self.ntoipv4(sip), cidr=32-pw))
        sip += 2**pw
        return self._tocidrv4(sip, num - 2**pw, cidrlist=cidrlist)

    def _tocidrv6(self, sip, num, cidrlist=None):
        if num == 0: return cidrlist
        if cidrlist is None:
            cidrlist = []
        pw = int(math.log(num, 2))
        cidrlist.append('{ip}/{cidr}'.format(ip=self.ntoipv6(sip), cidr=128-pw))
        sip += 2**pw
        return self._tocidrv6(sip, num - 2**pw, cidrlist=cidrlist)

class rir(ip):
    
    __select_sql = {}
    __default_dbname = 'rirdb'
    __rirlist = 'rirlist'
    __sqldir = './sql'

    def __init__(self, dbpath=None):
        self.__v6li = None
        self.__c = None
        ip.__init__(self)
        rir.regex['cc'] = re.compile('^[a-z]{2}$', re.I)
        if dbpath is None:
            dbpath = rir.__default_dbname
        if os.path.exists(dbpath):
            self.__c = sqlite3.connect(dbpath).cursor()

    def setdb(self, dbpath):
        if os.path.exists(dbpath):
            self.__c = sqlite3.connect(dbpath).cursor()
        else:
            raise IOError('{0} is not found.'.format(dbpath))
        return

    def __merge(self, list):
        s, res = 0, []
        for i in range(1, len(list)):
            if list[i-1][1] + 1 != list[i][0] or list[i-1][2] != list[i][2]:
                res.append([ list[s][0], list[i-1][1], list[s][2] ])
                s=i
        res.append([ list[s][0], list[i][1], list[s][2] ])
        return res 
       
    def __sqlreader(self, fpath, re_igchar=re.compile('^\s*$|^#|^;'), re_vname=re.compile('^\'(.*)\'\s*:(.*)$')):
        key, buf = None, None
        sqldict = {}
        if not os.path.exists(fpath):
            raise IOError('{0} is not found.'.format(fpath))
        with open(fpath) as fh:
            for line in fh:
                ln = re.sub(r'\n|\r\n', ' ', line)
                if not re_igchar.match(ln):
                    if re_vname.match(ln):
                        if not key is None:
                            sqldict[key] = re.sub(r'^\s*', '', re.sub(r'\s{2,}', ' ', buf))
                        m = re_vname.search(ln)
                        key, buf = m.group(1), m.group(2)
                    else:
                        buf += ln
        sqldict[key] = re.sub(r'^\s*', '', re.sub(r'\s{2,}', ' ', buf))
        return sqldict

    def create_db(self, dbpath=None):
        import urllib
        urllist = {}
        if dbpath is None:
            dbpath = self.__default_dbname
        elif not type(dbpath) is str:
            raise ValueError('%s is not str type.' % dbpath)
        dbpath_tmp = dbpath + '.new'

        with open(self.__rirlist) as fh:
            for line in fh:
                ary = line.replace("'", '').rstrip().split(',')
                urllist[ary[0]] = ary[1]

        create_sql = self.__sqlreader(self.__sqldir + '/create.sql')
        insert_sql = 'INSERT INTO {0} VALUES ({1})'
        
        if os.path.exists(dbpath_tmp):
            os.remove(dbpath_tmp)
        conn = sqlite3.connect(dbpath_tmp)
        c = conn.cursor()
        for sql in create_sql.values():
            c.execute(sql)
            conn.commit()
        
        v4id, v6id, asnid = 0, 0, 0
        print 'Start...\n'
        for rir, url in urllist.iteritems():
            print 'Loading {0} data...'.format(rir)
            drows = [r.rstrip().split('|') for r in urllib.urlopen(url).read().split('\n')]
            print 'Done, making table...'.format(rir)
            for drow in drows:
                id = None
                if len(drow) in (7, 8):
                    type = drow[2]
                    if type in ('asn', 'ipv4', 'ipv6') and len(drow) in (7, 8):
                        if type == 'ipv4':
                            v4id += 1
                            id = v4id
                            drow[3] = self.ipv4ton(drow[3])
                            # https://www.arin.net/knowledge/statistics/nro_extended_stats_format.pdf
                            drow[4] = drow[3] + int(drow[4]) - 1
                        elif type == 'ipv6':
                            v6id += 1
                            id = v6id
                            drow[3] = self.ipv6ton(drow[3])
                            drow[4] = drow[3] + 2**(128-int(drow[4])) - 1
                        else:
                            asnid += 1
                            id = asnid
                        drow.insert(0, id)
                        row_str = "'{0}'".format("','".join([str(clm) for clm in drow[:8]]))
                        c.execute(insert_sql.format('all_{0}'.format(type), row_str))
            conn.commit()
            del drows
            print 'Done.\n'
        # exclude available, reserved
        select_sql = "SELECT ADDR_MINIMUM, ADDR_MAXIMUM, COUNTRY FROM {0} WHERE STATUS IN ('allocated', 'assigned')"
        
        c.execute(select_sql.format('all_ipv4'))
        drows = self.__merge(sorted(c.fetchall(), key=lambda x: x[0]))
        for drow in drows:
            row_str = "'{0}'".format("','".join([str(clm) for clm in drow]))
            c.execute(insert_sql.format('all_ipv4_mini', row_str))
        conn.commit()

        c.execute(select_sql.format('all_ipv6'))
        drows = self.__merge(sorted([[int(r[0]), int(r[1]), r[2]] for r in c.fetchall()], key=lambda x: x[0]))
        for drow in drows:
            row_str = "'{0}'".format("','".join([str(clm) for clm in drow]))
            c.execute(insert_sql.format('all_ipv6_mini', row_str))
        conn.commit()
        
        with open('iso3166-1') as fh:
            id = 0
            for line in fh:
                id += 1
                c.execute(insert_sql.format('iso3166_1', '\'{0}\','.format(id) + line.rstrip()))
        conn.commit()
        c.close()

        if os.path.exists(dbpath):
            os.remove(dbpath)
        os.rename(dbpath_tmp, dbpath)
        
        print 'Finish.'
        return dbpath

    def __getdata(self, name, arg1=None, arg2=None):
        if rir.__select_sql == {}:
            rir.__select_sql =  self.__sqlreader(self.__sqldir + '/select.sql')
        
        if self.__c is None:
            raise IOError('DB connection is not found.')
        elif not name in rir.__select_sql.keys():
            raise IOError('\'{0}\' identifier is not defined in the file({1}/select.sql).'.format(name, self.__sqldir))
        
        self.__c.execute(rir.__select_sql[name].format(arg1, arg2))
        result = self.__c.fetchall()
        if result == []:
            result = None
        else:
            rnum = len(result)
            # column数は一定
            cnum = len(result[0])
            if cnum == 1 and rnum > 1:
                result = [e[0] for e in result]
            elif cnum == 1 and rnum == 1:
                result = result[0][0]
                if type(result) is type(str()):
                    result = result.encode('utf-8')
            elif cnum == 3:
                result = sorted([[int(r[0]), int(r[1]), r[2]] for r in result], key=lambda x: x[1])
            elif cnum == 2:
                if name == 'cc_to_name':
                    result = list(result[0])
                else:
                    result = sorted([[int(e[0]), int(e[1])] for e in result], key=lambda x: x[1])
        return result
        
    def is_asn(self, num):
        if type(num) in (int, long) and self.__getdata('asn_exist', num) > 0:
            return True
        else:
            return False
    
    def is_cc(self, cc):
        cc = str(cc)
        if type(cc) is str and rir.regex['cc'].match(cc) and self.__getdata('cc_exist', cc) > 0:
            return True
        else:
            return False

    def getririnfo(self, arg):
        if self.is_ipv4(arg):
            return self.__getdata('ipv4_to_all', self.ipv4ton(arg))
        elif self.is_ipv6(arg):
            res = self.__binsearch(self.ipv6ton(arg))
            if res is None:
                return None
            return self.__getdata('ipv6_to_all', res[0], res[1])
        elif self.is_asn(arg):
            return self.__getdata('asn_to_all', arg)
        else:
            raise ValueError('{0} is not both IPv4,6 Address and ASN.'.format(arg))
    
    def ipv4tocc(self, addr):
        return self.__getdata('ipv4_to_cc', self.ipv4ton(addr))

    def ipv6tocc(self, addr):
        res = self.__binsearch(self.ipv6ton(addr))
        if res is None:
            return None
        else:
            return self.__binsearch(self.ipv6ton(addr))[2]

    def __binsearch(self, val):
        res = None
        if not type(val) in (long, int):
            raise ValueError('{0} is not integer.'.format(val))
        if self.__v6li is None:
            self.__v6li = self.__getdata('get_ipv6ranges')
        min = 0
        max = len(self.__v6li) - 1        
        while(min <= max):
            i = (min + max) / 2
            if val >= self.__v6li[i][0] and val <= self.__v6li[i][1]:
                res = self.__v6li[i]
                break
            elif val < self.__v6li[i][0]:
                max = i - 1
            elif val > self.__v6li[i][1]:
                min = i + 1
        return res

    def asntocc(self, asn):
        if not self.is_asn(asn):
            raise ValueError('{0} is not ASN.'.format(asn))
        return self.__getdata('asn_to_cc', asn)

    def cctoasns(self, cc):
        if not self.is_cc(cc):
            raise ValueError('{0} is not country code.'.format(cc))
        return self.__getdata('cc_to_asns', cc)
    
    def cctoipv4s(self, cc):
        if not self.is_cc(cc):
            raise ValueError('{0} is not country code.'.format(cc))
        cidrlist = []
        for e in self.__getdata('cc_to_ipv4s', cc):
            for cidr in self._tocidrv4(e[0], e[1] - e[0] + 1):
                cidrlist.append(cidr)
        return cidrlist

    def cctoipv6s(self, cc):
        if not self.is_cc(cc):
            raise ValueError('{0} is not country code.'.format(cc)) 
        cidrlist = []
        for e in self.__getdata('cc_to_ipv6s', cc):
            for cidr in self._tocidrv6(e[0], e[1] - e[0] + 1):
                cidrlist.append(cidr)
        return cidrlist

    def cctoname(self, cc):
        if not self.is_cc(cc):
            raise ValueError('{0} is not country code.'.format(cc))
        return self.__getdata('cc_to_name', cc)

    def nametocc(self, name):
        if not type(name) is str:
            raise ValueError('%s is not str type' % name)
        return self.__getdata('name_to_cc', name)
