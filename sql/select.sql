'ipv4_to_cc':

SELECT COUNTRY 
FROM all_ipv4_mini 
WHERE ADDR_MINIMUM <= '{0}' 
AND   ADDR_MAXIMUM >= '{0}'

'cc_to_ipv4s':

SELECT ADDR_MINIMUM, ADDR_MAXIMUM 
FROM all_ipv4_mini
WHERE COUNTRY = '{0}'

'cc_to_ipv6s':
SELECT ADDR_MINIMUM, ADDR_MAXIMUM 
FROM all_ipv6_mini
WHERE COUNTRY = '{0}'

'get_ipv6ranges':

SELECT ADDR_MINIMUM, ADDR_MAXIMUM, COUNTRY 
FROM all_ipv6_mini

'asn_to_cc':

SELECT COUNTRY 
FROM all_asn
WHERE ASN = '{0}'

'asn_exist':

SELECT COUNT(ASN)
FROM all_asn
Where ASN = '{0}'

'cc_exist':

SELECT COUNT(CC2)
FROM iso3166_1
WHERE CC2 = '{0}'

'cc_to_asns':

SELECT ASN
FROM all_asn
WHERE COUNTRY = '{0}'

'cc_to_name':

SELECT NAME_EN, NAME_JP 
FROM iso3166_1 
WHERE CC2 = '{0}'

'name_to_cc':

SELECT CC2
FROM iso3166_1
WHERE NAME_EN = '{0}'

'ipv4_to_all':

SELECT COUNTRY, RIR, STATUS, DATE 
FROM all_ipv4
WHERE ADDR_MINIMUM <= '{0}' 
AND   ADDR_MAXIMUM >= '{0}'

'ipv6_to_all':

SELECT COUNTRY, RIR, STATUS, DATE 
FROM all_ipv6
WHERE ADDR_MINIMUM = '{0}'
AND ADDR_MAXIMUM = '{1}'

'asn_to_all':

SELECT COUNTRY, RIR, STATUS, DATE 
FROM all_asn
WHERE ASN = '{0}'
