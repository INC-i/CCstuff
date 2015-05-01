'all_asn' :
CREATE TABLE 'all_asn' ('ID' TEXT PRIMARY KEY,
                        'RIR' TEXT,
                        'COUNTRY' CHAR COLLATE nocase,
                        'TYPE' TEXT,
                        'ASN' NUMERIC,
                        'NUM' NUMERIC,
                        'DATE' TEXT,
                        'STATUS' TEXT)
'all_ipv4_mini' :
CREATE TABLE 'all_ipv4_mini' ('ADDR_MINIMUM' INTEGER,
                              'ADDR_MAXIMUM' INTEGER,
                              'COUNTRY' CHAR COLLATE nocase)
'all_ipv4' :
CREATE TABLE 'all_ipv4' ('ID' TEXT PRIMARY KEY,
                         'RIR' CHAR,
                         'COUNTRY' CHAR COLLATE nocase,
                         'TYPE' CHAR,
                         'ADDR_MINIMUM' INTEGER,
                         'ADDR_MAXIMUM' INTEGER,
                         'DATE' CHAR,
                         'STATUS' CHAR)
'all_ipv6_mini' :
CREATE TABLE 'all_ipv6_mini' ('ADDR_MINIMUM' TEXT,
                              'ADDR_MAXIMUM' TEXT,
                              'COUNTRY' CHAR COLLATE nocase)
'all_ipv6' :
CREATE TABLE 'all_ipv6' ('ID' TEXT PRIMARY KEY,
                         'RIR' CHAR,
                         'COUNTRY' CHAR COLLATE nocase,
                         'TYPE' CHAR,
                         'ADDR_MINIMUM' TEXT,
                         'ADDR_MAXIMUM' TEXT,
                         'DATE' CHAR,
                         'STATUS' CHAR)
'iso3166_1' :
CREATE TABLE 'iso3166_1' ('ID' TEXT PRIMARY KEY,
                          'NAME_JP' CHAR,
                          'NAME_EN' CHAR COLLATE nocase,
                          'NUM' INTEGER,
                          'CC3' CHAR COLLATE nocase,
                          'CC2' CHAR COLLATE nocase,
                          'LOCATE' CHAR,
                          'BOROUGH' CHAR)
