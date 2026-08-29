"""
SecureVault Suricata / Snort Intrusion Detection System (IDS) Rule Signatures
"""

SURICATA_IDS_RULES = [
    {
        'sid': 3000001,
        'rule_name': 'ET EXPLOIT Apache Struts2 Remote Code Execution',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HTTP_PORTS',
        'match_string': 'content:"%{(#_='multipart/form-data')"; http_header;',
        'severity': 'CRITICAL',
        'action': 'ALERT'
    },
    {
        'sid': 3000002,
        'rule_name': 'ET WEB_SERVER SQL Injection Attempt in URI',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HTTP_PORTS',
        'match_string': 'content:"UNION SELECT"; nocase; http_uri;',
        'severity': 'CRITICAL',
        'action': 'ALERT'
    },
    {
        'sid': 3000003,
        'rule_name': 'ET MALWARE Cobalt Strike Malleable C2 Beacon',
        'protocol': 'http',
        'source': '$HOME_NET',
        'destination': '$EXTERNAL_NET',
        'match_string': 'content:"/api/v1/telemetry"; http_uri; content:"Bearer "; http_header;',
        'severity': 'CRITICAL',
        'action': 'ALERT'
    },
    {
        'sid': 3000004,
        'rule_name': 'ET HUNTING Suspicious Outbound DNS Tunneling Query',
        'protocol': 'dns',
        'source': '$HOME_NET',
        'destination': '53',
        'match_string': 'content:"|01 00 00 01|"; byte_test:1,>,64,12;',
        'severity': 'CRITICAL',
        'action': 'ALERT'
    },
    {
        'sid': 3000005,
        'rule_name': 'ET SCAN Nmap Scripting Engine User-Agent Detected',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HTTP_PORTS',
        'match_string': 'content:"User-Agent|3a| Mozilla/5.0 (compatible|3b| Nmap Scripting Engine)";',
        'severity': 'CRITICAL',
        'action': 'ALERT'
    },
    {
        'sid': 3000006,
        'rule_name': 'ET ATTACK_RESPONSE Metasploit Meterpreter Reverse TCP Stage',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': 'any',
        'match_string': 'content:"|6a 00 53 ff d5|"; depth:16;',
        'severity': 'CRITICAL',
        'action': 'ALERT'
    },
    {
        'sid': 3000007,
        'rule_name': 'ET POLICY TLS 1.0 Obsolete Protocol Connection Attempt',
        'protocol': 'tls',
        'source': 'any',
        'destination': 'any',
        'match_string': 'tls.version:0x0301;',
        'severity': 'CRITICAL',
        'action': 'ALERT'
    },
    {
        'sid': 3000008,
        'rule_name': 'ET RANSOMWARE LockBit 3.0 Associated Domain Lookup',
        'protocol': 'dns',
        'source': '$HOME_NET',
        'destination': '53',
        'match_string': 'content:"lockbit"; nocase; dns.query;',
        'severity': 'CRITICAL',
        'action': 'ALERT'
    },
    {
        'sid': 3100001,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #001',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_001"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100002,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #002',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_002"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100003,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #003',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_003"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100004,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #004',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_004"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100005,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #005',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_005"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100006,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #006',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_006"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100007,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #007',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_007"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100008,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #008',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_008"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100009,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #009',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_009"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100010,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #010',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_010"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100011,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #011',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_011"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100012,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #012',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_012"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100013,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #013',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_013"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100014,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #014',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_014"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100015,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #015',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_015"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100016,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #016',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_016"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100017,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #017',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_017"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100018,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #018',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_018"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100019,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #019',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_019"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100020,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #020',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_020"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100021,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #021',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_021"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100022,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #022',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_022"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100023,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #023',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_023"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100024,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #024',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_024"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100025,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #025',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_025"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100026,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #026',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_026"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100027,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #027',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_027"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100028,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #028',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_028"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100029,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #029',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_029"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100030,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #030',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_030"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100031,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #031',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_031"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100032,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #032',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_032"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100033,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #033',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_033"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100034,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #034',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_034"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100035,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #035',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_035"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100036,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #036',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_036"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100037,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #037',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_037"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100038,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #038',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_038"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100039,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #039',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_039"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100040,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #040',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_040"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100041,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #041',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_041"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100042,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #042',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_042"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100043,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #043',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_043"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100044,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #044',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_044"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100045,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #045',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_045"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100046,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #046',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_046"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100047,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #047',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_047"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100048,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #048',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_048"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100049,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #049',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_049"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100050,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #050',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_050"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100051,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #051',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_051"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100052,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #052',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_052"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100053,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #053',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_053"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100054,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #054',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_054"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100055,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #055',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_055"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100056,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #056',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_056"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100057,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #057',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_057"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100058,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #058',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_058"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100059,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #059',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_059"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100060,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #060',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_060"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100061,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #061',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_061"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100062,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #062',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_062"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100063,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #063',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_063"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100064,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #064',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_064"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100065,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #065',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_065"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100066,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #066',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_066"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100067,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #067',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_067"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100068,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #068',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_068"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100069,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #069',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_069"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100070,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #070',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_070"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100071,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #071',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_071"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100072,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #072',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_072"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100073,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #073',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_073"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100074,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #074',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_074"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100075,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #075',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_075"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100076,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #076',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_076"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100077,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #077',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_077"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100078,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #078',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_078"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100079,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #079',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_079"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100080,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #080',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_080"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100081,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #081',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_081"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100082,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #082',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_082"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100083,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #083',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_083"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100084,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #084',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_084"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100085,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #085',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_085"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100086,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #086',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_086"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100087,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #087',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_087"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100088,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #088',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_088"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100089,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #089',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_089"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100090,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #090',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_090"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100091,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #091',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_091"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100092,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #092',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_092"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100093,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #093',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_093"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100094,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #094',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_094"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100095,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #095',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_095"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100096,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #096',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_096"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100097,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #097',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_097"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100098,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #098',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_098"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100099,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #099',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_099"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100100,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #100',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_100"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100101,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #101',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_101"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100102,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #102',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_102"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100103,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #103',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_103"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100104,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #104',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_104"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100105,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #105',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_105"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100106,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #106',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_106"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100107,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #107',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_107"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100108,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #108',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_108"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100109,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #109',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_109"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100110,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #110',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_110"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100111,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #111',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_111"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100112,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #112',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_112"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100113,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #113',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_113"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100114,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #114',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_114"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100115,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #115',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_115"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100116,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #116',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_116"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100117,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #117',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_117"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100118,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #118',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_118"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100119,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #119',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_119"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100120,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #120',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_120"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100121,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #121',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_121"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100122,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #122',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_122"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100123,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #123',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_123"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100124,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #124',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_124"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100125,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #125',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_125"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100126,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #126',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_126"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100127,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #127',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_127"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100128,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #128',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_128"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100129,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #129',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_129"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100130,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #130',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_130"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100131,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #131',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_131"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100132,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #132',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_132"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100133,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #133',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_133"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100134,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #134',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_134"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100135,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #135',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_135"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100136,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #136',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_136"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100137,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #137',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_137"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100138,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #138',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_138"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100139,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #139',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_139"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100140,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #140',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_140"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100141,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #141',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_141"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100142,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #142',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_142"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100143,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #143',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_143"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100144,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #144',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_144"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100145,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #145',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_145"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100146,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #146',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_146"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100147,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #147',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_147"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100148,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #148',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_148"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100149,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #149',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_149"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100150,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #150',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_150"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100151,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #151',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_151"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100152,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #152',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_152"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100153,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #153',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_153"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100154,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #154',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_154"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100155,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #155',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_155"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100156,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #156',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_156"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100157,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #157',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_157"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100158,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #158',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_158"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100159,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #159',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_159"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100160,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #160',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_160"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100161,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #161',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_161"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100162,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #162',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_162"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100163,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #163',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_163"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100164,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #164',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_164"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100165,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #165',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_165"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100166,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #166',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_166"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100167,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #167',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_167"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100168,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #168',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_168"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100169,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #169',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_169"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100170,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #170',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_170"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100171,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #171',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_171"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100172,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #172',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_172"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100173,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #173',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_173"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100174,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #174',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_174"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100175,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #175',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_175"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100176,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #176',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_176"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100177,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #177',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_177"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100178,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #178',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_178"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100179,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #179',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_179"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100180,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #180',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_180"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100181,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #181',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_181"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100182,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #182',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_182"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100183,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #183',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_183"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100184,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #184',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_184"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100185,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #185',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_185"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100186,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #186',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_186"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100187,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #187',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_187"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100188,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #188',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_188"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100189,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #189',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_189"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100190,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #190',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_190"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100191,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #191',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_191"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100192,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #192',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_192"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100193,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #193',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_193"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100194,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #194',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_194"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100195,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #195',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_195"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100196,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #196',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_196"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100197,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #197',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_197"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100198,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #198',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_198"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100199,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #199',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_199"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100200,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #200',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_200"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100201,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #201',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_201"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100202,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #202',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_202"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100203,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #203',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_203"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100204,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #204',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_204"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100205,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #205',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_205"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100206,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #206',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_206"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100207,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #207',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_207"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100208,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #208',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_208"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100209,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #209',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_209"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100210,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #210',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_210"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100211,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #211',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_211"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100212,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #212',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_212"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100213,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #213',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_213"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100214,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #214',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_214"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100215,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #215',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_215"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100216,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #216',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_216"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100217,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #217',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_217"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100218,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #218',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_218"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100219,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #219',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_219"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100220,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #220',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_220"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100221,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #221',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_221"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100222,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #222',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_222"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100223,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #223',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_223"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100224,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #224',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_224"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100225,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #225',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_225"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100226,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #226',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_226"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100227,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #227',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_227"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100228,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #228',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_228"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100229,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #229',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_229"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100230,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #230',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_230"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100231,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #231',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_231"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100232,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #232',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_232"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100233,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #233',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_233"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100234,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #234',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_234"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100235,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #235',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_235"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100236,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #236',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_236"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100237,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #237',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_237"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100238,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #238',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_238"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100239,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #239',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_239"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100240,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #240',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_240"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100241,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #241',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_241"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100242,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #242',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_242"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100243,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #243',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_243"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100244,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #244',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_244"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100245,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #245',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_245"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100246,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #246',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_246"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100247,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #247',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_247"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100248,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #248',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_248"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100249,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #249',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_249"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100250,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #250',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_250"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100251,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #251',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_251"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100252,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #252',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_252"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100253,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #253',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_253"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100254,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #254',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_254"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100255,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #255',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_255"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100256,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #256',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_256"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100257,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #257',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_257"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100258,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #258',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_258"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100259,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #259',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_259"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100260,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #260',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_260"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100261,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #261',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_261"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100262,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #262',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_262"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100263,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #263',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_263"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100264,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #264',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_264"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100265,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #265',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_265"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100266,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #266',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_266"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100267,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #267',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_267"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100268,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #268',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_268"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100269,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #269',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_269"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100270,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #270',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_270"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100271,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #271',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_271"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100272,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #272',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_272"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100273,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #273',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_273"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100274,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #274',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_274"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100275,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #275',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_275"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100276,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #276',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_276"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100277,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #277',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_277"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100278,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #278',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_278"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100279,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #279',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_279"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100280,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #280',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_280"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100281,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #281',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_281"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100282,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #282',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_282"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100283,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #283',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_283"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100284,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #284',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_284"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100285,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #285',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_285"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100286,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #286',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_286"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100287,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #287',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_287"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100288,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #288',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_288"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100289,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #289',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_289"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100290,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #290',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_290"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100291,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #291',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_291"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100292,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #292',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_292"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100293,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #293',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_293"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100294,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #294',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_294"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100295,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #295',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_295"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100296,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #296',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_296"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100297,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #297',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_297"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100298,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #298',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_298"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100299,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #299',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_299"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100300,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #300',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_300"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100301,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #301',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_301"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100302,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #302',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_302"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100303,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #303',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_303"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100304,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #304',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_304"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100305,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #305',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_305"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100306,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #306',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_306"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100307,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #307',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_307"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100308,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #308',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_308"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100309,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #309',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_309"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100310,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #310',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_310"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100311,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #311',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_311"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100312,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #312',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_312"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100313,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #313',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_313"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100314,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #314',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_314"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100315,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #315',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_315"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100316,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #316',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_316"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100317,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #317',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_317"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100318,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #318',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_318"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100319,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #319',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_319"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100320,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #320',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_320"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100321,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #321',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_321"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100322,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #322',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_322"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100323,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #323',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_323"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100324,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #324',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_324"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100325,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #325',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_325"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100326,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #326',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_326"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100327,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #327',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_327"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100328,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #328',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_328"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100329,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #329',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_329"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100330,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #330',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_330"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100331,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #331',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_331"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100332,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #332',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_332"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100333,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #333',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_333"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100334,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #334',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_334"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100335,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #335',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_335"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100336,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #336',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_336"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100337,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #337',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_337"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100338,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #338',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_338"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100339,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #339',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_339"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100340,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #340',
        'protocol': 'http',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_340"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100341,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #341',
        'protocol': 'tls',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_341"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100342,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #342',
        'protocol': 'dns',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_342"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100343,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #343',
        'protocol': 'ssh',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_343"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100344,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #344',
        'protocol': 'tcp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_344"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100345,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #345',
        'protocol': 'udp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_345"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100346,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #346',
        'protocol': 'smb',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_346"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100347,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #347',
        'protocol': 'rdp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_347"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100348,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #348',
        'protocol': 'smtp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_348"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
    {
        'sid': 3100349,
        'rule_name': 'ET PROPRIETARY Enterprise Network Security Signature #349',
        'protocol': 'icmp',
        'source': '$EXTERNAL_NET',
        'destination': '$HOME_NET',
        'match_string': 'content:"malicious_payload_349"; nocase; flow:established,to_server;',
        'severity': 'HIGH',
        'action': 'ALERT'
    },
]

def get_all_suricata_rules():
    return SURICATA_IDS_RULES
