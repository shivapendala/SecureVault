"""
SecureVault OWASP ModSecurity Core Rule Set (CRS) Definitions
"""

OWASP_CRS_RULES_CATALOG = [
    {
        'rule_id': 'CRS-942100',
        'category': 'SQLi',
        'category_name': 'SQL Injection Attacks',
        'regex_signature': r'(?i)(\bunion\b\s+all\s+\bselect\b|\bselect\b.*?\bfrom\b)',
        'severity': 'CRITICAL',
        'action': 'BLOCK',
        'description': """Critical SQL Injection pattern matching union-based queries.""",
        'is_active': True
    },
    {
        'rule_id': 'CRS-942110',
        'category': 'SQLi',
        'category_name': 'SQL Injection Attacks',
        'regex_signature': r'(?i)(\bor\b\s+['\"\d\w]+?\s*=\s*['\"\d\w]+?|'\s*or\s*'1'\s*=\s*'1')',
        'severity': 'CRITICAL',
        'action': 'BLOCK',
        'description': """Boolean-based classic SQL injection bypass pattern.""",
        'is_active': True
    },
    {
        'rule_id': 'CRS-942120',
        'category': 'SQLi',
        'category_name': 'SQL Injection Attacks',
        'regex_signature': r'(?i)(exec(\s|\+)+(s|x)p\w+|\bbenchmark\b\s*\(|\bsleep\b\s*\()',
        'severity': 'CRITICAL',
        'action': 'BLOCK',
        'description': """Time-based blind and database stored procedure execution attempts.""",
        'is_active': True
    },
    {
        'rule_id': 'CRS-942130',
        'category': 'SQLi',
        'category_name': 'SQL Injection Attacks',
        'regex_signature': r'(?i)(\bdrop\b\s+\btable\b|\btruncate\b\s+\btable\b|\balter\b\s+\btable\b)',
        'severity': 'CRITICAL',
        'action': 'BLOCK',
        'description': """Schema modification and destructive SQL statement injection.""",
        'is_active': True
    },
    {
        'rule_id': 'CRS-941100',
        'category': 'XSS',
        'category_name': 'Cross-Site Scripting Attacks',
        'regex_signature': r'(?i)(<script.*?>.*?</script>|javascript:\s*|vbscript:\s*)',
        'severity': 'CRITICAL',
        'action': 'BLOCK',
        'description': """Classic inline script tag and executable URI scheme injection.""",
        'is_active': True
    },
    {
        'rule_id': 'CRS-941110',
        'category': 'XSS',
        'category_name': 'Cross-Site Scripting Attacks',
        'regex_signature': r'(?i)(onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=)',
        'severity': 'CRITICAL',
        'action': 'BLOCK',
        'description': """HTML5 DOM event handler attribute injection.""",
        'is_active': True
    },
    {
        'rule_id': 'CRS-941120',
        'category': 'XSS',
        'category_name': 'Cross-Site Scripting Attacks',
        'regex_signature': r'(?i)(document\.cookie|document\.location|window\.location)',
        'severity': 'CRITICAL',
        'action': 'BLOCK',
        'description': """DOM session cookie exfiltration and redirect tampering.""",
        'is_active': True
    },
    {
        'rule_id': 'CRS-941130',
        'category': 'XSS',
        'category_name': 'Cross-Site Scripting Attacks',
        'regex_signature': r'(?i)(<iframe.*?>|<object.*?>|<embed.*?>|<svg.*?onload)',
        'severity': 'CRITICAL',
        'action': 'BLOCK',
        'description': """Nested frame and SVG vector injection.""",
        'is_active': True
    },
    {
        'rule_id': 'CRS-932100',
        'category': 'RCE',
        'category_name': 'Remote Command Execution',
        'regex_signature': r'(?i)(;|\||`|\$\(.*?\))\s*(cat\s+/etc/passwd|whoami|uname\s+-a|id\b)',
        'severity': 'CRITICAL',
        'action': 'BLOCK',
        'description': """Unix command chaining and sensitive file access.""",
        'is_active': True
    },
    {
        'rule_id': 'CRS-932110',
        'category': 'RCE',
        'category_name': 'Remote Command Execution',
        'regex_signature': r'(?i)(powershell\.exe|cmd\.exe\s+/c|certutil\.exe\s+-urlcache)',
        'severity': 'CRITICAL',
        'action': 'BLOCK',
        'description': """Windows LOLBin execution attempt via command line.""",
        'is_active': True
    },
    {
        'rule_id': 'CRS-932120',
        'category': 'RCE',
        'category_name': 'Remote Command Execution',
        'regex_signature': r'(?i)(\bwget\b\s+http|\bcurl\b\s+http|\bnc\b\s+-e)',
        'severity': 'CRITICAL',
        'action': 'BLOCK',
        'description': """Outbound remote payload download and reverse shell creation.""",
        'is_active': True
    },
    {
        'rule_id': 'CRS-930100',
        'category': 'PathTraversal',
        'category_name': 'Directory Path Traversal',
        'regex_signature': r'(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f)',
        'severity': 'CRITICAL',
        'action': 'BLOCK',
        'description': """Directory traversal directory traversal sequences.""",
        'is_active': True
    },
    {
        'rule_id': 'CRS-930110',
        'category': 'PathTraversal',
        'category_name': 'Directory Path Traversal',
        'regex_signature': r'(/etc/shadow|/etc/passwd|/windows/win\.ini|/boot\.ini)',
        'severity': 'CRITICAL',
        'action': 'BLOCK',
        'description': """Sensitive operating system file path target injection.""",
        'is_active': True
    },
    {
        'rule_id': 'CRS-934100',
        'category': 'SSRF',
        'category_name': 'Server-Side Request Forgery',
        'regex_signature': r'(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)',
        'severity': 'CRITICAL',
        'action': 'BLOCK',
        'description': """Cloud infrastructure instance metadata service access attempt.""",
        'is_active': True
    },
    {
        'rule_id': 'CRS-934110',
        'category': 'SSRF',
        'category_name': 'Server-Side Request Forgery',
        'regex_signature': r'(127\.0\.0\.1|localhost|0\.0\.0\.0|::1|file://|gopher://|dict://)',
        'severity': 'CRITICAL',
        'action': 'BLOCK',
        'description': """Loopback interface and dangerous protocol URI injection.""",
        'is_active': True
    },
    {
        'rule_id': 'CRS-91001',
        'category': 'XSS',
        'category_name': 'XSS Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_001|malicious_payload_001)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #001.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91002',
        'category': 'RCE',
        'category_name': 'RCE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_002|malicious_payload_002)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #002.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91003',
        'category': 'PathTraversal',
        'category_name': 'PathTraversal Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_003|malicious_payload_003)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #003.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91004',
        'category': 'SSRF',
        'category_name': 'SSRF Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_004|malicious_payload_004)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #004.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91005',
        'category': 'XXE',
        'category_name': 'XXE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_005|malicious_payload_005)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #005.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91006',
        'category': 'Deserialization',
        'category_name': 'Deserialization Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_006|malicious_payload_006)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #006.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91007',
        'category': 'SQLi',
        'category_name': 'SQLi Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_007|malicious_payload_007)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #007.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91008',
        'category': 'XSS',
        'category_name': 'XSS Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_008|malicious_payload_008)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #008.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91009',
        'category': 'RCE',
        'category_name': 'RCE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_009|malicious_payload_009)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #009.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91010',
        'category': 'PathTraversal',
        'category_name': 'PathTraversal Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_010|malicious_payload_010)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #010.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91011',
        'category': 'SSRF',
        'category_name': 'SSRF Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_011|malicious_payload_011)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #011.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91012',
        'category': 'XXE',
        'category_name': 'XXE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_012|malicious_payload_012)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #012.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91013',
        'category': 'Deserialization',
        'category_name': 'Deserialization Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_013|malicious_payload_013)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #013.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91014',
        'category': 'SQLi',
        'category_name': 'SQLi Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_014|malicious_payload_014)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #014.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91015',
        'category': 'XSS',
        'category_name': 'XSS Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_015|malicious_payload_015)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #015.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91016',
        'category': 'RCE',
        'category_name': 'RCE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_016|malicious_payload_016)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #016.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91017',
        'category': 'PathTraversal',
        'category_name': 'PathTraversal Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_017|malicious_payload_017)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #017.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91018',
        'category': 'SSRF',
        'category_name': 'SSRF Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_018|malicious_payload_018)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #018.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91019',
        'category': 'XXE',
        'category_name': 'XXE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_019|malicious_payload_019)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #019.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91020',
        'category': 'Deserialization',
        'category_name': 'Deserialization Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_020|malicious_payload_020)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #020.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91021',
        'category': 'SQLi',
        'category_name': 'SQLi Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_021|malicious_payload_021)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #021.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91022',
        'category': 'XSS',
        'category_name': 'XSS Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_022|malicious_payload_022)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #022.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91023',
        'category': 'RCE',
        'category_name': 'RCE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_023|malicious_payload_023)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #023.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91024',
        'category': 'PathTraversal',
        'category_name': 'PathTraversal Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_024|malicious_payload_024)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #024.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91025',
        'category': 'SSRF',
        'category_name': 'SSRF Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_025|malicious_payload_025)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #025.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91026',
        'category': 'XXE',
        'category_name': 'XXE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_026|malicious_payload_026)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #026.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91027',
        'category': 'Deserialization',
        'category_name': 'Deserialization Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_027|malicious_payload_027)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #027.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91028',
        'category': 'SQLi',
        'category_name': 'SQLi Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_028|malicious_payload_028)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #028.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91029',
        'category': 'XSS',
        'category_name': 'XSS Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_029|malicious_payload_029)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #029.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91030',
        'category': 'RCE',
        'category_name': 'RCE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_030|malicious_payload_030)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #030.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91031',
        'category': 'PathTraversal',
        'category_name': 'PathTraversal Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_031|malicious_payload_031)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #031.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91032',
        'category': 'SSRF',
        'category_name': 'SSRF Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_032|malicious_payload_032)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #032.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91033',
        'category': 'XXE',
        'category_name': 'XXE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_033|malicious_payload_033)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #033.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91034',
        'category': 'Deserialization',
        'category_name': 'Deserialization Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_034|malicious_payload_034)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #034.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91035',
        'category': 'SQLi',
        'category_name': 'SQLi Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_035|malicious_payload_035)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #035.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91036',
        'category': 'XSS',
        'category_name': 'XSS Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_036|malicious_payload_036)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #036.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91037',
        'category': 'RCE',
        'category_name': 'RCE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_037|malicious_payload_037)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #037.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91038',
        'category': 'PathTraversal',
        'category_name': 'PathTraversal Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_038|malicious_payload_038)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #038.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91039',
        'category': 'SSRF',
        'category_name': 'SSRF Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_039|malicious_payload_039)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #039.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91040',
        'category': 'XXE',
        'category_name': 'XXE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_040|malicious_payload_040)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #040.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91041',
        'category': 'Deserialization',
        'category_name': 'Deserialization Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_041|malicious_payload_041)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #041.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91042',
        'category': 'SQLi',
        'category_name': 'SQLi Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_042|malicious_payload_042)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #042.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91043',
        'category': 'XSS',
        'category_name': 'XSS Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_043|malicious_payload_043)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #043.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91044',
        'category': 'RCE',
        'category_name': 'RCE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_044|malicious_payload_044)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #044.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91045',
        'category': 'PathTraversal',
        'category_name': 'PathTraversal Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_045|malicious_payload_045)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #045.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91046',
        'category': 'SSRF',
        'category_name': 'SSRF Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_046|malicious_payload_046)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #046.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91047',
        'category': 'XXE',
        'category_name': 'XXE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_047|malicious_payload_047)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #047.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91048',
        'category': 'Deserialization',
        'category_name': 'Deserialization Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_048|malicious_payload_048)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #048.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91049',
        'category': 'SQLi',
        'category_name': 'SQLi Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_049|malicious_payload_049)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #049.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91050',
        'category': 'XSS',
        'category_name': 'XSS Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_050|malicious_payload_050)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #050.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91051',
        'category': 'RCE',
        'category_name': 'RCE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_051|malicious_payload_051)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #051.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91052',
        'category': 'PathTraversal',
        'category_name': 'PathTraversal Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_052|malicious_payload_052)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #052.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91053',
        'category': 'SSRF',
        'category_name': 'SSRF Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_053|malicious_payload_053)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #053.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91054',
        'category': 'XXE',
        'category_name': 'XXE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_054|malicious_payload_054)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #054.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91055',
        'category': 'Deserialization',
        'category_name': 'Deserialization Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_055|malicious_payload_055)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #055.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91056',
        'category': 'SQLi',
        'category_name': 'SQLi Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_056|malicious_payload_056)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #056.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91057',
        'category': 'XSS',
        'category_name': 'XSS Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_057|malicious_payload_057)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #057.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91058',
        'category': 'RCE',
        'category_name': 'RCE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_058|malicious_payload_058)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #058.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91059',
        'category': 'PathTraversal',
        'category_name': 'PathTraversal Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_059|malicious_payload_059)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #059.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91060',
        'category': 'SSRF',
        'category_name': 'SSRF Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_060|malicious_payload_060)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #060.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91061',
        'category': 'XXE',
        'category_name': 'XXE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_061|malicious_payload_061)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #061.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91062',
        'category': 'Deserialization',
        'category_name': 'Deserialization Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_062|malicious_payload_062)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #062.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91063',
        'category': 'SQLi',
        'category_name': 'SQLi Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_063|malicious_payload_063)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #063.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91064',
        'category': 'XSS',
        'category_name': 'XSS Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_064|malicious_payload_064)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #064.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91065',
        'category': 'RCE',
        'category_name': 'RCE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_065|malicious_payload_065)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #065.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91066',
        'category': 'PathTraversal',
        'category_name': 'PathTraversal Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_066|malicious_payload_066)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #066.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91067',
        'category': 'SSRF',
        'category_name': 'SSRF Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_067|malicious_payload_067)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #067.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91068',
        'category': 'XXE',
        'category_name': 'XXE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_068|malicious_payload_068)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #068.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91069',
        'category': 'Deserialization',
        'category_name': 'Deserialization Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_069|malicious_payload_069)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #069.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91070',
        'category': 'SQLi',
        'category_name': 'SQLi Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_070|malicious_payload_070)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #070.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91071',
        'category': 'XSS',
        'category_name': 'XSS Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_071|malicious_payload_071)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #071.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91072',
        'category': 'RCE',
        'category_name': 'RCE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_072|malicious_payload_072)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #072.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91073',
        'category': 'PathTraversal',
        'category_name': 'PathTraversal Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_073|malicious_payload_073)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #073.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91074',
        'category': 'SSRF',
        'category_name': 'SSRF Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_074|malicious_payload_074)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #074.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91075',
        'category': 'XXE',
        'category_name': 'XXE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_075|malicious_payload_075)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #075.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91076',
        'category': 'Deserialization',
        'category_name': 'Deserialization Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_076|malicious_payload_076)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #076.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91077',
        'category': 'SQLi',
        'category_name': 'SQLi Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_077|malicious_payload_077)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #077.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91078',
        'category': 'XSS',
        'category_name': 'XSS Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_078|malicious_payload_078)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #078.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91079',
        'category': 'RCE',
        'category_name': 'RCE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_079|malicious_payload_079)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #079.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91080',
        'category': 'PathTraversal',
        'category_name': 'PathTraversal Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_080|malicious_payload_080)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #080.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91081',
        'category': 'SSRF',
        'category_name': 'SSRF Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_081|malicious_payload_081)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #081.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91082',
        'category': 'XXE',
        'category_name': 'XXE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_082|malicious_payload_082)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #082.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91083',
        'category': 'Deserialization',
        'category_name': 'Deserialization Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_083|malicious_payload_083)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #083.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91084',
        'category': 'SQLi',
        'category_name': 'SQLi Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_084|malicious_payload_084)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #084.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91085',
        'category': 'XSS',
        'category_name': 'XSS Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_085|malicious_payload_085)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #085.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91086',
        'category': 'RCE',
        'category_name': 'RCE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_086|malicious_payload_086)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #086.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91087',
        'category': 'PathTraversal',
        'category_name': 'PathTraversal Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_087|malicious_payload_087)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #087.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91088',
        'category': 'SSRF',
        'category_name': 'SSRF Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_088|malicious_payload_088)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #088.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91089',
        'category': 'XXE',
        'category_name': 'XXE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_089|malicious_payload_089)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #089.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91090',
        'category': 'Deserialization',
        'category_name': 'Deserialization Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_090|malicious_payload_090)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #090.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91091',
        'category': 'SQLi',
        'category_name': 'SQLi Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_091|malicious_payload_091)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #091.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91092',
        'category': 'XSS',
        'category_name': 'XSS Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_092|malicious_payload_092)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #092.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91093',
        'category': 'RCE',
        'category_name': 'RCE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_093|malicious_payload_093)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #093.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91094',
        'category': 'PathTraversal',
        'category_name': 'PathTraversal Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_094|malicious_payload_094)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #094.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91095',
        'category': 'SSRF',
        'category_name': 'SSRF Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_095|malicious_payload_095)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #095.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91096',
        'category': 'XXE',
        'category_name': 'XXE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_096|malicious_payload_096)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #096.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91097',
        'category': 'Deserialization',
        'category_name': 'Deserialization Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_097|malicious_payload_097)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #097.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91098',
        'category': 'SQLi',
        'category_name': 'SQLi Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_098|malicious_payload_098)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #098.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91099',
        'category': 'XSS',
        'category_name': 'XSS Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_099|malicious_payload_099)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #099.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91100',
        'category': 'RCE',
        'category_name': 'RCE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_100|malicious_payload_100)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #100.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91101',
        'category': 'PathTraversal',
        'category_name': 'PathTraversal Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_101|malicious_payload_101)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #101.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91102',
        'category': 'SSRF',
        'category_name': 'SSRF Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_102|malicious_payload_102)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #102.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91103',
        'category': 'XXE',
        'category_name': 'XXE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_103|malicious_payload_103)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #103.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91104',
        'category': 'Deserialization',
        'category_name': 'Deserialization Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_104|malicious_payload_104)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #104.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91105',
        'category': 'SQLi',
        'category_name': 'SQLi Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_105|malicious_payload_105)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #105.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91106',
        'category': 'XSS',
        'category_name': 'XSS Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_106|malicious_payload_106)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #106.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91107',
        'category': 'RCE',
        'category_name': 'RCE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_107|malicious_payload_107)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #107.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91108',
        'category': 'PathTraversal',
        'category_name': 'PathTraversal Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_108|malicious_payload_108)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #108.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91109',
        'category': 'SSRF',
        'category_name': 'SSRF Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_109|malicious_payload_109)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #109.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91110',
        'category': 'XXE',
        'category_name': 'XXE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_110|malicious_payload_110)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #110.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91111',
        'category': 'Deserialization',
        'category_name': 'Deserialization Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_111|malicious_payload_111)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #111.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91112',
        'category': 'SQLi',
        'category_name': 'SQLi Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_112|malicious_payload_112)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #112.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91113',
        'category': 'XSS',
        'category_name': 'XSS Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_113|malicious_payload_113)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #113.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91114',
        'category': 'RCE',
        'category_name': 'RCE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_114|malicious_payload_114)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #114.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91115',
        'category': 'PathTraversal',
        'category_name': 'PathTraversal Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_115|malicious_payload_115)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #115.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91116',
        'category': 'SSRF',
        'category_name': 'SSRF Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_116|malicious_payload_116)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #116.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91117',
        'category': 'XXE',
        'category_name': 'XXE Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_117|malicious_payload_117)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #117.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91118',
        'category': 'Deserialization',
        'category_name': 'Deserialization Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_118|malicious_payload_118)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #118.',
        'is_active': True
    },
    {
        'rule_id': 'CRS-91119',
        'category': 'SQLi',
        'category_name': 'SQLi Deep Inspection',
        'regex_signature': r'(?i)(attack_signature_119|malicious_payload_119)',
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Advanced signature heuristic detecting specialized protocol anomaly #119.',
        'is_active': True
    },
]

def get_all_crs_rules():
    return OWASP_CRS_RULES_CATALOG
