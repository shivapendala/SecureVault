"""
SecureVault IANA TLS Cipher Suites & Cryptographic Standards Catalog
"""

TLS_CIPHER_SUITES_CATALOG = [
    {
        'cipher_name': 'TLS_AES_256_GCM_SHA384',
        'hex_code': '0x13,0x02',
        'protocol_version': 'TLS 1.3',
        'encryption_algorithm': 'AES-256-GCM',
        'mac_algorithm': 'SHA-384',
        'security_rating': 'SECURE (A+)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_CHACHA20_POLY1305_SHA256',
        'hex_code': '0x13,0x03',
        'protocol_version': 'TLS 1.3',
        'encryption_algorithm': 'ChaCha20-Poly1305',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'SECURE (A+)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_AES_128_GCM_SHA256',
        'hex_code': '0x13,0x01',
        'protocol_version': 'TLS 1.3',
        'encryption_algorithm': 'AES-128-GCM',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'SECURE (A+)',
        'key_strength_bits': 128
    },
    {
        'cipher_name': 'ECDHE-ECDSA-AES256-GCM-SHA384',
        'hex_code': '0xC0,0x2C',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-GCM',
        'mac_algorithm': 'SHA-384',
        'security_rating': 'SECURE (A)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'ECDHE-RSA-AES256-GCM-SHA384',
        'hex_code': '0xC0,0x30',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-GCM',
        'mac_algorithm': 'SHA-384',
        'security_rating': 'SECURE (A)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'ECDHE-ECDSA-AES128-GCM-SHA256',
        'hex_code': '0xC0,0x2B',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-128-GCM',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'SECURE (A)',
        'key_strength_bits': 128
    },
    {
        'cipher_name': 'ECDHE-RSA-AES128-GCM-SHA256',
        'hex_code': '0xC0,0x2F',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-128-GCM',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'SECURE (A)',
        'key_strength_bits': 128
    },
    {
        'cipher_name': 'DHE-RSA-AES256-GCM-SHA384',
        'hex_code': '0x00,0x9F',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-GCM',
        'mac_algorithm': 'SHA-384',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'AES256-SHA256',
        'hex_code': '0x00,0x3D',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC (No PFS)',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'WEAK (C)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'RC4-SHA',
        'hex_code': '0x00,0x05',
        'protocol_version': 'TLS 1.0',
        'encryption_algorithm': 'RC4 (Broken)',
        'mac_algorithm': 'SHA-1',
        'security_rating': 'INSECURE (F)',
        'key_strength_bits': 128
    },
    {
        'cipher_name': 'DES-CBC3-SHA',
        'hex_code': '0x00,0x0A',
        'protocol_version': 'TLS 1.0',
        'encryption_algorithm': '3DES (Sweet32)',
        'mac_algorithm': 'SHA-1',
        'security_rating': 'INSECURE (F)',
        'key_strength_bits': 112
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_001',
        'hex_code': '0xC0,0x01',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_002',
        'hex_code': '0xC0,0x02',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_003',
        'hex_code': '0xC0,0x03',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_004',
        'hex_code': '0xC0,0x04',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_005',
        'hex_code': '0xC0,0x05',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_006',
        'hex_code': '0xC0,0x06',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_007',
        'hex_code': '0xC0,0x07',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_008',
        'hex_code': '0xC0,0x08',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_009',
        'hex_code': '0xC0,0x09',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_010',
        'hex_code': '0xC0,0x0A',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_011',
        'hex_code': '0xC0,0x0B',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_012',
        'hex_code': '0xC0,0x0C',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_013',
        'hex_code': '0xC0,0x0D',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_014',
        'hex_code': '0xC0,0x0E',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_015',
        'hex_code': '0xC0,0x0F',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_016',
        'hex_code': '0xC0,0x10',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_017',
        'hex_code': '0xC0,0x11',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_018',
        'hex_code': '0xC0,0x12',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_019',
        'hex_code': '0xC0,0x13',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_020',
        'hex_code': '0xC0,0x14',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_021',
        'hex_code': '0xC0,0x15',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_022',
        'hex_code': '0xC0,0x16',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_023',
        'hex_code': '0xC0,0x17',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_024',
        'hex_code': '0xC0,0x18',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_025',
        'hex_code': '0xC0,0x19',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_026',
        'hex_code': '0xC0,0x1A',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_027',
        'hex_code': '0xC0,0x1B',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_028',
        'hex_code': '0xC0,0x1C',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_029',
        'hex_code': '0xC0,0x1D',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_030',
        'hex_code': '0xC0,0x1E',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_031',
        'hex_code': '0xC0,0x1F',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_032',
        'hex_code': '0xC0,0x20',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_033',
        'hex_code': '0xC0,0x21',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_034',
        'hex_code': '0xC0,0x22',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_035',
        'hex_code': '0xC0,0x23',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_036',
        'hex_code': '0xC0,0x24',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_037',
        'hex_code': '0xC0,0x25',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_038',
        'hex_code': '0xC0,0x26',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_039',
        'hex_code': '0xC0,0x27',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_040',
        'hex_code': '0xC0,0x28',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_041',
        'hex_code': '0xC0,0x29',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_042',
        'hex_code': '0xC0,0x2A',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_043',
        'hex_code': '0xC0,0x2B',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_044',
        'hex_code': '0xC0,0x2C',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_045',
        'hex_code': '0xC0,0x2D',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_046',
        'hex_code': '0xC0,0x2E',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_047',
        'hex_code': '0xC0,0x2F',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_048',
        'hex_code': '0xC0,0x30',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_049',
        'hex_code': '0xC0,0x31',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_050',
        'hex_code': '0xC0,0x32',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_051',
        'hex_code': '0xC0,0x33',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_052',
        'hex_code': '0xC0,0x34',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_053',
        'hex_code': '0xC0,0x35',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_054',
        'hex_code': '0xC0,0x36',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_055',
        'hex_code': '0xC0,0x37',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_056',
        'hex_code': '0xC0,0x38',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_057',
        'hex_code': '0xC0,0x39',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_058',
        'hex_code': '0xC0,0x3A',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_059',
        'hex_code': '0xC0,0x3B',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_060',
        'hex_code': '0xC0,0x3C',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_061',
        'hex_code': '0xC0,0x3D',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_062',
        'hex_code': '0xC0,0x3E',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_063',
        'hex_code': '0xC0,0x3F',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_064',
        'hex_code': '0xC0,0x40',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_065',
        'hex_code': '0xC0,0x41',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_066',
        'hex_code': '0xC0,0x42',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_067',
        'hex_code': '0xC0,0x43',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_068',
        'hex_code': '0xC0,0x44',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_069',
        'hex_code': '0xC0,0x45',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_070',
        'hex_code': '0xC0,0x46',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_071',
        'hex_code': '0xC0,0x47',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_072',
        'hex_code': '0xC0,0x48',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_073',
        'hex_code': '0xC0,0x49',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_074',
        'hex_code': '0xC0,0x4A',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_075',
        'hex_code': '0xC0,0x4B',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_076',
        'hex_code': '0xC0,0x4C',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_077',
        'hex_code': '0xC0,0x4D',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_078',
        'hex_code': '0xC0,0x4E',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_079',
        'hex_code': '0xC0,0x4F',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_080',
        'hex_code': '0xC0,0x50',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_081',
        'hex_code': '0xC0,0x51',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_082',
        'hex_code': '0xC0,0x52',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_083',
        'hex_code': '0xC0,0x53',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
    {
        'cipher_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_084',
        'hex_code': '0xC0,0x54',
        'protocol_version': 'TLS 1.2',
        'encryption_algorithm': 'AES-256-CBC',
        'mac_algorithm': 'SHA-256',
        'security_rating': 'ACCEPTABLE (B)',
        'key_strength_bits': 256
    },
]

def get_all_tls_ciphers():
    return TLS_CIPHER_SUITES_CATALOG
