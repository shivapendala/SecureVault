"""
SecureVault Network Service Fingerprint and Banner Signatures
"""

SERVICE_BANNER_SIGNATURES = [
    {
        'port': 22,
        'service_name': 'SSH',
        'banner_regex': r'OpenSSH_8.9p1',
        'vendor': 'OpenSSH',
        'os_guess': 'Ubuntu 22.04',
        'is_standard': True
    },
    {
        'port': 22,
        'service_name': 'SSH',
        'banner_regex': r'OpenSSH_9.6',
        'vendor': 'OpenSSH',
        'os_guess': 'Debian 12',
        'is_standard': True
    },
    {
        'port': 22,
        'service_name': 'SSH',
        'banner_regex': r'libssh-0.9.6',
        'vendor': 'libssh',
        'os_guess': 'Embedded',
        'is_standard': True
    },
    {
        'port': 80,
        'service_name': 'HTTP',
        'banner_regex': r'nginx/1.24.0',
        'vendor': 'Nginx',
        'os_guess': 'Linux',
        'is_standard': True
    },
    {
        'port': 80,
        'service_name': 'HTTP',
        'banner_regex': r'Apache/2.4.58',
        'vendor': 'Apache HTTP Server',
        'os_guess': 'Unix',
        'is_standard': True
    },
    {
        'port': 80,
        'service_name': 'HTTP',
        'banner_regex': r'Microsoft-IIS/10.0',
        'vendor': 'IIS',
        'os_guess': 'Windows Server 2022',
        'is_standard': True
    },
    {
        'port': 443,
        'service_name': 'HTTPS',
        'banner_regex': r'cloudflare',
        'vendor': 'Cloudflare Edge',
        'os_guess': 'Cloud CDN',
        'is_standard': True
    },
    {
        'port': 443,
        'service_name': 'HTTPS',
        'banner_regex': r'Envoy/1.28.0',
        'vendor': 'Envoy Proxy',
        'os_guess': 'Service Mesh',
        'is_standard': True
    },
    {
        'port': 3306,
        'service_name': 'MySQL',
        'banner_regex': r'8.0.36-MySQL Community',
        'vendor': 'Oracle MySQL',
        'os_guess': 'Linux x86_64',
        'is_standard': True
    },
    {
        'port': 3306,
        'service_name': 'MySQL',
        'banner_regex': r'10.11.6-MariaDB',
        'vendor': 'MariaDB',
        'os_guess': 'Debian',
        'is_standard': True
    },
    {
        'port': 5432,
        'service_name': 'PostgreSQL',
        'banner_regex': r'PostgreSQL 16.2 on x86_64',
        'vendor': 'PostgreSQL',
        'os_guess': 'Linux x86_64',
        'is_standard': True
    },
    {
        'port': 6379,
        'service_name': 'Redis',
        'banner_regex': r'redis_version:7.2.4',
        'vendor': 'Redis Cache',
        'os_guess': 'Linux Standalone',
        'is_standard': True
    },
    {
        'port': 27017,
        'service_name': 'MongoDB',
        'banner_regex': r'MongoDB 7.0.5 Community',
        'vendor': 'MongoDB',
        'os_guess': 'NoSQL Cluster',
        'is_standard': True
    },
    {
        'port': 8001,
        'service_name': 'HTTP-ALT-01',
        'banner_regex': r'Server: Enterprise-Daemon-01',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8002,
        'service_name': 'HTTP-ALT-02',
        'banner_regex': r'Server: Enterprise-Daemon-02',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8003,
        'service_name': 'HTTP-ALT-03',
        'banner_regex': r'Server: Enterprise-Daemon-03',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8004,
        'service_name': 'HTTP-ALT-04',
        'banner_regex': r'Server: Enterprise-Daemon-04',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8005,
        'service_name': 'HTTP-ALT-05',
        'banner_regex': r'Server: Enterprise-Daemon-05',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8006,
        'service_name': 'HTTP-ALT-06',
        'banner_regex': r'Server: Enterprise-Daemon-06',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8007,
        'service_name': 'HTTP-ALT-07',
        'banner_regex': r'Server: Enterprise-Daemon-07',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8008,
        'service_name': 'HTTP-ALT-08',
        'banner_regex': r'Server: Enterprise-Daemon-08',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8009,
        'service_name': 'HTTP-ALT-09',
        'banner_regex': r'Server: Enterprise-Daemon-09',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8010,
        'service_name': 'HTTP-ALT-10',
        'banner_regex': r'Server: Enterprise-Daemon-10',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8011,
        'service_name': 'HTTP-ALT-11',
        'banner_regex': r'Server: Enterprise-Daemon-11',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8012,
        'service_name': 'HTTP-ALT-12',
        'banner_regex': r'Server: Enterprise-Daemon-12',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8013,
        'service_name': 'HTTP-ALT-13',
        'banner_regex': r'Server: Enterprise-Daemon-13',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8014,
        'service_name': 'HTTP-ALT-14',
        'banner_regex': r'Server: Enterprise-Daemon-14',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8015,
        'service_name': 'HTTP-ALT-15',
        'banner_regex': r'Server: Enterprise-Daemon-15',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8016,
        'service_name': 'HTTP-ALT-16',
        'banner_regex': r'Server: Enterprise-Daemon-16',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8017,
        'service_name': 'HTTP-ALT-17',
        'banner_regex': r'Server: Enterprise-Daemon-17',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8018,
        'service_name': 'HTTP-ALT-18',
        'banner_regex': r'Server: Enterprise-Daemon-18',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8019,
        'service_name': 'HTTP-ALT-19',
        'banner_regex': r'Server: Enterprise-Daemon-19',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8020,
        'service_name': 'HTTP-ALT-20',
        'banner_regex': r'Server: Enterprise-Daemon-20',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8021,
        'service_name': 'HTTP-ALT-21',
        'banner_regex': r'Server: Enterprise-Daemon-21',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8022,
        'service_name': 'HTTP-ALT-22',
        'banner_regex': r'Server: Enterprise-Daemon-22',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8023,
        'service_name': 'HTTP-ALT-23',
        'banner_regex': r'Server: Enterprise-Daemon-23',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8024,
        'service_name': 'HTTP-ALT-24',
        'banner_regex': r'Server: Enterprise-Daemon-24',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8025,
        'service_name': 'HTTP-ALT-25',
        'banner_regex': r'Server: Enterprise-Daemon-25',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8026,
        'service_name': 'HTTP-ALT-26',
        'banner_regex': r'Server: Enterprise-Daemon-26',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8027,
        'service_name': 'HTTP-ALT-27',
        'banner_regex': r'Server: Enterprise-Daemon-27',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8028,
        'service_name': 'HTTP-ALT-28',
        'banner_regex': r'Server: Enterprise-Daemon-28',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8029,
        'service_name': 'HTTP-ALT-29',
        'banner_regex': r'Server: Enterprise-Daemon-29',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8030,
        'service_name': 'HTTP-ALT-30',
        'banner_regex': r'Server: Enterprise-Daemon-30',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8031,
        'service_name': 'HTTP-ALT-31',
        'banner_regex': r'Server: Enterprise-Daemon-31',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8032,
        'service_name': 'HTTP-ALT-32',
        'banner_regex': r'Server: Enterprise-Daemon-32',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8033,
        'service_name': 'HTTP-ALT-33',
        'banner_regex': r'Server: Enterprise-Daemon-33',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8034,
        'service_name': 'HTTP-ALT-34',
        'banner_regex': r'Server: Enterprise-Daemon-34',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8035,
        'service_name': 'HTTP-ALT-35',
        'banner_regex': r'Server: Enterprise-Daemon-35',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8036,
        'service_name': 'HTTP-ALT-36',
        'banner_regex': r'Server: Enterprise-Daemon-36',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8037,
        'service_name': 'HTTP-ALT-37',
        'banner_regex': r'Server: Enterprise-Daemon-37',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8038,
        'service_name': 'HTTP-ALT-38',
        'banner_regex': r'Server: Enterprise-Daemon-38',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8039,
        'service_name': 'HTTP-ALT-39',
        'banner_regex': r'Server: Enterprise-Daemon-39',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8040,
        'service_name': 'HTTP-ALT-40',
        'banner_regex': r'Server: Enterprise-Daemon-40',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8041,
        'service_name': 'HTTP-ALT-41',
        'banner_regex': r'Server: Enterprise-Daemon-41',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8042,
        'service_name': 'HTTP-ALT-42',
        'banner_regex': r'Server: Enterprise-Daemon-42',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8043,
        'service_name': 'HTTP-ALT-43',
        'banner_regex': r'Server: Enterprise-Daemon-43',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8044,
        'service_name': 'HTTP-ALT-44',
        'banner_regex': r'Server: Enterprise-Daemon-44',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8045,
        'service_name': 'HTTP-ALT-45',
        'banner_regex': r'Server: Enterprise-Daemon-45',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8046,
        'service_name': 'HTTP-ALT-46',
        'banner_regex': r'Server: Enterprise-Daemon-46',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8047,
        'service_name': 'HTTP-ALT-47',
        'banner_regex': r'Server: Enterprise-Daemon-47',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8048,
        'service_name': 'HTTP-ALT-48',
        'banner_regex': r'Server: Enterprise-Daemon-48',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8049,
        'service_name': 'HTTP-ALT-49',
        'banner_regex': r'Server: Enterprise-Daemon-49',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8050,
        'service_name': 'HTTP-ALT-50',
        'banner_regex': r'Server: Enterprise-Daemon-50',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8051,
        'service_name': 'HTTP-ALT-51',
        'banner_regex': r'Server: Enterprise-Daemon-51',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8052,
        'service_name': 'HTTP-ALT-52',
        'banner_regex': r'Server: Enterprise-Daemon-52',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8053,
        'service_name': 'HTTP-ALT-53',
        'banner_regex': r'Server: Enterprise-Daemon-53',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8054,
        'service_name': 'HTTP-ALT-54',
        'banner_regex': r'Server: Enterprise-Daemon-54',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8055,
        'service_name': 'HTTP-ALT-55',
        'banner_regex': r'Server: Enterprise-Daemon-55',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8056,
        'service_name': 'HTTP-ALT-56',
        'banner_regex': r'Server: Enterprise-Daemon-56',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8057,
        'service_name': 'HTTP-ALT-57',
        'banner_regex': r'Server: Enterprise-Daemon-57',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8058,
        'service_name': 'HTTP-ALT-58',
        'banner_regex': r'Server: Enterprise-Daemon-58',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8059,
        'service_name': 'HTTP-ALT-59',
        'banner_regex': r'Server: Enterprise-Daemon-59',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8060,
        'service_name': 'HTTP-ALT-60',
        'banner_regex': r'Server: Enterprise-Daemon-60',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8061,
        'service_name': 'HTTP-ALT-61',
        'banner_regex': r'Server: Enterprise-Daemon-61',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8062,
        'service_name': 'HTTP-ALT-62',
        'banner_regex': r'Server: Enterprise-Daemon-62',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8063,
        'service_name': 'HTTP-ALT-63',
        'banner_regex': r'Server: Enterprise-Daemon-63',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
    {
        'port': 8064,
        'service_name': 'HTTP-ALT-64',
        'banner_regex': r'Server: Enterprise-Daemon-64',
        'vendor': 'SecureVault Daemon',
        'os_guess': 'Linux / Container',
        'is_standard': False
    },
]

def get_all_service_banners():
    return SERVICE_BANNER_SIGNATURES
