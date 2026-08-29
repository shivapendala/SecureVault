import hashlib
import ipaddress

KNOWN_ASN_DATABASE = {
    '127.0.0.1': {'country': 'Localhost', 'country_code': 'LO', 'city': 'Secure Enclave', 'asn': 'AS0 - Local Loopback', 'org': 'SecureVault Internal', 'risk_score': 0},
    '192.168.': {'country': 'Private Subnet', 'country_code': 'PV', 'city': 'Intranet', 'asn': 'AS-RFC1918', 'org': 'Corporate LAN', 'risk_score': 5},
    '10.': {'country': 'Private Subnet', 'country_code': 'PV', 'city': 'Intranet', 'asn': 'AS-RFC1918', 'org': 'Corporate LAN', 'risk_score': 5},
    '185.220.': {'country': 'Germany', 'country_code': 'DE', 'city': 'Frankfurt', 'asn': 'AS200052 - Tor Exit Node Network', 'org': 'Zwiebelfreunde e.V.', 'risk_score': 95},
    '45.154.': {'country': 'Russia', 'country_code': 'RU', 'city': 'Moscow', 'asn': 'AS44050 - Bulletproof Hosting Co', 'org': 'Cybercrime Egress ASN', 'risk_score': 90},
    '198.51.100.': {'country': 'United States', 'country_code': 'US', 'city': 'Ashburn', 'asn': 'AS15169 - Test Net 3', 'org': 'Cloud Provider DC', 'risk_score': 20},
    '8.8.8.8': {'country': 'United States', 'country_code': 'US', 'city': 'Mountain View', 'asn': 'AS15169 - Google LLC', 'org': 'Google Public DNS', 'risk_score': 0},
    '1.1.1.1': {'country': 'Australia', 'country_code': 'AU', 'city': 'Sydney', 'asn': 'AS13335 - Cloudflare, Inc.', 'org': 'Cloudflare DNS', 'risk_score': 0}
}

class GeoIpService:
    """Provides IP geographical intelligence, ASN organization lookup, and reputation scoring."""

    @classmethod
    def lookup_ip_intelligence(cls, ip_address: str) -> dict:
        """Lookup geographical data, ASN metadata, and risk score for an IP address."""
        if not ip_address:
            return {'ip': '0.0.0.0', 'country': 'Unknown', 'country_code': 'XX', 'city': 'Unknown', 'asn': 'AS0', 'org': 'Unknown', 'risk_score': 0}

        ip_clean = ip_address.strip()
        
        # Check known ASN subnets
        for prefix, data in KNOWN_ASN_DATABASE.items():
            if ip_clean.startswith(prefix) or ip_clean == prefix:
                return {
                    'ip': ip_clean,
                    **data
                }

        # Deterministic hash mock for diverse realistic IP testing
        h_val = int(hashlib.md5(ip_clean.encode()).hexdigest()[:4], 16)
        countries = [
            ('United States', 'US', 'Dallas', 'AS7018 - AT&T Services', 15),
            ('United Kingdom', 'GB', 'London', 'AS2856 - British Telecommunications', 10),
            ('Germany', 'DE', 'Frankfurt', 'AS3209 - Vodafone GmbH', 12),
            ('Netherlands', 'NL', 'Amsterdam', 'AS1103 - SURFnet', 25),
            ('Singapore', 'SG', 'Singapore', 'AS4657 - StarHub Ltd', 18),
            ('Japan', 'JP', 'Tokyo', 'AS2516 - KDDI Corporation', 10),
            ('Brazil', 'BR', 'Sao Paulo', 'AS27699 - Telecomunicacoes de Sao Paulo', 35),
            ('Seychelles', 'SC', 'Victoria', 'AS36994 - Unknown Off-Shore Proxy', 85)
        ]
        chosen = countries[h_val % len(countries)]

        return {
            'ip': ip_clean,
            'country': chosen[0],
            'country_code': chosen[1],
            'city': chosen[2],
            'asn': chosen[3],
            'org': chosen[3].split(' - ')[-1],
            'risk_score': chosen[4]
        }
