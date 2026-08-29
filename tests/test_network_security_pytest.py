import pytest
import json
from app.models.network_security import TlsCertificateScan, HttpSecurityHeadersScan, DnsSecRecordScan, PortScanResult
from app.services.network_security.tls_inspector import TlsInspectorService
from app.services.network_security.headers_analyzer import HttpHeadersAnalyzerService
from app.services.network_security.dns_security import DnsSecurityService
from app.services.network_security.port_scanner import PortScannerService

def test_tls_certificate_inspector(app, db_session):
    """Test X.509 TLS certificate extraction, cipher identification, and grading."""
    with app.app_context():
        res = TlsInspectorService.inspect_host_certificate('github.com')
        assert res['target_host'] == 'github.com'
        assert res['grade'] in ['A+', 'A', 'B']
        assert res['key_size_bits'] >= 2048
        assert res['days_remaining'] > 0

        # DB persistence
        found = TlsCertificateScan.query.filter_by(target_host='github.com').first()
        assert found is not None

def test_http_security_headers_analyzer(app, db_session):
    """Test HTTP security response headers audit against OWASP Top 10 standards."""
    with app.app_context():
        # Complete headers test
        good_headers = {
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            'Content-Security-Policy': "default-src 'self'",
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'camera=(), microphone=()'
        }
        res_good = HttpHeadersAnalyzerService.analyze_headers('https://securevault.local', custom_headers_dict=good_headers)
        assert res_good['score'] == 100
        assert res_good['grade'] == 'A+'
        assert res_good['hsts_present'] is True
        assert res_good['csp_present'] is True

        # Insecure missing headers test
        res_bad = HttpHeadersAnalyzerService.analyze_headers('https://insecure-site.local', custom_headers_dict={})
        assert res_bad['score'] < 50
        assert res_bad['grade'] == 'F'
        assert len(res_bad['findings']) >= 4

def test_dnssec_and_email_spoofing_defense(app, db_session):
    """Test DNSSEC validation, SPF / DMARC policy parsing, and resistance score."""
    with app.app_context():
        res = DnsSecurityService.evaluate_domain_defense('securevault.io')
        assert res['domain_name'] == 'securevault.io'
        assert res['dnssec_enabled'] is True
        assert res['dmarc_policy'] == 'reject'
        assert res['spoofing_resistance_score'] >= 90

def test_port_scanner_and_service_fingerprinting(app, db_session):
    """Test TCP port probing and service banner identification."""
    with app.app_context():
        ports = PortScannerService.scan_target_ports('127.0.0.1', port_list=[(5005, 'HTTP-Flask', 'LOW'), (3306, 'MySQL', 'HIGH')])
        assert len(ports) == 2
        assert any(p['service_name'] in ['HTTP-Flask', 'MySQL'] for p in ports)

def test_network_security_web_routes_and_api(client, admin_user):
    """Test Network Security UI consoles and REST API endpoints."""
    # Login admin
    client.post('/login', data={'identifier': 'admin', 'password': 'Admin@SecureVault2026!'}, follow_redirects=True)

    # 1. Main Hub
    hub_res = client.get('/network-security/', follow_redirects=True)
    assert hub_res.status_code == 200
    assert b"Network, TLS & Perimeter Security Hub" in hub_res.data

    # 2. TLS Inspector UI
    tls_ui_res = client.get('/network-security/tls?host=github.com')
    assert tls_ui_res.status_code == 200
    assert b"Certificate Cryptographic Specifications" in tls_ui_res.data

    # 3. REST API Scan TLS
    api_tls = client.post('/network-security/api/scan-tls', json={'host': 'github.com'})
    assert api_tls.status_code == 200
    tls_json = json.loads(api_tls.data)
    assert tls_json['success'] is True
    assert 'tls_data' in tls_json

    # 4. REST API Scan Headers
    api_headers = client.post('/network-security/api/scan-headers', json={'url': 'https://github.com'})
    assert api_headers.status_code == 200
    headers_json = json.loads(api_headers.data)
    assert headers_json['success'] is True
    assert 'headers_data' in headers_json
