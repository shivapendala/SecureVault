import pytest
import json
from app.models.appsec import WafRule, WafSecurityEvent, SecretLeakFinding, ScaDependencyFinding
from app.services.appsec.waf_engine import WafEngineService
from app.services.appsec.secret_leak_detector import SecretLeakDetectorService
from app.services.appsec.sca_analyzer import ScaAnalyzerService

def test_waf_rules_seeding_and_sql_injection_blocking(app, db_session):
    """Test WAF rule initialization and interception of SQL Injection & XSS payloads."""
    with app.app_context():
        WafEngineService.seed_waf_rules()
        assert WafRule.query.count() >= 5

        # 1. Test SQL Injection Block
        sqli_payload = "admin' UNION SELECT id, username, password_hash FROM users --"
        res_sqli = WafEngineService.inspect_request_payload(sqli_payload, endpoint='/api/login')
        assert res_sqli['blocked'] is True
        assert res_sqli['action'] == 'BLOCK'
        assert any(r['category'] == 'SQLi' for r in res_sqli['triggered_rules'])

        # 2. Test XSS Block
        xss_payload = "<script>alert(document.cookie)</script>"
        res_xss = WafEngineService.inspect_request_payload(xss_payload, endpoint='/api/comment')
        assert res_xss['blocked'] is True
        assert any(r['category'] == 'XSS' for r in res_xss['triggered_rules'])

        # 3. Clean payload
        res_clean = WafEngineService.inspect_request_payload("Regular safe user input text", endpoint='/api/search')
        assert res_clean['blocked'] is False
        assert res_clean['action'] == 'ALLOW'

def test_secret_leak_detector(app, db_session):
    """Test detecting and masking leaked AWS keys, GitHub PATs, and Stripe tokens."""
    with app.app_context():
        leaked_snippet = f"""
        # Production deployment keys
        AWS_KEY = "{'AK' + 'IA1234567890ABCDEF'}"
        GITHUB_TOKEN = "{'gh' + 'p_1234567890abcdefghijklmnopqrstuvwxyz'}"
        STRIPE_SECRET = "{'sk_' + 'live_1234567890abcdef12345678'}"
        """

        findings = SecretLeakDetectorService.scan_text_for_secrets(leaked_snippet, file_path='deploy.py')
        assert len(findings) >= 3

        types_found = [f['secret_type'] for f in findings]
        assert 'AWS_ACCESS_KEY' in types_found
        assert 'GITHUB_PAT' in types_found
        assert 'STRIPE_API_KEY' in types_found

        # Verify masking
        for f in findings:
            assert '****' in f['snippet_masked']

def test_sca_dependency_auditor(app, db_session):
    """Test SCA package version audit against known CVE security advisories."""
    with app.app_context():
        packages = [
            ('requests', '2.28.1'),
            ('urllib3', '1.26.10'),
            ('safe-pkg', '1.0.0')
        ]
        findings = ScaAnalyzerService.audit_dependencies(packages)
        assert len(findings) >= 2
        cves = [f['cve_id'] for f in findings]
        assert 'CVE-2023-32681' in cves

def test_appsec_web_routes_and_api(client, admin_user):
    """Test AppSec & WAF web dashboards and REST API endpoints."""
    # Login admin
    client.post('/login', data={'identifier': 'admin', 'password': 'Admin@SecureVault2026!'}, follow_redirects=True)

    # 1. Main Hub
    hub_res = client.get('/appsec/', follow_redirects=True)
    assert hub_res.status_code == 200
    assert b"Application Security & WAF Center" in hub_res.data

    # 2. WAF Monitor UI Simulation
    waf_res = client.post('/appsec/waf', data={'payload': "SELECT * FROM users WHERE '1'='1'"}, follow_redirects=True)
    assert waf_res.status_code == 200
    assert b"PAYLOAD BLOCKED" in waf_res.data

    # 3. REST API Inspect Payload
    api_waf = client.post('/appsec/api/inspect-payload', json={'payload': '<img src=x onerror=alert(1)>'})
    assert api_waf.status_code == 200
    waf_json = json.loads(api_waf.data)
    assert waf_json['success'] is True
    assert waf_json['waf_result']['blocked'] is True

    # 4. REST API Scan Secrets
    api_sec = client.post('/appsec/api/scan-secrets', json={'content': f'AWS_KEY = "{"AK" + "IA9876543210ZYXWVU"}"'})
    assert api_sec.status_code == 200
    sec_json = json.loads(api_sec.data)
    assert sec_json['success'] is True
    assert sec_json['findings_count'] >= 1
