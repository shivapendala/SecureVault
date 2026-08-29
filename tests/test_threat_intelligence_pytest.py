import pytest
import json
from app.models.threat_intel import ThreatIndicator, ThreatFeedSource, IoCMatchEvent, MitreAttackTechnique
from app.services.threat_intelligence.ioc_matcher import IoCMatcherService
from app.services.threat_intelligence.geoip_service import GeoIpService
from app.services.threat_intelligence.mitre_mapper import MitreMapperService
from app.services.threat_intelligence.feed_manager import ThreatFeedManager

def test_threat_intelligence_seeding_and_classification(app, db_session):
    """Test seeding built-in feeds and correctly classifying indicator types."""
    with app.app_context():
        ThreatFeedManager.seed_initial_threat_data()
        MitreMapperService.seed_mitre_techniques()

        assert ThreatIndicator.query.count() >= 5
        assert ThreatFeedSource.query.count() >= 3
        assert MitreAttackTechnique.query.count() >= 5

        # Test classifier
        assert IoCMatcherService.identify_indicator_type('185.220.101.5') == 'IP'
        assert IoCMatcherService.identify_indicator_type('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') == 'SHA256'
        assert IoCMatcherService.identify_indicator_type('login-secure-verification-portal.com') == 'DOMAIN'
        assert IoCMatcherService.identify_indicator_type('https://phishing.site/login') == 'URL'

def test_ioc_query_and_threat_scoring(app, db_session):
    """Test querying specific indicators against the Threat Intelligence repository."""
    with app.app_context():
        ThreatFeedManager.seed_initial_threat_data()

        # Known malicious Tor Exit Node
        res_mal = IoCMatcherService.query_indicator('185.220.101.5')
        assert res_mal['found'] is True
        assert res_mal['verdict'] == 'MALICIOUS'
        assert res_mal['threat_score'] >= 90

        # Clean IP
        res_clean = IoCMatcherService.query_indicator('192.0.2.1')
        assert res_clean['found'] is False
        assert res_clean['verdict'] == 'CLEAN'

def test_deep_payload_scan_and_correlation(app, db_session):
    """Test deep inspection of text/log payload finding embedded IoCs."""
    with app.app_context():
        ThreatFeedManager.seed_initial_threat_data()

        sample_log = """
        [2026-08-30 02:15:00] Inbound connection accepted from 185.220.101.5:443
        Payload hash computed: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        HTTP Referer: https://legitimate-service.com/dashboard
        """

        matches = IoCMatcherService.scan_payload_for_iocs(sample_log, source_ip='198.51.100.10')
        assert len(matches) >= 2
        matched_values = [m['value'] for m in matches]
        assert '185.220.101.5' in matched_values

def test_geoip_and_asn_intelligence():
    """Test GeoIP resolution, ASN organization lookup, and risk factors."""
    tor_geo = GeoIpService.lookup_ip_intelligence('185.220.101.5')
    assert tor_geo['country_code'] == 'DE'
    assert 'Tor' in tor_geo['asn']
    assert tor_geo['risk_score'] >= 90

    local_geo = GeoIpService.lookup_ip_intelligence('127.0.0.1')
    assert local_geo['risk_score'] == 0

def test_threat_intel_web_routes_and_api(client, admin_user):
    """Test Threat Intel dashboard, search, and REST API endpoints."""
    # Login admin
    client.post('/login', data={'identifier': 'admin', 'password': 'Admin@SecureVault2026!'}, follow_redirects=True)

    # 1. Main Dashboard
    index_res = client.get('/threat-intelligence/', follow_redirects=True)
    assert index_res.status_code == 200
    assert b"Threat Intelligence & SIEM Stream" in index_res.data

    # 2. MITRE Matrix
    mitre_res = client.get('/threat-intelligence/mitre')
    assert mitre_res.status_code == 200
    assert b"Tactical Defense Matrix" in mitre_res.data

    # 3. REST API lookup
    api_lookup_res = client.get('/threat-intelligence/api/lookup?indicator=185.220.101.5')
    assert api_lookup_res.status_code == 200
    lookup_json = json.loads(api_lookup_res.data)
    assert lookup_json['success'] is True
    assert lookup_json['result']['verdict'] == 'MALICIOUS'

    # 4. REST API payload scan
    api_scan_res = client.post('/threat-intelligence/api/scan-payload', json={
        'payload': 'Threat alert from 45.154.255.89 C2 node.'
    })
    assert api_scan_res.status_code == 200
    scan_json = json.loads(api_scan_res.data)
    assert scan_json['success'] is True
    assert scan_json['match_count'] >= 1
