from datetime import datetime
from app import db
from app.models.threat_intel import ThreatIndicator, ThreatFeedSource

BUILTIN_SEED_IOCS = [
    {
        'indicator_type': 'IP',
        'indicator_value': '185.220.101.5',
        'threat_type': 'TorExit',
        'severity': 'HIGH',
        'confidence_score': 95,
        'source_name': 'Tor Project Egress Matrix',
        'mitre_tactic': 'Initial Access',
        'mitre_technique_id': 'T1190',
        'description': 'Active Tor exit node implicated in anonymous credential stuffing attacks.'
    },
    {
        'indicator_type': 'IP',
        'indicator_value': '45.154.255.89',
        'threat_type': 'C2',
        'severity': 'CRITICAL',
        'confidence_score': 99,
        'source_name': 'SOC Threat Feeds',
        'mitre_tactic': 'Command and Control',
        'mitre_technique_id': 'T1071',
        'description': 'Cobalt Strike Beacon listener endpoint identified across APT29 campaigns.'
    },
    {
        'indicator_type': 'SHA256',
        'indicator_value': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'threat_type': 'Malware',
        'severity': 'MEDIUM',
        'confidence_score': 70,
        'source_name': 'Zero-Day Malware Lab',
        'mitre_tactic': 'Defense Evasion',
        'mitre_technique_id': 'T1070',
        'description': 'Known dropper payload fingerprint utilizing anti-sandbox sleep hooks.'
    },
    {
        'indicator_type': 'DOMAIN',
        'indicator_value': 'login-secure-verification-portal.com',
        'threat_type': 'Phishing',
        'severity': 'CRITICAL',
        'confidence_score': 98,
        'source_name': 'PhishTank Feed',
        'mitre_tactic': 'Initial Access',
        'mitre_technique_id': 'T1566',
        'description': 'Typosquatting credential harvester mimicking enterprise SSO gateways.'
    },
    {
        'indicator_type': 'SHA256',
        'indicator_value': '2c5a764d85600c92d5c3d2e6750050eeadcf4c2aa2d59cfbf90731df4a625f23',
        'threat_type': 'Ransomware',
        'severity': 'CRITICAL',
        'confidence_score': 100,
        'source_name': 'Abuse.ch Ransomware Tracker',
        'mitre_tactic': 'Exfiltration',
        'mitre_technique_id': 'T1048',
        'description': 'LockBit 3.0 cryptographic encryptor executable artifact.'
    }
]

BUILTIN_FEED_SOURCES = [
    {
        'name': 'AlienVault OTX Global Threat Stream',
        'feed_url': 'https://otx.alienvault.com/api/v1/pulses/subscribed',
        'feed_type': 'JSON',
        'update_frequency_hours': 12
    },
    {
        'name': 'Abuse.ch URLhaus & Malware Registry',
        'feed_url': 'https://urlhaus.abuse.ch/downloads/csv/recent/',
        'feed_type': 'CSV',
        'update_frequency_hours': 6
    },
    {
        'name': 'Tor Project Active Exit Relays',
        'feed_url': 'https://check.torproject.org/exit-addresses',
        'feed_type': 'TXT',
        'update_frequency_hours': 4
    }
]

class ThreatFeedManager:
    """Manages threat feed sources, periodic synchronization, and IoC database lifecycle."""

    @classmethod
    def seed_initial_threat_data(cls):
        """Seed default feeds and representative IoCs."""
        # 1. Feed sources
        for src in BUILTIN_FEED_SOURCES:
            existing = ThreatFeedSource.query.filter_by(name=src['name']).first()
            if not existing:
                feed = ThreatFeedSource(
                    name=src['name'],
                    feed_url=src['feed_url'],
                    feed_type=src['feed_type'],
                    update_frequency_hours=src['update_frequency_hours'],
                    last_synced_at=datetime.utcnow(),
                    status='ACTIVE'
                )
                db.session.add(feed)

        # 2. Indicators
        for ioc in BUILTIN_SEED_IOCS:
            existing = ThreatIndicator.query.filter_by(indicator_value=ioc['indicator_value']).first()
            if not existing:
                ind = ThreatIndicator(
                    indicator_type=ioc['indicator_type'],
                    indicator_value=ioc['indicator_value'],
                    threat_type=ioc['threat_type'],
                    severity=ioc['severity'],
                    confidence_score=ioc['confidence_score'],
                    source_name=ioc['source_name'],
                    mitre_tactic=ioc['mitre_tactic'],
                    mitre_technique_id=ioc['mitre_technique_id'],
                    description=ioc['description']
                )
                db.session.add(ind)

        db.session.commit()

    @classmethod
    def sync_feed(cls, feed_id: int) -> dict:
        """Simulate live synchronization and indicator ingestion from a threat feed."""
        feed = ThreatFeedSource.query.get_or_404(feed_id)
        feed.last_synced_at = datetime.utcnow()
        feed.indicator_count += 5
        db.session.commit()

        return {
            'success': True,
            'message': f"Threat feed '{feed.name}' synchronized successfully.",
            'synced_at': feed.last_synced_at.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'total_indicators': feed.indicator_count
        }
