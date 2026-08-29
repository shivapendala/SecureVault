from datetime import datetime
from app import db

class ThreatIndicator(db.Model):
    """Stores Indicators of Compromise (IoCs) including IP, Domain, URL, SHA256, MD5."""
    __tablename__ = 'threat_indicators'

    id = db.Column(db.Integer, primary_key=True)
    indicator_type = db.Column(db.String(32), nullable=False, index=True) # IP, DOMAIN, URL, SHA256, MD5, CVE
    indicator_value = db.Column(db.String(512), nullable=False, unique=True, index=True)
    threat_type = db.Column(db.String(64), nullable=False, default='Malware') # Malware, Phishing, C2, Ransomware, TorExit, Scanner
    severity = db.Column(db.String(20), nullable=False, default='HIGH') # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence_score = db.Column(db.Integer, default=85) # 0 - 100
    source_name = db.Column(db.String(128), default='SOC Internal Feeds')
    mitre_tactic = db.Column(db.String(64), nullable=True) # e.g. TA0001 Initial Access
    mitre_technique_id = db.Column(db.String(32), nullable=True) # e.g. T1190 Exploit Public-Facing App
    description = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True, index=True)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    match_count = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            'id': self.id,
            'indicator_type': self.indicator_type,
            'indicator_value': self.indicator_value,
            'threat_type': self.threat_type,
            'severity': self.severity,
            'confidence_score': self.confidence_score,
            'source_name': self.source_name,
            'mitre_tactic': self.mitre_tactic,
            'mitre_technique_id': self.mitre_technique_id,
            'description': self.description,
            'is_active': self.is_active,
            'first_seen': self.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC') if self.first_seen else None,
            'last_seen': self.last_seen.strftime('%Y-%m-%d %H:%M:%S UTC') if self.last_seen else None,
            'match_count': self.match_count
        }

class ThreatFeedSource(db.Model):
    """External threat intelligence feeds configuration."""
    __tablename__ = 'threat_feed_sources'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False, unique=True)
    feed_url = db.Column(db.String(512), nullable=True)
    feed_type = db.Column(db.String(32), default='JSON') # JSON, CSV, STIX, TAXII, TXT
    update_frequency_hours = db.Column(db.Integer, default=24)
    last_synced_at = db.Column(db.DateTime, nullable=True)
    indicator_count = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='ACTIVE') # ACTIVE, PAUSED, ERROR
    auth_header = db.Column(db.String(255), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'feed_url': self.feed_url,
            'feed_type': self.feed_type,
            'update_frequency_hours': self.update_frequency_hours,
            'last_synced_at': self.last_synced_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.last_synced_at else None,
            'indicator_count': self.indicator_count,
            'status': self.status
        }

class IoCMatchEvent(db.Model):
    """Security events matched against Threat Intelligence IoCs."""
    __tablename__ = 'ioc_match_events'

    id = db.Column(db.Integer, primary_key=True)
    indicator_id = db.Column(db.Integer, db.ForeignKey('threat_indicators.id'), nullable=False)
    matched_value = db.Column(db.String(512), nullable=False)
    source_ip = db.Column(db.String(45), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    event_context = db.Column(db.Text, nullable=True)
    action_taken = db.Column(db.String(64), default='FLAGGED_ALERT') # FLAGGED_ALERT, BLOCKED_IP, ACCOUNT_LOCKED, SESSION_KILLED
    matched_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    indicator = db.relationship('ThreatIndicator', backref=db.backref('matches', lazy=True, cascade='all, delete-orphan'))
    user = db.relationship('User', backref=db.backref('ioc_matches', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'indicator_id': self.indicator_id,
            'indicator_type': self.indicator.indicator_type if self.indicator else None,
            'threat_type': self.indicator.threat_type if self.indicator else None,
            'severity': self.indicator.severity if self.indicator else None,
            'matched_value': self.matched_value,
            'source_ip': self.source_ip,
            'user_id': self.user_id,
            'action_taken': self.action_taken,
            'event_context': self.event_context,
            'matched_at': self.matched_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.matched_at else None
        }

class MitreAttackTechnique(db.Model):
    """MITRE ATT&CK Matrix Enterprise Matrix catalog."""
    __tablename__ = 'mitre_attack_techniques'

    id = db.Column(db.Integer, primary_key=True)
    tactic_id = db.Column(db.String(16), nullable=False) # e.g. TA0001
    tactic_name = db.Column(db.String(64), nullable=False) # e.g. Initial Access
    technique_id = db.Column(db.String(16), nullable=False, unique=True, index=True) # e.g. T1190
    technique_name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=True)
    detection_strategy = db.Column(db.Text, nullable=True)
    mitigation = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'tactic_id': self.tactic_id,
            'tactic_name': self.tactic_name,
            'technique_id': self.technique_id,
            'technique_name': self.technique_name,
            'description': self.description,
            'detection_strategy': self.detection_strategy,
            'mitigation': self.mitigation
        }
