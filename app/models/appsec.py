from datetime import datetime
from app import db

class WafRule(db.Model):
    """Web Application Firewall inspection rule definition."""
    __tablename__ = 'waf_rules'

    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.String(32), unique=True, nullable=False, index=True) # e.g. WAF-SQLI-001
    rule_name = db.Column(db.String(128), nullable=False)
    category = db.Column(db.String(64), nullable=False) # SQLi, XSS, PathTraversal, SSRF, RCE, XXE
    regex_pattern = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default='HIGH') # CRITICAL, HIGH, MEDIUM, LOW
    action = db.Column(db.String(20), default='BLOCK') # BLOCK, LOG, CHALLENGE
    is_enabled = db.Column(db.Boolean, default=True, index=True)
    description = db.Column(db.Text, nullable=True)
    hit_count = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            'id': self.id,
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'category': self.category,
            'regex_pattern': self.regex_pattern,
            'severity': self.severity,
            'action': self.action,
            'is_enabled': self.is_enabled,
            'hit_count': self.hit_count,
            'description': self.description
        }

class WafSecurityEvent(db.Model):
    """WAF interception events and blocked payload logs."""
    __tablename__ = 'waf_security_events'

    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.String(32), nullable=False, index=True)
    category = db.Column(db.String(64), nullable=False)
    target_endpoint = db.Column(db.String(255), nullable=False)
    http_method = db.Column(db.String(10), default='POST')
    client_ip = db.Column(db.String(45), nullable=False, index=True)
    user_agent = db.Column(db.String(255), nullable=True)
    intercepted_payload = db.Column(db.Text, nullable=False)
    action_taken = db.Column(db.String(20), default='BLOCKED')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'rule_id': self.rule_id,
            'category': self.category,
            'target_endpoint': self.target_endpoint,
            'http_method': self.http_method,
            'client_ip': self.client_ip,
            'user_agent': self.user_agent,
            'intercepted_payload': self.intercepted_payload,
            'action_taken': self.action_taken,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.created_at else None
        }

class SecretLeakFinding(db.Model):
    """Stores hardcoded secrets, API tokens, and key exposure findings."""
    __tablename__ = 'secret_leak_findings'

    id = db.Column(db.Integer, primary_key=True)
    secret_type = db.Column(db.String(64), nullable=False) # AWS_KEY, GITHUB_PAT, PRIVATE_KEY, JWT, STRIPE_KEY, DB_URI
    snippet_masked = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=True)
    line_number = db.Column(db.Integer, default=1)
    severity = db.Column(db.String(20), default='CRITICAL')
    confidence = db.Column(db.Integer, default=95)
    status = db.Column(db.String(20), default='OPEN') # OPEN, REMEDIATED, FALSE_POSITIVE
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'secret_type': self.secret_type,
            'snippet_masked': self.snippet_masked,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'severity': self.severity,
            'confidence': self.confidence,
            'status': self.status,
            'scanned_at': self.scanned_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.scanned_at else None
        }

class ScaDependencyFinding(db.Model):
    """Software Composition Analysis (SCA) dependency CVE findings."""
    __tablename__ = 'sca_dependency_findings'

    id = db.Column(db.Integer, primary_key=True)
    package_name = db.Column(db.String(128), nullable=False, index=True)
    current_version = db.Column(db.String(32), nullable=False)
    patched_version = db.Column(db.String(32), nullable=True)
    cve_id = db.Column(db.String(32), nullable=False, index=True)
    cvss_score = db.Column(db.Float, default=7.5)
    severity = db.Column(db.String(20), default='HIGH')
    description = db.Column(db.Text, nullable=True)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'package_name': self.package_name,
            'current_version': self.current_version,
            'patched_version': self.patched_version,
            'cve_id': self.cve_id,
            'cvss_score': self.cvss_score,
            'severity': self.severity,
            'description': self.description,
            'discovered_at': self.discovered_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.discovered_at else None
        }
