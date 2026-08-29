from datetime import datetime
from app import db

class ComplianceFramework(db.Model):
    """Stores Cybersecurity Governance Frameworks (e.g. SOC 2 Type II, ISO 27001:2022, NIST SP 800-53, GDPR, HIPAA)."""
    __tablename__ = 'compliance_frameworks'

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(32), unique=True, nullable=False, index=True) # SOC2, ISO27001, NIST80053, GDPR, HIPAA
    name = db.Column(db.String(128), nullable=False)
    version = db.Column(db.String(32), default='2026.1')
    description = db.Column(db.Text, nullable=True)
    total_controls = db.Column(db.Integer, default=0)
    passed_controls = db.Column(db.Integer, default=0)
    readiness_percentage = db.Column(db.Float, default=100.0)

    controls = db.relationship('ComplianceControl', backref='framework', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'code': self.code,
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'total_controls': self.total_controls,
            'passed_controls': self.passed_controls,
            'readiness_percentage': self.readiness_percentage
        }

class ComplianceControl(db.Model):
    """Specific compliance control requirements within a governance framework."""
    __tablename__ = 'compliance_controls'

    id = db.Column(db.Integer, primary_key=True)
    framework_id = db.Column(db.Integer, db.ForeignKey('compliance_frameworks.id'), nullable=False)
    control_id = db.Column(db.String(32), nullable=False, index=True) # e.g. CC6.1, A.9.2.1, AC-2
    title = db.Column(db.String(255), nullable=False)
    domain = db.Column(db.String(128), default='Access Control')
    status = db.Column(db.String(20), default='COMPLIANT') # COMPLIANT, IN_PROGRESS, NON_COMPLIANT, NOT_APPLICABLE
    automated_check_key = db.Column(db.String(64), nullable=True) # e.g. check_mfa_enforced, check_encryption_at_rest
    description = db.Column(db.Text, nullable=True)
    remediation_guidance = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'framework_id': self.framework_id,
            'control_id': self.control_id,
            'title': self.title,
            'domain': self.domain,
            'status': self.status,
            'description': self.description,
            'remediation_guidance': self.remediation_guidance
        }

class RiskRegisterItem(db.Model):
    """Enterprise Cybersecurity Risk Register entry with 5x5 Likelihood x Impact scoring."""
    __tablename__ = 'risk_register_items'

    id = db.Column(db.Integer, primary_key=True)
    risk_id = db.Column(db.String(32), unique=True, nullable=False, index=True) # e.g. RSK-001
    title = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(64), default='Infrastructure') # Infrastructure, Application, Identity, Compliance, Cryptography
    likelihood = db.Column(db.Integer, default=3) # 1 - 5 (Rare, Unlikely, Moderate, Likely, Almost Certain)
    impact = db.Column(db.Integer, default=3) # 1 - 5 (Insignificant, Minor, Moderate, Major, Severe)
    risk_score = db.Column(db.Integer, default=9) # likelihood * impact (1 - 25)
    risk_rating = db.Column(db.String(20), default='MEDIUM') # CRITICAL (20-25), HIGH (15-19), MEDIUM (8-14), LOW (1-7)
    mitigation_strategy = db.Column(db.Text, nullable=True)
    owner = db.Column(db.String(128), default='CISO Team')
    status = db.Column(db.String(20), default='ACTIVE') # ACTIVE, MITIGATED, ACCEPTED, RETIRED

    def to_dict(self):
        return {
            'id': self.id,
            'risk_id': self.risk_id,
            'title': self.title,
            'category': self.category,
            'likelihood': self.likelihood,
            'impact': self.impact,
            'risk_score': self.risk_score,
            'risk_rating': self.risk_rating,
            'mitigation_strategy': self.mitigation_strategy,
            'owner': self.owner,
            'status': self.status
        }

class AuditEvidence(db.Model):
    """Immutable audit compliance evidence records with cryptographic SHA-256 integrity seal."""
    __tablename__ = 'audit_evidence_records'

    id = db.Column(db.Integer, primary_key=True)
    evidence_code = db.Column(db.String(64), unique=True, nullable=False, index=True)
    framework_code = db.Column(db.String(32), nullable=False)
    control_id = db.Column(db.String(32), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    evidence_type = db.Column(db.String(64), default='Automated Telemetry Log')
    sha256_seal = db.Column(db.String(64), nullable=False)
    verified = db.Column(db.Boolean, default=True)
    collected_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'evidence_code': self.evidence_code,
            'framework_code': self.framework_code,
            'control_id': self.control_id,
            'title': self.title,
            'evidence_type': self.evidence_type,
            'sha256_seal': self.sha256_seal,
            'verified': self.verified,
            'collected_at': self.collected_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.collected_at else None
        }
