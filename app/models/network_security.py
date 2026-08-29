from datetime import datetime
from app import db

class TlsCertificateScan(db.Model):
    """Stores SSL/TLS X.509 Certificate analysis results."""
    __tablename__ = 'tls_certificate_scans'

    id = db.Column(db.Integer, primary_key=True)
    target_host = db.Column(db.String(255), nullable=False, index=True)
    target_port = db.Column(db.Integer, default=443)
    subject_cn = db.Column(db.String(255), nullable=True)
    issuer_org = db.Column(db.String(255), nullable=True)
    valid_from = db.Column(db.DateTime, nullable=True)
    valid_to = db.Column(db.DateTime, nullable=True)
    days_remaining = db.Column(db.Integer, default=0)
    signature_algorithm = db.Column(db.String(64), nullable=True)
    key_size_bits = db.Column(db.Integer, default=2048)
    tls_version = db.Column(db.String(32), default='TLSv1.3')
    cipher_suite = db.Column(db.String(128), nullable=True)
    san_domains = db.Column(db.Text, nullable=True)
    is_expired = db.Column(db.Boolean, default=False)
    grade = db.Column(db.String(4), default='A+') # A+, A, B, C, F
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'target_host': self.target_host,
            'target_port': self.target_port,
            'subject_cn': self.subject_cn,
            'issuer_org': self.issuer_org,
            'valid_from': self.valid_from.strftime('%Y-%m-%d %H:%M:%S UTC') if self.valid_from else None,
            'valid_to': self.valid_to.strftime('%Y-%m-%d %H:%M:%S UTC') if self.valid_to else None,
            'days_remaining': self.days_remaining,
            'signature_algorithm': self.signature_algorithm,
            'key_size_bits': self.key_size_bits,
            'tls_version': self.tls_version,
            'cipher_suite': self.cipher_suite,
            'san_domains': (self.san_domains or '').split(','),
            'is_expired': self.is_expired,
            'grade': self.grade,
            'scanned_at': self.scanned_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.scanned_at else None
        }

class HttpSecurityHeadersScan(db.Model):
    """Stores HTTP Security Response Headers evaluation."""
    __tablename__ = 'http_security_headers_scans'

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(512), nullable=False, index=True)
    score = db.Column(db.Integer, default=100) # 0 - 100
    grade = db.Column(db.String(4), default='A+') # A+, A, B, C, D, F
    hsts_present = db.Column(db.Boolean, default=False)
    csp_present = db.Column(db.Boolean, default=False)
    x_frame_options = db.Column(db.String(64), nullable=True)
    x_content_type_options = db.Column(db.String(64), nullable=True)
    referrer_policy = db.Column(db.String(64), nullable=True)
    permissions_policy = db.Column(db.Boolean, default=False)
    server_banner = db.Column(db.String(128), nullable=True)
    findings_json = db.Column(db.Text, nullable=True)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'target_url': self.target_url,
            'score': self.score,
            'grade': self.grade,
            'hsts_present': self.hsts_present,
            'csp_present': self.csp_present,
            'x_frame_options': self.x_frame_options,
            'x_content_type_options': self.x_content_type_options,
            'referrer_policy': self.referrer_policy,
            'permissions_policy': self.permissions_policy,
            'server_banner': self.server_banner,
            'scanned_at': self.scanned_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.scanned_at else None
        }

class DnsSecRecordScan(db.Model):
    """Stores DNSSEC and Email Authentication (SPF, DKIM, DMARC) records."""
    __tablename__ = 'dnssec_record_scans'

    id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.String(255), nullable=False, index=True)
    dnssec_enabled = db.Column(db.Boolean, default=False)
    spf_record = db.Column(db.String(512), nullable=True)
    spf_valid = db.Column(db.Boolean, default=False)
    dmarc_record = db.Column(db.String(512), nullable=True)
    dmarc_policy = db.Column(db.String(32), default='none') # reject, quarantine, none
    mx_records = db.Column(db.Text, nullable=True)
    spoofing_resistance_score = db.Column(db.Integer, default=80)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'domain_name': self.domain_name,
            'dnssec_enabled': self.dnssec_enabled,
            'spf_record': self.spf_record,
            'spf_valid': self.spf_valid,
            'dmarc_record': self.dmarc_record,
            'dmarc_policy': self.dmarc_policy,
            'mx_records': (self.mx_records or '').split(','),
            'spoofing_resistance_score': self.spoofing_resistance_score,
            'scanned_at': self.scanned_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.scanned_at else None
        }

class PortScanResult(db.Model):
    """Stores Port Scanning and Service Banner Grab results."""
    __tablename__ = 'port_scan_results'

    id = db.Column(db.Integer, primary_key=True)
    target_ip = db.Column(db.String(45), nullable=False, index=True)
    port_number = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), default='TCP')
    service_name = db.Column(db.String(64), nullable=True) # HTTPS, SSH, MySQL, Redis, DNS
    state = db.Column(db.String(20), default='OPEN') # OPEN, CLOSED, FILTERED
    banner = db.Column(db.String(255), nullable=True)
    risk_level = db.Column(db.String(20), default='LOW') # CRITICAL, HIGH, MEDIUM, LOW
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'target_ip': self.target_ip,
            'port_number': self.port_number,
            'protocol': self.protocol,
            'service_name': self.service_name,
            'state': self.state,
            'banner': self.banner,
            'risk_level': self.risk_level,
            'scanned_at': self.scanned_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.scanned_at else None
        }
