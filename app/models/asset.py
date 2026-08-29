from datetime import datetime
from app import db

class SecurityAsset(db.Model):
    __tablename__ = 'security_assets'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, index=True)
    asset_type = db.Column(db.String(50), nullable=False) # Cloud VPC, Kubernetes, Linux Server, Windows AD, Firewall, Database Cluster, API Gateway
    ip_address = db.Column(db.String(64), nullable=True)
    fqdn = db.Column(db.String(120), nullable=True)
    environment = db.Column(db.String(30), default='Production') # Production, Staging, DMZ, Internal
    criticality = db.Column(db.String(20), default='High') # Mission Critical, High, Medium, Low
    risk_score = db.Column(db.Integer, default=35) # 0 - 100 Risk Score
    status = db.Column(db.String(30), default='Active') # Active, Isolated, Offline, Maintenance
    agent_installed = db.Column(db.Boolean, default=True)
    open_ports = db.Column(db.String(120), default='22, 80, 443')
    owner = db.Column(db.String(100), default='Infrastructure Team')
    last_scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='asset', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'asset_type': self.asset_type,
            'ip_address': self.ip_address,
            'fqdn': self.fqdn,
            'environment': self.environment,
            'criticality': self.criticality,
            'risk_score': self.risk_score,
            'status': self.status,
            'agent_installed': self.agent_installed,
            'open_ports': self.open_ports,
            'owner': self.owner,
            'vulnerabilities_count': len(self.vulnerabilities),
            'last_scan_date': self.last_scan_date.strftime('%Y-%m-%d %H:%M') if self.last_scan_date else None,
            'created_at': self.created_at.strftime('%Y-%m-%d')
        }
