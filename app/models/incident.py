from datetime import datetime
from app import db

class Incident(db.Model):
    __tablename__ = 'incidents'
    
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.String(32), unique=True, index=True, nullable=False) # e.g. INC-8042
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default='High') # Critical, High, Medium, Low
    status = db.Column(db.String(30), default='Investigating') # Triage, Investigating, Contained, Eradicated, Closed
    threat_actor = db.Column(db.String(100), default='Unknown / APT Activity')
    mitre_technique = db.Column(db.String(100), default='T1190 - Exploit Public-Facing App')
    iocs = db.Column(db.Text, nullable=True) # Indicators of Compromise (IPs, hashes, domains)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'ticket_id': self.ticket_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'status': self.status,
            'threat_actor': self.threat_actor,
            'mitre_technique': self.mitre_technique,
            'iocs': self.iocs,
            'assignee': self.assignee.username if self.assignee else 'Unassigned',
            'assigned_to_id': self.assigned_to_id,
            'detected_at': self.detected_at.strftime('%Y-%m-%d %H:%M'),
            'resolved_at': self.resolved_at.strftime('%Y-%m-%d %H:%M') if self.resolved_at else None
        }
