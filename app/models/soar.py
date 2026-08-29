from datetime import datetime
from app import db

class SoarPlaybook(db.Model):
    """Automated incident response playbook definition."""
    __tablename__ = 'soar_playbooks'

    id = db.Column(db.Integer, primary_key=True)
    playbook_id = db.Column(db.String(32), unique=True, nullable=False, index=True) # e.g. PB-BRUTE-01, PB-RANSOM-02
    name = db.Column(db.String(128), nullable=False)
    trigger_event_type = db.Column(db.String(64), nullable=False) # BRUTE_FORCE, RANSOMWARE, DATA_EXFILTRATION, IMPOSSIBLE_TRAVEL
    description = db.Column(db.Text, nullable=True)
    is_automated = db.Column(db.Boolean, default=True)
    execution_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    executions = db.relationship('PlaybookExecution', backref='playbook', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'playbook_id': self.playbook_id,
            'name': self.name,
            'trigger_event_type': self.trigger_event_type,
            'description': self.description,
            'is_automated': self.is_automated,
            'execution_count': self.execution_count,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.created_at else None
        }

class PlaybookExecution(db.Model):
    """Historical execution instance of an incident remediation playbook."""
    __tablename__ = 'playbook_executions'

    id = db.Column(db.Integer, primary_key=True)
    playbook_id = db.Column(db.Integer, db.ForeignKey('soar_playbooks.id'), nullable=False)
    incident_id = db.Column(db.String(64), nullable=True) # Reference to Incident or IoC event
    target_identifier = db.Column(db.String(128), nullable=False) # IP, Username, Hash, or Hostname
    status = db.Column(db.String(20), default='COMPLETED') # RUNNING, COMPLETED, FAILED, PARTIAL
    steps_executed = db.Column(db.Integer, default=0)
    remediation_summary = db.Column(db.Text, nullable=True)
    started_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    finished_at = db.Column(db.DateTime, nullable=True)

    steps = db.relationship('PlaybookStep', backref='execution', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'playbook_id': self.playbook_id,
            'playbook_name': self.playbook.name if self.playbook else None,
            'incident_id': self.incident_id,
            'target_identifier': self.target_identifier,
            'status': self.status,
            'steps_executed': self.steps_executed,
            'remediation_summary': self.remediation_summary,
            'started_at': self.started_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.started_at else None,
            'finished_at': self.finished_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.finished_at else None
        }

class PlaybookStep(db.Model):
    """Individual atomic action step within an executed playbook."""
    __tablename__ = 'playbook_steps'

    id = db.Column(db.Integer, primary_key=True)
    execution_id = db.Column(db.Integer, db.ForeignKey('playbook_executions.id'), nullable=False)
    step_number = db.Column(db.Integer, default=1)
    action_type = db.Column(db.String(64), nullable=False) # IP_BLOCK, SESSION_KILL, PASSWORD_RESET, ISOLATE_HOST, NOTIFY_SOC
    output_message = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='SUCCESS') # SUCCESS, FAILED, SKIPPED

    def to_dict(self):
        return {
            'id': self.id,
            'step_number': self.step_number,
            'action_type': self.action_type,
            'output_message': self.output_message,
            'status': self.status
        }
