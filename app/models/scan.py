from datetime import datetime
import json
from app import db

class ScanReport(db.Model):
    __tablename__ = 'scan_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(50), nullable=False) # Web Header & SSL, Port Recon, Password Entropy
    target = db.Column(db.String(255), nullable=False)
    grade = db.Column(db.String(10), default='A')
    score = db.Column(db.Integer, default=100)
    summary = db.Column(db.String(255), nullable=True)
    result_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_result(self, data_dict):
        self.result_json = json.dumps(data_dict)

    def get_result(self):
        if not self.result_json:
            return {}
        try:
            return json.loads(self.result_json)
        except Exception:
            return {}

    def to_dict(self):
        return {
            'id': self.id,
            'scan_type': self.scan_type,
            'target': self.target,
            'grade': self.grade,
            'score': self.score,
            'summary': self.summary,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'result': self.get_result()
        }
