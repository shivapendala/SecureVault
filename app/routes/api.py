from flask import Blueprint, jsonify
from app.models.vault import SecretVault
from app.models.asset import SecurityAsset
from app.models.vulnerability import Vulnerability
from app.models.incident import Incident
from app.models.audit import AuditLog
from app.utils.decorators import login_required

api_bp = Blueprint('api', __name__)

@api_bp.route('/metrics')
@login_required
def get_metrics():
    # Vulnerability severity counts for doughnut chart
    crit_v = Vulnerability.query.filter_by(severity='Critical').count()
    high_v = Vulnerability.query.filter_by(severity='High').count()
    med_v = Vulnerability.query.filter_by(severity='Medium').count()
    low_v = Vulnerability.query.filter_by(severity='Low').count()
    
    # Secrets by category
    categories = ['API Key', 'Database', 'SSH Key', 'Cloud Secret', 'SSL Certificate', 'Token']
    cat_counts = {}
    for c in categories:
        cat_counts[c] = SecretVault.query.filter_by(category=c).count()
        
    # Incident status distribution
    inc_investigating = Incident.query.filter_by(status='Investigating').count()
    inc_triage = Incident.query.filter_by(status='Triage').count()
    inc_contained = Incident.query.filter_by(status='Contained').count()
    inc_resolved = Incident.query.filter(Incident.status.in_(['Eradicated', 'Closed'])).count()
    
    # Assets risk tiers
    high_risk_assets = SecurityAsset.query.filter(SecurityAsset.risk_score >= 70).count()
    med_risk_assets = SecurityAsset.query.filter(SecurityAsset.risk_score.between(40, 69)).count()
    low_risk_assets = SecurityAsset.query.filter(SecurityAsset.risk_score < 40).count()

    return jsonify({
        'vulnerabilities': {
            'critical': crit_v,
            'high': high_v,
            'medium': med_v,
            'low': low_v
        },
        'vault_categories': cat_counts,
        'incidents': {
            'investigating': inc_investigating,
            'triage': inc_triage,
            'contained': inc_contained,
            'resolved': inc_resolved
        },
        'asset_risk': {
            'critical_high': high_risk_assets,
            'moderate': med_risk_assets,
            'low_secure': low_risk_assets
        }
    })

@api_bp.route('/threat-feed')
@login_required
def threat_feed():
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    return jsonify({
        'feed': [l.to_dict() for l in recent_logs]
    })
