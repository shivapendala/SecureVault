from datetime import datetime, timedelta
from flask import Blueprint, render_template, session
from app.models.user import User
from app.models.vault import SecretVault
from app.models.asset import SecurityAsset
from app.models.vulnerability import Vulnerability
from app.models.incident import Incident
from app.models.audit import AuditLog
from app.models.scan import ScanReport
from app.utils.decorators import login_required

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@login_required
def index():
    # Metrics
    total_assets = SecurityAsset.query.count()
    active_assets = SecurityAsset.query.filter_by(status='Active').count()
    
    total_secrets = SecretVault.query.count()
    expiring_secrets = SecretVault.query.filter(
        SecretVault.expires_at != None,
        SecretVault.expires_at <= datetime.utcnow() + timedelta(days=30)
    ).count()
    
    total_vulns = Vulnerability.query.count()
    critical_vulns = Vulnerability.query.filter_by(severity='Critical', status='Open').count()
    high_vulns = Vulnerability.query.filter_by(severity='High', status='Open').count()
    open_vulns = Vulnerability.query.filter(Vulnerability.status.in_(['Open', 'In Progress'])).count()
    
    total_incidents = Incident.query.count()
    active_incidents = Incident.query.filter(Incident.status.in_(['Investigating', 'Triage', 'Contained'])).count()
    critical_incidents = Incident.query.filter_by(severity='Critical').filter(Incident.status.in_(['Investigating', 'Triage'])).count()
    
    # Calculate Overall Cyber Posture Score (0-100)
    # Deductions: -10 per critical vuln, -5 per high vuln, -12 per open critical incident
    base_score = 98
    base_score -= (critical_vulns * 8)
    base_score -= (high_vulns * 3)
    base_score -= (critical_incidents * 10)
    security_score = max(15, min(99, base_score))
    
    if security_score >= 85:
        posture_status = "DEFENSE OPTIMAL"
        posture_color = "emerald"
    elif security_score >= 65:
        posture_status = "ELEVATED ALERT"
        posture_color = "amber"
    else:
        posture_status = "CRITICAL THREAT"
        posture_color = "danger"

    # Recent Incidents
    recent_incidents = Incident.query.order_by(Incident.detected_at.desc()).limit(5).all()
    
    # Critical Vulnerabilities
    top_vulns = Vulnerability.query.filter(Vulnerability.status.in_(['Open', 'In Progress']))\
                                   .order_by(Vulnerability.cvss_score.desc()).limit(5).all()
                                   
    # Recent Audit Logs
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(8).all()
    
    # Recent Scans
    recent_scans = ScanReport.query.order_by(ScanReport.created_at.desc()).limit(4).all()

    return render_template(
        'dashboard/index.html',
        total_assets=total_assets,
        active_assets=active_assets,
        total_secrets=total_secrets,
        expiring_secrets=expiring_secrets,
        total_vulns=total_vulns,
        critical_vulns=critical_vulns,
        high_vulns=high_vulns,
        open_vulns=open_vulns,
        total_incidents=total_incidents,
        active_incidents=active_incidents,
        critical_incidents=critical_incidents,
        security_score=security_score,
        posture_status=posture_status,
        posture_color=posture_color,
        recent_incidents=recent_incidents,
        top_vulns=top_vulns,
        recent_logs=recent_logs,
        recent_scans=recent_scans
    )
