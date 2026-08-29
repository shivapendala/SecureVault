from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from app import db
from app.utils.decorators import login_required, roles_required
from app.models.compliance import ComplianceFramework, ComplianceControl, RiskRegisterItem, AuditEvidence
from app.services.compliance.compliance_evaluator import ComplianceEvaluatorService
from app.services.compliance.risk_matrix_service import RiskMatrixService
from app.services.compliance.evidence_locker import EvidenceLockerService

compliance_bp = Blueprint('compliance', __name__, url_prefix='/compliance')

@compliance_bp.route('/')
@login_required
def index():
    if ComplianceFramework.query.count() == 0:
        ComplianceEvaluatorService.seed_compliance_frameworks()
    if RiskRegisterItem.query.count() == 0:
        RiskMatrixService.seed_initial_risks()

    frameworks = ComplianceFramework.query.all()
    risk_summary = RiskMatrixService.get_risk_matrix_heatmap()
    recent_evidence = AuditEvidence.query.order_by(AuditEvidence.collected_at.desc()).limit(6).all()

    return render_template(
        'compliance/index.html',
        frameworks=frameworks,
        risk_summary=risk_summary,
        recent_evidence=recent_evidence
    )

@compliance_bp.route('/frameworks/<int:framework_id>')
@login_required
def framework_details(framework_id):
    framework = ComplianceFramework.query.get_or_404(framework_id)
    controls = ComplianceControl.query.filter_by(framework_id=framework.id).all()
    return render_template('compliance/framework_details.html', framework=framework, controls=controls)

@compliance_bp.route('/risk-matrix')
@login_required
def risk_matrix():
    if RiskRegisterItem.query.count() == 0:
        RiskMatrixService.seed_initial_risks()

    risks = RiskRegisterItem.query.order_by(RiskRegisterItem.risk_score.desc()).all()
    matrix_data = RiskMatrixService.get_risk_matrix_heatmap()
    return render_template('compliance/risk_matrix.html', risks=risks, matrix_data=matrix_data)

@compliance_bp.route('/evidence', methods=['GET', 'POST'])
@login_required
def evidence_locker():
    if request.method == 'POST':
        fw = request.form.get('framework_code', 'SOC2').strip()
        ctrl = request.form.get('control_id', 'CC6.1').strip()
        title = request.form.get('title', '').strip()
        raw_text = request.form.get('raw_content', '').strip()

        if title and raw_text:
            ev = EvidenceLockerService.seal_evidence(fw, ctrl, title, raw_text)
            flash(f"Audit evidence record '{ev.evidence_code}' cryptographically sealed (SHA-256: {ev.sha256_seal[:16]}...).", "success")

    all_evidence = AuditEvidence.query.order_by(AuditEvidence.collected_at.desc()).all()
    return render_template('compliance/evidence_locker.html', all_evidence=all_evidence)

# REST API Endpoints
@compliance_bp.route('/api/frameworks', methods=['GET'])
def api_frameworks():
    if ComplianceFramework.query.count() == 0:
        ComplianceEvaluatorService.seed_compliance_frameworks()
    frameworks = ComplianceFramework.query.all()
    return jsonify({'success': True, 'frameworks': [f.to_dict() for f in frameworks]})

@compliance_bp.route('/api/risk-matrix', methods=['GET'])
def api_risk_matrix():
    if RiskRegisterItem.query.count() == 0:
        RiskMatrixService.seed_initial_risks()
    data = RiskMatrixService.get_risk_matrix_heatmap()
    return jsonify({'success': True, 'risk_matrix': data})

@compliance_bp.route('/api/seal-evidence', methods=['POST'])
def api_seal_evidence():
    data = request.get_json() or {}
    fw = data.get('framework_code', 'SOC2')
    ctrl = data.get('control_id', 'CC6.1')
    title = data.get('title', 'API Evidence')
    content = data.get('content', '')

    if not content:
        return jsonify({'success': False, 'error': 'Missing content parameter'}), 400

    ev = EvidenceLockerService.seal_evidence(fw, ctrl, title, content)
    return jsonify({'success': True, 'evidence': ev.to_dict()}), 201
