from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from app import db
from app.utils.decorators import login_required, roles_required
from app.models.appsec import WafRule, WafSecurityEvent, SecretLeakFinding, ScaDependencyFinding
from app.services.appsec.waf_engine import WafEngineService
from app.services.appsec.secret_leak_detector import SecretLeakDetectorService
from app.services.appsec.sca_analyzer import ScaAnalyzerService

appsec_bp = Blueprint('appsec', __name__, url_prefix='/appsec')

@appsec_bp.route('/')
@login_required
def index():
    if WafRule.query.count() == 0:
        WafEngineService.seed_waf_rules()

    total_rules = WafRule.query.count()
    total_waf_blocks = WafSecurityEvent.query.filter_by(action_taken='BLOCK').count()
    open_secrets = SecretLeakFinding.query.filter_by(status='OPEN').count()
    sca_count = ScaDependencyFinding.query.count()

    recent_waf_events = WafSecurityEvent.query.order_by(WafSecurityEvent.created_at.desc()).limit(8).all()
    recent_secrets = SecretLeakFinding.query.order_by(SecretLeakFinding.scanned_at.desc()).limit(6).all()
    recent_sca = ScaDependencyFinding.query.order_by(ScaDependencyFinding.discovered_at.desc()).limit(6).all()

    return render_template(
        'appsec/index.html',
        total_rules=total_rules,
        total_waf_blocks=total_waf_blocks,
        open_secrets=open_secrets,
        sca_count=sca_count,
        recent_waf_events=recent_waf_events,
        recent_secrets=recent_secrets,
        recent_sca=recent_sca
    )

@appsec_bp.route('/waf', methods=['GET', 'POST'])
@login_required
def waf_monitor():
    if WafRule.query.count() == 0:
        WafEngineService.seed_waf_rules()

    rules = WafRule.query.all()
    test_result = None
    payload_input = None

    if request.method == 'POST':
        payload_input = request.form.get('payload', '').strip()
        if payload_input:
            ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1'
            test_result = WafEngineService.inspect_request_payload(
                payload=payload_input,
                endpoint='/appsec/waf/simulate',
                method='POST',
                client_ip=ip_addr
            )

    return render_template('appsec/waf_monitor.html', rules=rules, test_result=test_result, payload_input=payload_input)

@appsec_bp.route('/secrets', methods=['GET', 'POST'])
@login_required
def secret_scanner():
    findings = []
    code_snippet = None

    if request.method == 'POST':
        code_snippet = request.form.get('code_content', '').strip()
        file_path = request.form.get('file_path', 'workbench_snippet.py').strip()
        if code_snippet:
            findings = SecretLeakDetectorService.scan_text_for_secrets(code_snippet, file_path=file_path)
            flash(f"Scan complete: {len(findings)} credential exposures flagged.", "warning" if findings else "success")

    all_findings = SecretLeakFinding.query.order_by(SecretLeakFinding.scanned_at.desc()).limit(15).all()
    return render_template('appsec/secret_scanner.html', findings=findings, all_findings=all_findings, code_snippet=code_snippet)

@appsec_bp.route('/sca', methods=['GET', 'POST'])
@login_required
def sca_auditor():
    sample_packages = [
        ('requests', '2.28.1'),
        ('cryptography', '41.0.2'),
        ('flask', '3.0.2'),
        ('urllib3', '1.26.15')
    ]
    findings = []
    if request.method == 'POST':
        findings = ScaAnalyzerService.audit_dependencies(sample_packages)
        flash(f"SCA Audit finished: {len(findings)} vulnerable dependencies identified.", "warning" if findings else "success")

    all_sca = ScaDependencyFinding.query.order_by(ScaDependencyFinding.discovered_at.desc()).all()
    return render_template('appsec/sca_auditor.html', findings=findings, all_sca=all_sca)

# REST API Endpoints
@appsec_bp.route('/api/inspect-payload', methods=['POST'])
def api_inspect_payload():
    data = request.get_json() or {}
    payload = data.get('payload', '')
    if not payload:
        return jsonify({'success': False, 'error': 'Missing payload parameter'}), 400

    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1'
    result = WafEngineService.inspect_request_payload(payload=payload, client_ip=ip_addr)
    return jsonify({'success': True, 'waf_result': result})

@appsec_bp.route('/api/scan-secrets', methods=['POST'])
def api_scan_secrets():
    data = request.get_json() or {}
    content = data.get('content', '')
    if not content:
        return jsonify({'success': False, 'error': 'Missing content parameter'}), 400

    findings = SecretLeakDetectorService.scan_text_for_secrets(content)
    return jsonify({'success': True, 'findings_count': len(findings), 'findings': findings})

@appsec_bp.route('/api/audit-sca', methods=['POST'])
def api_audit_sca():
    data = request.get_json() or {}
    packages = data.get('packages', [])
    findings = ScaAnalyzerService.audit_dependencies(packages)
    return jsonify({'success': True, 'vulnerable_dependencies_count': len(findings), 'findings': findings})
