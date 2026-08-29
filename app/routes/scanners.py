from flask import Blueprint, render_template, request, jsonify
from app import db
from app.models.scan import ScanReport
from app.utils.decorators import login_required, log_audit
from app.utils.scanners_engine import analyze_security_headers, scan_target_ports
from app.utils.crypto import calculate_password_entropy

scanners_bp = Blueprint('scanners', __name__)

@scanners_bp.route('/')
@login_required
def index():
    reports = ScanReport.query.order_by(ScanReport.created_at.desc()).limit(10).all()
    return render_template('scanners/index.html', reports=reports)

@scanners_bp.route('/api/scan-headers', methods=['POST'])
@login_required
def api_scan_headers():
    data = request.get_json() or {}
    target_url = data.get('url', '').strip()
    
    if not target_url:
        return jsonify({'status': 'error', 'message': 'Target URL is required.'}), 400
        
    results = analyze_security_headers(target_url)
    
    # Save report
    report = ScanReport(
        scan_type='Web Headers & SSL',
        target=target_url,
        grade=results.get('grade', 'C'),
        score=results.get('score', 50),
        summary=f"Analyzed {results.get('domain')} - Grade {results.get('grade')} ({results.get('score')}/100)"
    )
    report.set_result(results)
    db.session.add(report)
    db.session.commit()
    
    log_audit('HEADER_SCAN', 'Scanner', report.id, f"Executed web header scan on {target_url} (Grade {results.get('grade')})", status='SUCCESS')
    
    return jsonify({
        'status': 'success',
        'report_id': report.id,
        'results': results
    })

@scanners_bp.route('/api/scan-ports', methods=['POST'])
@login_required
def api_scan_ports():
    data = request.get_json() or {}
    host = data.get('host', '').strip()
    
    if not host:
        return jsonify({'status': 'error', 'message': 'Target host is required.'}), 400
        
    ports_res = scan_target_ports(host)
    open_count = sum(1 for p in ports_res if p['status'] == 'Open')
    
    report = ScanReport(
        scan_type='Port Recon',
        target=host,
        grade='PASS' if open_count < 3 else 'WARN',
        score=max(20, 100 - (open_count * 15)),
        summary=f"Recon completed on {host}: {open_count} open service ports detected."
    )
    report.set_result({'host': host, 'ports': ports_res, 'open_count': open_count})
    db.session.add(report)
    db.session.commit()
    
    log_audit('PORT_SCAN_TOOL', 'Scanner', report.id, f"Executed port recon on {host}", status='SUCCESS')
    
    return jsonify({
        'status': 'success',
        'report_id': report.id,
        'results': {'host': host, 'ports': ports_res, 'open_count': open_count}
    })

@scanners_bp.route('/api/password-entropy', methods=['POST'])
@login_required
def api_password_entropy():
    data = request.get_json() or {}
    password = data.get('password', '')
    
    entropy_info = calculate_password_entropy(password)
    return jsonify({
        'status': 'success',
        'analysis': entropy_info
    })
