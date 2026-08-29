from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from app import db
from app.utils.decorators import login_required, roles_required
from app.models.network_security import TlsCertificateScan, HttpSecurityHeadersScan, DnsSecRecordScan, PortScanResult
from app.services.network_security.tls_inspector import TlsInspectorService
from app.services.network_security.headers_analyzer import HttpHeadersAnalyzerService
from app.services.network_security.dns_security import DnsSecurityService
from app.services.network_security.port_scanner import PortScannerService

netsec_bp = Blueprint('network_security', __name__, url_prefix='/network-security')

@netsec_bp.route('/')
@login_required
def index():
    recent_tls = TlsCertificateScan.query.order_by(TlsCertificateScan.scanned_at.desc()).limit(5).all()
    recent_headers = HttpSecurityHeadersScan.query.order_by(HttpSecurityHeadersScan.scanned_at.desc()).limit(5).all()
    recent_dns = DnsSecRecordScan.query.order_by(DnsSecRecordScan.scanned_at.desc()).limit(5).all()
    recent_ports = PortScanResult.query.filter_by(state='OPEN').order_by(PortScanResult.scanned_at.desc()).limit(8).all()

    return render_template(
        'network_security/index.html',
        recent_tls=recent_tls,
        recent_headers=recent_headers,
        recent_dns=recent_dns,
        recent_ports=recent_ports
    )

@netsec_bp.route('/tls', methods=['GET', 'POST'])
@login_required
def tls_inspector():
    host = request.args.get('host', '').strip() or request.form.get('host', '').strip()
    result = None
    if host:
        result = TlsInspectorService.inspect_host_certificate(host)
    return render_template('network_security/tls_inspector.html', host=host, result=result)

@netsec_bp.route('/headers', methods=['GET', 'POST'])
@login_required
def headers_analyzer():
    url = request.args.get('url', '').strip() or request.form.get('url', '').strip()
    result = None
    if url:
        result = HttpHeadersAnalyzerService.analyze_headers(url)
    return render_template('network_security/headers_analyzer.html', url=url, result=result)

@netsec_bp.route('/dns', methods=['GET', 'POST'])
@login_required
def dns_defense():
    domain = request.args.get('domain', '').strip() or request.form.get('domain', '').strip()
    result = None
    if domain:
        result = DnsSecurityService.evaluate_domain_defense(domain)
    return render_template('network_security/dns_defense.html', domain=domain, result=result)

@netsec_bp.route('/ports', methods=['GET', 'POST'])
@login_required
def port_scanner():
    target = request.args.get('target', '').strip() or request.form.get('target', '').strip()
    results = []
    if target:
        results = PortScannerService.scan_target_ports(target)
    return render_template('network_security/port_scanner.html', target=target, results=results)

# REST API Endpoints
@netsec_bp.route('/api/scan-tls', methods=['POST'])
def api_scan_tls():
    data = request.get_json() or {}
    host = data.get('host')
    if not host:
        return jsonify({'success': False, 'error': 'Missing host parameter'}), 400
    res = TlsInspectorService.inspect_host_certificate(host)
    return jsonify({'success': True, 'tls_data': res})

@netsec_bp.route('/api/scan-headers', methods=['POST'])
def api_scan_headers():
    data = request.get_json() or {}
    url = data.get('url')
    if not url:
        return jsonify({'success': False, 'error': 'Missing url parameter'}), 400
    res = HttpHeadersAnalyzerService.analyze_headers(url)
    return jsonify({'success': True, 'headers_data': res})

@netsec_bp.route('/api/scan-dns', methods=['POST'])
def api_scan_dns():
    data = request.get_json() or {}
    domain = data.get('domain')
    if not domain:
        return jsonify({'success': False, 'error': 'Missing domain parameter'}), 400
    res = DnsSecurityService.evaluate_domain_defense(domain)
    return jsonify({'success': True, 'dns_data': res})

@netsec_bp.route('/api/scan-ports', methods=['POST'])
def api_scan_ports():
    data = request.get_json() or {}
    host = data.get('host')
    if not host:
        return jsonify({'success': False, 'error': 'Missing host parameter'}), 400
    res = PortScannerService.scan_target_ports(host)
    return jsonify({'success': True, 'ports_data': res})
