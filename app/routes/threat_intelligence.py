from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, session
from app import db
from app.utils.decorators import login_required, roles_required
from app.models.threat_intel import ThreatIndicator, ThreatFeedSource, IoCMatchEvent, MitreAttackTechnique
from app.services.threat_intelligence.ioc_matcher import IoCMatcherService
from app.services.threat_intelligence.mitre_mapper import MitreMapperService
from app.services.threat_intelligence.geoip_service import GeoIpService
from app.services.threat_intelligence.feed_manager import ThreatFeedManager

threat_intel_bp = Blueprint('threat_intel', __name__, url_prefix='/threat-intelligence')

@threat_intel_bp.route('/')
@login_required
def index():
    # Ensure seed data exists
    if ThreatIndicator.query.count() == 0:
        ThreatFeedManager.seed_initial_threat_data()
    if MitreAttackTechnique.query.count() == 0:
        MitreMapperService.seed_mitre_techniques()

    total_iocs = ThreatIndicator.query.count()
    critical_iocs = ThreatIndicator.query.filter_by(severity='CRITICAL').count()
    high_iocs = ThreatIndicator.query.filter_by(severity='HIGH').count()
    total_matches = IoCMatchEvent.query.count()
    active_feeds = ThreatFeedSource.query.filter_by(status='ACTIVE').count()

    recent_indicators = ThreatIndicator.query.order_by(ThreatIndicator.last_seen.desc()).limit(10).all()
    recent_matches = IoCMatchEvent.query.order_by(IoCMatchEvent.matched_at.desc()).limit(8).all()
    feed_sources = ThreatFeedSource.query.all()

    return render_template(
        'threat_intelligence/index.html',
        total_iocs=total_iocs,
        critical_iocs=critical_iocs,
        high_iocs=high_iocs,
        total_matches=total_matches,
        active_feeds=active_feeds,
        recent_indicators=recent_indicators,
        recent_matches=recent_matches,
        feed_sources=feed_sources
    )

@threat_intel_bp.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    query = request.args.get('q', '').strip() or request.form.get('query', '').strip()
    result = None
    geo_data = None

    if query:
        result = IoCMatcherService.query_indicator(query)
        # If IP, enrich with GeoIP intelligence
        ind_type = IoCMatcherService.identify_indicator_type(query)
        if ind_type == 'IP':
            geo_data = GeoIpService.lookup_ip_intelligence(query)

    return render_template('threat_intelligence/search.html', query=query, result=result, geo_data=geo_data)

@threat_intel_bp.route('/mitre')
@login_required
def mitre_matrix():
    if MitreAttackTechnique.query.count() == 0:
        MitreMapperService.seed_mitre_techniques()

    tactics = MitreMapperService.get_tactics_overview()
    return render_template('threat_intelligence/mitre.html', tactics=tactics)

@threat_intel_bp.route('/iocs/add', methods=['GET', 'POST'])
@login_required
@roles_required('Admin', 'Security Analyst', 'Analyst')
def add_ioc():
    if request.method == 'POST':
        val = request.form.get('indicator_value', '').strip()
        threat_type = request.form.get('threat_type', 'Malware').strip()
        severity = request.form.get('severity', 'HIGH').strip()
        confidence = int(request.form.get('confidence_score', 85))
        mitre_tech = request.form.get('mitre_technique_id', '').strip()
        description = request.form.get('description', '').strip()

        if not val:
            flash("Indicator value cannot be empty.", "warning")
            return redirect(url_for('threat_intel.add_ioc'))

        existing = ThreatIndicator.query.filter_by(indicator_value=val).first()
        if existing:
            flash(f"Indicator '{val}' is already registered in the Threat Intelligence matrix.", "info")
            return redirect(url_for('threat_intel.index'))

        ind_type = IoCMatcherService.identify_indicator_type(val)
        new_ind = ThreatIndicator(
            indicator_type=ind_type,
            indicator_value=val,
            threat_type=threat_type,
            severity=severity,
            confidence_score=confidence,
            source_name=f"Manual Operator Entry ({session.get('user_name', 'Analyst')})",
            mitre_technique_id=mitre_tech if mitre_tech else None,
            description=description
        )
        db.session.add(new_ind)
        db.session.commit()

        flash(f"Threat Indicator '{val}' ({ind_type}) successfully enrolled with {severity} severity.", "success")
        return redirect(url_for('threat_intel.index'))

    techniques = MitreAttackTechnique.query.all()
    return render_template('threat_intelligence/add_ioc.html', techniques=techniques)

@threat_intel_bp.route('/feeds/sync/<int:feed_id>', methods=['POST'])
@login_required
@roles_required('Admin', 'Security Analyst', 'Analyst')
def sync_feed(feed_id):
    res = ThreatFeedManager.sync_feed(feed_id)
    flash(res['message'], "success")
    return redirect(url_for('threat_intel.index'))

# REST API Endpoints for Threat Intel
@threat_intel_bp.route('/api/lookup', methods=['GET', 'POST'])
def api_lookup():
    val = request.args.get('indicator') or (request.get_json() or {}).get('indicator')
    if not val:
        return jsonify({'success': False, 'error': 'Missing indicator parameter'}), 400

    result = IoCMatcherService.query_indicator(val)
    geo = None
    if IoCMatcherService.identify_indicator_type(val) == 'IP':
        geo = GeoIpService.lookup_ip_intelligence(val)

    return jsonify({
        'success': True,
        'query': val,
        'result': result,
        'geo_intelligence': geo
    })

@threat_intel_bp.route('/api/scan-payload', methods=['POST'])
def api_scan_payload():
    data = request.get_json() or {}
    payload = data.get('payload', '')
    if not payload:
        return jsonify({'success': False, 'error': 'Missing payload body'}), 400

    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_id = session.get('user_id')

    matches = IoCMatcherService.scan_payload_for_iocs(payload, source_ip=ip_addr, user_id=user_id)
    return jsonify({
        'success': True,
        'scanned_characters': len(payload),
        'match_count': len(matches),
        'matches': matches
    })
