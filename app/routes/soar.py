from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from app import db
from app.utils.decorators import login_required, roles_required, admin_required
from app.models.soar import SoarPlaybook, PlaybookExecution, PlaybookStep
from app.services.soar.playbook_engine import PlaybookEngineService
from app.services.soar.threat_containment import ThreatContainmentCoordinator

soar_bp = Blueprint('soar', __name__, url_prefix='/soar')

@soar_bp.route('/')
@login_required
def index():
    if SoarPlaybook.query.count() == 0:
        PlaybookEngineService.seed_playbooks()

    playbooks = SoarPlaybook.query.all()
    executions_count = PlaybookExecution.query.count()
    recent_executions = PlaybookExecution.query.order_by(PlaybookExecution.started_at.desc()).limit(8).all()

    return render_template(
        'soar/index.html',
        playbooks=playbooks,
        executions_count=executions_count,
        recent_executions=recent_executions
    )

@soar_bp.route('/playbooks')
@login_required
def playbook_list():
    if SoarPlaybook.query.count() == 0:
        PlaybookEngineService.seed_playbooks()
    playbooks = SoarPlaybook.query.all()
    return render_template('soar/playbook_list.html', playbooks=playbooks)

@soar_bp.route('/executions/<int:execution_id>')
@login_required
def execution_detail(execution_id):
    execution = PlaybookExecution.query.get_or_404(execution_id)
    steps = PlaybookStep.query.filter_by(execution_id=execution.id).order_by(PlaybookStep.step_number.asc()).all()
    return render_template('soar/execution_detail.html', execution=execution, steps=steps)

@soar_bp.route('/trigger', methods=['GET', 'POST'])
@login_required
@roles_required('Admin', 'Security Analyst', 'Analyst')
def trigger_incident():
    if SoarPlaybook.query.count() == 0:
        PlaybookEngineService.seed_playbooks()

    playbooks = SoarPlaybook.query.all()

    if request.method == 'POST':
        pb_code = request.form.get('playbook_id', '').strip()
        target = request.form.get('target_identifier', '').strip()
        incident_ref = request.form.get('incident_id', '').strip()

        if pb_code and target:
            try:
                execution = PlaybookEngineService.execute_playbook(pb_code, target, incident_ref)
                flash(f"Playbook {pb_code} executed successfully! ({execution.steps_executed} containment steps applied).", "success")
                return redirect(url_for('soar.execution_detail', execution_id=execution.id))
            except Exception as e:
                flash(f"Execution failed: {str(e)}", "danger")

    return render_template('soar/trigger_incident.html', playbooks=playbooks)

# REST API Endpoints
@soar_bp.route('/api/playbooks', methods=['GET'])
def api_playbooks():
    if SoarPlaybook.query.count() == 0:
        PlaybookEngineService.seed_playbooks()
    playbooks = SoarPlaybook.query.all()
    return jsonify({'success': True, 'playbooks': [pb.to_dict() for pb in playbooks]})

@soar_bp.route('/api/trigger-playbook', methods=['POST'])
def api_trigger_playbook():
    data = request.get_json() or {}
    pb_code = data.get('playbook_id', 'PB-BRUTE-01')
    target = data.get('target_identifier', '198.51.100.22')
    incident_id = data.get('incident_id')

    if not target:
        return jsonify({'success': False, 'error': 'Missing target_identifier parameter'}), 400

    try:
        execution = PlaybookEngineService.execute_playbook(pb_code, target, incident_id)
        return jsonify({'success': True, 'execution': execution.to_dict()}), 201
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400
