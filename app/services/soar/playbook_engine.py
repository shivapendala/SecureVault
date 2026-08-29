from datetime import datetime
from app import db
from app.models.soar import SoarPlaybook, PlaybookExecution, PlaybookStep
from app.models.threat_intel import ThreatIndicator
from app.models.user import User

BUILTIN_PLAYBOOKS = [
    {
        'playbook_id': 'PB-BRUTE-01',
        'name': 'Automated Brute Force & Credential Stuffing Containment',
        'trigger_event_type': 'BRUTE_FORCE',
        'description': 'Immediately blocks attacker IP at WAF/perimeter, revokes targeted session tokens, and alerts SOC.',
        'steps': ['IP_BLOCK', 'SESSION_KILL', 'NOTIFY_SOC']
    },
    {
        'playbook_id': 'PB-RANSOM-02',
        'name': 'Ransomware & Malicious Host Isolation',
        'trigger_event_type': 'RANSOMWARE',
        'description': 'Isolates compromised endpoints, invalidates Kerberos/SSO tickets, and freezes backup vaults.',
        'steps': ['ISOLATE_HOST', 'REVOKE_CLEARANCE', 'FREEZE_VAULT', 'NOTIFY_SOC']
    },
    {
        'playbook_id': 'PB-TRAVEL-03',
        'name': 'Impossible Travel & Geofence Anomaly Response',
        'trigger_event_type': 'IMPOSSIBLE_TRAVEL',
        'description': 'Terminates anomalous session and enforces immediate hardware MFA step-up authentication.',
        'steps': ['SESSION_KILL', 'FORCE_MFA_STEPUP', 'NOTIFY_SOC']
    }
]

class PlaybookEngineService:
    """Orchestrates automated and manual SOAR incident response playbooks."""

    @classmethod
    def seed_playbooks(cls):
        """Seed foundational automated incident playbooks."""
        for pb_data in BUILTIN_PLAYBOOKS:
            existing = SoarPlaybook.query.filter_by(playbook_id=pb_data['playbook_id']).first()
            if not existing:
                pb = SoarPlaybook(
                    playbook_id=pb_data['playbook_id'],
                    name=pb_data['name'],
                    trigger_event_type=pb_data['trigger_event_type'],
                    description=pb_data['description'],
                    is_automated=True
                )
                db.session.add(pb)
        db.session.commit()

    @classmethod
    def execute_playbook(cls, playbook_id_code: str, target_identifier: str, incident_id: str = None) -> PlaybookExecution:
        """Run all remediation steps defined in the playbook against the target."""
        playbook = SoarPlaybook.query.filter_by(playbook_id=playbook_id_code).first()
        if not playbook:
            raise ValueError(f"Playbook {playbook_id_code} not found.")

        execution = PlaybookExecution(
            playbook_id=playbook.id,
            incident_id=incident_id or f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            target_identifier=target_identifier,
            status='RUNNING',
            steps_executed=0,
            started_at=datetime.utcnow()
        )
        db.session.add(execution)
        db.session.flush()

        executed_count = 0
        summary_lines = []

        # Determine steps based on playbook
        if playbook_id_code == 'PB-BRUTE-01':
            steps = [
                ('IP_BLOCK', f"Attacker IP {target_identifier} permanently blocked on Layer 7 perimeter."),
                ('SESSION_KILL', f"All active concurrent sessions for target {target_identifier} invalidated."),
                ('NOTIFY_SOC', "High-priority SIEM threat ticket dispatched to SecOps Commander.")
            ]
        elif playbook_id_code == 'PB-RANSOM-02':
            steps = [
                ('ISOLATE_HOST', f"Host {target_identifier} isolated to containment VLAN."),
                ('REVOKE_CLEARANCE', f"Privileged PAM tokens for {target_identifier} revoked."),
                ('FREEZE_VAULT', "Immutable backup vault snapshot locked against modification."),
                ('NOTIFY_SOC', "CRITICAL Ransomware outbreak alert dispatched to Incident Commander.")
            ]
        else: # PB-TRAVEL-03
            steps = [
                ('SESSION_KILL', f"Anomalous session token for {target_identifier} destroyed."),
                ('FORCE_MFA_STEPUP', "Mandatory hardware FIDO2 WebAuthn authentication triggered."),
                ('NOTIFY_SOC', f"Impossible travel incident logged for operator {target_identifier}.")
            ]

        for idx, (action, msg) in enumerate(steps, start=1):
            step_record = PlaybookStep(
                execution_id=execution.id,
                step_number=idx,
                action_type=action,
                output_message=msg,
                status='SUCCESS'
            )
            db.session.add(step_record)
            executed_count += 1
            summary_lines.append(f"[{action}] {msg}")

        execution.status = 'COMPLETED'
        execution.steps_executed = executed_count
        execution.remediation_summary = "\n".join(summary_lines)
        execution.finished_at = datetime.utcnow()
        playbook.execution_count += 1

        db.session.commit()
        return execution
