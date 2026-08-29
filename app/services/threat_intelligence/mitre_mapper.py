from app import db
from app.models.threat_intel import MitreAttackTechnique, ThreatIndicator

ENTERPRISE_MITRE_DATA = [
    {
        'tactic_id': 'TA0001',
        'tactic_name': 'Initial Access',
        'technique_id': 'T1190',
        'technique_name': 'Exploit Public-Facing Application',
        'description': 'Adversaries may attempt to exploit a weakness in an Internet-facing host or software.',
        'detection_strategy': 'Monitor application logs, WAF alerts for unusual payload spikes, and out-of-band requests.',
        'mitigation': 'Deploy web application firewalls, apply vendor patches, and segment public subnets.'
    },
    {
        'tactic_id': 'TA0001',
        'tactic_name': 'Initial Access',
        'technique_id': 'T1566',
        'technique_name': 'Phishing',
        'description': 'Adversaries send phishing messages with malicious attachments or links to obtain credentials or execute code.',
        'detection_strategy': 'Inspect email header SPF/DKIM/DMARC signatures, analyze attachment hashes, and scan links against IoC lists.',
        'mitigation': 'Enforce DMARC quarantine policy, implement multi-factor authentication, and host security awareness training.'
    },
    {
        'tactic_id': 'TA0006',
        'tactic_name': 'Credential Access',
        'technique_id': 'T1110',
        'technique_name': 'Brute Force',
        'description': 'Adversaries may attempt to systematically guess passwords or credential tokens to gain authentication clearance.',
        'detection_strategy': 'Aggregate authentication telemetry, flag 5+ failures within a 15-minute window, and inspect IP distributions.',
        'mitigation': 'Enforce account lockouts, dynamic exponential backoff, and require hardware FIDO2 MFA tokens.'
    },
    {
        'tactic_id': 'TA0005',
        'tactic_name': 'Defense Evasion',
        'technique_id': 'T1070',
        'technique_name': 'Indicator Removal on Host',
        'description': 'Adversaries may delete or alter event logs, audit trails, and file baselines to obfuscate intrusion evidence.',
        'detection_strategy': 'Forward logs to immutable append-only SIEM and verify SHA-256 cryptographic checksum chains on audit ledgers.',
        'mitigation': 'Restrict log file permissions, enable remote syslog streaming, and store hash baselines in separate secure vault.'
    },
    {
        'tactic_id': 'TA0011',
        'tactic_name': 'Command and Control',
        'technique_id': 'T1071',
        'technique_name': 'Application Layer Protocol',
        'description': 'Adversaries may communicate using application layer protocols (HTTP/HTTPS/DNS) to blend in with legitimate network traffic.',
        'detection_strategy': 'Analyze TLS certificate parameters, domain age, beacon intervals, and query reputation feeds.',
        'mitigation': 'Inspect encrypted egress traffic with next-gen firewalls and enforce strict DNS filtering.'
    },
    {
        'tactic_id': 'TA0010',
        'tactic_name': 'Exfiltration',
        'technique_id': 'T1048',
        'technique_name': 'Exfiltration Over Alternative Protocol',
        'description': 'Adversaries may steal data using different protocols or encrypted tunnels to bypass standard perimeter filters.',
        'detection_strategy': 'Monitor outbound payload sizes, high-entropy uploads, and irregular data transfer volumes.',
        'mitigation': 'Enforce zero-trust data loss prevention (DLP), block unauthorized cloud storage, and inspect upload mime-types.'
    }
]

class MitreMapperService:
    """Service to map threat detections, vulnerabilities, and IoCs to the MITRE ATT&CK Matrix."""

    @classmethod
    def seed_mitre_techniques(cls):
        """Seed foundational MITRE ATT&CK Enterprise matrix techniques."""
        for item in ENTERPRISE_MITRE_DATA:
            existing = MitreAttackTechnique.query.filter_by(technique_id=item['technique_id']).first()
            if not existing:
                tech = MitreAttackTechnique(
                    tactic_id=item['tactic_id'],
                    tactic_name=item['tactic_name'],
                    technique_id=item['technique_id'],
                    technique_name=item['technique_name'],
                    description=item['description'],
                    detection_strategy=item['detection_strategy'],
                    mitigation=item['mitigation']
                )
                db.session.add(tech)
        db.session.commit()

    @classmethod
    def get_tactics_overview(cls) -> list[dict]:
        """Aggregate tactics, techniques, and active IoC coverage."""
        techniques = MitreAttackTechnique.query.all()
        tactics_map = {}

        for tech in techniques:
            t_name = tech.tactic_name
            if t_name not in tactics_map:
                tactics_map[t_name] = {
                    'tactic_id': tech.tactic_id,
                    'tactic_name': t_name,
                    'techniques': [],
                    'associated_iocs': 0
                }
            
            # Count IoCs mapped to this technique
            ioc_count = ThreatIndicator.query.filter_by(mitre_technique_id=tech.technique_id).count()
            tactics_map[t_name]['associated_iocs'] += ioc_count

            tactics_map[t_name]['techniques'].append({
                'id': tech.id,
                'technique_id': tech.technique_id,
                'technique_name': tech.technique_name,
                'description': tech.description,
                'ioc_count': ioc_count
            })

        return list(tactics_map.values())
