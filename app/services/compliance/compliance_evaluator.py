from app import db
from app.models.compliance import ComplianceFramework, ComplianceControl

SEED_FRAMEWORKS = [
    {
        'code': 'SOC2',
        'name': 'SOC 2 Type II Security & Confidentiality',
        'description': 'AICPA Trust Services Criteria addressing access control, encryption, monitoring, and incident response.',
        'controls': [
            {'control_id': 'CC6.1', 'title': 'Logical Access Security Controls', 'domain': 'Access Control', 'status': 'COMPLIANT', 'desc': 'Restricts logical access to authorized personnel via RBAC/PAM.'},
            {'control_id': 'CC6.6', 'title': 'Perimeter Threat Defense & WAF', 'domain': 'Network Defense', 'status': 'COMPLIANT', 'desc': 'Deploys WAF and network perimeter filters against injection and malware.'},
            {'control_id': 'CC6.7', 'title': 'Data Transmission Cryptographic Encryption', 'domain': 'Cryptography', 'status': 'COMPLIANT', 'desc': 'Enforces TLS 1.3 encryption across all network boundaries.'},
            {'control_id': 'CC7.2', 'title': 'Security Event Monitoring & Audit Trail', 'domain': 'Operations', 'status': 'COMPLIANT', 'desc': 'Maintains centralized audit logs of system activity and failed authentications.'}
        ]
    },
    {
        'code': 'ISO27001',
        'name': 'ISO/IEC 27001:2022 Information Security Management',
        'description': 'International standard for establishing, implementing, and maintaining an Information Security Management System (ISMS).',
        'controls': [
            {'control_id': 'A.5.15', 'title': 'Access Control Policies', 'domain': 'Governance', 'status': 'COMPLIANT', 'desc': 'Establishes zero-trust access control policy based on business requirements.'},
            {'control_id': 'A.8.20', 'title': 'Network Security Segregation', 'domain': 'Infrastructure', 'status': 'COMPLIANT', 'desc': 'Segregates sensitive vault enclaves from general subnets.'},
            {'control_id': 'A.8.24', 'title': 'Use of Cryptography & KMS', 'domain': 'Cryptography', 'status': 'COMPLIANT', 'desc': 'Defines rules for cryptographic key generation, rotation, and lifecycle.'}
        ]
    },
    {
        'code': 'NIST80053',
        'name': 'NIST SP 800-53 Rev. 5 Security Controls',
        'description': 'Federal information security standards catalog for federal and enterprise computing environments.',
        'controls': [
            {'control_id': 'AC-2', 'title': 'Account Management & JIT Elevation', 'domain': 'Access Control', 'status': 'COMPLIANT', 'desc': 'Automates account provisioning, suspension, and temporary PAM elevations.'},
            {'control_id': 'IA-2', 'title': 'Multi-Factor Authentication Identification', 'domain': 'Identity', 'status': 'COMPLIANT', 'desc': 'Mandates hardware MFA for privileged access to sensitive assets.'},
            {'control_id': 'SC-13', 'title': 'Cryptographic Protection & Key Management', 'domain': 'Cryptography', 'status': 'COMPLIANT', 'desc': 'Utilizes FIPS-approved algorithms (AES-256, RSA-2048, SHA-256) for data security.'}
        ]
    }
]

class ComplianceEvaluatorService:
    """Evaluates compliance frameworks, audits controls, and computes readiness percentages."""

    @classmethod
    def seed_compliance_frameworks(cls):
        """Seed default compliance frameworks and controls."""
        for f_data in SEED_FRAMEWORKS:
            framework = ComplianceFramework.query.filter_by(code=f_data['code']).first()
            if not framework:
                framework = ComplianceFramework(
                    code=f_data['code'],
                    name=f_data['name'],
                    description=f_data['description'],
                    total_controls=len(f_data['controls']),
                    passed_controls=len(f_data['controls']),
                    readiness_percentage=100.0
                )
                db.session.add(framework)
                db.session.flush()

                for c_data in f_data['controls']:
                    control = ComplianceControl(
                        framework_id=framework.id,
                        control_id=c_data['control_id'],
                        title=c_data['title'],
                        domain=c_data['domain'],
                        status=c_data['status'],
                        description=c_data['desc']
                    )
                    db.session.add(control)

        db.session.commit()

    @classmethod
    def recalculate_readiness(cls, framework_id: int) -> dict:
        """Recompute compliance readiness percentage based on control statuses."""
        framework = ComplianceFramework.query.get_or_404(framework_id)
        controls = ComplianceControl.query.filter_by(framework_id=framework.id).all()

        total = len(controls)
        passed = sum(1 for c in controls if c.status == 'COMPLIANT')

        pct = round((passed / max(1, total)) * 100.0, 1)
        framework.total_controls = total
        framework.passed_controls = passed
        framework.readiness_percentage = pct
        db.session.commit()

        return {
            'framework_code': framework.code,
            'total_controls': total,
            'passed_controls': passed,
            'readiness_percentage': pct
        }
