from app import db
from app.models.compliance import RiskRegisterItem

BUILTIN_RISKS = [
    {
        'risk_id': 'RSK-001',
        'title': 'Compromise of Root Master Encryption Key',
        'category': 'Cryptography',
        'likelihood': 1, # Rare
        'impact': 5, # Severe
        'mitigation': 'Split master key across 5 custodians via Shamir Secret Sharing; enforce annual rotation in hardware enclave.',
        'owner': 'CISO'
    },
    {
        'risk_id': 'RSK-002',
        'title': 'Credential Stuffing on Public SSO Gateway',
        'category': 'Identity',
        'likelihood': 4, # Likely
        'impact': 4, # Major
        'mitigation': 'Enforce exponential lockout, Cloudflare WAF bot mitigation, and mandatory WebAuthn hardware keys.',
        'owner': 'IAM Lead'
    },
    {
        'risk_id': 'RSK-003',
        'title': 'Zero-Day Vulnerability in Web Application Firewall',
        'category': 'Application',
        'likelihood': 2, # Unlikely
        'impact': 4, # Major
        'mitigation': 'Daily automated SCA scanning, container immutability, and rapid patch deployment CI/CD pipeline.',
        'owner': 'SecOps Lead'
    },
    {
        'risk_id': 'RSK-004',
        'title': 'Accidental Secret Exposure in Public Git Repositories',
        'category': 'Application',
        'likelihood': 3, # Moderate
        'impact': 3, # Moderate
        'mitigation': 'Pre-commit hook scanning with SecretLeakDetector and automated token revocation webhooks.',
        'owner': 'DevSecOps'
    }
]

class RiskMatrixService:
    """Computes 5x5 Likelihood x Impact enterprise risk matrix distribution."""

    @classmethod
    def seed_initial_risks(cls):
        """Seed foundational enterprise risks."""
        for r in BUILTIN_RISKS:
            existing = RiskRegisterItem.query.filter_by(risk_id=r['risk_id']).first()
            if not existing:
                score = r['likelihood'] * r['impact']
                rating = cls.calculate_risk_rating(score)
                item = RiskRegisterItem(
                    risk_id=r['risk_id'],
                    title=r['title'],
                    category=r['category'],
                    likelihood=r['likelihood'],
                    impact=r['impact'],
                    risk_score=score,
                    risk_rating=rating,
                    mitigation_strategy=r['mitigation'],
                    owner=r['owner'],
                    status='ACTIVE'
                )
                db.session.add(item)
        db.session.commit()

    @staticmethod
    def calculate_risk_rating(score: int) -> str:
        """Categorize 1 - 25 score into rating level."""
        if score >= 20:
            return 'CRITICAL'
        elif score >= 15:
            return 'HIGH'
        elif score >= 8:
            return 'MEDIUM'
        return 'LOW'

    @classmethod
    def get_risk_matrix_heatmap(cls) -> dict:
        """Generate 5x5 heatmap distribution counts."""
        items = RiskRegisterItem.query.filter_by(status='ACTIVE').all()
        matrix = [[0 for _ in range(5)] for _ in range(5)] # matrix[likelihood-1][impact-1]

        for item in items:
            l_idx = max(0, min(4, item.likelihood - 1))
            i_idx = max(0, min(4, item.impact - 1))
            matrix[l_idx][i_idx] += 1

        return {
            'matrix': matrix,
            'total_risks': len(items),
            'critical_risks': sum(1 for i in items if i.risk_rating == 'CRITICAL'),
            'high_risks': sum(1 for i in items if i.risk_rating == 'HIGH'),
            'medium_risks': sum(1 for i in items if i.risk_rating == 'MEDIUM'),
            'low_risks': sum(1 for i in items if i.risk_rating == 'LOW')
        }
