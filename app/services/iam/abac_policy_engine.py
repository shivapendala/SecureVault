import ipaddress
import fnmatch
from app import db
from app.models.iam import PermissionPolicy

BUILTIN_ABAC_POLICIES = [
    {
        'policy_name': 'Vault-Secrets-Admin-Enclave',
        'action': 'READ',
        'resource_pattern': '/vault/*',
        'required_role': 'Admin',
        'require_mfa': True,
        'ip_subnet_restriction': None
    },
    {
        'policy_name': 'SOC-Incident-Response-Write',
        'action': 'WRITE',
        'resource_pattern': '/incidents/*',
        'required_role': 'Analyst',
        'require_mfa': True,
        'ip_subnet_restriction': None
    },
    {
        'policy_name': 'Cryptographic-Key-Rotation-Execute',
        'action': 'ELEVATE',
        'resource_pattern': '/kms/*',
        'required_role': 'Admin',
        'require_mfa': True,
        'ip_subnet_restriction': '127.0.0.1/32'
    }
]

class AbacPolicyEngine:
    """Attribute-Based Access Control (ABAC) dynamic evaluation engine."""

    @classmethod
    def seed_policies(cls):
        """Seed foundational ABAC policies."""
        for p in BUILTIN_ABAC_POLICIES:
            existing = PermissionPolicy.query.filter_by(policy_name=p['policy_name']).first()
            if not existing:
                pol = PermissionPolicy(
                    policy_name=p['policy_name'],
                    action=p['action'],
                    resource_pattern=p['resource_pattern'],
                    required_role=p['required_role'],
                    require_mfa=p['require_mfa'],
                    ip_subnet_restriction=p['ip_subnet_restriction'],
                    is_active=True
                )
                db.session.add(pol)
        db.session.commit()

    @classmethod
    def evaluate_access(cls, user_role: str, user_has_mfa: bool, client_ip: str, requested_resource: str, action: str) -> dict:
        """Evaluate if user context matches ABAC policies."""
        policies = PermissionPolicy.query.filter_by(is_active=True, action=action).all()

        for pol in policies:
            if fnmatch.fnmatch(requested_resource, pol.resource_pattern):
                # 1. Role clearance check
                if pol.required_role != user_role and user_role != 'Admin':
                    return {'allowed': False, 'reason': f"Requires '{pol.required_role}' clearance (Current: '{user_role}')."}

                # 2. MFA Requirement
                if pol.require_mfa and not user_has_mfa:
                    return {'allowed': False, 'reason': "Zero-Trust policy requires hardware 2FA/MFA token verification."}

                # 3. IP Subnet restriction
                if pol.ip_subnet_restriction:
                    try:
                        net = ipaddress.ip_network(pol.ip_subnet_restriction, strict=False)
                        if ipaddress.ip_address(client_ip) not in net:
                            return {'allowed': False, 'reason': f"Client IP {client_ip} outside authorized subnet ({pol.ip_subnet_restriction})."}
                    except ValueError:
                        pass

                return {'allowed': True, 'matched_policy': pol.policy_name, 'reason': 'All ABAC criteria satisfied.'}

        # Default open for unmapped standard routes
        return {'allowed': True, 'matched_policy': 'DEFAULT_PERMIT', 'reason': 'No restrictive policy applied.'}
