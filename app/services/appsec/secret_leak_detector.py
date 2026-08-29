import re
from datetime import datetime
from app import db
from app.models.appsec import SecretLeakFinding

SECRET_PATTERNS = [
    {
        'type': 'AWS_ACCESS_KEY',
        'pattern': r'\b(AKIA[0-9A-Z]{16})\b',
        'severity': 'CRITICAL',
        'confidence': 98
    },
    {
        'type': 'GITHUB_PAT',
        'pattern': r'\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{50,})\b',
        'severity': 'CRITICAL',
        'confidence': 99
    },
    {
        'type': 'PRIVATE_RSA_KEY',
        'pattern': r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
        'severity': 'CRITICAL',
        'confidence': 100
    },
    {
        'type': 'JWT_TOKEN',
        'pattern': r'\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b',
        'severity': 'HIGH',
        'confidence': 90
    },
    {
        'type': 'STRIPE_API_KEY',
        'pattern': r'\b(sk_live_[0-9a-zA-Z]{24})\b',
        'severity': 'CRITICAL',
        'confidence': 95
    },
    {
        'type': 'DATABASE_URI_CREDENTIALS',
        'pattern': r'(mysql|postgres|mongodb):\/\/[^:]+:([^@]+)@',
        'severity': 'HIGH',
        'confidence': 85
    }
]

class SecretLeakDetectorService:
    """Scans code snippets, config files, and commit payloads for leaked credentials and API tokens."""

    @classmethod
    def scan_text_for_secrets(cls, text: str, file_path: str = 'memory_scan.py') -> list[dict]:
        """Scan text and mask detected credentials."""
        if not text:
            return []

        findings = []
        lines = text.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            for sec in SECRET_PATTERNS:
                matches = re.finditer(sec['pattern'], line)
                for match in matches:
                    raw_val = match.group(0)
                    masked_val = raw_val[:4] + '****' + raw_val[-4:] if len(raw_val) > 8 else '****'

                    finding = SecretLeakFinding(
                        secret_type=sec['type'],
                        snippet_masked=masked_val,
                        file_path=file_path,
                        line_number=line_idx,
                        severity=sec['severity'],
                        confidence=sec['confidence'],
                        status='OPEN'
                    )
                    db.session.add(finding)
                    findings.append(finding.to_dict())

        if findings:
            db.session.commit()

        return findings
