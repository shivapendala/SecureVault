import hashlib
import uuid
from datetime import datetime
from app import db
from app.models.compliance import AuditEvidence

class EvidenceLockerService:
    """Manages immutable cryptographic evidence records for SOC 2 and ISO 27001 audits."""

    @classmethod
    def seal_evidence(cls, framework_code: str, control_id: str, title: str, raw_content_str: str, evidence_type: str = 'System Telemetry') -> AuditEvidence:
        """Create an audit evidence record sealed with SHA-256 integrity hash."""
        seal_hash = hashlib.sha256(raw_content_str.encode('utf-8')).hexdigest()
        code = f"EVD-{framework_code}-{control_id}-{uuid.uuid4().hex[:6].upper()}"

        evidence = AuditEvidence(
            evidence_code=code,
            framework_code=framework_code,
            control_id=control_id,
            title=title,
            evidence_type=evidence_type,
            sha256_seal=seal_hash,
            verified=True
        )
        db.session.add(evidence)
        db.session.commit()
        return evidence

    @classmethod
    def verify_evidence_seal(cls, evidence_id: int, candidate_content_str: str) -> bool:
        """Verify candidate evidence content against stored cryptographic seal."""
        ev = AuditEvidence.query.get_or_404(evidence_id)
        computed_hash = hashlib.sha256(candidate_content_str.encode('utf-8')).hexdigest()
        return computed_hash == ev.sha256_seal
