from datetime import datetime, timedelta
from app import db
from app.models.iam import AccessRequest
from app.models.user import User

class PamService:
    """Privileged Access Management (PAM) Just-in-Time access elevation controller."""

    @classmethod
    def create_access_request(cls, user_id: int, target_resource: str, requested_role: str, justification: str, duration_hours: int = 2) -> AccessRequest:
        """Submit a Just-in-Time elevation access request."""
        req = AccessRequest(
            user_id=user_id,
            target_resource=target_resource,
            requested_role=requested_role,
            duration_hours=duration_hours,
            justification=justification,
            status='PENDING'
        )
        db.session.add(req)
        db.session.commit()
        return req

    @classmethod
    def approve_request(cls, request_id: int, approver_id: int) -> dict:
        """Dual-operator approval of PAM elevation request."""
        req = AccessRequest.query.get_or_404(request_id)
        if req.user_id == approver_id:
            return {'success': False, 'message': 'Self-approval is blocked by Zero-Trust Dual-Operator policy.'}

        req.status = 'APPROVED'
        req.approved_by_id = approver_id
        req.expires_at = datetime.utcnow() + timedelta(hours=req.duration_hours)

        # Elevate user's active clearance
        user = User.query.get(req.user_id)
        if user:
            user.role = req.requested_role

        db.session.commit()
        return {'success': True, 'message': f"Access granted for {req.duration_hours} hours.", 'request': req.to_dict()}

    @classmethod
    def reject_request(cls, request_id: int, approver_id: int) -> dict:
        """Reject PAM elevation request."""
        req = AccessRequest.query.get_or_404(request_id)
        req.status = 'REJECTED'
        req.approved_by_id = approver_id
        db.session.commit()
        return {'success': True, 'message': 'Access request rejected.', 'request': req.to_dict()}
