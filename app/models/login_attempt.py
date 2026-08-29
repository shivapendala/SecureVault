from datetime import datetime
from app import db

class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username_attempted = db.Column(db.String(120), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    user_agent = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(20), nullable=False, default='SUCCESS') # SUCCESS, FAILED, BLOCKED, MFA_REQUIRED
    failure_reason = db.Column(db.String(255), nullable=True)
    attempted_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def get_browser_info(self) -> str:
        """Parse user agent into a human-friendly format."""
        ua = (self.user_agent or "").lower()
        if not ua:
            return "Standard Client"
        
        # Determine OS
        if "windows nt 10" in ua:
            os_name = "Windows 10/11"
        elif "windows" in ua:
            os_name = "Windows"
        elif "macintosh" in ua or "mac os x" in ua:
            os_name = "macOS"
        elif "iphone" in ua or "ipad" in ua:
            os_name = "iOS"
        elif "android" in ua:
            os_name = "Android"
        elif "linux" in ua:
            os_name = "Linux"
        else:
            os_name = "Device"

        # Determine Browser
        if "edg" in ua:
            browser = "Edge"
        elif "chrome" in ua and "safari" in ua:
            browser = "Chrome"
        elif "safari" in ua and "chrome" not in ua:
            browser = "Safari"
        elif "firefox" in ua:
            browser = "Firefox"
        elif "opr" in ua or "opera" in ua:
            browser = "Opera"
        elif "curl" in ua or "requests" in ua or "python" in ua:
            browser = "API/CLI Script"
        else:
            browser = "Web Browser"

        return f"{browser} ({os_name})"

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username_attempted': self.username_attempted,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'browser_info': self.get_browser_info(),
            'status': self.status,
            'failure_reason': self.failure_reason,
            'attempted_at': self.attempted_at.strftime('%Y-%m-%d %H:%M:%S')
        }
