import re
from datetime import datetime
from app import db
from app.models.appsec import WafRule, WafSecurityEvent

BUILTIN_WAF_RULES = [
    {
        'rule_id': 'WAF-SQLI-001',
        'rule_name': 'SQL Injection - Union / Select Detection',
        'category': 'SQLi',
        'regex_pattern': r"(?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\binsert\b.*\binto\b|\bdrop\b.*\btable\b|--|\bOR\b\s+1\s*=\s*1|'\s*OR\s*'1'\s*=\s*'1')",
        'severity': 'CRITICAL',
        'action': 'BLOCK',
        'description': 'Intercepts classic and blind SQL injection payloads attempting unauthorized database exfiltration.'
    },
    {
        'rule_id': 'WAF-XSS-002',
        'rule_name': 'Cross-Site Scripting (XSS) Script Tag & Event Handler',
        'category': 'XSS',
        'regex_pattern': r"(?i)(<script.*?>.*?</script>|javascript:|onerror\s*=|onload\s*=|alert\(|document\.cookie|<img\s+src=.*?onerror)",
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Detects DOM and reflected XSS payloads attempting cookie theft or UI session hijacking.'
    },
    {
        'rule_id': 'WAF-TRAV-003',
        'rule_name': 'Directory Path Traversal Attempt',
        'category': 'PathTraversal',
        'regex_pattern': r"(\.\./|\.\.\\|/etc/passwd|/windows/win\.ini|%2e%2e%2f|%252e%252e%252f)",
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Blocks directory path traversal sequences targeting system and configuration files.'
    },
    {
        'rule_id': 'WAF-RCE-004',
        'rule_name': 'Remote Command Execution (RCE) Metacharacters',
        'category': 'RCE',
        'regex_pattern': r"(;|\||`|\$\(.*?\))\s*(cat\s+/etc|whoami|id|uname\s+-a|powershell|cmd\.exe|wget\s+|curl\s+)",
        'severity': 'CRITICAL',
        'action': 'BLOCK',
        'description': 'Detects shell command chaining and remote payload download execution attempts.'
    },
    {
        'rule_id': 'WAF-SSRF-005',
        'rule_name': 'Server-Side Request Forgery (SSRF) Cloud Metadata Access',
        'category': 'SSRF',
        'regex_pattern': r"(169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|localhost|0\.0\.0\.0)",
        'severity': 'HIGH',
        'action': 'BLOCK',
        'description': 'Blocks attempts by untrusted inputs to query cloud provider metadata and internal services.'
    }
]

class WafEngineService:
    """Core Web Application Firewall rule evaluation engine."""

    @classmethod
    def seed_waf_rules(cls):
        """Seed default OWASP Top 10 WAF rules."""
        for r in BUILTIN_WAF_RULES:
            existing = WafRule.query.filter_by(rule_id=r['rule_id']).first()
            if not existing:
                rule = WafRule(
                    rule_id=r['rule_id'],
                    rule_name=r['rule_name'],
                    category=r['category'],
                    regex_pattern=r['regex_pattern'],
                    severity=r['severity'],
                    action=r['action'],
                    description=r['description'],
                    is_enabled=True
                )
                db.session.add(rule)
        db.session.commit()

    @classmethod
    def inspect_request_payload(cls, payload: str, endpoint: str = '/api/resource', method: str = 'POST', client_ip: str = '127.0.0.1', user_agent: str = None) -> dict:
        """Inspect payload string against active WAF rules."""
        if not payload:
            return {'blocked': False, 'triggered_rules': [], 'action': 'ALLOW'}

        rules = WafRule.query.filter_by(is_enabled=True).all()
        triggered = []
        should_block = False

        for rule in rules:
            try:
                if re.search(rule.regex_pattern, payload):
                    rule.hit_count += 1
                    triggered.append(rule.to_dict())
                    if rule.action == 'BLOCK':
                        should_block = True

                    # Record WAF Event
                    event = WafSecurityEvent(
                        rule_id=rule.rule_id,
                        category=rule.category,
                        target_endpoint=endpoint,
                        http_method=method,
                        client_ip=client_ip,
                        user_agent=user_agent or 'Standard Web Client',
                        intercepted_payload=payload[:500],
                        action_taken=rule.action
                    )
                    db.session.add(event)
            except Exception as e:
                pass

        if triggered:
            db.session.commit()

        return {
            'blocked': should_block,
            'triggered_rules': triggered,
            'action': 'BLOCK' if should_block else ('LOG' if triggered else 'ALLOW')
        }
