import re
import ipaddress
from datetime import datetime
from app import db
from app.models.threat_intel import ThreatIndicator, IoCMatchEvent

class IoCMatcherService:
    """Core engine for detecting, normalizing, and correlating security events against Threat Intelligence IoCs."""

    @staticmethod
    def identify_indicator_type(value: str) -> str:
        """Classify value into IP, SHA256, MD5, DOMAIN, URL, or CVE."""
        val = value.strip()
        
        # IP Address check
        try:
            ipaddress.ip_address(val)
            return 'IP'
        except ValueError:
            pass

        # Hash checks
        if re.match(r'^[a-fA-F0-9]{64}$', val):
            return 'SHA256'
        if re.match(r'^[a-fA-F0-9]{32}$', val):
            return 'MD5'

        # CVE check
        if re.match(r'^CVE-\d{4}-\d{4,}$', val, re.IGNORECASE):
            return 'CVE'

        # URL check
        if val.startswith('http://') or val.startswith('https://'):
            return 'URL'

        # Domain check
        if '.' in val and not '/' in val and not ' ' in val:
            return 'DOMAIN'

        return 'UNKNOWN'

    @classmethod
    def query_indicator(cls, value: str) -> dict:
        """Query threat intelligence database for a specific indicator."""
        clean_val = value.strip().lower()
        ind_type = cls.identify_indicator_type(clean_val)

        indicator = ThreatIndicator.query.filter(
            db.func.lower(ThreatIndicator.indicator_value) == clean_val,
            ThreatIndicator.is_active == True
        ).first()

        if indicator:
            return {
                'found': True,
                'threat_score': indicator.confidence_score,
                'indicator': indicator.to_dict(),
                'verdict': 'MALICIOUS' if indicator.confidence_score >= 75 else 'SUSPICIOUS'
            }

        return {
            'found': False,
            'threat_score': 0,
            'indicator': None,
            'verdict': 'CLEAN',
            'detected_type': ind_type
        }

    @classmethod
    def scan_payload_for_iocs(cls, payload_text: str, source_ip: str = None, user_id: int = None) -> list[dict]:
        """Deep scan a text string, log file, or network payload for any embedded malicious IoCs."""
        if not payload_text:
            return []

        matches = []
        # Extract potential IPs
        ip_patterns = set(re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', payload_text))
        # Extract potential SHA-256 hashes
        sha256_patterns = set(re.findall(r'\b[a-fA-F0-9]{64}\b', payload_text))
        # Extract potential MD5 hashes
        md5_patterns = set(re.findall(r'\b[a-fA-F0-9]{32}\b', payload_text))
        # Extract potential Domains
        domain_patterns = set(re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', payload_text))

        all_candidates = ip_patterns.union(sha256_patterns).union(md5_patterns).union(domain_patterns)

        for cand in all_candidates:
            res = cls.query_indicator(cand)
            if res['found']:
                ind_obj = ThreatIndicator.query.get(res['indicator']['id'])
                if ind_obj:
                    ind_obj.match_count += 1
                    ind_obj.last_seen = datetime.utcnow()

                    # Record Match Event
                    match_event = IoCMatchEvent(
                        indicator_id=ind_obj.id,
                        matched_value=cand,
                        source_ip=source_ip,
                        user_id=user_id,
                        event_context=f"Embedded IoC match detected during payload scan: '{cand}'.",
                        action_taken='FLAGGED_ALERT' if ind_obj.severity != 'CRITICAL' else 'BLOCKED_IP'
                    )
                    db.session.add(match_event)
                    matches.append({
                        'value': cand,
                        'type': ind_obj.indicator_type,
                        'threat_type': ind_obj.threat_type,
                        'severity': ind_obj.severity,
                        'confidence': ind_obj.confidence_score,
                        'action': match_event.action_taken
                    })

        if matches:
            db.session.commit()

        return matches
