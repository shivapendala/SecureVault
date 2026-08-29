from app.services.soar.playbook_engine import PlaybookEngineService

class ThreatContainmentCoordinator:
    """Coordinates automated incident response triggers from SIEM/WAF/IAM events."""

    @classmethod
    def handle_threat_event(cls, event_type: str, target: str, incident_id: str = None) -> dict:
        """Route security incident event to matching SOAR playbook."""
        playbook_map = {
            'BRUTE_FORCE': 'PB-BRUTE-01',
            'RANSOMWARE': 'PB-RANSOM-02',
            'IMPOSSIBLE_TRAVEL': 'PB-TRAVEL-03'
        }

        pb_id = playbook_map.get(event_type, 'PB-BRUTE-01')
        execution = PlaybookEngineService.execute_playbook(pb_id, target, incident_id)
        return {
            'success': True,
            'playbook_id': pb_id,
            'execution': execution.to_dict()
        }
