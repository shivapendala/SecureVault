"""
SecureVault Automated Incident Playbooks Catalog
"""

SOAR_PLAYBOOK_CATALOG = [
    {
        'playbook_id': 'PB-BRUTE-01',
        'playbook_name': 'Automated Brute Force & Credential Spray Containment',
        'trigger_event': 'BRUTE_FORCE',
        'severity': 'CRITICAL',
        'execution_steps': ['1. Block IP on Perimeter WAF', '2. Invalidate Active Session Tokens', '3. Force Password Reset & Step-Up MFA', '4. Dispatch SIEM Critical Alert'],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-RANSOM-02',
        'playbook_name': 'Ransomware Endpoint & Host Isolation',
        'trigger_event': 'RANSOMWARE',
        'severity': 'CRITICAL',
        'execution_steps': ['1. Isolate Infected Host to Containment VLAN', '2. Freeze Active Vault Snapshot', '3. Revoke Kerberos/PAM Clearance', '4. Trigger Offline Backup Immutability Verification'],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-TRAVEL-03',
        'playbook_name': 'Impossible Travel & Geofence Anomaly Response',
        'trigger_event': 'IMPOSSIBLE_TRAVEL',
        'severity': 'HIGH',
        'execution_steps': ['1. Kill Active Session Token', '2. Require Hardware FIDO2 WebAuthn Verification', '3. Log Geofence Velocity Telemetry'],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-EXFIL-04',
        'playbook_name': 'Data Exfiltration & Bulk Vault Access Containment',
        'trigger_event': 'DATA_EXFILTRATION',
        'severity': 'CRITICAL',
        'execution_steps': ['1. Freeze Vault Access Keys', '2. Revoke IAM Cloud Tokens', '3. Restrict Ingress/Egress Subnet Traffic', '4. Alert Incident Commander'],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-SECRET-05',
        'playbook_name': 'Hardcoded Secret Leak Immediate Revocation',
        'trigger_event': 'SECRET_LEAK',
        'severity': 'CRITICAL',
        'execution_steps': ['1. Rotate Leaked API Key in Cryptographic KMS', '2. Revoke Compromised PAT/Access Token', '3. Trigger Git Repository Audit'],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-06',
        'playbook_name': 'Automated Enterprise Response Playbook #06',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-07',
        'playbook_name': 'Automated Enterprise Response Playbook #07',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-08',
        'playbook_name': 'Automated Enterprise Response Playbook #08',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-09',
        'playbook_name': 'Automated Enterprise Response Playbook #09',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-10',
        'playbook_name': 'Automated Enterprise Response Playbook #10',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-11',
        'playbook_name': 'Automated Enterprise Response Playbook #11',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-12',
        'playbook_name': 'Automated Enterprise Response Playbook #12',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-13',
        'playbook_name': 'Automated Enterprise Response Playbook #13',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-14',
        'playbook_name': 'Automated Enterprise Response Playbook #14',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-15',
        'playbook_name': 'Automated Enterprise Response Playbook #15',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-16',
        'playbook_name': 'Automated Enterprise Response Playbook #16',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-17',
        'playbook_name': 'Automated Enterprise Response Playbook #17',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-18',
        'playbook_name': 'Automated Enterprise Response Playbook #18',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-19',
        'playbook_name': 'Automated Enterprise Response Playbook #19',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-20',
        'playbook_name': 'Automated Enterprise Response Playbook #20',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-21',
        'playbook_name': 'Automated Enterprise Response Playbook #21',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-22',
        'playbook_name': 'Automated Enterprise Response Playbook #22',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-23',
        'playbook_name': 'Automated Enterprise Response Playbook #23',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-24',
        'playbook_name': 'Automated Enterprise Response Playbook #24',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-25',
        'playbook_name': 'Automated Enterprise Response Playbook #25',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-26',
        'playbook_name': 'Automated Enterprise Response Playbook #26',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-27',
        'playbook_name': 'Automated Enterprise Response Playbook #27',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-28',
        'playbook_name': 'Automated Enterprise Response Playbook #28',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-29',
        'playbook_name': 'Automated Enterprise Response Playbook #29',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-30',
        'playbook_name': 'Automated Enterprise Response Playbook #30',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-31',
        'playbook_name': 'Automated Enterprise Response Playbook #31',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-32',
        'playbook_name': 'Automated Enterprise Response Playbook #32',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-33',
        'playbook_name': 'Automated Enterprise Response Playbook #33',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-34',
        'playbook_name': 'Automated Enterprise Response Playbook #34',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-35',
        'playbook_name': 'Automated Enterprise Response Playbook #35',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-36',
        'playbook_name': 'Automated Enterprise Response Playbook #36',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-37',
        'playbook_name': 'Automated Enterprise Response Playbook #37',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-38',
        'playbook_name': 'Automated Enterprise Response Playbook #38',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
    {
        'playbook_id': 'PB-INCIDENT-39',
        'playbook_name': 'Automated Enterprise Response Playbook #39',
        'trigger_event': 'ANOMALOUS_SECURITY_EVENT',
        'severity': 'HIGH',
        'execution_steps': [
            '1. Analyze Event Telemetry and Correlate IoCs',
            '2. Apply Contextual Zero-Trust Authorization Quarantine',
            '3. Enforce Step-Up Hardware MFA Challenge',
            '4. Archive Forensic Evidence in Cryptographic Locker'
        ],
        'is_automated': True
    },
]

def get_all_playbook_definitions():
    return SOAR_PLAYBOOK_CATALOG
