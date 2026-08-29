"""
SecureVault Sigma SIEM Threat Hunting Rules Catalog
"""

SIGMA_RULES_CATALOG = [
    {
        'rule_id': 'SIGMA-WIN-001',
        'title': 'LSASS Process Memory Access by Non-System Process',
        'log_source': 'Windows Security (EID 4663 / Sysmon 10)',
        'tactic': 'Credential Access',
        'severity': 'HIGH',
        'detection_condition': 'TargetImage: lsass.exe, GrantedAccess: 0x1010 or 0x1FFFFF',
        'description': """Detects unauthorized read access to LSASS memory indicative of Procdump or Mimikatz.""",
        'status': 'ACTIVE'
    },
    {
        'rule_id': 'SIGMA-WIN-002',
        'title': 'Suspicious Process Spawning from Microsoft Office',
        'log_source': 'Windows Sysmon (EID 1)',
        'tactic': 'Execution',
        'severity': 'HIGH',
        'detection_condition': 'ParentImage: winword.exe / excel.exe -> Image: powershell.exe / cmd.exe / mshta.exe',
        'description': """Detects malicious macro execution launching command shells.""",
        'status': 'ACTIVE'
    },
    {
        'rule_id': 'SIGMA-WIN-003',
        'title': 'Volume Shadow Copy Deletion via VSSAdmin',
        'log_source': 'Windows Security (EID 4688)',
        'tactic': 'Impact',
        'severity': 'CRITICAL',
        'detection_condition': 'CommandLine contains 'vssadmin delete shadows' or 'wbadmin delete catalog'',
        'description': """Detects pre-ransomware execution attempting to eliminate local backup copies.""",
        'status': 'ACTIVE'
    },
    {
        'rule_id': 'SIGMA-LNX-004',
        'title': 'Suspicious Sudoers File Modification',
        'log_source': 'Linux Auditd',
        'tactic': 'Privilege Escalation',
        'severity': 'HIGH',
        'detection_condition': 'File modification targeting /etc/sudoers or /etc/sudoers.d/*',
        'description': """Detects unauthorized persistence or privilege escalation in Linux systems.""",
        'status': 'ACTIVE'
    },
    {
        'rule_id': 'SIGMA-CLD-005',
        'title': 'AWS Root Account Usage without MFA',
        'log_source': 'AWS CloudTrail',
        'tactic': 'Account Access',
        'severity': 'CRITICAL',
        'detection_condition': 'userIdentity.type == 'Root' and not additionalEventData.MFAUsed',
        'description': """Detects root account activity bypassing multi-factor authentication.""",
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Execution',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Execution',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Execution activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Persistence',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Persistence',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Persistence activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Privilege Escalation',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Privilege Escalation',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Privilege Escalation activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Defense Evasion',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Defense Evasion',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Defense Evasion activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Credential Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Credential Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Credential Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Lateral Movement',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Lateral Movement',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Lateral Movement activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Initial Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Initial Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Initial Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Execution',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Execution',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Execution activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Persistence',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Persistence',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Persistence activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Privilege Escalation',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Privilege Escalation',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Privilege Escalation activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Defense Evasion',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Defense Evasion',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Defense Evasion activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Credential Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Credential Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Credential Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Lateral Movement',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Lateral Movement',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Lateral Movement activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Initial Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Initial Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Initial Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Execution',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Execution',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Execution activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Persistence',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Persistence',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Persistence activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Privilege Escalation',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Privilege Escalation',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Privilege Escalation activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Defense Evasion',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Defense Evasion',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Defense Evasion activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Credential Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Credential Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Credential Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Lateral Movement',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Lateral Movement',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Lateral Movement activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Initial Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Initial Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Initial Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Execution',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Execution',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Execution activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Persistence',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Persistence',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Persistence activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Privilege Escalation',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Privilege Escalation',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Privilege Escalation activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Defense Evasion',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Defense Evasion',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Defense Evasion activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Credential Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Credential Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Credential Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Lateral Movement',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Lateral Movement',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Lateral Movement activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Initial Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Initial Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Initial Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Execution',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Execution',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Execution activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Persistence',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Persistence',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Persistence activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Privilege Escalation',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Privilege Escalation',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Privilege Escalation activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Defense Evasion',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Defense Evasion',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Defense Evasion activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Credential Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Credential Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Credential Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Lateral Movement',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Lateral Movement',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Lateral Movement activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Initial Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Initial Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Initial Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Execution',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Execution',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Execution activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Persistence',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Persistence',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Persistence activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Privilege Escalation',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Privilege Escalation',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Privilege Escalation activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Defense Evasion',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Defense Evasion',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Defense Evasion activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Credential Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Credential Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Credential Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Lateral Movement',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Lateral Movement',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Lateral Movement activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Initial Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Initial Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Initial Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Execution',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Execution',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Execution activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Persistence',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Persistence',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Persistence activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Privilege Escalation',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Privilege Escalation',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Privilege Escalation activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Defense Evasion',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Defense Evasion',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Defense Evasion activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Credential Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Credential Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Credential Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Lateral Movement',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Lateral Movement',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Lateral Movement activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Initial Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Initial Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Initial Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Execution',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Execution',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Execution activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Persistence',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Persistence',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Persistence activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Privilege Escalation',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Privilege Escalation',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Privilege Escalation activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Defense Evasion',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Defense Evasion',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Defense Evasion activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Credential Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Credential Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Credential Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Lateral Movement',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Lateral Movement',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Lateral Movement activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Initial Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Initial Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Initial Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Execution',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Execution',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Execution activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Persistence',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Persistence',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Persistence activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Privilege Escalation',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Privilege Escalation',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Privilege Escalation activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Defense Evasion',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Defense Evasion',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Defense Evasion activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Credential Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Credential Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Credential Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Lateral Movement',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Lateral Movement',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Lateral Movement activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Initial Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Initial Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Initial Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Execution',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Execution',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Execution activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Persistence',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Persistence',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Persistence activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Privilege Escalation',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Privilege Escalation',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Privilege Escalation activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Defense Evasion',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Defense Evasion',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Defense Evasion activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Credential Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Credential Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Credential Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Lateral Movement',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Lateral Movement',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Lateral Movement activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Initial Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Initial Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Initial Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Execution',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Execution',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Execution activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Persistence',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Persistence',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Persistence activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Privilege Escalation',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Privilege Escalation',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Privilege Escalation activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Defense Evasion',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Defense Evasion',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Defense Evasion activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Credential Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Credential Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Credential Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Lateral Movement',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Lateral Movement',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Lateral Movement activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Initial Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Initial Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Initial Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Execution',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Execution',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Execution activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Persistence',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Persistence',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Persistence activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Privilege Escalation',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Privilege Escalation',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Privilege Escalation activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Defense Evasion',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Defense Evasion',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Defense Evasion activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Credential Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Credential Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Credential Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Lateral Movement',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Lateral Movement',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Lateral Movement activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Initial Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Initial Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Initial Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Execution',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Execution',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Execution activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Persistence',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Persistence',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Persistence activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Privilege Escalation',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Privilege Escalation',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Privilege Escalation activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Defense Evasion',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Defense Evasion',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Defense Evasion activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Credential Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Credential Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Credential Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Lateral Movement',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Lateral Movement',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Lateral Movement activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Initial Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Initial Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Initial Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Execution',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Execution',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Execution activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Persistence',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Persistence',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Persistence activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Privilege Escalation',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Privilege Escalation',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Privilege Escalation activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Defense Evasion',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Defense Evasion',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Defense Evasion activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Credential Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Credential Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Credential Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Lateral Movement',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Lateral Movement',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Lateral Movement activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Initial Access',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Initial Access',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Initial Access activity.',
        'status': 'ACTIVE'
    },
    {
        'rule_id': f'SIGMA-HUNT-{i:03d}',
        'title': 'Enterprise SIEM Threat Hunting Rule #{i:03d} - Execution',
        'log_source': 'Windows Security / Linux Syslog / Cloud Audit',
        'tactic': 'Execution',
        'severity': 'HIGH',
        'detection_condition': 'CommandLine contains abnormal regex pattern or API call frequency > 100/sec',
        'description': 'Heuristic detection rule monitoring telemetry for Execution activity.',
        'status': 'ACTIVE'
    },
]

def get_all_sigma_rules():
    return SIGMA_RULES_CATALOG
