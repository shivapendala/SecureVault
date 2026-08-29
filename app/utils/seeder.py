from datetime import datetime, timedelta
from app import db
from app.models.user import User
from app.models.vault import SecretVault
from app.models.asset import SecurityAsset
from app.models.vulnerability import Vulnerability
from app.models.incident import Incident
from app.models.audit import AuditLog
from app.models.scan import ScanReport

def seed_database():
    """Seed sample cybersecurity database entries if empty."""
    # Check if already seeded
    if User.query.first() is not None:
        return

    print(">>> Seeding SecureVault with cybersecurity data...")

    # 1. Users
    admin = User(
        username='admin',
        email='admin@securevault.io',
        full_name='Chief Information Security Officer',
        role='Admin',
        department='Global Cyber Command',
        mfa_enabled=True,
        status='Active'
    )
    admin.set_password('Admin@SecureVault2026!')

    analyst = User(
        username='analyst_sarah',
        email='sarah.connor@securevault.io',
        full_name='Sarah Connor (Lead SOC Analyst)',
        role='Analyst',
        department='Threat Intelligence & Response',
        mfa_enabled=True,
        status='Active'
    )
    analyst.set_password('Analyst@SecureVault2026!')

    devops = User(
        username='devops_alex',
        email='alex.vance@securevault.io',
        full_name='Alex Vance (DevSecOps Lead)',
        role='DevOps',
        department='Cloud Infrastructure Sec',
        mfa_enabled=False,
        status='Active'
    )
    devops.set_password('DevOps@SecureVault2026!')

    auditor = User(
        username='auditor_chen',
        email='chen.wei@securevault.io',
        full_name='Chen Wei (Compliance & ISO Auditor)',
        role='Auditor',
        department='Governance, Risk & Compliance',
        mfa_enabled=True,
        status='Active'
    )
    auditor.set_password('Auditor@SecureVault2026!')

    db.session.add_all([admin, analyst, devops, auditor])
    db.session.commit()

    # 2. Security Assets
    assets_data = [
        SecurityAsset(
            name='AWS Production VPC Cluster (us-east-1)',
            asset_type='Cloud VPC',
            ip_address='10.0.0.1/16',
            fqdn='prod-vpc.aws.securevault.internal',
            environment='Production',
            criticality='Mission Critical',
            risk_score=78,
            status='Active',
            agent_installed=True,
            open_ports='443, 8443, 6443',
            owner='Cloud Platform Engineering',
            last_scan_date=datetime.utcnow() - timedelta(hours=3)
        ),
        SecurityAsset(
            name='Kubernetes Ingress Controller & API Gateway',
            asset_type='Kubernetes Cluster',
            ip_address='52.84.120.45',
            fqdn='api-gateway.securevault.io',
            environment='Production',
            criticality='Mission Critical',
            risk_score=64,
            status='Active',
            agent_installed=True,
            open_ports='80, 443, 9090',
            owner='DevSecOps Team',
            last_scan_date=datetime.utcnow() - timedelta(hours=8)
        ),
        SecurityAsset(
            name='Corporate Active Directory & IdP (DC-01)',
            asset_type='Windows AD',
            ip_address='192.168.10.5',
            fqdn='dc01.corp.securevault.net',
            environment='Internal',
            criticality='Mission Critical',
            risk_score=85,
            status='Active',
            agent_installed=True,
            open_ports='53, 88, 135, 389, 445, 636',
            owner='Enterprise IT Security',
            last_scan_date=datetime.utcnow() - timedelta(hours=12)
        ),
        SecurityAsset(
            name='Core Edge Next-Gen Firewall (Palo Alto)',
            asset_type='Firewall',
            ip_address='198.51.100.1',
            fqdn='fw01.perimeter.securevault.io',
            environment='DMZ',
            criticality='Mission Critical',
            risk_score=22,
            status='Active',
            agent_installed=True,
            open_ports='22, 443',
            owner='Network Security Ops',
            last_scan_date=datetime.utcnow() - timedelta(days=1)
        ),
        SecurityAsset(
            name='Primary MySQL & Redis Database Cluster',
            asset_type='Database Cluster',
            ip_address='10.0.30.12',
            fqdn='db-master.prod.securevault.internal',
            environment='Production',
            criticality='Mission Critical',
            risk_score=52,
            status='Active',
            agent_installed=True,
            open_ports='3306, 6379',
            owner='Database Reliability Team',
            last_scan_date=datetime.utcnow() - timedelta(days=2)
        ),
        SecurityAsset(
            name='Payment Gateway Microservice (PCI-DSS Zone)',
            asset_type='API Gateway',
            ip_address='10.0.50.88',
            fqdn='payments.vaultpay.internal',
            environment='Production',
            criticality='Mission Critical',
            risk_score=40,
            status='Active',
            agent_installed=True,
            open_ports='443, 8080',
            owner='FinTech Security Squad',
            last_scan_date=datetime.utcnow() - timedelta(days=1)
        )
    ]
    db.session.add_all(assets_data)
    db.session.commit()

    # 3. Vault Encrypted Secrets
    s1 = SecretVault(
        title='AWS Production Root IAM Access Key & Secret',
        category='Cloud Secret',
        description='Master IAM credentials for provisioning Terraform infrastructure in us-east-1.',
        environment='Production',
        risk_level='Critical',
        rotation_days=60,
        expires_at=datetime.utcnow() + timedelta(days=45),
        created_by_id=admin.id
    )
    s1.set_secret('AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')

    s2 = SecretVault(
        title='Production Master MySQL Root Database Password',
        category='Database',
        description='Superuser password for production replicated MySQL DB cluster.',
        environment='Production',
        risk_level='Critical',
        rotation_days=30,
        expires_at=datetime.utcnow() + timedelta(days=14),
        created_by_id=admin.id
    )
    s2.set_secret('SecVault_Prod_MySQL_99$SecureRootKey#2026')

    s3 = SecretVault(
        title='Bastion Host SSH Ed25519 Private Key',
        category='SSH Key',
        description='Primary deployment key for jumping into DMZ and production VPC bastions.',
        environment='Production',
        risk_level='High',
        rotation_days=90,
        expires_at=datetime.utcnow() + timedelta(days=72),
        created_by_id=devops.id
    )
    s3.set_secret('-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACDH4q8f48q9a3j+example+ed25519+key==\n-----END OPENSSH PRIVATE KEY-----')

    s4 = SecretVault(
        title='Stripe Live Merchant API Secret Key',
        category='API Key',
        description='Production webhook and payment processing secret token.',
        environment='Production',
        risk_level='Critical',
        rotation_days=180,
        expires_at=datetime.utcnow() + timedelta(days=120),
        created_by_id=admin.id
    )
    s4.set_secret('sec_vault_mock_merchant_token_09876543210FEdCba')

    s5 = SecretVault(
        title='Cloudflare Enterprise Zero-Trust API Token',
        category='Token',
        description='WAF management and DDoS mitigation zone authorization token.',
        environment='Production',
        risk_level='High',
        rotation_days=90,
        expires_at=datetime.utcnow() + timedelta(days=80),
        created_by_id=devops.id
    )
    s5.set_secret('cftok_9f8e7d6c5b4a3210deadbeefcafe0123456789')

    s6 = SecretVault(
        title='Wildcard SSL Certificate Private Key (*.securevault.io)',
        category='SSL Certificate',
        description='TLS 1.3 certificate private key for public web load balancers.',
        environment='Production',
        risk_level='Critical',
        rotation_days=365,
        expires_at=datetime.utcnow() + timedelta(days=210),
        created_by_id=admin.id
    )
    s6.set_secret('-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7V9EXAMPLEKey...\n-----END PRIVATE KEY-----')

    db.session.add_all([s1, s2, s3, s4, s5, s6])
    db.session.commit()

    # 4. Vulnerabilities
    v1 = Vulnerability(
        cve_id='CVE-2024-6387',
        title='RegreSSHion: Remote Unauthenticated Code Execution in OpenSSH',
        description='A signal handler race condition vulnerability in OpenSSH server (sshd) allows unauthenticated remote attackers to execute arbitrary code with root privileges.',
        severity='Critical',
        cvss_score=9.8,
        cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        affected_asset_id=assets_data[0].id,
        mitre_tactic='Initial Access & Execution',
        status='In Progress',
        remediation_guidance='Upgrade OpenSSH to version 9.8p1 or newer. Set LoginGraceTime 0 in sshd_config as a temporary mitigation.',
        exploit_available=True,
        discovered_at=datetime.utcnow() - timedelta(days=4)
    )

    v2 = Vulnerability(
        cve_id='CVE-2024-21626',
        title='runc Leaky File Descriptors Container Escape to Host',
        description='In runc through 1.1.11, internal file descriptors are leaked to child processes during container creation, permitting an attacker to overwrite host binaries.',
        severity='Critical',
        cvss_score=9.0,
        cvss_vector='CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        affected_asset_id=assets_data[1].id,
        mitre_tactic='Privilege Escalation & Escape',
        status='Open',
        remediation_guidance='Upgrade container runtime and runc package to version 1.1.12+. Enforce AppArmor and SELinux policies on cluster worker nodes.',
        exploit_available=True,
        discovered_at=datetime.utcnow() - timedelta(days=6)
    )

    v3 = Vulnerability(
        cve_id='CVE-2024-38077',
        title='Windows Remote Desktop Licensing Service RCE (MadLicensing)',
        description='Remote code execution vulnerability in the Windows Remote Desktop Licensing service that allows unauthenticated remote exploitation over port 135/RPC.',
        severity='Critical',
        cvss_score=9.8,
        cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        affected_asset_id=assets_data[2].id,
        mitre_tactic='Lateral Movement',
        status='Open',
        remediation_guidance='Apply Microsoft Security Bulletin patch KB5040442 immediately. Disable RDL service on domain controllers where not required.',
        exploit_available=True,
        discovered_at=datetime.utcnow() - timedelta(days=2)
    )

    v4 = Vulnerability(
        cve_id='CVE-2023-4863',
        title='Heap Buffer Overflow in libwebp Processing (WebP zero-day)',
        description='A heap buffer overflow in WebP image processing allows remote code execution via specially crafted WebP image files.',
        severity='High',
        cvss_score=8.8,
        cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
        affected_asset_id=assets_data[5].id,
        mitre_tactic='Execution',
        status='Mitigated',
        remediation_guidance='Update libwebp and all dependent image conversion services to version 1.3.2+.',
        exploit_available=False,
        discovered_at=datetime.utcnow() - timedelta(days=20),
        resolved_at=datetime.utcnow() - timedelta(days=2)
    )

    v5 = Vulnerability(
        cve_id='CVE-2023-38606',
        title='Operation Triangulation Kernel Memory Modification Vulnerability',
        description='Hardware memory-mapped I/O register manipulation bypasses page table protections and enables kernel execution privilege escalation.',
        severity='High',
        cvss_score=7.8,
        cvss_vector='CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
        affected_asset_id=assets_data[3].id,
        mitre_tactic='Defense Evasion',
        status='Mitigated',
        remediation_guidance='Firmware patch applied by vendor. Memory integrity guard enabled.',
        exploit_available=False,
        discovered_at=datetime.utcnow() - timedelta(days=35),
        resolved_at=datetime.utcnow() - timedelta(days=5)
    )

    db.session.add_all([v1, v2, v3, v4, v5])
    db.session.commit()

    # 5. Security Incidents
    inc1 = Incident(
        ticket_id='INC-9102',
        title='APT Reconnaissance & Password Spraying on Active Directory DC-01',
        description='SIEM triggered multiple anomalous authentication failures (1,400 attempts in 3 minutes) originating from rotating Tor exit nodes against enterprise IdP.',
        severity='Critical',
        status='Investigating',
        threat_actor='UNC3886 / Advanced Persistent Threat',
        mitre_technique='T1110.003 - Password Spraying',
        iocs='185.220.101.5, 185.220.101.7, 45.154.255.89 | Usernames targeted: admin, service_account_sql',
        assigned_to_id=analyst.id,
        detected_at=datetime.utcnow() - timedelta(hours=2)
    )

    inc2 = Incident(
        ticket_id='INC-8401',
        title='Suspicious Outbound S3 Data Sync Spike from Kubernetes Ingress',
        description='NetFlow anomaly detected 42 GB encrypted outbound stream to unsanctioned foreign IP address during non-business hours.',
        severity='High',
        status='Contained',
        threat_actor='Unknown Extortion Group',
        mitre_technique='T1048.003 - Exfiltration Over Unencrypted/Encrypted Non-C2 Protocol',
        iocs='Target IP: 194.26.29.112 | Port: 443 | Transfer size: 42.8 GB',
        assigned_to_id=analyst.id,
        detected_at=datetime.utcnow() - timedelta(hours=14)
    )

    inc3 = Incident(
        ticket_id='INC-7622',
        title='SSH Brute Force Attack on Cloud Bastion Node',
        description='Automated botnet initiated dictionary attack against Bastion SSH port 22. Fail2ban and Cloudflare WAF successfully blocked 12,000 requests.',
        severity='Medium',
        status='Eradicated',
        threat_actor='Mirai/Mozi IoT Botnet Variant',
        mitre_technique='T1110.001 - Brute Force',
        iocs='Subnets: 103.145.2.0/24, 185.191.171.0/24',
        assigned_to_id=devops.id,
        detected_at=datetime.utcnow() - timedelta(days=1),
        resolved_at=datetime.utcnow() - timedelta(hours=6)
    )

    db.session.add_all([inc1, inc2, inc3])
    db.session.commit()

    # 6. Audit Logs
    logs = [
        AuditLog(
            user_id=admin.id,
            action='VAULT_INITIALIZE',
            target_type='Vault',
            target_id='SYSTEM',
            ip_address='192.168.1.100',
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecureVault/2.0',
            details='Initialized Master Encryption Key and generated root credential vault.',
            status='SUCCESS',
            timestamp=datetime.utcnow() - timedelta(days=3)
        ),
        AuditLog(
            user_id=admin.id,
            action='SECRET_CREATE',
            target_type='Secret',
            target_id='1',
            ip_address='192.168.1.100',
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            details='Created encrypted credential: AWS Production Root IAM Access Key',
            status='SUCCESS',
            timestamp=datetime.utcnow() - timedelta(days=2)
        ),
        AuditLog(
            user_id=analyst.id,
            action='LOGIN_SUCCESS',
            target_type='Auth',
            target_id='analyst_sarah',
            ip_address='192.168.1.105',
            user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            details='User authenticated successfully with 2FA TOTP verified.',
            status='SUCCESS',
            timestamp=datetime.utcnow() - timedelta(hours=4)
        ),
        AuditLog(
            user_id=analyst.id,
            action='INCIDENT_TRIAGE',
            target_type='Incident',
            target_id='INC-9102',
            ip_address='192.168.1.105',
            user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            details='Elevated incident severity to Critical and initiated SOC containment playbook.',
            status='SUCCESS',
            timestamp=datetime.utcnow() - timedelta(hours=2)
        )
    ]
    db.session.add_all(logs)
    db.session.commit()

    print(">>> SecureVault database seeded successfully!")
