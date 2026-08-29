from datetime import datetime, timedelta
from app import db
from app.models.user import User
from app.models.login_attempt import LoginAttempt
from app.models.security_log import SecurityLog
from app.models.password import Password
from app.models.file import FileVault
from app.models.notification import Notification
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

    print(">>> Seeding SecureVault with cybersecurity data across all tables...")

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

    # 2. Passwords Table
    p1 = Password(
        user_id=admin.id,
        title='AWS Production Master Root',
        category='Cloud Secret',
        site_url='https://aws.amazon.com/console',
        username='root@securevault.io',
        environment='Production',
        risk_level='Critical',
        notes='Master root account credentials. Requires physical MFA key.',
        expires_at=datetime.utcnow() + timedelta(days=60)
    )
    p1.set_password_val('AWS_SecVault_Root#2026!MasterKey')

    p2 = Password(
        user_id=devops.id,
        title='Production PostgreSQL Database Master',
        category='Database',
        site_url='postgresql://db-master.prod.securevault.internal:5432',
        username='postgres_admin',
        environment='Production',
        risk_level='Critical',
        notes='Primary DB superuser credentials.',
        expires_at=datetime.utcnow() + timedelta(days=30)
    )
    p2.set_password_val('P0stgr3s_SecVault_DB_99!')

    p3 = Password(
        user_id=admin.id,
        title='Cloudflare Zero Trust Gateway Token',
        category='API Key',
        site_url='https://dash.cloudflare.com',
        username='cloudflare-service-account',
        environment='Production',
        risk_level='High',
        notes='WAF and edge security management token.',
        expires_at=datetime.utcnow() + timedelta(days=90)
    )
    p3.set_password_val('cf_api_tok_9f8e7d6c5b4a3210deadbeef')

    db.session.add_all([p1, p2, p3])
    db.session.commit()

    # 3. Files Table (Encrypted File Vault)
    f1 = FileVault(
        user_id=admin.id,
        filename='ssl_wildcard_securevault_io.key.enc',
        original_filename='ssl_wildcard_securevault_io.key',
        file_path='vault_storage/certs/ssl_wildcard_securevault_io.key.enc',
        mime_type='application/x-pem-file',
        file_size=3240,
        checksum_sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        is_encrypted=True,
        encryption_algorithm='AES-256-GCM',
        description='Production wildcard private key for *.securevault.io'
    )

    f2 = FileVault(
        user_id=devops.id,
        filename='k8s_cluster_kubeconfig_prod.yaml.enc',
        original_filename='k8s_cluster_kubeconfig_prod.yaml',
        file_path='vault_storage/configs/k8s_cluster_kubeconfig_prod.yaml.enc',
        mime_type='text/yaml',
        file_size=5812,
        checksum_sha256='8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
        is_encrypted=True,
        encryption_algorithm='AES-256-GCM',
        description='Production Kubernetes cluster cluster-admin kubeconfig credentials'
    )
    db.session.add_all([f1, f2])
    db.session.commit()

    # 4. Notifications Table
    n1 = Notification(
        user_id=admin.id,
        title='Critical CVE Discovered: RegreSSHion (CVE-2024-6387)',
        message='A critical RCE vulnerability in OpenSSH has been mapped to AWS Production VPC Cluster.',
        category='threat',
        priority='high',
        is_read=False,
        action_url='/vulnerabilities'
    )

    n2 = Notification(
        user_id=None, # Global broadcast
        title='Zero-Trust Access Policy Enforced',
        message='All operators must re-verify TOTP hardware keys every 12 hours.',
        category='security',
        priority='normal',
        is_read=False,
        action_url='/audit'
    )

    n3 = Notification(
        user_id=devops.id,
        title='Credential Expiry Reminder: PostgreSQL Master',
        message='PostgreSQL DB Master password expires in 14 days. Rotation required.',
        category='reminder',
        priority='normal',
        is_read=True,
        read_at=datetime.utcnow() - timedelta(hours=2),
        action_url='/vault'
    )
    db.session.add_all([n1, n2, n3])
    db.session.commit()

    # 5. Login Attempts Table
    la1 = LoginAttempt(
        user_id=admin.id,
        username_attempted='admin',
        ip_address='192.168.1.100',
        user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecureVault/2.0',
        status='SUCCESS',
        attempted_at=datetime.utcnow() - timedelta(hours=1)
    )

    la2 = LoginAttempt(
        user_id=None,
        username_attempted='root',
        ip_address='185.220.101.5',
        user_agent='python-requests/2.31.0',
        status='BLOCKED',
        failure_reason='Brute force threshold exceeded from Tor exit node',
        attempted_at=datetime.utcnow() - timedelta(hours=3)
    )
    db.session.add_all([la1, la2])
    db.session.commit()

    # 6. Security Logs Table
    sl1 = SecurityLog(
        user_id=admin.id,
        event_type='MASTER_KEY_DERIVATION',
        severity='INFO',
        details='Derived AES-256 master vault key using PBKDF2 with 100,000 SHA-256 iterations.',
        ip_address='192.168.1.100',
        status='SUCCESS',
        created_at=datetime.utcnow() - timedelta(days=2)
    )

    sl2 = SecurityLog(
        user_id=analyst.id,
        event_type='PASSWORD_DECRYPT_AUDIT',
        severity='MEDIUM',
        details='Decrypted password entry #1 (AWS Production Master Root).',
        ip_address='192.168.1.105',
        status='SUCCESS',
        created_at=datetime.utcnow() - timedelta(hours=4)
    )

    sl3 = SecurityLog(
        user_id=None,
        event_type='ANOMALOUS_RECON_DETECTED',
        severity='HIGH',
        details='Port sweep detected on perimeter IP 198.51.100.1 targeting ports 22, 80, 443, 3306.',
        ip_address='45.154.255.89',
        status='BLOCKED',
        created_at=datetime.utcnow() - timedelta(hours=6)
    )
    db.session.add_all([sl1, sl2, sl3])
    db.session.commit()

    # 7. Security Assets
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
        )
    ]
    db.session.add_all(assets_data)
    db.session.commit()

    # 8. Secret Vault (Encrypted)
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
    s1.set_secret('MOCK_CLOUD_IAM_KEY_99214:mock_wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')

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
    db.session.add_all([s1, s2])
    db.session.commit()

    # 9. Vulnerabilities
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
    db.session.add(v1)
    db.session.commit()

    # 10. Incidents
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
    db.session.add(inc1)
    db.session.commit()

    # 11. Audit Logs
    audit1 = AuditLog(
        user_id=admin.id,
        action='VAULT_INITIALIZE',
        target_type='Vault',
        target_id='SYSTEM',
        ip_address='192.168.1.100',
        user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecureVault/2.0',
        details='Initialized Master Encryption Key and generated root credential vault.',
        status='SUCCESS',
        timestamp=datetime.utcnow() - timedelta(days=3)
    )
    db.session.add(audit1)
    db.session.commit()

    # 12. Enterprise Engines Seed
    try:
        from app.services.threat_intelligence.feed_manager import ThreatFeedManager
        ThreatFeedManager.seed_initial_threat_data()
    except Exception as e:
        print(f"[Warning] Threat Intelligence seeding: {e}")

    try:
        from app.services.appsec.waf_engine import WafEngineService
        WafEngineService.seed_waf_rules()
    except Exception as e:
        print(f"[Warning] WAF rules seeding: {e}")

    try:
        from app.services.iam.abac_policy_engine import AbacPolicyEngine
        AbacPolicyEngine.seed_policies()
    except Exception as e:
        print(f"[Warning] ABAC policies seeding: {e}")

    try:
        from app.services.crypto_kms.asymmetric_kms import AsymmetricKmsService
        from app.models.crypto_kms import AsymmetricKeyPair
        if AsymmetricKeyPair.query.count() == 0:
            AsymmetricKmsService.generate_key_pair('SOC-Root-Master-Key', algorithm='RSA-2048')
    except Exception as e:
        print(f"[Warning] Crypto KMS seeding: {e}")

    try:
        from app.services.compliance.compliance_evaluator import ComplianceEvaluatorService
        ComplianceEvaluatorService.seed_compliance_frameworks()
    except Exception as e:
        print(f"[Warning] Compliance frameworks seeding: {e}")

    try:
        from app.services.compliance.risk_matrix_service import RiskMatrixService
        RiskMatrixService.seed_initial_risks()
    except Exception as e:
        print(f"[Warning] Risk matrix seeding: {e}")

    try:
        from app.services.soar.playbook_engine import PlaybookEngineService
        PlaybookEngineService.seed_playbooks()
    except Exception as e:
        print(f"[Warning] SOAR playbooks seeding: {e}")

    print(">>> SecureVault database seeded successfully across all tables!")
