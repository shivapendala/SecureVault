# 🛡️ SecureVault — Enterprise Cybersecurity & Zero-Trust Governance Platform

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/shivapendala/SecureVault)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-Flask%203.0%20%2B%20SQLAlchemy%202.0-orange.svg)](https://flask.palletsprojects.com/)
[![Database](https://img.shields.io/badge/database-MySQL%20%7C%20SQLite-blue.svg)](https://www.mysql.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security Tested](https://img.shields.io/badge/tests-54%2F54%20passing%20(100%25)-success.svg)](tests/)

**SecureVault** is an enterprise-grade, Zero-Trust Cybersecurity and Secret Management platform built with Python, Flask, SQLAlchemy, MySQL, and modern cryptographic primitives. It integrates real-time threat intelligence ingestion, perimeter Layer 7 WAF inspection, Just-in-Time privileged access management (PAM), asymmetric key management (KMS), Shamir's $(k, n)$ secret sharing, automated compliance evaluation (SOC 2, ISO 27001, NIST SP 800-53), and automated SOAR incident response playbooks into a unified, high-assurance security console.

---

## 📑 Table of Contents

- [Key Capabilities & Modules](#-key-capabilities--modules)
- [System Architecture](#-system-architecture)
- [Technology Stack](#-technology-stack)
- [Prerequisites & System Requirements](#-prerequisites--system-requirements)
- [Installation & Setup](#-installation--setup)
- [Database Configuration & Bootstrapping](#-database-configuration--bootstrapping)
- [Environment Variables](#-environment-variables)
- [Running the Application](#-running-the-application)
- [REST API Gateway Documentation](#-rest-api-gateway-documentation)
- [Automated Testing Suite](#-automated-testing-suite)
- [Project Directory Structure](#-project-directory-structure)
- [Contributing & Security Policy](#-contributing--security-policy)
- [License](#-license)

---

## 🚀 Key Capabilities & Modules

### 1. 🔐 Core Vault & Secret Cryptography
- **AES-256 Fernet Credential Vault**: Zero-knowledge password, API token, and cloud secret encryption at rest using PBKDF2/scrypt key derivation.
- **Encrypted File Vault & Integrity Verification**: File upload scanner computing SHA-256 hash baselines to detect post-upload tampering.
- **NIST Password Entropy & Password History**: Real-time entropy evaluator preventing dictionary reuse and weak passwords.

### 2. 📡 Threat Intelligence & SIEM Feed Processing Engine
- **Multi-Feed Ingestion**: Ingests threat feeds from AlienVault OTX, Abuse.ch Malware Registry, and Tor Project exit relays.
- **Deep Payload Inspector & IoC Scoring**: Regex and confidence-based IoC matcher for IPs, Domains, URLs, SHA-256 hashes, and CVEs.
- **MITRE ATT&CK Matrix Correlation**: Maps indicators to tactics (Initial Access, Execution, C2) and enterprise techniques.
- **GeoIP & Autonomous System Number (ASN) Intelligence**: Resolves threat origin countries, latitude/longitude, and risk factors.

### 3. 🌐 Network & TLS Security Inspection Engine
- **X.509 TLS Certificate Inspector**: Real-time certificate parsing, expiry tracking, SAN domain validation, and letter grades (A+ to F).
- **HTTP Security Headers Evaluator**: Audits HSTS, Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- **DNSSEC & Anti-Spoofing Defense**: Analyzes DNSSEC records, SPF syntax, and DMARC enforcement policies.
- **Non-blocking TCP Port Scanner**: Discovers open service ports and grabs daemon banners.

### 4. 🛡️ Application Security (AppSec), WAF & SAST Engine
- **Layer 7 Web Application Firewall (WAF)**: Built-in OWASP Top 10 inspection rules blocking SQL Injection, Cross-Site Scripting (XSS), Directory Traversal, SSRF, and RCE payloads.
- **Hardcoded Secret Leak Detector**: Scans source code and configs for leaked AWS keys, GitHub PATs, JWT tokens, and private SSH keys with automated masking.
- **Software Composition Analysis (SCA)**: Analyzes Python package dependencies against known CVE security advisories and CVSS scores.

### 5. 👤 Identity Governance (IAM) & Privileged Access Management (PAM)
- **Just-in-Time (JIT) Elevation**: Self-service role elevation with dual-operator approval and automatic time-based expiry.
- **Zero-Trust Self-Approval Prevention**: Enforces separation of duties—users cannot approve their own elevation requests.
- **Attribute-Based Access Control (ABAC)**: Contextual policy engine evaluating user role, hardware MFA verification, and client IP subnet allowlists.
- **Impossible Travel Anomaly Detector**: Calculates great-circle Haversine distance and travel velocity ($>800\text{ km/h}$) between consecutive user authentications.

### 6. 🔑 Cryptographic KMS & Asymmetric Cryptography Suite
- **Managed Asymmetric Keypairs**: Generates RSA (2048/4096-bit) and ECC (secp256r1) key pairs with encrypted private keys at rest.
- **Shamir's $(k, n)$ Threshold Secret Sharing**: Splits master recovery secrets into $n$ distributed custodian shares requiring any $k$ shares to reconstruct via Galois field Lagrange polynomial interpolation.
- **Digital Signature & Attestation Studio**: Cryptographic document signing and verification using RSA-PSS and ECDSA.
- **Automated Key Rotation Lifecycle**: Retires deprecated keys and logs immutable rotation audit events.

### 7. 📋 Enterprise Compliance & Risk Matrix
- **Automated Framework Audit**: Real-time readiness scoring against SOC 2 Type II, ISO/IEC 27001:2022, and NIST SP 800-53 Rev. 5.
- **Interactive 5x5 Risk Heatmap**: Quantifies institutional exposures across Likelihood vs Impact dimensions (Scores 1 to 25).
- **Cryptographically Sealed Evidence Locker**: Stores audit artifacts sealed with immutable SHA-256 integrity checksums.

### 8. ⚡ SOAR & Automated Incident Response Playbooks
- **Automated Incident Containment**: Multi-step containment workflows (`PB-BRUTE-01`, `PB-RANSOM-02`, `PB-TRAVEL-03`).
- **Atomic Containment Primitives**: Perimeter IP blocking, immediate user session token revocation, and account deactivation.

---

## 🏛️ System Architecture

SecureVault follows a clean layered architecture adhering to Defense-in-Depth and Zero-Trust principles:

```
                               ┌─────────────────────────────────────────────────┐
                               │             Web Browser & REST API Clients      │
                               └────────────────────────┬────────────────────────┘
                                                        │ HTTP / HTTPS (JSON & HTML5)
                                                        ▼
                               ┌─────────────────────────────────────────────────┐
                               │           Flask Application Core Router         │
                               │  - Session Security (HttpOnly / SameSite=Lax)   │
                               │  - RBAC & PAM Authorization Decorators          │
                               │  - Layer 7 WAF Pre-Routing Inspection Filter   │
                               └────────────────────────┬────────────────────────┘
                                                        │
          ┌─────────────────────┬───────────────────────┼───────────────────────┬─────────────────────┐
          ▼                     ▼                       ▼                       ▼                     ▼
┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐
│ Threat Intel &    │ │ Network & TLS     │ │ AppSec & WAF      │ │ IAM & PAM         │ │ Cryptographic     │
│ SIEM Engine       │ │ Inspector         │ │ SAST/SCA Engine   │ │ Governance        │ │ KMS Suite         │
└─────────┬─────────┘ └─────────┬─────────┘ └─────────┬─────────┘ └─────────┬─────────┘ └─────────┬─────────┘
          │                     │                       │                       │                     │
          └─────────────────────┴───────────────────────┼───────────────────────┴─────────────────────┘
                                                        ▼
                               ┌─────────────────────────────────────────────────┐
                               │            Service Layer & Business Logic       │
                               │  - Shamir Polynomial Interpolator               │
                               │  - Haversine Velocity Anomaly Engine            │
                               │  - SOAR Automated Playbook Dispatcher           │
                               │  - Evidence Locker SHA-256 Seal Engine          │
                               └────────────────────────┬────────────────────────┘
                                                        │
                                                        ▼
                               ┌─────────────────────────────────────────────────┐
                               │        SQLAlchemy 2.0 ORM & Storage Layer       │
                               │  - MySQL 8.x (Production) / SQLite (Fallback)   │
                               │  - AES-256 Fernet Encrypted Field Converters    │
                               └─────────────────────────────────────────────────┘
```

---

## 🛠️ Technology Stack

| Category | Technology | Description |
| :--- | :--- | :--- |
| **Backend Framework** | **Flask 3.0+** | High-performance Python WSGI web application framework. |
| **ORM & Database** | **SQLAlchemy 2.0+ / Flask-SQLAlchemy** | Object-Relational Mapper with connection pooling. |
| **Database Engine** | **MySQL 8.0+** (with **SQLite** fallback) | Enterprise relational database with UTF8mb4 charset. |
| **Cryptography** | **Python `cryptography` 42.0+** | AES-256-GCM, RSA-PSS, ECDSA, and SHA-256 primitives. |
| **Frontend UI** | **HTML5, Vanilla CSS3, Bootstrap 5** | Responsive dark-themed SOC Command Console UI. |
| **Test Framework** | **Pytest 7.4+ & pytest-flask** | Automated fixture-driven test runner (54 test suites). |
| **Configuration** | **python-dotenv** | 12-factor environment variable management. |

---

## 📋 Prerequisites & System Requirements

- **Python**: Version 3.10, 3.11, 3.12, or 3.14+
- **MySQL Server** (Optional for local testing, fallback to SQLite available): Version 8.0+ running on `localhost:3306`
- **Operating System**: Windows, Linux, or macOS
- **Git**: Installed and configured

---

## 📦 Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/shivapendala/SecureVault.git
cd SecureVault
```

### 2. Create and Activate a Python Virtual Environment
```bash
# On Linux / macOS:
python3 -m venv venv
source venv/bin/activate

# On Windows (PowerShell):
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🗄️ Database Configuration & Bootstrapping

### 1. Configure Environment Variables
Copy the environment template file:
```bash
# On Linux / macOS:
cp .env.example .env

# On Windows:
copy .env.example .env
```

Edit `.env` to match your MySQL database credentials:
```ini
DB_TYPE=mysql
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=root
DB_NAME=securevault_db
```
*(If MySQL is not installed, set `DB_TYPE=sqlite` to run automatically on SQLite).*

### 2. Initialize and Seed the Database
Run the automated bootstrap script:
```bash
python init_db.py
```
This script will:
1. Connect to MySQL and execute `CREATE DATABASE IF NOT EXISTS securevault_db`.
2. Generate all database tables via SQLAlchemy ORM.
3. Pre-seed default security accounts, threat feeds, WAF rules, ABAC policies, compliance frameworks, and SOAR playbooks.

---

## ⚙️ Environment Variables

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `SECRET_KEY` | *(Random 32-byte string)* | Flask session encryption and CSRF signing key. |
| `MASTER_ENCRYPTION_KEY` | *(Fernet 32-byte base64)* | Master key used to encrypt private keys and secrets at rest. |
| `DB_TYPE` | `mysql` | Database driver (`mysql` or `sqlite`). |
| `DB_HOST` | `localhost` | MySQL hostname or IP address. |
| `DB_PORT` | `3306` | MySQL port. |
| `DB_USER` | `root` | Database username. |
| `DB_PASSWORD` | `root` | Database password. |
| `DB_NAME` | `securevault_db` | Database schema name. |
| `SQLITE_DB_PATH` | `securevault.db` | SQLite database file path if `DB_TYPE=sqlite`. |
| `PORT` | `5005` | Application HTTP listening port. |
| `FLASK_DEBUG` | `False` | Debug mode toggle (must be `False` in production). |

---

## 🏃 Running the Application

Start the SecureVault server:
```bash
python run.py
```

Access the web interface at:
```
http://127.0.0.1:5005
```

### Default Credentials (Created on Seeding)

| Account Role | Username | Default Password | Clearance Level |
| :--- | :--- | :--- | :--- |
| **SOC Administrator** | `admin` | `Admin@SecureVault2026!` | Root / Full Platform Access |
| **Lead SOC Analyst** | `analyst_sarah` | `Analyst@SecureVault2026!` | Threat Intel, Incident Response & WAF |
| **DevSecOps Lead** | `devops_alex` | `DevOps@SecureVault2026!` | Vault Credentials & Infrastructure |
| **Compliance Auditor** | `auditor_chen` | `Auditor@SecureVault2026!` | GRC, Risk Matrix & Evidence Locker |

---

## 🌐 REST API Gateway Documentation

SecureVault provides a standardized JSON REST API gateway:

### 1. Authentication & Session Gateway
- `POST /api/auth/register` — Register a new operator account.
- `POST /api/auth/login` — Authenticate and obtain session cookie.
- `POST /api/auth/logout` — Invalidate operator session.

### 2. Threat Intelligence APIs
- `POST /threat-intelligence/api/lookup` — Query threat indicators (IP, Domain, Hash).
- `POST /threat-intelligence/api/scan-payload` — Deep regex payload analysis against known IoCs.

### 3. Network & TLS Security APIs
- `POST /network-security/api/scan-tls` — Inspect X.509 SSL/TLS certificate for domain.
- `POST /network-security/api/scan-headers` — Analyze HTTP security response headers.
- `POST /network-security/api/scan-dns` — Audit DNSSEC and DMARC enforcement.
- `POST /network-security/api/scan-ports` — Scan TCP ports on target host.

### 4. Application Security & WAF APIs
- `POST /appsec/api/inspect-payload` — Evaluate payload against active OWASP Top 10 WAF rules.
- `POST /appsec/api/scan-secrets` — Scan source code or config string for leaked API tokens.
- `POST /appsec/api/audit-sca` — Check package dependencies against CVE vulnerability database.

### 5. Identity & PAM Governance APIs
- `POST /iam/api/request-elevation` — Submit a Just-in-Time PAM role elevation request.
- `POST /iam/api/evaluate-policy` — Test dynamic ABAC permission policy evaluation.

### 6. Cryptographic KMS APIs
- `POST /kms/api/generate-key` — Generate managed RSA or ECC asymmetric keypair.
- `POST /kms/api/shamir-split` — Split master secret into $(k, n)$ threshold shares.
- `POST /kms/api/shamir-combine` — Reconstruct master secret from threshold shares.
- `POST /kms/api/sign-payload` — Sign data payload with managed private key.

### 7. Compliance & Risk APIs
- `GET /compliance/api/frameworks` — Get readiness status across SOC 2, ISO 27001, and NIST frameworks.
- `GET /compliance/api/risk-matrix` — Retrieve 5x5 Likelihood vs Impact risk heatmap distribution.
- `POST /compliance/api/seal-evidence` — Store audit artifact sealed with SHA-256 checksum.

### 8. SOAR Automation APIs
- `GET /soar/api/playbooks` — List all automated incident response playbooks.
- `POST /soar/api/trigger-playbook` — Trigger playbook execution against malicious IP or host.

---

## 🧪 Automated Testing Suite

SecureVault includes an automated **Pytest** testing framework covering models, crypto routines, security validators, web routes, and REST APIs:

```bash
# Execute entire pytest test suite:
python -m pytest

# Run with detailed verbose output:
python -m pytest -v

# Run a specific security test module:
python -m pytest tests/test_appsec_waf_pytest.py
python -m pytest tests/test_crypto_kms_pytest.py
python -m pytest tests/test_soar_playbooks_pytest.py
```

### Verification Test Summary
```
tests/test_admin_pytest.py ..................... [  5%]
tests/test_api_endpoints_pytest.py ............. [ 11%]
tests/test_appsec_waf_pytest.py ................ [ 18%]
tests/test_auth_pytest.py ...................... [ 27%]
tests/test_compliance_matrix_pytest.py ......... [ 35%]
tests/test_crypto_kms_pytest.py ................ [ 44%]
tests/test_file_hashing_pytest.py .............. [ 48%]
tests/test_iam_pam_pytest.py ................... [ 55%]
tests/test_login_monitoring_pytest.py .......... [ 59%]
tests/test_network_security_pytest.py .......... [ 68%]
tests/test_notifications_pytest.py ............. [ 72%]
tests/test_password_hashing_pytest.py .......... [ 79%]
tests/test_security_logs_pytest.py ............. [ 83%]
tests/test_soar_playbooks_pytest.py ............ [ 90%]
tests/test_threat_intelligence_pytest.py ....... [100%]

============================= 54 passed in 12.41s =============================
```

---

## 📂 Project Directory Structure

```
SecureVault/
├── app/
│   ├── __init__.py                 # Flask app factory, extension registry & blueprints
│   ├── config.py                   # 12-factor configuration & security cookie policies
│   ├── models/                     # SQLAlchemy data models
│   │   ├── appsec.py               # WAF rules, security events & secret leak models
│   │   ├── asset.py                # Enterprise asset inventory models
│   │   ├── audit.py                # Audit log trail models
│   │   ├── compliance.py           # Compliance framework, control & risk matrix models
│   │   ├── crypto_kms.py           # Asymmetric keypairs & Shamir share models
│   │   ├── file.py                 # Encrypted file vault models
│   │   ├── iam.py                  # PAM requests, ABAC policies & session telemetry
│   │   ├── incident.py             # Security incident models
│   │   ├── login_attempt.py        # Login attempt telemetry models
│   │   ├── network_security.py     # TLS certificate, header & port scan models
│   │   ├── notification.py         # Notification dispatch models
│   │   ├── password.py             # Password vault & history models
│   │   ├── scan.py                 # Automated scanner report models
│   │   ├── security_log.py         # Centralized security log models
│   │   ├── soar.py                 # SOAR playbook, execution & step models
│   │   ├── threat_intel.py         # Threat indicator, feeds & MITRE models
│   │   ├── user.py                 # User identity & role clearance models
│   │   └── vault.py                # Secret vault credential models
│   ├── routes/                     # Blueprint controllers & REST API endpoints
│   │   ├── admin.py                # SOC administrative governance console
│   │   ├── api.py                  # Unified REST API gateway
│   │   ├── appsec.py               # WAF, SAST & SCA dependency routes
│   │   ├── assets.py               # Asset inventory routes
│   │   ├── auth.py                 # Authentication, registration & session routes
│   │   ├── compliance.py           # SOC 2, ISO 27001 & Risk Matrix routes
│   │   ├── crypto_kms.py           # Asymmetric KMS, Shamir & Signer routes
│   │   ├── dashboard.py            # Main SOC & User Command Center routes
│   │   ├── file_security.py        # Encrypted file vault & hash verification
│   │   ├── iam.py                  # PAM JIT elevation & ABAC policy routes
│   │   ├── network_security.py     # TLS, HTTP Headers & Port scan routes
│   │   ├── notifications.py        # Notification dispatch & read status routes
│   │   ├── password_security.py    # Password vault & entropy analyzer routes
│   │   ├── reports.py              # Security audit & analytics reporting
│   │   ├── scanners.py             # Security scan utilities
│   │   ├── security_logs.py        # Centralized audit log viewer & CSV/JSON export
│   │   ├── soar.py                 # SOAR automated playbook trigger & execution routes
│   │   ├── threat_intelligence.py  # Threat feed & IoC lookup routes
│   │   └── vault.py                # Secret vault routes
│   ├── services/                   # Business logic & security service engines
│   │   ├── appsec/                 # WAF engine, secret detector & SCA analyzer
│   │   ├── compliance/             # Framework readiness evaluator & 5x5 risk matrix
│   │   ├── crypto_kms/             # RSA/ECC KMS, Shamir secret sharing & digital signer
│   │   ├── iam/                    # PAM JIT approvals, ABAC engine & anomaly detector
│   │   ├── network_security/       # TLS inspector, HTTP header audit & port prober
│   │   ├── soar/                   # Playbook orchestrator & containment primitives
│   │   └── threat_intelligence/    # IoC matcher, GeoIP service & feed synchronizer
│   ├── static/                     # CSS stylesheets, JavaScript & icon assets
│   ├── templates/                  # Jinja2 HTML5 UI templates & consoles
│   └── utils/                      # Cryptographic helpers, validators & database seeders
├── tests/                          # Comprehensive Pytest test suites (54 tests)
│   ├── conftest.py                 # Pytest test fixtures & factory instances
│   ├── test_admin_pytest.py        # Admin governance test suite
│   ├── test_api_endpoints_pytest.py# REST API gateway test suite
│   ├── test_appsec_waf_pytest.py   # WAF, SAST & SCA test suite
│   ├── test_auth_pytest.py         # Authentication & session test suite
│   ├── test_compliance_matrix_pytest.py # Compliance & 5x5 risk test suite
│   ├── test_crypto_kms_pytest.py   # Asymmetric KMS & Shamir test suite
│   ├── test_file_hashing_pytest.py # File integrity & encryption test suite
│   ├── test_iam_pam_pytest.py      # PAM elevation & ABAC test suite
│   ├── test_login_monitoring_pytest.py # Login attempt telemetry test suite
│   ├── test_network_security_pytest.py # TLS, HTTP headers & port scan test suite
│   ├── test_notifications_pytest.py# Threat notification test suite
│   ├── test_password_hashing_pytest.py # Password entropy & hashing test suite
│   ├── test_security_logs_pytest.py# Security audit log test suite
│   ├── test_soar_playbooks_pytest.py   # SOAR incident response test suite
│   └── test_threat_intelligence_pytest.py # Threat Intel & MITRE test suite
├── .env.example                    # Environment variable template
├── init_db.py                      # Database schema creator & engine seeder
├── pytest.ini                      # Pytest runner configuration
├── README.md                       # Comprehensive platform documentation
├── requirements.txt                # Pinned production Python dependencies
└── run.py                          # Application entry point & development server
```

---

## 🔒 Contributing & Security Policy

1. **Reporting Vulnerabilities**: If you discover a potential security flaw in SecureVault, please open a private vulnerability report or email security@securevault.io rather than submitting a public issue.
2. **Pull Requests**: Ensure all pull requests include corresponding automated pytest test suites and pass `python -m pytest` with 100% success rate.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for full details.
