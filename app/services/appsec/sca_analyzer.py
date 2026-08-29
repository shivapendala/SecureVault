from datetime import datetime
from app import db
from app.models.appsec import ScaDependencyFinding

KNOWN_SCA_VULNERABILITIES = [
    {
        'package': 'requests',
        'vulnerable_below': '2.31.0',
        'patched': '2.31.0',
        'cve': 'CVE-2023-32681',
        'cvss': 6.1,
        'severity': 'MEDIUM',
        'desc': 'Unintended leak of Proxy-Authorization header during cross-origin redirect.'
    },
    {
        'package': 'cryptography',
        'vulnerable_below': '42.0.4',
        'patched': '42.0.4',
        'cve': 'CVE-2024-26130',
        'cvss': 7.5,
        'severity': 'HIGH',
        'desc': 'NULL pointer dereference when loading PKCS#7 or PKCS#12 certificates.'
    },
    {
        'package': 'werkzeug',
        'vulnerable_below': '3.0.3',
        'patched': '3.0.3',
        'cve': 'CVE-2024-34069',
        'cvss': 7.5,
        'severity': 'HIGH',
        'desc': 'Debugger execution vulnerability in development mode endpoint.'
    },
    {
        'package': 'urllib3',
        'vulnerable_below': '2.0.7',
        'patched': '2.0.7',
        'cve': 'CVE-2023-45803',
        'cvss': 8.2,
        'severity': 'HIGH',
        'desc': 'Request body not stripped during 303 redirect with sensitive session tokens.'
    }
]

class ScaAnalyzerService:
    """Software Composition Analysis (SCA) dependency auditor."""

    @classmethod
    def audit_dependencies(cls, package_list: list[tuple]) -> list[dict]:
        """Audit list of (package_name, version_str) against known CVE advisories."""
        findings = []

        for pkg_name, ver_str in package_list:
            clean_pkg = pkg_name.strip().lower()
            for adv in KNOWN_SCA_VULNERABILITIES:
                if adv['package'] == clean_pkg:
                    finding = ScaDependencyFinding(
                        package_name=pkg_name,
                        current_version=ver_str,
                        patched_version=adv['patched'],
                        cve_id=adv['cve'],
                        cvss_score=adv['cvss'],
                        severity=adv['severity'],
                        description=adv['desc']
                    )
                    db.session.add(finding)
                    findings.append(finding.to_dict())

        if findings:
            db.session.commit()

        return findings
