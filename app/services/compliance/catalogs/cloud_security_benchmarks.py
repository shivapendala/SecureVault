"""
SecureVault Cloud Security Posture Management (CSPM) CIS Benchmarks
"""

CSPM_BENCHMARK_RULES = [
    {
        'benchmark_id': 'CIS-AWS-1.1',
        'cloud_provider': 'AWS',
        'security_domain': 'Identity',
        'title': 'Avoid the use of the root user account',
        'severity': 'CRITICAL',
        'remediation_guidance': """Do not use the AWS root account for administrative tasks; mandate IAM/SSO credentials.""",
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-1.4',
        'cloud_provider': 'AWS',
        'security_domain': 'Identity',
        'title': 'Ensure MFA is enabled for all IAM users with console passwords',
        'severity': 'HIGH',
        'remediation_guidance': """Enforce hardware MFA on all console-accessible IAM accounts.""",
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-2.1.1',
        'cloud_provider': 'AWS',
        'security_domain': 'Storage',
        'title': 'Ensure all S3 buckets employ encryption at rest',
        'severity': 'HIGH',
        'remediation_guidance': """Enable SSE-S3 or SSE-KMS on all S3 buckets.""",
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-2.1.2',
        'cloud_provider': 'AWS',
        'security_domain': 'Storage',
        'title': 'Ensure S3 Bucket Policy blocks public read/write access',
        'severity': 'CRITICAL',
        'remediation_guidance': """Enable S3 Block Public Access at account and bucket levels.""",
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-3.1',
        'cloud_provider': 'AWS',
        'security_domain': 'Logging',
        'title': 'Ensure CloudTrail is enabled across all AWS regions',
        'severity': 'HIGH',
        'remediation_guidance': """Enable multi-region CloudTrail with KMS encryption and log file validation.""",
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AZURE-1.1',
        'cloud_provider': 'Azure',
        'security_domain': 'Identity',
        'title': 'Ensure Multi-Factor Authentication is required for all administrators',
        'severity': 'HIGH',
        'remediation_guidance': """Configure Entra ID Conditional Access policies requiring MFA for administrative roles.""",
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AZURE-2.1',
        'cloud_provider': 'Azure',
        'security_domain': 'Security Center',
        'title': 'Ensure Microsoft Defender for Cloud is enabled across subscriptions',
        'severity': 'MEDIUM',
        'remediation_guidance': """Enable standard tier Defender for Cloud on all subscription resources.""",
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-1.1',
        'cloud_provider': 'GCP',
        'security_domain': 'Identity',
        'title': 'Ensure corporate login credentials are used instead of personal accounts',
        'severity': 'HIGH',
        'remediation_guidance': """Enforce Google Cloud Identity Federation with enterprise IdP.""",
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-K8S-1.1.1',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Control Plane',
        'title': 'Ensure API server pod specification file permissions are 600 or more restrictive',
        'severity': 'HIGH',
        'remediation_guidance': """chmod 600 /etc/kubernetes/manifests/kube-apiserver.yaml""",
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-K8S-5.1.1',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'RBAC',
        'title': 'Ensure cluster-admin role is only assigned to authorized groups',
        'severity': 'CRITICAL',
        'remediation_guidance': """Audit ClusterRoleBindings and restrict cluster-admin privilege.""",
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-GCP-{i:03d}',
        'cloud_provider': 'GCP',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for GCP',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Kubernetes-{i:03d}',
        'cloud_provider': 'Kubernetes',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Kubernetes',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-AWS-{i:03d}',
        'cloud_provider': 'AWS',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for AWS',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
    {
        'benchmark_id': 'CIS-Azure-{i:03d}',
        'cloud_provider': 'Azure',
        'security_domain': 'Infrastructure Configuration',
        'title': 'CIS Benchmark Safeguard #{i:03d} for Azure',
        'severity': 'HIGH',
        'remediation_guidance': 'Verify cloud resource configuration against secure baseline policy.',
        'evaluation_status': 'COMPLIANT'
    },
]

def get_all_cspm_benchmarks():
    return CSPM_BENCHMARK_RULES
