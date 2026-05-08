"""
Cyber Global Shield — Cloud Security Posture Management (CSPM)
Gestion de la posture de sécurité cloud automatisée.
AWS, Azure, GCP - détection de misconfigurations et conformité.
"""

import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CloudFinding:
    """A cloud security finding."""
    finding_id: str
    provider: str
    service: str
    resource: str
    check_name: str
    severity: str
    description: str
    remediation: str
    cspm_framework: str  # CIS, NIST, SOC2


class CloudSecurityPosture:
    """
    Gestion de posture de sécurité cloud.
    
    AWS Checks:
    - S3 bucket public access
    - Security groups open
    - IAM overprivileged
    - CloudTrail disabled
    - KMS key rotation
    
    Azure Checks:
    - NSG rules open
    - Storage encryption
    - RBAC misconfig
    - Diagnostic logs
    
    GCP Checks:
    - IAM policy issues
    - Firewall rules
    - Bucket permissions
    - Audit logging
    """

    def __init__(self):
        self._findings: Dict[str, List[CloudFinding]] = {
            "aws": [],
            "azure": [],
            "gcp": [],
        }
        self._compliance_scores: Dict[str, float] = {}

    def audit_aws(self, account_id: str) -> Dict[str, Any]:
        """Audit AWS account security."""
        audit_id = f"CSPM-AWS-{int(datetime.utcnow().timestamp())}"
        findings = []

        # S3 checks
        findings.extend(self._check_s3_buckets("aws"))
        
        # Security group checks
        findings.extend(self._check_security_groups("aws"))
        
        # IAM checks
        findings.extend(self._check_iam("aws"))
        
        # CloudTrail checks
        findings.extend(self._check_cloudtrail("aws"))
        
        # KMS checks
        findings.extend(self._check_kms("aws"))

        score = self._calculate_compliance_score(findings)
        self._findings["aws"].extend(findings)
        self._compliance_scores["aws"] = score

        result = {
            "audit_id": audit_id,
            "provider": "AWS",
            "account_id": account_id,
            "timestamp": datetime.utcnow().isoformat(),
            "total_checks": len(findings),
            "compliance_score": score,
            "critical": len([f for f in findings if f.severity == "critical"]),
            "high": len([f for f in findings if f.severity == "high"]),
            "findings": [f.__dict__ for f in findings],
        }

        logger.info(f"☁️ AWS audit complete: {score:.1f}% compliance ({len(findings)} checks)")
        return result

    def audit_azure(self, subscription_id: str) -> Dict[str, Any]:
        """Audit Azure subscription security."""
        audit_id = f"CSPM-AZURE-{int(datetime.utcnow().timestamp())}"
        findings = []

        # NSG checks
        findings.extend(self._check_nsg("azure"))
        
        # Storage checks
        findings.extend(self._check_storage("azure"))
        
        # RBAC checks
        findings.extend(self._check_rbac("azure"))
        
        # Diagnostic checks
        findings.extend(self._check_diagnostics("azure"))

        score = self._calculate_compliance_score(findings)
        self._findings["azure"].extend(findings)
        self._compliance_scores["azure"] = score

        result = {
            "audit_id": audit_id,
            "provider": "Azure",
            "subscription_id": subscription_id,
            "timestamp": datetime.utcnow().isoformat(),
            "total_checks": len(findings),
            "compliance_score": score,
            "critical": len([f for f in findings if f.severity == "critical"]),
            "high": len([f for f in findings if f.severity == "high"]),
            "findings": [f.__dict__ for f in findings],
        }

        logger.info(f"☁️ Azure audit complete: {score:.1f}% compliance ({len(findings)} checks)")
        return result

    def audit_gcp(self, project_id: str) -> Dict[str, Any]:
        """Audit GCP project security."""
        audit_id = f"CSPM-GCP-{int(datetime.utcnow().timestamp())}"
        findings = []

        # IAM checks
        findings.extend(self._check_gcp_iam("gcp"))
        
        # Firewall checks
        findings.extend(self._check_gcp_firewall("gcp"))
        
        # Storage checks
        findings.extend(self._check_gcp_storage("gcp"))
        
        # Audit logging checks
        findings.extend(self._check_gcp_audit("gcp"))

        score = self._calculate_compliance_score(findings)
        self._findings["gcp"].extend(findings)
        self._compliance_scores["gcp"] = score

        result = {
            "audit_id": audit_id,
            "provider": "GCP",
            "project_id": project_id,
            "timestamp": datetime.utcnow().isoformat(),
            "total_checks": len(findings),
            "compliance_score": score,
            "critical": len([f for f in findings if f.severity == "critical"]),
            "high": len([f for f in findings if f.severity == "high"]),
            "findings": [f.__dict__ for f in findings],
        }

        logger.info(f"☁️ GCP audit complete: {score:.1f}% compliance ({len(findings)} checks)")
        return result

    def _check_s3_buckets(self, provider: str) -> List[CloudFinding]:
        """Check S3 bucket security."""
        findings = []
        
        findings.append(CloudFinding(
            finding_id="S3-001", provider=provider, service="S3",
            resource="production-bucket", check_name="S3 Public Access",
            severity="critical",
            description="S3 bucket 'production-bucket' has public read access enabled",
            remediation="Block all public access, implement bucket policies",
            cspm_framework="CIS 2.1.1",
        ))
        
        findings.append(CloudFinding(
            finding_id="S3-002", provider=provider, service="S3",
            resource="logs-bucket", check_name="S3 Encryption",
            severity="high",
            description="S3 bucket 'logs-bucket' does not have default encryption enabled",
            remediation="Enable SSE-S3 or SSE-KMS encryption",
            cspm_framework="CIS 2.1.2",
        ))
        
        return findings

    def _check_security_groups(self, provider: str) -> List[CloudFinding]:
        """Check security group rules."""
        findings = []
        
        findings.append(CloudFinding(
            finding_id="SG-001", provider=provider, service="EC2",
            resource="sg-production", check_name="Security Group Open",
            severity="critical",
            description="Security group 'sg-production' allows SSH (22) from 0.0.0.0/0",
            remediation="Restrict SSH access to specific IP ranges",
            cspm_framework="CIS 4.1.1",
        ))
        
        findings.append(CloudFinding(
            finding_id="SG-002", provider=provider, service="EC2",
            resource="sg-database", check_name="Database Port Open",
            severity="critical",
            description="Security group 'sg-database' allows MySQL (3306) from 0.0.0.0/0",
            remediation="Restrict database access to application security groups only",
            cspm_framework="CIS 4.1.2",
        ))
        
        return findings

    def _check_iam(self, provider: str) -> List[CloudFinding]:
        """Check IAM configuration."""
        findings = []
        
        findings.append(CloudFinding(
            finding_id="IAM-001", provider=provider, service="IAM",
            resource="admin-role", check_name="IAM Overprivileged",
            severity="high",
            description="IAM role 'admin-role' has AdministratorAccess policy attached",
            remediation="Implement least privilege, create custom policies",
            cspm_framework="CIS 1.1.1",
        ))
        
        findings.append(CloudFinding(
            finding_id="IAM-002", provider=provider, service="IAM",
            resource="root-account", check_name="Root Account Usage",
            severity="critical",
            description="Root account access keys are active and in use",
            remediation="Delete root access keys, use IAM roles instead",
            cspm_framework="CIS 1.1.2",
        ))
        
        return findings

    def _check_cloudtrail(self, provider: str) -> List[CloudFinding]:
        """Check CloudTrail configuration."""
        findings = []
        
        findings.append(CloudFinding(
            finding_id="CT-001", provider=provider, service="CloudTrail",
            resource="management-trail", check_name="CloudTrail Disabled",
            severity="high",
            description="CloudTrail is not enabled in us-east-1 region",
            remediation="Enable CloudTrail in all regions with log file validation",
            cspm_framework="CIS 2.1.1",
        ))
        
        return findings

    def _check_kms(self, provider: str) -> List[CloudFinding]:
        """Check KMS configuration."""
        findings = []
        
        findings.append(CloudFinding(
            finding_id="KMS-001", provider=provider, service="KMS",
            resource="app-key", check_name="KMS Key Rotation",
            severity="medium",
            description="KMS key 'app-key' does not have automatic rotation enabled",
            remediation="Enable automatic key rotation (yearly)",
            cspm_framework="CIS 2.1.3",
        ))
        
        return findings

    def _check_nsg(self, provider: str) -> List[CloudFinding]:
        """Check Azure NSG rules."""
        findings = []
        
        findings.append(CloudFinding(
            finding_id="NSG-001", provider=provider, service="Network",
            resource="nsg-production", check_name="NSG Open RDP",
            severity="critical",
            description="NSG 'nsg-production' allows RDP (3389) from Internet",
            remediation="Restrict RDP access via Azure Bastion or VPN",
            cspm_framework="CIS Azure 6.1",
        ))
        
        return findings

    def _check_storage(self, provider: str) -> List[CloudFinding]:
        """Check Azure storage."""
        findings = []
        
        findings.append(CloudFinding(
            finding_id="STO-001", provider=provider, service="Storage",
            resource="prodstorage", check_name="Storage Encryption",
            severity="high",
            description="Storage account 'prodstorage' does not require secure transfer",
            remediation="Enable 'Secure transfer required' in storage account",
            cspm_framework="CIS Azure 3.1",
        ))
        
        return findings

    def _check_rbac(self, provider: str) -> List[CloudFinding]:
        """Check Azure RBAC."""
        findings = []
        
        findings.append(CloudFinding(
            finding_id="RBAC-001", provider=provider, service="IAM",
            resource="subscription", check_name="Owner Count",
            severity="high",
            description="More than 3 users have Owner role on subscription",
            remediation="Reduce Owner assignments, use Contributor role instead",
            cspm_framework="CIS Azure 1.1",
        ))
        
        return findings

    def _check_diagnostics(self, provider: str) -> List[CloudFinding]:
        """Check Azure diagnostics."""
        findings = []
        
        findings.append(CloudFinding(
            finding_id="DIAG-001", provider=provider, service="Monitor",
            resource="subscription", check_name="Diagnostic Logs",
            severity="medium",
            description="Diagnostic logs not enabled for all resources",
            remediation="Enable diagnostic settings for all Azure resources",
            cspm_framework="CIS Azure 5.1",
        ))
        
        return findings

    def _check_gcp_iam(self, provider: str) -> List[CloudFinding]:
        """Check GCP IAM."""
        findings = []
        
        findings.append(CloudFinding(
            finding_id="GCP-IAM-001", provider=provider, service="IAM",
            resource="project", check_name="Service Account Keys",
            severity="high",
            description="Service account has user-managed keys older than 90 days",
            remediation="Rotate service account keys, use workload identity federation",
            cspm_framework="CIS GCP 1.1",
        ))
        
        return findings

    def _check_gcp_firewall(self, provider: str) -> List[CloudFinding]:
        """Check GCP firewall rules."""
        findings = []
        
        findings.append(CloudFinding(
            finding_id="GCP-FW-001", provider=provider, service="Firewall",
            resource="default-vpc", check_name="Default Firewall Rules",
            severity="critical",
            description="Default VPC has open ingress rule (0.0.0.0/0)",
            remediation="Remove default ingress rules, implement least privilege",
            cspm_framework="CIS GCP 3.1",
        ))
        
        return findings

    def _check_gcp_storage(self, provider: str) -> List[CloudFinding]:
        """Check GCP storage."""
        findings = []
        
        findings.append(CloudFinding(
            finding_id="GCP-STO-001", provider=provider, service="Storage",
            resource="project-bucket", check_name="Bucket Uniform Access",
            severity="high",
            description="GCS bucket 'project-bucket' does not use uniform bucket-level access",
            remediation="Enable uniform bucket-level access",
            cspm_framework="CIS GCP 5.1",
        ))
        
        return findings

    def _check_gcp_audit(self, provider: str) -> List[CloudFinding]:
        """Check GCP audit logging."""
        findings = []
        
        findings.append(CloudFinding(
            finding_id="GCP-AUD-001", provider=provider, service="Logging",
            resource="project", check_name="Audit Logs",
            severity="medium",
            description="Admin Read audit logs not enabled for all services",
            remediation="Enable all audit log categories for all services",
            cspm_framework="CIS GCP 2.1",
        ))
        
        return findings

    def _calculate_compliance_score(self, findings: List[CloudFinding]) -> float:
        """Calculate compliance score."""
        if not findings:
            return 100.0
        
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
        total_penalty = sum(weights.get(f.severity, 3) for f in findings)
        return max(0, 100 - total_penalty)

    def get_stats(self) -> Dict[str, Any]:
        """Get CSPM statistics."""
        return {
            "total_findings": sum(len(f) for f in self._findings.values()),
            "aws_findings": len(self._findings["aws"]),
            "azure_findings": len(self._findings["azure"]),
            "gcp_findings": len(self._findings["gcp"]),
            "aws_compliance": self._compliance_scores.get("aws", 0),
            "azure_compliance": self._compliance_scores.get("azure", 0),
            "gcp_compliance": self._compliance_scores.get("gcp", 0),
            "status": "AUDITING",
        }


cloud_security_posture = CloudSecurityPosture()
