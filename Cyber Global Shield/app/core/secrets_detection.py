"""
Cyber Global Shield — Secrets Detection Engine
Détection de secrets, tokens, clés API, et credentials dans le code.
Pattern matching avancé avec validation contextuelle.
"""

import json
import logging
import re
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SecretFinding:
    """A detected secret finding."""
    finding_id: str
    secret_type: str
    file_path: str
    line_number: int
    context: str
    severity: str
    description: str
    remediation: str


class SecretsDetectionEngine:
    """
    Moteur de détection de secrets.
    
    Détecte:
    - AWS Access Keys (AKIA...)
    - GitHub Tokens (ghp_...)
    - Private Keys (RSA, DSA, EC)
    - JWT Tokens
    - API Keys (various formats)
    - Database URLs
    - Slack Tokens
    - Google Service Accounts
    - Generic passwords/secrets
    """

    def __init__(self):
        self._scans: List[Dict] = []
        self._patterns = self._load_patterns()
        self._false_positive_patterns = self._load_false_positive_patterns()

    def _load_patterns(self) -> Dict[str, Dict]:
        """Load secret detection patterns."""
        return {
            "aws_access_key": {
                "pattern": r"AKIA[0-9A-Z]{16}",
                "severity": "critical",
                "description": "AWS Access Key ID exposed",
                "remediation": "Revoke key immediately, rotate credentials",
            },
            "aws_secret_key": {
                "pattern": r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]",
                "severity": "critical",
                "description": "AWS Secret Access Key exposed",
                "remediation": "Revoke key immediately, rotate credentials",
            },
            "github_token": {
                "pattern": r"ghp_[0-9a-zA-Z]{36}",
                "severity": "critical",
                "description": "GitHub Personal Access Token exposed",
                "remediation": "Revoke token in GitHub settings, rotate immediately",
            },
            "github_old_token": {
                "pattern": r"gho_[0-9a-zA-Z]{36}",
                "severity": "critical",
                "description": "GitHub OAuth Access Token exposed",
                "remediation": "Revoke token in GitHub settings",
            },
            "gitlab_token": {
                "pattern": r"glpat-[0-9a-zA-Z\-_]{20,}",
                "severity": "critical",
                "description": "GitLab Personal Access Token exposed",
                "remediation": "Revoke token in GitLab settings",
            },
            "slack_token": {
                "pattern": r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
                "severity": "critical",
                "description": "Slack API Token exposed",
                "remediation": "Revoke token in Slack API dashboard",
            },
            "slack_webhook": {
                "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,}",
                "severity": "high",
                "description": "Slack Webhook URL exposed",
                "remediation": "Rotate webhook URL in Slack",
            },
            "private_key": {
                "pattern": r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
                "severity": "critical",
                "description": "Private cryptographic key exposed",
                "remediation": "Rotate key pair immediately, check for unauthorized access",
            },
            "jwt_token": {
                "pattern": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
                "severity": "high",
                "description": "JWT Token exposed",
                "remediation": "Invalidate token, rotate signing key",
            },
            "google_api_key": {
                "pattern": r"AIza[0-9A-Za-z\-_]{35}",
                "severity": "high",
                "description": "Google API Key exposed",
                "remediation": "Regenerate key in Google Cloud Console",
            },
            "google_service_account": {
                "pattern": r"\"type\": \"service_account\"",
                "severity": "critical",
                "description": "Google Service Account JSON exposed",
                "remediation": "Delete service account key, create new one",
            },
            "heroku_api_key": {
                "pattern": r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
                "severity": "high",
                "description": "Heroku API Key exposed",
                "remediation": "Regenerate API key in Heroku dashboard",
            },
            "database_url": {
                "pattern": r"(postgres|mysql|mongodb|redis)://[a-zA-Z0-9_]+:[^@\s]+@",
                "severity": "critical",
                "description": "Database connection string with credentials exposed",
                "remediation": "Rotate database password, use secrets manager",
            },
            "password_in_code": {
                "pattern": r"(?i)(password|passwd|pwd|secret|token|api_key|apikey)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
                "severity": "high",
                "description": "Potential hardcoded credential",
                "remediation": "Move to environment variables or secrets manager",
            },
            "npm_token": {
                "pattern": r"npm_[a-zA-Z0-9]{36}",
                "severity": "high",
                "description": "npm access token exposed",
                "remediation": "Revoke token in npm settings",
            },
            "twilio_api_key": {
                "pattern": r"SK[a-f0-9]{32}",
                "severity": "high",
                "description": "Twilio API Key exposed",
                "remediation": "Rotate key in Twilio Console",
            },
            "stripe_api_key": {
                "pattern": r"(sk_live|pk_live)_[0-9a-zA-Z]{24,}",
                "severity": "critical",
                "description": "Stripe Live API Key exposed",
                "remediation": "Rotate key in Stripe Dashboard immediately",
            },
            "azure_connection_string": {
                "pattern": r"DefaultEndpointsProtocol=https;AccountName=[a-zA-Z0-9]+;AccountKey=[a-zA-Z0-9+/=]+",
                "severity": "critical",
                "description": "Azure Storage connection string exposed",
                "remediation": "Regenerate storage account keys in Azure Portal",
            },
        }

    def _load_false_positive_patterns(self) -> List[str]:
        """Load patterns to ignore (false positives)."""
        return [
            r"example\.com",
            r"your-",
            r"<YOUR_",
            r"YOUR_API_KEY",
            r"xxxx",
            r"test_key",
            r"dummy",
            r"placeholder",
        ]

    def scan_file(self, file_path: str, content: str) -> List[SecretFinding]:
        """Scan a file for secrets."""
        findings = []
        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            for secret_type, config in self._patterns.items():
                matches = re.finditer(config["pattern"], line)
                
                for match in matches:
                    # Check for false positives
                    if self._is_false_positive(line, match.group()):
                        continue

                    # Get context (surrounding lines)
                    context_start = max(0, line_num - 2)
                    context_end = min(len(lines), line_num + 2)
                    context = '\n'.join(lines[context_start:context_end])

                    finding = SecretFinding(
                        finding_id=f"SEC-{secret_type}-{len(findings)+1}",
                        secret_type=secret_type,
                        file_path=file_path,
                        line_number=line_num,
                        context=context,
                        severity=config["severity"],
                        description=config["description"],
                        remediation=config["remediation"],
                    )
                    findings.append(finding)

        return findings

    def _is_false_positive(self, line: str, match: str) -> bool:
        """Check if a match is a false positive."""
        for pattern in self._false_positive_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        return False

    def scan_repository(self, repo_path: str, files: Dict[str, str]) -> Dict[str, Any]:
        """Scan a repository for secrets."""
        scan_id = f"SECSCAN-{int(datetime.utcnow().timestamp())}"
        all_findings = []

        for file_path, content in files.items():
            findings = self.scan_file(file_path, content)
            all_findings.extend(findings)

        scan_result = {
            "scan_id": scan_id,
            "timestamp": datetime.utcnow().isoformat(),
            "repository": repo_path,
            "files_scanned": len(files),
            "total_findings": len(all_findings),
            "critical": len([f for f in all_findings if f.severity == "critical"]),
            "high": len([f for f in all_findings if f.severity == "high"]),
            "medium": len([f for f in all_findings if f.severity == "medium"]),
            "findings": [f.__dict__ for f in all_findings],
            "summary": self._generate_summary(all_findings),
        }

        self._scans.append(scan_result)
        
        if scan_result["critical"] > 0:
            logger.critical(
                f"🔑 Secrets scan: {scan_result['critical']} critical secrets "
                f"found in {repo_path}"
            )

        return scan_result

    def _generate_summary(self, findings: List[SecretFinding]) -> Dict:
        """Generate scan summary."""
        types = {}
        for f in findings:
            types[f.secret_type] = types.get(f.secret_type, 0) + 1
        
        return {
            "secret_types": types,
            "most_common": max(types, key=types.get) if types else None,
            "risk_level": "critical" if any(f.severity == "critical" for f in findings) else "high",
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get secrets detection statistics."""
        return {
            "total_scans": len(self._scans),
            "total_secrets_found": sum(s["total_findings"] for s in self._scans),
            "critical_secrets": sum(s["critical"] for s in self._scans),
            "files_scanned": sum(s["files_scanned"] for s in self._scans),
            "status": "SCANNING",
        }


secrets_detection = SecretsDetectionEngine()
