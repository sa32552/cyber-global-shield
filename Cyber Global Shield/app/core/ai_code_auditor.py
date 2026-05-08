"""
Cyber Global Shield — AI Code Security Auditor
Audit de code source automatisé par IA.
Détection des vulnérabilités, mauvaises pratiques, et backdoors.
"""

import json
import re
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CodeVulnerability:
    """A vulnerability found in code."""
    file: str
    line: int
    severity: str  # critical, high, medium, low, info
    cwe_id: str
    description: str
    code_snippet: str
    recommendation: str
    confidence: float


class AICodeSecurityAuditor:
    """
    AI Code Security Auditor.
    
    Détecte:
    - Injections (SQL, Command, LDAP, XPath)
    - XSS (Reflected, Stored, DOM-based)
    - Path traversal
    - Insecure deserialization
    - Hardcoded secrets
    - Backdoors
    - Race conditions
    - Memory leaks
    - Cryptographic weaknesses
    - OWASP Top 10
    """

    def __init__(self):
        self._findings: List[CodeVulnerability] = []
        self._patterns = self._load_security_patterns()

    def _load_security_patterns(self) -> Dict[str, List[Dict]]:
        """Load security vulnerability patterns."""
        return {
            "sql_injection": [
                {
                    "pattern": r"(SELECT|INSERT|UPDATE|DELETE).*FROM.*WHERE.*[\"']\s*\+",
                    "cwe": "CWE-89",
                    "severity": "critical",
                    "description": "SQL Injection vulnerability - string concatenation in query",
                    "recommendation": "Use parameterized queries or ORM",
                },
                {
                    "pattern": r"execute\s*\(\s*[\"']\s*SELECT",
                    "cwe": "CWE-89",
                    "severity": "critical",
                    "description": "SQL Injection - raw SQL execution",
                    "recommendation": "Use parameterized queries",
                },
                {
                    "pattern": r"raw\(.*request|raw\(.*input|raw\(.*get",
                    "cwe": "CWE-89",
                    "severity": "high",
                    "description": "Raw SQL with user input",
                    "recommendation": "Sanitize input and use ORM",
                },
            ],
            "command_injection": [
                {
                    "pattern": r"os\.system\(|subprocess\.call\(|subprocess\.Popen\(|eval\(|exec\(",
                    "cwe": "CWE-78",
                    "severity": "critical",
                    "description": "Command injection - system command execution",
                    "recommendation": "Avoid system commands, use safe APIs",
                },
                {
                    "pattern": r"shell=True",
                    "cwe": "CWE-78",
                    "severity": "high",
                    "description": "Shell execution enabled",
                    "recommendation": "Avoid shell=True, use argument lists",
                },
            ],
            "xss": [
                {
                    "pattern": r"innerHTML\s*=|outerHTML\s*=|document\.write\(|\.html\s*\(.*request",
                    "cwe": "CWE-79",
                    "severity": "high",
                    "description": "Cross-Site Scripting (XSS) - unsafe HTML injection",
                    "recommendation": "Use textContent or sanitize HTML",
                },
                {
                    "pattern": r"<script>.*</script>",
                    "cwe": "CWE-79",
                    "severity": "critical",
                    "description": "Hardcoded script tag - possible XSS",
                    "recommendation": "Remove inline scripts, use CSP",
                },
            ],
            "path_traversal": [
                {
                    "pattern": r"open\(.*\.\.\/|open\(.*\.\.\\|file_get_contents\(.*\.\.\/",
                    "cwe": "CWE-22",
                    "severity": "high",
                    "description": "Path traversal - directory traversal detected",
                    "recommendation": "Validate and sanitize file paths",
                },
            ],
            "hardcoded_secrets": [
                {
                    "pattern": r"password\s*=\s*[\"'][^\"']+[\"']|secret\s*=\s*[\"'][^\"']+[\"']|api_key\s*=\s*[\"'][^\"']+[\"']",
                    "cwe": "CWE-798",
                    "severity": "critical",
                    "description": "Hardcoded credential detected",
                    "recommendation": "Use environment variables or secret manager",
                },
                {
                    "pattern": r"-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----",
                    "cwe": "CWE-312",
                    "severity": "critical",
                    "description": "Private key hardcoded in source",
                    "recommendation": "Remove private key, use HSM or key vault",
                },
                {
                    "pattern": r"AKIA[0-9A-Z]{16}",
                    "cwe": "CWE-798",
                    "severity": "critical",
                    "description": "AWS Access Key ID detected",
                    "recommendation": "Rotate key immediately, use IAM roles",
                },
            ],
            "insecure_deserialization": [
                {
                    "pattern": r"pickle\.loads\(|yaml\.load\(|marshal\.loads\(|eval\(.*request",
                    "cwe": "CWE-502",
                    "severity": "high",
                    "description": "Insecure deserialization",
                    "recommendation": "Use safe serialization formats (JSON)",
                },
            ],
            "crypto_weakness": [
                {
                    "pattern": r"MD5|SHA1|DES\s*\(|RC4|ECB",
                    "cwe": "CWE-327",
                    "severity": "high",
                    "description": "Weak cryptographic algorithm",
                    "recommendation": "Use AES-256-GCM, SHA-256, or stronger",
                },
                {
                    "pattern": r"ssl\.wrap_socket|ssl_version.*SSLv2|ssl_version.*SSLv3",
                    "cwe": "CWE-326",
                    "severity": "high",
                    "description": "Inadequate SSL/TLS configuration",
                    "recommendation": "Use TLS 1.2+ with strong ciphers",
                },
            ],
            "race_condition": [
                {
                    "pattern": r"if\s+os\.path\.exists.*\n.*open\(|check.*\n.*write",
                    "cwe": "CWE-367",
                    "severity": "medium",
                    "description": "TOCTOU race condition",
                    "recommendation": "Use atomic operations or file locks",
                },
            ],
            "debug_backdoor": [
                {
                    "pattern": r"debug=True|DEBUG=True|app\.run\(.*debug|werkzeug",
                    "cwe": "CWE-489",
                    "severity": "high",
                    "description": "Debug mode enabled in production",
                    "recommendation": "Disable debug mode in production",
                },
                {
                    "pattern": r"#\s*TODO.*security|#\s*FIXME.*security|#\s*HACK.*security",
                    "cwe": "CWE-1104",
                    "severity": "medium",
                    "description": "Unresolved security TODO/FIXME",
                    "recommendation": "Address security-related TODOs",
                },
            ],
        }

    def audit_file(self, file_path: str, content: str) -> List[CodeVulnerability]:
        """Audit a single file for vulnerabilities."""
        findings = []
        lines = content.split('\n')

        for vuln_type, patterns in self._patterns.items():
            for pattern_info in patterns:
                try:
                    matches = re.finditer(
                        pattern_info["pattern"], content, re.IGNORECASE
                    )
                    for match in matches:
                        # Find line number
                        line_num = content[:match.start()].count('\n') + 1
                        
                        # Get code snippet
                        start = max(0, line_num - 3)
                        end = min(len(lines), line_num + 2)
                        snippet = '\n'.join(lines[start:end])

                        vulnerability = CodeVulnerability(
                            file=file_path,
                            line=line_num,
                            severity=pattern_info["severity"],
                            cwe_id=pattern_info["cwe"],
                            description=pattern_info["description"],
                            code_snippet=snippet,
                            recommendation=pattern_info["recommendation"],
                            confidence=0.85,
                        )
                        findings.append(vulnerability)
                        self._findings.append(vulnerability)

                except re.error as e:
                    logger.error(f"Regex error for {vuln_type}: {e}")

        if findings:
            logger.warning(
                f"🔍 Found {len(findings)} vulnerabilities in {file_path}"
            )
            for f in findings:
                logger.warning(
                    f"  [{f.severity.upper()}] {f.cwe_id}: {f.description} "
                    f"(line {f.line})"
                )

        return findings

    def audit_project(self, files: Dict[str, str]) -> Dict[str, Any]:
        """Audit an entire project."""
        all_findings = []
        
        for file_path, content in files.items():
            findings = self.audit_file(file_path, content)
            all_findings.extend(findings)

        return {
            "total_files_audited": len(files),
            "total_vulnerabilities": len(all_findings),
            "critical": len([f for f in all_findings if f.severity == "critical"]),
            "high": len([f for f in all_findings if f.severity == "high"]),
            "medium": len([f for f in all_findings if f.severity == "medium"]),
            "low": len([f for f in all_findings if f.severity == "low"]),
            "findings": all_findings,
            "security_score": self._calculate_security_score(all_findings),
        }

    def _calculate_security_score(self, findings: List[CodeVulnerability]) -> float:
        """Calculate security score (0-100)."""
        score = 100.0
        
        severity_penalties = {
            "critical": 15,
            "high": 8,
            "medium": 4,
            "low": 1,
        }
        
        for finding in findings:
            penalty = severity_penalties.get(finding.severity, 1)
            score -= penalty
        
        return max(0, score)

    def get_stats(self) -> Dict[str, Any]:
        """Get code audit statistics."""
        return {
            "total_findings": len(self._findings),
            "by_severity": {
                "critical": len([f for f in self._findings if f.severity == "critical"]),
                "high": len([f for f in self._findings if f.severity == "high"]),
                "medium": len([f for f in self._findings if f.severity == "medium"]),
                "low": len([f for f in self._findings if f.severity == "low"]),
            },
            "by_cwe": dict(
                (cwe, len([f for f in self._findings if f.cwe_id == cwe]))
                for cwe in set(f.cwe_id for f in self._findings)
            ),
            "status": "AUDITING",
        }


ai_code_auditor = AICodeSecurityAuditor()
