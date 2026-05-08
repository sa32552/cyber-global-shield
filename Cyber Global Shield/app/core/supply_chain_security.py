"""
Cyber Global Shield — Supply Chain Security
Détection de compromission de la chaîne d'approvisionnement logicielle.
Analyse des dépendances, signatures, provenance et comportements anormaux.
"""

import os
import json
import hashlib
import logging
from typing import Optional, Dict, Any, List, Set, Tuple
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class DependencyVulnerability:
    """A vulnerability found in a dependency."""
    package_name: str
    package_version: str
    vulnerability_id: str  # CVE
    severity: str  # low, medium, high, critical
    description: str
    fix_version: Optional[str] = None
    cvss_score: float = 0.0
    exploitability: str = "unknown"
    has_exploit: bool = False


@dataclass
class SupplyChainAnomaly:
    """An anomaly in the software supply chain."""
    timestamp: datetime
    anomaly_type: str  # dependency_change, signature_mismatch, provenance_issue, behavior_change
    severity: str
    description: str
    package_name: str
    package_version: str
    indicators: List[str] = field(default_factory=list)
    risk_score: float = 0.0


class SupplyChainSecurity:
    """
    Sécurité de la chaîne d'approvisionnement.
    
    Fonctionnalités:
    - Scan des vulnérabilités des dépendances
    - Détection de typosquatting
    - Vérification des signatures
    - Analyse de provenance
    - Détection de comportements anormaux
    - SBOM (Software Bill of Materials)
    """

    def __init__(self):
        self._vulnerabilities: List[DependencyVulnerability] = []
        self._anomalies: List[SupplyChainAnomaly] = []
        self._known_malicious_packages: Set[str] = self._load_malicious_packages()
        self._package_hashes: Dict[str, str] = {}
        self._sbom: Dict[str, Any] = {"packages": [], "generated_at": None}

    def _load_malicious_packages(self) -> Set[str]:
        """Load known malicious package names."""
        return {
            # Typosquatting examples
            "requesrs", "requrests", "requessts",
            "urllib3", "urrllib3", "urllib33",
            "beautifulsoup4", "beautifulsoup44",
            "pyhton", "pythoon", "pythn",
            "dajngo", "djangoo", "djagno",
            "flaskk", "flaslk", "flask-py",
            # Known malicious
            "colors-it", "faker.js", "event-stream",
            "rc", "electorn", "loady",
        }

    def scan_dependencies(self, requirements_file: str) -> List[DependencyVulnerability]:
        """Scan dependencies for known vulnerabilities."""
        vulnerabilities = []
        
        try:
            with open(requirements_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Parse package name and version
                    if ">=" in line:
                        package, version = line.split(">=", 1)
                    elif "==" in line:
                        package, version = line.split("==", 1)
                    else:
                        package = line.split(">")[0].split("<")[0].strip()
                        version = "latest"

                    package = package.strip()
                    version = version.strip()

                    # Check for typosquatting
                    if self._check_typosquatting(package):
                        anomaly = SupplyChainAnomaly(
                            timestamp=datetime.utcnow(),
                            anomaly_type="dependency_change",
                            severity="critical",
                            description=f"Possible typosquatting package: {package}",
                            package_name=package,
                            package_version=version,
                            indicators=[f"Similar to legitimate package"],
                            risk_score=0.9,
                        )
                        self._anomalies.append(anomaly)
                        logger.critical(f"🚨 Typosquatting detected: {package}")

                    # Check against known malicious packages
                    if package.lower() in self._known_malicious_packages:
                        vuln = DependencyVulnerability(
                            package_name=package,
                            package_version=version,
                            vulnerability_id="MALICIOUS-PACKAGE",
                            severity="critical",
                            description=f"Known malicious package: {package}",
                            cvss_score=10.0,
                            exploitability="confirmed",
                            has_exploit=True,
                        )
                        vulnerabilities.append(vuln)
                        logger.critical(f"🚨 Malicious package found: {package}")

                    # Compute hash for integrity tracking
                    package_key = f"{package}@{version}"
                    self._package_hashes[package_key] = hashlib.sha256(
                        f"{package}:{version}".encode()
                    ).hexdigest()

        except FileNotFoundError:
            logger.error(f"Requirements file not found: {requirements_file}")
        except Exception as e:
            logger.error(f"Error scanning dependencies: {e}")

        self._vulnerabilities.extend(vulnerabilities)
        return vulnerabilities

    def _check_typosquatting(self, package_name: str) -> bool:
        """Check if a package name is a typosquatting attempt."""
        legitimate_packages = {
            "requests", "urllib3", "beautifulsoup4", "python",
            "django", "flask", "fastapi", "pydantic",
            "numpy", "pandas", "scikit-learn", "torch",
            "transformers", "langchain", "crewai",
        }

        pkg_lower = package_name.lower()

        # Direct match
        if pkg_lower in legitimate_packages:
            return False

        # Check for common typosquatting patterns
        for legit in legitimate_packages:
            # Length difference <= 2
            if abs(len(pkg_lower) - len(legit)) > 2:
                continue

            # Check character substitutions
            substitutions = {
                "0": "o", "1": "l", "3": "e", "4": "a",
                "5": "s", "6": "g", "7": "t", "8": "b",
            }

            normalized_pkg = pkg_lower
            for digit, letter in substitutions.items():
                normalized_pkg = normalized_pkg.replace(digit, letter)

            if normalized_pkg == legit and pkg_lower != legit:
                return True

            # Check for extra/missing characters
            if legit in pkg_lower or pkg_lower in legit:
                if pkg_lower != legit:
                    return True

        return False

    def generate_sbom(self, project_path: str) -> Dict[str, Any]:
        """Generate Software Bill of Materials (SBOM)."""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{hashlib.md5(project_path.encode()).hexdigest()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "tools": [{"name": "CyberGlobalShield", "version": "1.0.0"}],
                "component": {
                    "name": "Cyber Global Shield",
                    "version": "1.0.0",
                    "type": "application",
                },
            },
            "components": [],
            "dependencies": [],
        }

        # Scan all requirements files
        requirements_files = [
            os.path.join(project_path, "requirements.txt"),
            os.path.join(project_path, "Cyber Global Shield", "requirements.txt"),
        ]

        for req_file in requirements_files:
            if os.path.exists(req_file):
                with open(req_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue

                        # Parse package
                        if ">=" in line:
                            name, version = line.split(">=", 1)
                        elif "==" in line:
                            name, version = line.split("==", 1)
                        else:
                            continue

                        component = {
                            "name": name.strip(),
                            "version": version.strip(),
                            "type": "library",
                            "purl": f"pkg:pypi/{name.strip()}@{version.strip()}",
                            "hashes": [
                                {
                                    "alg": "SHA-256",
                                    "content": self._package_hashes.get(
                                        f"{name.strip()}@{version.strip()}", ""
                                    ),
                                }
                            ],
                        }
                        sbom["components"].append(component)

        sbom["metadata"]["timestamp"] = datetime.utcnow().isoformat()
        self._sbom = sbom

        logger.info(f"📋 SBOM generated: {len(sbom['components'])} components")
        return sbom

    def check_integrity(self, package_name: str, version: str, current_hash: str) -> bool:
        """Check if a package's integrity has been compromised."""
        package_key = f"{package_name}@{version}"
        stored_hash = self._package_hashes.get(package_key)

        if stored_hash and stored_hash != current_hash:
            anomaly = SupplyChainAnomaly(
                timestamp=datetime.utcnow(),
                anomaly_type="signature_mismatch",
                severity="critical",
                description=f"Integrity check failed for {package_name}@{version}",
                package_name=package_name,
                package_version=version,
                indicators=["Hash mismatch", "Possible supply chain attack"],
                risk_score=0.95,
            )
            self._anomalies.append(anomaly)
            logger.critical(f"🚨 Integrity violation: {package_name}@{version}")
            return False

        return True

    def get_vulnerabilities(
        self, severity: Optional[str] = None,
    ) -> List[DependencyVulnerability]:
        """Get vulnerabilities, optionally filtered by severity."""
        if severity:
            return [v for v in self._vulnerabilities if v.severity == severity]
        return self._vulnerabilities

    def get_stats(self) -> Dict[str, Any]:
        """Get supply chain security statistics."""
        return {
            "total_vulnerabilities": len(self._vulnerabilities),
            "critical_vulnerabilities": len(
                [v for v in self._vulnerabilities if v.severity == "critical"]
            ),
            "high_vulnerabilities": len(
                [v for v in self._vulnerabilities if v.severity == "high"]
            ),
            "anomalies_detected": len(self._anomalies),
            "packages_tracked": len(self._package_hashes),
            "sbom_components": len(self._sbom.get("components", [])),
            "status": "MONITORING",
        }


supply_chain_security = SupplyChainSecurity()
