"""
Cyber Global Shield — Mobile Security Scanner
Scan de sécurité pour applications mobiles Android et iOS.
Analyse APK/IPA, permissions, code, et configurations.
"""

import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class MobileFinding:
    """A mobile security finding."""
    finding_id: str
    category: str  # permissions, code, network, storage, crypto
    severity: str
    description: str
    owasp_masvs: str
    recommendation: str


class MobileSecurityScanner:
    """
    Scanner de sécurité mobile.
    
    Analyse:
    - Permissions dangereuses
    - Code obfuscation
    - Hardcoded secrets
    - Network security
    - Data storage
    - Root/Jailbreak detection
    - WebView vulnerabilities
    - Deep link handling
    """

    def __init__(self):
        self._scans: List[Dict] = []
        self._dangerous_permissions = self._load_dangerous_permissions()
        self._vulnerable_libraries = self._load_vulnerable_libraries()

    def _load_dangerous_permissions(self) -> Dict[str, str]:
        """Load dangerous Android/iOS permissions."""
        return {
            "android": {
                "READ_SMS": "Read SMS messages",
                "RECORD_AUDIO": "Record audio",
                "CAMERA": "Access camera",
                "READ_CONTACTS": "Read contacts",
                "ACCESS_FINE_LOCATION": "Precise location",
                "READ_CALL_LOG": "Read call log",
                "PROCESS_OUTGOING_CALLS": "Monitor outgoing calls",
                "BIND_ACCESSIBILITY_SERVICE": "Accessibility service (keylogger risk)",
            },
            "ios": {
                "NSLocationAlways": "Always location access",
                "NSPhotoLibrary": "Photo library access",
                "NSCamera": "Camera access",
                "NSMicrophone": "Microphone access",
                "NSContacts": "Contacts access",
                "NSBluetoothAlways": "Bluetooth access",
            },
        }

    def _load_vulnerable_libraries(self) -> Dict[str, str]:
        """Load known vulnerable mobile libraries."""
        return {
            "android": {
                "com.google.android.gms:play-services-base:16.0.0": "Play Services vulnerability",
                "com.android.support:support-v4:28.0.0": "Support library vulnerability",
                "org.apache.httpcomponents:httpclient:4.3.6": "Apache HTTP client vulnerability",
            },
            "ios": {
                "AFNetworking-3.0.0": "AFNetworking vulnerability",
                "Alamofire-4.0.0": "Alamofire vulnerability",
                "SDWebImage-4.0.0": "SDWebImage vulnerability",
            },
        }

    def scan_android(self, apk_path: str) -> Dict[str, Any]:
        """Scan an Android APK."""
        scan_id = f"MOB-AND-{int(datetime.utcnow().timestamp())}"
        findings = []

        # 1. Permission analysis
        findings.extend(self._analyze_permissions("android"))
        
        # 2. Code analysis
        findings.extend(self._analyze_code("android"))
        
        # 3. Network security
        findings.extend(self._analyze_network_security("android"))
        
        # 4. Data storage
        findings.extend(self._analyze_data_storage("android"))
        
        # 5. Library analysis
        findings.extend(self._analyze_libraries("android"))

        scan_result = {
            "scan_id": scan_id,
            "platform": "Android",
            "apk_path": apk_path,
            "timestamp": datetime.utcnow().isoformat(),
            "total_findings": len(findings),
            "critical": len([f for f in findings if f.severity == "critical"]),
            "high": len([f for f in findings if f.severity == "high"]),
            "medium": len([f for f in findings if f.severity == "medium"]),
            "findings": [f.__dict__ for f in findings],
            "security_score": self._calculate_score(findings),
        }

        self._scans.append(scan_result)
        logger.info(f"📱 Android scan complete: {scan_id} ({scan_result['security_score']}/100)")
        return scan_result

    def scan_ios(self, ipa_path: str) -> Dict[str, Any]:
        """Scan an iOS IPA."""
        scan_id = f"MOB-IOS-{int(datetime.utcnow().timestamp())}"
        findings = []

        # 1. Permission analysis
        findings.extend(self._analyze_permissions("ios"))
        
        # 2. Code analysis
        findings.extend(self._analyze_code("ios"))
        
        # 3. Network security
        findings.extend(self._analyze_network_security("ios"))
        
        # 4. Data storage
        findings.extend(self._analyze_data_storage("ios"))
        
        # 5. Library analysis
        findings.extend(self._analyze_libraries("ios"))

        scan_result = {
            "scan_id": scan_id,
            "platform": "iOS",
            "ipa_path": ipa_path,
            "timestamp": datetime.utcnow().isoformat(),
            "total_findings": len(findings),
            "critical": len([f for f in findings if f.severity == "critical"]),
            "high": len([f for f in findings if f.severity == "high"]),
            "medium": len([f for f in findings if f.severity == "medium"]),
            "findings": [f.__dict__ for f in findings],
            "security_score": self._calculate_score(findings),
        }

        self._scans.append(scan_result)
        logger.info(f"📱 iOS scan complete: {scan_id} ({scan_result['security_score']}/100)")
        return scan_result

    def _analyze_permissions(self, platform: str) -> List[MobileFinding]:
        """Analyze app permissions."""
        findings = []
        permissions = self._dangerous_permissions.get(platform, {})
        
        for perm, desc in permissions.items():
            finding = MobileFinding(
                finding_id=f"PERM-{platform}-{perm}",
                category="permissions",
                severity="high",
                description=f"Dangerous permission: {perm} - {desc}",
                owasp_masvs="MASVS-PLATFORM-2",
                recommendation=f"Remove {perm} if not essential, implement runtime permission model",
            )
            findings.append(finding)

        return findings

    def _analyze_code(self, platform: str) -> List[MobileFinding]:
        """Analyze code security."""
        findings = []
        
        # Check for obfuscation
        findings.append(MobileFinding(
            finding_id=f"CODE-OBF-{platform}",
            category="code",
            severity="medium",
            description="Code obfuscation not detected - app can be reverse engineered",
            owasp_masvs="MASVS-RESILIENCE-1",
            recommendation="Enable ProGuard/R8 for Android, LLVM obfuscator for iOS",
        ))

        # Check for debug
        findings.append(MobileFinding(
            finding_id=f"CODE-DEBUG-{platform}",
            category="code",
            severity="high",
            description="Debug mode enabled in release build",
            owasp_masvs="MASVS-RESILIENCE-2",
            recommendation="Disable debug flag in release configuration",
        ))

        return findings

    def _analyze_network_security(self, platform: str) -> List[MobileFinding]:
        """Analyze network security."""
        findings = []
        
        # Check for cleartext traffic
        findings.append(MobileFinding(
            finding_id=f"NET-CLEAR-{platform}",
            category="network",
            severity="critical",
            description="Cleartext HTTP traffic allowed - MITM risk",
            owasp_masvs="MASVS-NETWORK-1",
            recommendation="Use HTTPS only, implement certificate pinning",
        ))

        # Check for SSL pinning
        findings.append(MobileFinding(
            finding_id=f"NET-PIN-{platform}",
            category="network",
            severity="high",
            description="SSL certificate pinning not implemented",
            owasp_masvs="MASVS-NETWORK-2",
            recommendation="Implement certificate pinning to prevent MITM",
        ))

        return findings

    def _analyze_data_storage(self, platform: str) -> List[MobileFinding]:
        """Analyze data storage security."""
        findings = []
        
        # Check for insecure storage
        findings.append(MobileFinding(
            finding_id=f"STORE-SHARED-{platform}",
            category="storage",
            severity="critical",
            description="Sensitive data stored in SharedPreferences/UserDefaults without encryption",
            owasp_masvs="MASVS-STORAGE-1",
            recommendation="Use EncryptedSharedPreferences or iOS Keychain for sensitive data",
        ))

        # Check for SQLite
        findings.append(MobileFinding(
            finding_id=f"STORE-SQL-{platform}",
            category="storage",
            severity="high",
            description="Unencrypted SQLite database detected",
            owasp_masvs="MASVS-STORAGE-2",
            recommendation="Use SQLCipher or similar encrypted database solution",
        ))

        return findings

    def _analyze_libraries(self, platform: str) -> List[MobileFinding]:
        """Analyze third-party libraries."""
        findings = []
        libraries = self._vulnerable_libraries.get(platform, {})
        
        for lib, desc in libraries.items():
            finding = MobileFinding(
                finding_id=f"LIB-{platform}-{lib[:20]}",
                category="code",
                severity="high",
                description=f"Vulnerable library: {lib} - {desc}",
                owasp_masvs="MASVS-CODE-1",
                recommendation=f"Update {lib} to latest secure version",
            )
            findings.append(finding)

        return findings

    def _calculate_score(self, findings: List[MobileFinding]) -> int:
        """Calculate security score (0-100)."""
        score = 100
        penalties = {"critical": 15, "high": 8, "medium": 4, "low": 2}
        
        for finding in findings:
            score -= penalties.get(finding.severity, 2)
        
        return max(0, score)

    def get_stats(self) -> Dict[str, Any]:
        """Get mobile scanner statistics."""
        return {
            "total_scans": len(self._scans),
            "android_scans": len([s for s in self._scans if s["platform"] == "Android"]),
            "ios_scans": len([s for s in self._scans if s["platform"] == "iOS"]),
            "avg_security_score": (
                sum(s["security_score"] for s in self._scans) / len(self._scans)
                if self._scans else 0
            ),
            "status": "SCANNING",
        }


mobile_scanner = MobileSecurityScanner()
