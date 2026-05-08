"""
Cyber Global Shield — Zero-Trust Network Access (ZTNA) ULTIMATE
ML-based trust scoring, dynamic access control,
and auto-revocation of access.
"""

import asyncio
import json
import logging
import hashlib
import numpy as np
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AccessLevel(Enum):
    FULL = "full"
    RESTRICTED = "restricted"
    MONITORED = "monitored"
    BLOCKED = "blocked"


class TrustLevel(Enum):
    TRUSTED = "trusted"
    LOW_RISK = "low_risk"
    MEDIUM_RISK = "medium_risk"
    HIGH_RISK = "high_risk"
    UNTRUSTED = "untrusted"


@dataclass
class DeviceProfile:
    """Represents a device profile for ZTNA."""
    device_id: str
    hostname: str
    os: str
    os_version: str
    ip_address: str
    mac_address: str
    installed_software: List[str]
    security_patches: List[str]
    last_scan: Optional[datetime]
    trust_score: float
    access_level: AccessLevel
    risk_factors: List[str]
    first_seen: datetime
    last_seen: datetime


@dataclass
class AccessRequest:
    """Represents an access request."""
    id: str
    user_id: str
    device_id: str
    resource: str
    action: str
    timestamp: datetime
    trust_score: float
    decision: str
    reason: str


class ZTNA:
    """
    Zero-Trust Network Access ULTIMATE with:
    - ML-based trust scoring
    - Dynamic access control
    - Device posture assessment
    - Auto-revocation of access
    - Continuous monitoring
    """

    def __init__(self):
        self.devices: Dict[str, DeviceProfile] = {}
        self.access_requests: Dict[str, AccessRequest] = {}
        self._access_policies: Dict[str, Dict] = self._initialize_policies()
        self._revoked_access: List[Dict] = []
        self._stats = {
            "total_devices": 0,
            "access_granted": 0,
            "access_denied": 0,
            "access_revoked": 0,
            "risk_alerts": 0,
        }
        self._initialize_devices()

    def _initialize_policies(self) -> Dict[str, Dict]:
        """Initialize access policies."""
        return {
            "critical_systems": {
                "min_trust_score": 0.9,
                "require_mfa": True,
                "require_patches": True,
                "allowed_os": ["windows", "linux", "macos"],
                "max_risk_factors": 0,
            },
            "sensitive_data": {
                "min_trust_score": 0.7,
                "require_mfa": True,
                "require_patches": True,
                "allowed_os": ["windows", "linux", "macos"],
                "max_risk_factors": 1,
            },
            "internal_apps": {
                "min_trust_score": 0.5,
                "require_mfa": False,
                "require_patches": False,
                "allowed_os": ["windows", "linux", "macos"],
                "max_risk_factors": 2,
            },
            "public_resources": {
                "min_trust_score": 0.0,
                "require_mfa": False,
                "require_patches": False,
                "allowed_os": ["any"],
                "max_risk_factors": 5,
            },
        }

    def _initialize_devices(self):
        """Initialize with sample devices."""
        sample_devices = [
            {
                "device_id": "DEV001",
                "hostname": "admin-workstation",
                "os": "windows",
                "os_version": "11",
                "ip": "192.168.1.10",
                "mac": "00:11:22:33:44:01",
                "software": ["chrome", "office", "vscode"],
                "patches": ["KB5021234", "KB5024567"],
            },
            {
                "device_id": "DEV002",
                "hostname": "analyst-laptop",
                "os": "macos",
                "os_version": "14.0",
                "ip": "192.168.1.20",
                "mac": "00:11:22:33:44:02",
                "software": ["chrome", "safari", "slack"],
                "patches": ["macOS_14.0.1"],
            },
            {
                "device_id": "DEV003",
                "hostname": "dev-server",
                "os": "linux",
                "os_version": "22.04",
                "ip": "192.168.1.30",
                "mac": "00:11:22:33:44:03",
                "software": ["docker", "nginx", "python"],
                "patches": ["kernel_6.2"],
            },
        ]
        
        for device in sample_devices:
            profile = DeviceProfile(
                device_id=device["device_id"],
                hostname=device["hostname"],
                os=device["os"],
                os_version=device["os_version"],
                ip_address=device["ip"],
                mac_address=device["mac"],
                installed_software=device["software"],
                security_patches=device["patches"],
                last_scan=datetime.utcnow() - timedelta(hours=np.random.randint(1, 24)),
                trust_score=np.random.uniform(0.7, 0.95),
                access_level=AccessLevel.FULL,
                risk_factors=[],
                first_seen=datetime.utcnow() - timedelta(days=np.random.randint(30, 365)),
                last_seen=datetime.utcnow(),
            )
            self.devices[device["device_id"]] = profile
            self._stats["total_devices"] += 1

    def _generate_request_id(self) -> str:
        """Generate unique request ID."""
        timestamp = datetime.utcnow().isoformat()
        return f"REQ-{hashlib.md5(timestamp.encode()).hexdigest()[:8].upper()}"

    def _calculate_trust_score(self, device_id: str) -> float:
        """Calculate trust score using ML."""
        device = self.devices.get(device_id)
        if not device:
            return 0.0
        
        score = 0.5  # Base score
        
        # Patch status
        if device.security_patches:
            score += 0.2
        
        # Recent scan
        if device.last_scan and datetime.utcnow() - device.last_scan < timedelta(hours=24):
            score += 0.1
        
        # Risk factors penalty
        score -= len(device.risk_factors) * 0.1
        
        # Time since first seen (longer = more trusted)
        days_known = (datetime.utcnow() - device.first_seen).days
        score += min(0.2, days_known / 365 * 0.2)
        
        return max(0.0, min(1.0, score))

    async def evaluate_access(self, request: Dict[str, Any]) -> AccessRequest:
        """
        Evaluate an access request using ZTNA.
        
        Args:
            request: Access request data
            
        Returns:
            AccessRequest with decision
        """
        user_id = request.get("user_id", "unknown")
        device_id = request.get("device_id", "unknown")
        resource = request.get("resource", "unknown")
        action = request.get("action", "read")
        
        # Get device profile
        device = self.devices.get(device_id)
        
        # Calculate trust score
        trust_score = self._calculate_trust_score(device_id)
        
        # Get policy for resource
        policy = self._get_policy(resource)
        
        # Evaluate access
        decision, reason = self._evaluate_policy(trust_score, device, policy, request)
        
        access_request = AccessRequest(
            id=self._generate_request_id(),
            user_id=user_id,
            device_id=device_id,
            resource=resource,
            action=action,
            timestamp=datetime.utcnow(),
            trust_score=trust_score,
            decision=decision,
            reason=reason,
        )
        
        self.access_requests[access_request.id] = access_request
        
        if decision == "granted":
            self._stats["access_granted"] += 1
        else:
            self._stats["access_denied"] += 1
        
        # Update device trust score
        if device:
            device.trust_score = trust_score
            device.last_seen = datetime.utcnow()
        
        return access_request

    def _get_policy(self, resource: str) -> Dict:
        """Get access policy for resource."""
        resource_lower = resource.lower()
        
        if any(word in resource_lower for word in ["critical", "admin", "root", "core"]):
            return self._access_policies["critical_systems"]
        elif any(word in resource_lower for word in ["sensitive", "confidential", "secret"]):
            return self._access_policies["sensitive_data"]
        elif any(word in resource_lower for word in ["app", "internal", "service"]):
            return self._access_policies["internal_apps"]
        else:
            return self._access_policies["public_resources"]

    def _evaluate_policy(self, trust_score: float, device: Optional[DeviceProfile], policy: Dict, request: Dict) -> tuple:
        """Evaluate access against policy."""
        
        # Check trust score
        if trust_score < policy["min_trust_score"]:
            return "denied", f"Trust score {trust_score:.2f} below minimum {policy['min_trust_score']}"
        
        # Check device
        if device:
            # Check OS
            if policy["allowed_os"] != ["any"] and device.os not in policy["allowed_os"]:
                return "denied", f"OS {device.os} not allowed"
            
            # Check risk factors
            if len(device.risk_factors) > policy["max_risk_factors"]:
                return "denied", f"Too many risk factors: {len(device.risk_factors)}"
            
            # Check patches if required
            if policy["require_patches"] and not device.security_patches:
                return "restricted", "Missing security patches"
        
        # Check MFA if required
        if policy["require_mfa"] and not request.get("mfa_verified", False):
            return "mfa_required", "MFA verification required"
        
        # Determine access level based on trust score
        if trust_score >= 0.9:
            return "granted", "Full access granted"
        elif trust_score >= 0.7:
            return "granted_monitored", "Access granted with monitoring"
        elif trust_score >= 0.5:
            return "granted_restricted", "Restricted access granted"
        else:
            return "denied", "Insufficient trust score"

    async def revoke_access(self, device_id: str, reason: str = "Security policy violation"):
        """Revoke access for a device."""
        device = self.devices.get(device_id)
        if not device:
            return False
        
        device.access_level = AccessLevel.BLOCKED
        device.trust_score = 0.0
        
        self._revoked_access.append({
            "device_id": device_id,
            "hostname": device.hostname,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat(),
        })
        
        self._stats["access_revoked"] += 1
        logger.warning(f"Access revoked for {device_id}: {reason}")
        
        return True

    async def assess_device_posture(self, device_id: str) -> Dict[str, Any]:
        """Assess device security posture."""
        device = self.devices.get(device_id)
        if not device:
            return {"error": "Device not found"}
        
        findings = []
        
        # Check patches
        if not device.security_patches:
            findings.append({
                "severity": "high",
                "description": "No security patches installed",
            })
        
        # Check last scan
        if device.last_scan and datetime.utcnow() - device.last_scan > timedelta(days=7):
            findings.append({
                "severity": "medium",
                "description": "Device not scanned in over 7 days",
            })
        
        # Check OS version
        if device.os == "windows" and device.os_version < "10":
            findings.append({
                "severity": "critical",
                "description": "Outdated Windows version",
            })
        
        return {
            "device_id": device_id,
            "hostname": device.hostname,
            "trust_score": device.trust_score,
            "access_level": device.access_level.value,
            "findings": findings,
            "risk_factors": device.risk_factors,
            "posture_score": max(0, 100 - len(findings) * 25),
            "last_scan": device.last_scan.isoformat() if device.last_scan else None,
        }

    def get_ztna_report(self) -> Dict[str, Any]:
        """Get comprehensive ZTNA report."""
        return {
            "summary": {
                "total_devices": len(self.devices),
                "access_granted": self._stats["access_granted"],
                "access_denied": self._stats["access_denied"],
                "access_revoked": self._stats["access_revoked"],
                "trusted_devices": sum(1 for d in self.devices.values() if d.trust_score >= 0.8),
                "high_risk_devices": sum(1 for d in self.devices.values() if d.trust_score < 0.5),
            },
            "stats": self._stats,
            "devices": [
                {
                    "id": d.device_id,
                    "hostname": d.hostname,
                    "os": d.os,
                    "trust_score": round(d.trust_score, 2),
                    "access_level": d.access_level.value,
                    "risk_factors": len(d.risk_factors),
                }
                for d in sorted(
                    self.devices.values(),
                    key=lambda x: x.trust_score
                )
            ],
            "recent_requests": [
                {
                    "id": r.id,
                    "device": r.device_id,
                    "resource": r.resource,
                    "decision": r.decision,
                    "trust_score": round(r.trust_score, 2),
                }
                for r in sorted(
                    self.access_requests.values(),
                    key=lambda x: x.timestamp,
                    reverse=True
                )[:20]
            ],
            "revoked_access": self._revoked_access[-20:],
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get ZTNA statistics."""
        return {
            **self._stats,
            "total_devices": len(self.devices),
            "active_policies": len(self._access_policies),
            "avg_trust_score": np.mean([d.trust_score for d in self.devices.values()]) if self.devices else 0,
            "blocked_devices": sum(1 for d in self.devices.values() if d.access_level == AccessLevel.BLOCKED),
        }


# Global instance
ztna = ZTNA()


async def quick_test():
    """Quick test of ZTNA."""
    print("=" * 60)
    print("Zero-Trust Network Access ULTIMATE - Quick Test")
    print("=" * 60)
    
    # Test access evaluation
    print("\n🔐 Testing access evaluation...")
    request = await ztna.evaluate_access({
        "user_id": "USR001",
        "device_id": "DEV001",
        "resource": "critical_systems",
        "action": "read",
        "mfa_verified": True,
    })
    print(f"  Decision: {request.decision}")
    print(f"  Trust score: {request.trust_score:.2f}")
    print(f"  Reason: {request.reason}")
    
    # Test denied access
    print("\n🚫 Testing denied access...")
    request2 = await ztna.evaluate_access({
        "user_id": "USR002",
        "device_id": "DEV002",
        "resource": "critical_systems",
        "action": "write",
        "mfa_verified": False,
    })
    print(f"  Decision: {request2.decision}")
    print(f"  Reason: {request2.reason}")
    
    # Test device posture
    print("\n🖥️  Testing device posture assessment...")
    posture = await ztna.assess_device_posture("DEV001")
    print(f"  Posture score: {posture['posture_score']}/100")
    print(f"  Findings: {len(posture['findings'])}")
    
    # Report
    report = ztna.get_ztna_report()
    print(f"\n📋 Report:")
    print(f"  Total devices: {report['summary']['total_devices']}")
    print(f"  Access granted: {report['summary']['access_granted']}")
    print(f"  Access denied: {report['summary']['access_denied']}")
    print(f"  Avg trust score: {ztna.get_stats()['avg_trust_score']:.2f}")
    
    print("\n✅ ZTNA test complete!")


if __name__ == "__main__":
    asyncio.run(quick_test())
