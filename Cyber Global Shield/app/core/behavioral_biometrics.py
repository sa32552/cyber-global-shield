"""
Cyber Global Shield — Behavioral Biometrics
Détection d'anomalies comportementales utilisateur en temps réel.
Analyse les patterns de frappe, souris, navigation, horaires et accès.
"""

import json
import logging
import hashlib
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class UserBehavior:
    """User behavior profile."""
    user_id: str
    username: str
    department: str = ""
    role: str = ""
    normal_hours: Tuple[int, int] = (8, 18)  # 8AM-6PM
    usual_ips: List[str] = field(default_factory=list)
    usual_devices: List[str] = field(default_factory=list)
    usual_locations: List[str] = field(default_factory=list)
    avg_login_frequency: int = 5  # per day
    avg_file_downloads: int = 10  # per day
    avg_api_calls: int = 100  # per day
    sensitive_data_access: bool = False


@dataclass
class BehavioralAnomaly:
    """A behavioral anomaly detected."""
    timestamp: datetime
    user_id: str
    anomaly_type: str  # unusual_time, unusual_ip, unusual_location, unusual_volume, impossible_travel
    severity: str  # low, medium, high, critical
    description: str
    actual_value: str
    expected_value: str
    risk_score: float = 0.0


class BehavioralBiometrics:
    """
    Analyse comportementale des utilisateurs.
    
    Détecte:
    - Connexions à des heures inhabituelles
    - Accès depuis des IPs/locations inconnues
    - Impossible travel (connexions géographiquement impossibles)
    - Volume anormal de téléchargements
    - Accès à des données sensibles inhabituelles
    - Changement de pattern de frappe
    """

    def __init__(self):
        self._users: Dict[str, UserBehavior] = {}
        self._anomalies: List[BehavioralAnomaly] = []
        self._login_history: Dict[str, List[Dict]] = defaultdict(list)
        self._access_history: Dict[str, List[Dict]] = defaultdict(list)
        self._impossible_travel_cache: Dict[str, Tuple[datetime, str]] = {}

    def register_user(
        self,
        user_id: str,
        username: str,
        department: str = "",
        role: str = "",
        normal_hours: Tuple[int, int] = (8, 18),
    ) -> UserBehavior:
        """Register a user for behavioral monitoring."""
        user = UserBehavior(
            user_id=user_id,
            username=username,
            department=department,
            role=role,
            normal_hours=normal_hours,
        )
        self._users[user_id] = user
        logger.info(f"👤 User registered for behavioral monitoring: {username}")
        return user

    def analyze_login(
        self,
        user_id: str,
        ip_address: str,
        location: str,
        device: str,
        timestamp: Optional[datetime] = None,
    ) -> Optional[BehavioralAnomaly]:
        """Analyze a login event for behavioral anomalies."""
        if timestamp is None:
            timestamp = datetime.utcnow()

        user = self._users.get(user_id)
        if not user:
            logger.warning(f"Unknown user: {user_id}")
            return None

        # Record login
        self._login_history[user_id].append({
            "timestamp": timestamp,
            "ip": ip_address,
            "location": location,
            "device": device,
        })

        # 1. Check unusual time
        hour = timestamp.hour
        if hour < user.normal_hours[0] or hour > user.normal_hours[1]:
            anomaly = BehavioralAnomaly(
                timestamp=timestamp,
                user_id=user_id,
                anomaly_type="unusual_time",
                severity="medium",
                description=f"Login at unusual hour: {hour}:00 (normal: {user.normal_hours[0]}-{user.normal_hours[1]})",
                actual_value=f"{hour}:00",
                expected_value=f"{user.normal_hours[0]}-{user.normal_hours[1]}",
                risk_score=0.5,
            )
            self._anomalies.append(anomaly)
            logger.warning(f"⏰ Unusual login time for {user.username}: {hour}:00")
            return anomaly

        # 2. Check unusual IP
        if user.usual_ips and ip_address not in user.usual_ips:
            anomaly = BehavioralAnomaly(
                timestamp=timestamp,
                user_id=user_id,
                anomaly_type="unusual_ip",
                severity="high",
                description=f"Login from unknown IP: {ip_address}",
                actual_value=ip_address,
                expected_value=", ".join(user.usual_ips[:3]),
                risk_score=0.7,
            )
            self._anomalies.append(anomaly)
            logger.warning(f"🌐 Unknown IP for {user.username}: {ip_address}")
            return anomaly

        # 3. Check unusual location
        if user.usual_locations and location not in user.usual_locations:
            anomaly = BehavioralAnomaly(
                timestamp=timestamp,
                user_id=user_id,
                anomaly_type="unusual_location",
                severity="high",
                description=f"Login from unknown location: {location}",
                actual_value=location,
                expected_value=", ".join(user.usual_locations[:3]),
                risk_score=0.65,
            )
            self._anomalies.append(anomaly)
            logger.warning(f"📍 Unknown location for {user.username}: {location}")
            return anomaly

        # 4. Check impossible travel
        if user_id in self._impossible_travel_cache:
            last_time, last_location = self._impossible_travel_cache[user_id]
            time_diff = (timestamp - last_time).total_seconds() / 3600  # hours

            if time_diff < 2 and last_location != location:
                # Estimate distance (simplified)
                estimated_distance = time_diff * 800  # 800 km/h (plane speed)
                if estimated_distance < 100:  # Too close for different location
                    anomaly = BehavioralAnomaly(
                        timestamp=timestamp,
                        user_id=user_id,
                        anomaly_type="impossible_travel",
                        severity="critical",
                        description=f"Impossible travel detected: {last_location} -> {location} in {time_diff:.1f}h",
                        actual_value=f"{last_location} -> {location}",
                        expected_value="Same location or longer travel time",
                        risk_score=0.95,
                    )
                    self._anomalies.append(anomaly)
                    logger.critical(f"✈️ Impossible travel for {user.username}: {last_location} -> {location}")
                    return anomaly

        self._impossible_travel_cache[user_id] = (timestamp, location)

        return None

    def analyze_data_access(
        self,
        user_id: str,
        resource: str,
        action: str,  # read, write, download, delete
        data_size: int = 0,
        is_sensitive: bool = False,
    ) -> Optional[BehavioralAnomaly]:
        """Analyze data access for unusual patterns."""
        user = self._users.get(user_id)
        if not user:
            return None

        # Record access
        self._access_history[user_id].append({
            "timestamp": datetime.utcnow(),
            "resource": resource,
            "action": action,
            "data_size": data_size,
            "is_sensitive": is_sensitive,
        })

        # 1. Mass download detection
        recent_downloads = [
            a for a in self._access_history[user_id]
            if a["action"] == "download"
            and (datetime.utcnow() - a["timestamp"]).total_seconds() < 3600
        ]
        if len(recent_downloads) > user.avg_file_downloads * 3:
            anomaly = BehavioralAnomaly(
                timestamp=datetime.utcnow(),
                user_id=user_id,
                anomaly_type="unusual_volume",
                severity="high",
                description=f"Mass downloads detected: {len(recent_downloads)} in 1h (normal: {user.avg_file_downloads})",
                actual_value=str(len(recent_downloads)),
                expected_value=str(user.avg_file_downloads),
                risk_score=0.75,
            )
            self._anomalies.append(anomaly)
            logger.warning(f"📥 Mass downloads by {user.username}: {len(recent_downloads)}")
            return anomaly

        # 2. Sensitive data access by non-privileged user
        if is_sensitive and not user.sensitive_data_access:
            anomaly = BehavioralAnomaly(
                timestamp=datetime.utcnow(),
                user_id=user_id,
                anomaly_type="unusual_volume",
                severity="critical",
                description=f"Unauthorized sensitive data access: {resource}",
                actual_value=resource,
                expected_value="No sensitive data access expected",
                risk_score=0.9,
            )
            self._anomalies.append(anomaly)
            logger.critical(f"🔒 Sensitive data access by {user.username}: {resource}")
            return anomaly

        return None

    def update_user_profile(self, user_id: str, **kwargs):
        """Update user behavior profile."""
        user = self._users.get(user_id)
        if user:
            for key, value in kwargs.items():
                if hasattr(user, key):
                    setattr(user, key, value)
            logger.info(f"📝 Updated profile for {user.username}")

    def get_user_risk_score(self, user_id: str) -> float:
        """Get current risk score for a user."""
        recent_anomalies = [
            a for a in self._anomalies
            if a.user_id == user_id
            and (datetime.utcnow() - a.timestamp).total_seconds() < 3600
        ]
        if not recent_anomalies:
            return 0.0
        return max(a.risk_score for a in recent_anomalies)

    def get_stats(self) -> Dict[str, Any]:
        """Get behavioral biometrics statistics."""
        recent = [
            a for a in self._anomalies
            if (datetime.utcnow() - a.timestamp).total_seconds() < 3600
        ]
        return {
            "total_users": len(self._users),
            "total_anomalies": len(self._anomalies),
            "recent_anomalies": len(recent),
            "critical_anomalies": len([a for a in recent if a.severity == "critical"]),
            "high_risk_users": len([
                uid for uid in self._users
                if self.get_user_risk_score(uid) > 0.7
            ]),
            "anomaly_types": dict(
                (t, len([a for a in recent if a.anomaly_type == t]))
                for t in set(a.anomaly_type for a in recent)
            ),
            "status": "MONITORING",
        }


behavioral_biometrics = BehavioralBiometrics()
