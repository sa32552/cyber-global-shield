"""
Cyber Global Shield — Dark Web Monitoring
Surveillance automatisée du dark web pour détecter les fuites de données,
credentials volés, et menaces ciblant l'organisation.
"""

import json
import logging
import hashlib
from typing import Optional, Dict, Any, List, Set
from datetime import datetime
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class DarkWebAlert:
    """An alert from dark web monitoring."""
    timestamp: datetime
    alert_type: str  # credential_leak, data_breach, mention, exploit, ransomware
    severity: str  # low, medium, high, critical
    source: str  # pastebin, forum, marketplace, telegram, irc
    title: str
    description: str
    affected_domains: List[str] = field(default_factory=list)
    affected_emails: List[str] = field(default_factory=list)
    leaked_data_types: List[str] = field(default_factory=list)
    sample_data: str = ""
    risk_score: float = 0.0
    is_verified: bool = False


@dataclass
class MonitoredAsset:
    """An asset being monitored on the dark web."""
    asset_type: str  # domain, email, keyword, ip, credential
    value: str
    description: str = ""
    alerts_count: int = 0
    last_alert: Optional[datetime] = None


class DarkWebMonitor:
    """
    Surveillance du dark web.
    
    Surveille:
    - Fuites de credentials (pastebin, forums, marketplace)
    - Mentions de l'organisation
    - Exploits zero-day en vente
    - Ransomware negotiations
    - Données volées en vente
    """

    def __init__(self):
        self._alerts: List[DarkWebAlert] = []
        self._monitored_assets: List[MonitoredAsset] = []
        self._known_breach_sources = self._load_breach_sources()
        self._leaked_credentials: Dict[str, List[str]] = {}  # email -> passwords

    def _load_breach_sources(self) -> Dict[str, List[str]]:
        """Load known breach data sources."""
        return {
            "pastebin": [
                "pastebin.com", "paste.ee", "pastebin.pl",
                "rentry.co", "controlc.com",
            ],
            "forums": [
                "exploit.in", "xss.is", "cracking.org",
                "nulled.to", "sinister.ly",
            ],
            "marketplaces": [
                "alphabay", "dreammarket", "wallstreet",
                "darkmarket", "torrez",
            ],
            "ransomware_sites": [
                "lockbit", "clop", "blackcat", "alphv",
                "hive", "royal", "blackbasta",
            ],
            "telegram": [
                "combolist", "leakbase", "databreach",
                "hackerforums", "exploitmarket",
            ],
        }

    def add_monitored_asset(self, asset_type: str, value: str, description: str = ""):
        """Add an asset to monitor on the dark web."""
        asset = MonitoredAsset(
            asset_type=asset_type,
            value=value,
            description=description,
        )
        self._monitored_assets.append(asset)
        logger.info(f"🔍 Now monitoring: {asset_type} = {value}")

    def analyze_breach_data(
        self,
        source: str,
        data: Dict[str, Any],
    ) -> Optional[DarkWebAlert]:
        """Analyze potential breach data from dark web sources."""
        alert = None

        # Check for credential leaks
        if "credentials" in data or "emails" in data or "passwords" in data:
            alert = self._analyze_credential_leak(source, data)

        # Check for data breach mentions
        if "database" in data or "dump" in data or "leak" in data:
            alert = self._analyze_data_breach(source, data)

        # Check for organization mentions
        if "mentions" in data:
            alert = self._analyze_mentions(source, data)

        # Check for exploit sales
        if "exploit" in data or "0day" in data or "zero-day" in data:
            alert = self._analyze_exploit(source, data)

        # Check for ransomware
        if "ransomware" in data or "ransom" in data:
            alert = self._analyze_ransomware(source, data)

        if alert:
            self._alerts.append(alert)
            logger.warning(f"🌑 Dark web alert: {alert.title} (severity: {alert.severity})")

        return alert

    def _analyze_credential_leak(self, source: str, data: Dict) -> Optional[DarkWebAlert]:
        """Analyze a credential leak."""
        affected_emails = []
        affected_domains = set()
        leaked_passwords = []

        # Extract emails and check against monitored assets
        for email in data.get("emails", []):
            for asset in self._monitored_assets:
                if asset.asset_type == "email" and email == asset.value:
                    affected_emails.append(email)
                    domain = email.split("@")[-1]
                    affected_domains.add(domain)

                if asset.asset_type == "domain" and asset.value in email:
                    affected_emails.append(email)
                    affected_domains.add(asset.value)

        if not affected_emails:
            return None

        # Extract passwords
        for cred in data.get("credentials", []):
            if isinstance(cred, dict):
                leaked_passwords.append(cred.get("password", ""))

        # Store leaked credentials
        for email in affected_emails:
            if email not in self._leaked_credentials:
                self._leaked_credentials[email] = []
            self._leaked_credentials[email].extend(leaked_passwords)

        severity = "critical" if len(affected_emails) > 10 else "high"

        return DarkWebAlert(
            timestamp=datetime.utcnow(),
            alert_type="credential_leak",
            severity=severity,
            source=source,
            title=f"Credential leak detected: {len(affected_emails)} emails compromised",
            description=f"Found {len(affected_emails)} employee emails in a credential dump on {source}",
            affected_domains=list(affected_domains),
            affected_emails=affected_emails,
            leaked_data_types=["email", "password"],
            sample_data=f"Sample: {affected_emails[0]}:{leaked_passwords[0] if leaked_passwords else '***'}",
            risk_score=0.85 if severity == "critical" else 0.7,
        )

    def _analyze_data_breach(self, source: str, data: Dict) -> Optional[DarkWebAlert]:
        """Analyze a data breach mention."""
        affected_domains = []
        description = data.get("description", "")

        for asset in self._monitored_assets:
            if asset.asset_type == "domain" and asset.value in description:
                affected_domains.append(asset.value)

        if not affected_domains:
            return None

        return DarkWebAlert(
            timestamp=datetime.utcnow(),
            alert_type="data_breach",
            severity="critical",
            source=source,
            title=f"Data breach mentioned on {source}",
            description=description[:500],
            affected_domains=affected_domains,
            leaked_data_types=data.get("data_types", ["unknown"]),
            risk_score=0.9,
        )

    def _analyze_mentions(self, source: str, data: Dict) -> Optional[DarkWebAlert]:
        """Analyze organization mentions."""
        mentions = data.get("mentions", [])
        relevant_mentions = []

        for mention in mentions:
            for asset in self._monitored_assets:
                if asset.asset_type == "keyword" and asset.value.lower() in mention.lower():
                    relevant_mentions.append(mention)
                elif asset.asset_type == "domain" and asset.value in mention:
                    relevant_mentions.append(mention)

        if not relevant_mentions:
            return None

        return DarkWebAlert(
            timestamp=datetime.utcnow(),
            alert_type="mention",
            severity="medium",
            source=source,
            title=f"Organization mentioned on {source}",
            description=f"Found {len(relevant_mentions)} mentions: {relevant_mentions[0][:200]}",
            risk_score=0.4,
        )

    def _analyze_exploit(self, source: str, data: Dict) -> Optional[DarkWebAlert]:
        """Analyze exploit sale mention."""
        description = data.get("description", "")
        affected_domains = []

        for asset in self._monitored_assets:
            if asset.asset_type == "domain" and asset.value in description:
                affected_domains.append(asset.value)

        if not affected_domains:
            return None

        return DarkWebAlert(
            timestamp=datetime.utcnow(),
            alert_type="exploit",
            severity="critical",
            source=source,
            title=f"Exploit/0-day mentioned targeting your infrastructure",
            description=description[:500],
            affected_domains=affected_domains,
            risk_score=0.95,
        )

    def _analyze_ransomware(self, source: str, data: Dict) -> Optional[DarkWebAlert]:
        """Analyze ransomware mention."""
        description = data.get("description", "")
        affected_domains = []

        for asset in self._monitored_assets:
            if asset.asset_type == "domain" and asset.value in description:
                affected_domains.append(asset.value)

        if not affected_domains:
            return None

        return DarkWebAlert(
            timestamp=datetime.utcnow(),
            alert_type="ransomware",
            severity="critical",
            source=source,
            title=f"Ransomware group mentions your organization",
            description=description[:500],
            affected_domains=affected_domains,
            risk_score=0.95,
        )

    def check_credential(self, email: str, password: str) -> bool:
        """Check if a credential has been leaked."""
        leaked_passwords = self._leaked_credentials.get(email, [])
        return password in leaked_passwords

    def get_stats(self) -> Dict[str, Any]:
        """Get dark web monitoring statistics."""
        recent = [
            a for a in self._alerts
            if (datetime.utcnow() - a.timestamp).total_seconds() < 86400 * 7  # 7 days
        ]
        return {
            "total_alerts": len(self._alerts),
            "recent_alerts": len(recent),
            "critical_alerts": len([a for a in recent if a.severity == "critical"]),
            "monitored_assets": len(self._monitored_assets),
            "leaked_credentials": sum(len(v) for v in self._leaked_credentials.values()),
            "affected_emails": len(self._leaked_credentials),
            "alert_types": dict(
                (t, len([a for a in recent if a.alert_type == t]))
                for t in set(a.alert_type for a in recent)
            ),
            "status": "MONITORING",
        }


dark_web_monitor = DarkWebMonitor()
