"""
Cyber Global Shield — Threat Intelligence Feeds
Agrégation et analyse de flux de renseignements sur les menaces.
Corrélation avec les événements internes pour priorisation.
"""

import json
import logging
import hashlib
from typing import Optional, Dict, Any, List, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class ThreatIntel:
    """A threat intelligence entry."""
    timestamp: datetime
    source: str  # alienvault, abuseipdb, virustotal, shodan, greynoise, etc.
    indicator_type: str  # ip, domain, url, hash, email, cve
    indicator: str
    confidence: int  # 0-100
    severity: str  # low, medium, high, critical
    tags: List[str] = field(default_factory=list)
    description: str = ""
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    related_indicators: List[str] = field(default_factory=list)
    mitre_technique: Optional[str] = None


@dataclass
class IntelMatch:
    """A match between threat intel and internal events."""
    timestamp: datetime
    intel: ThreatIntel
    matched_value: str
    matched_source: str  # log, alert, connection, etc.
    severity: str
    risk_score: float = 0.0


class ThreatIntelFeeds:
    """
    Agrégateur de flux de Threat Intelligence.
    
    Sources supportées:
    - AlienVault OTX
    - AbuseIPDB
    - VirusTotal
    - Shodan
    - GreyNoise
    - Feodo Tracker
    - URLhaus
    - MISP
    """

    def __init__(self):
        self._intel: List[ThreatIntel] = []
        self._matches: List[IntelMatch] = []
        self._indicator_cache: Dict[str, ThreatIntel] = {}
        self._feed_stats: Dict[str, Dict] = defaultdict(lambda: {"total": 0, "last_update": None})
        self._blocklist: Set[str] = set()

    def add_intel(
        self,
        source: str,
        indicator_type: str,
        indicator: str,
        confidence: int,
        severity: str = "medium",
        tags: Optional[List[str]] = None,
        description: str = "",
    ) -> ThreatIntel:
        """Add a threat intelligence entry."""
        intel = ThreatIntel(
            timestamp=datetime.utcnow(),
            source=source,
            indicator_type=indicator_type,
            indicator=indicator,
            confidence=min(confidence, 100),
            severity=severity,
            tags=tags or [],
            description=description,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        # Deduplicate by indicator
        if indicator not in self._indicator_cache:
            self._intel.append(intel)
            self._indicator_cache[indicator] = intel
            self._feed_stats[source]["total"] += 1
            self._feed_stats[source]["last_update"] = datetime.utcnow()

            # Auto-block high confidence threats
            if confidence >= 80 and severity in ["high", "critical"]:
                self._blocklist.add(indicator)
                logger.warning(f"🛑 Auto-blocked indicator: {indicator} ({source})")

        return intel

    def check_indicator(self, indicator: str) -> Optional[ThreatIntel]:
        """Check if an indicator is in the threat intel database."""
        return self._indicator_cache.get(indicator)

    def match_event(
        self,
        event_type: str,
        event_data: Dict[str, Any],
    ) -> Optional[IntelMatch]:
        """Match an internal event against threat intelligence."""
        best_match = None
        best_score = 0.0

        # Extract indicators from event
        indicators_to_check = []

        if "ip" in event_data:
            indicators_to_check.append(("ip", event_data["ip"]))
        if "domain" in event_data:
            indicators_to_check.append(("domain", event_data["domain"]))
        if "url" in event_data:
            indicators_to_check.append(("url", event_data["url"]))
        if "hash" in event_data:
            indicators_to_check.append(("hash", event_data["hash"]))
        if "email" in event_data:
            indicators_to_check.append(("email", event_data["email"]))

        for indicator_type, value in indicators_to_check:
            intel = self._indicator_cache.get(value)
            if intel:
                score = intel.confidence / 100.0
                if score > best_score:
                    best_score = score
                    best_match = IntelMatch(
                        timestamp=datetime.utcnow(),
                        intel=intel,
                        matched_value=value,
                        matched_source=event_type,
                        severity=intel.severity,
                        risk_score=score,
                    )

        if best_match:
            self._matches.append(best_match)
            logger.warning(
                f"🎯 Threat intel match: {best_match.matched_value} "
                f"(confidence: {best_match.intel.confidence}%)"
            )

        return best_match

    def get_threats_by_type(self, indicator_type: str) -> List[ThreatIntel]:
        """Get threats by indicator type."""
        return [
            i for i in self._intel
            if i.indicator_type == indicator_type
        ]

    def get_recent_threats(self, hours: int = 24) -> List[ThreatIntel]:
        """Get recent threats."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return [
            i for i in self._intel
            if i.timestamp > cutoff
        ]

    def get_top_indicators(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get most common indicator types."""
        type_count = defaultdict(int)
        for intel in self._intel:
            type_count[intel.indicator_type] += 1
        return sorted(type_count.items(), key=lambda x: x[1], reverse=True)[:limit]

    def get_stats(self) -> Dict[str, Any]:
        """Get threat intelligence statistics."""
        recent = self.get_recent_threats(24)
        return {
            "total_indicators": len(self._intel),
            "recent_indicators": len(recent),
            "total_matches": len(self._matches),
            "recent_matches": len([
                m for m in self._matches
                if (datetime.utcnow() - m.timestamp).total_seconds() < 3600
            ]),
            "blocklist_size": len(self._blocklist),
            "feed_sources": dict(
                (source, stats["total"])
                for source, stats in self._feed_stats.items()
            ),
            "top_indicator_types": self.get_top_indicators(5),
            "severity_breakdown": {
                "critical": len([i for i in recent if i.severity == "critical"]),
                "high": len([i for i in recent if i.severity == "high"]),
                "medium": len([i for i in recent if i.severity == "medium"]),
                "low": len([i for i in recent if i.severity == "low"]),
            },
            "status": "ACTIVE",
        }


threat_intel = ThreatIntelFeeds()
