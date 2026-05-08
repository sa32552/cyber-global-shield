"""
Cyber Global Shield — AbuseIPDB Connector
Real threat intelligence from AbuseIPDB API (free tier: 1000 req/day).
"""

import aiohttp
import logging
from typing import Optional, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

ABUSEIPDB_API_BASE = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBConnector:
    """Connector to AbuseIPDB API for IP reputation checking."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                headers={
                    "Key": self.api_key,
                    "Accept": "application/json",
                } if self.api_key else {}
            )
        return self._session

    async def check_ip(self, ip: str, max_age_in_days: int = 30) -> Optional[Dict[str, Any]]:
        """Check an IP address against AbuseIPDB."""
        if not self.api_key:
            logger.warning("No AbuseIPDB API key configured")
            return None

        session = await self._get_session()
        try:
            params = {
                "ipAddress": ip,
                "maxAgeInDays": max_age_in_days,
                "verbose": True,
            }
            async with session.get(
                f"{ABUSEIPDB_API_BASE}/check",
                params=params,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return self._parse_report(ip, data)
                elif resp.status == 429:
                    logger.warning("AbuseIPDB rate limit exceeded")
                    return None
                else:
                    logger.error(f"AbuseIPDB API error: {resp.status}")
                    return None
        except Exception as e:
            logger.error(f"AbuseIPDB request failed: {e}")
            return None

    def _parse_report(self, ip: str, data: Dict) -> Dict[str, Any]:
        """Parse AbuseIPDB report."""
        report = data.get("data", {})
        return {
            "indicator": ip,
            "indicator_type": "ip",
            "source": "abuseipdb",
            "abuse_confidence_score": report.get("abuseConfidenceScore", 0),
            "total_reports": report.get("totalReports", 0),
            "last_reported_at": report.get("lastReportedAt"),
            "country_code": report.get("countryCode", ""),
            "isp": report.get("isp", ""),
            "domain": report.get("domain", ""),
            "is_whitelisted": report.get("isWhitelisted", False),
            "is_tor": report.get("isTor", False),
            "usage_type": report.get("usageType", ""),
            "categories": report.get("categories", []),
        }

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
