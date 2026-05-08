"""
Cyber Global Shield — VirusTotal Connector
Real threat intelligence from VirusTotal API (free tier: 500 req/day).
"""

import aiohttp
import asyncio
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)

VIRUSTOTAL_API_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalConnector:
    """Connector to VirusTotal API for real threat intelligence."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self._session: Optional[aiohttp.ClientSession] = None
        self._rate_remaining = 500
        self._rate_reset = datetime.utcnow()

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                headers={"x-apikey": self.api_key} if self.api_key else {}
            )
        return self._session

    async def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check an IP address against VirusTotal."""
        if not self.api_key:
            logger.warning("No VirusTotal API key configured")
            return None

        session = await self._get_session()
        try:
            async with session.get(f"{VIRUSTOTAL_API_BASE}/ip_addresses/{ip}") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return self._parse_ip_report(ip, data)
                elif resp.status == 404:
                    logger.info(f"IP {ip} not found in VirusTotal")
                    return None
                else:
                    logger.error(f"VirusTotal API error: {resp.status}")
                    return None
        except Exception as e:
            logger.error(f"VirusTotal request failed: {e}")
            return None

    def _parse_ip_report(self, ip: str, data: Dict) -> Dict[str, Any]:
        """Parse VirusTotal IP report."""
        attributes = data.get("data", {}).get("attributes", {})
        last_analysis = attributes.get("last_analysis_stats", {})
        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        total = sum(last_analysis.values()) or 1

        return {
            "indicator": ip,
            "indicator_type": "ip",
            "source": "virustotal",
            "malicious_votes": malicious,
            "suspicious_votes": suspicious,
            "harmless_votes": last_analysis.get("harmless", 0),
            "malicious_ratio": (malicious + suspicious) / total,
            "reputation": attributes.get("reputation", 0),
            "country": attributes.get("country", ""),
            "asn": attributes.get("asn", ""),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "tags": attributes.get("tags", []),
            "categories": attributes.get("categories", {}),
        }

    async def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check a domain against VirusTotal."""
        if not self.api_key:
            return None

        session = await self._get_session()
        try:
            async with session.get(f"{VIRUSTOTAL_API_BASE}/domains/{domain}") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return self._parse_domain_report(domain, data)
                return None
        except Exception as e:
            logger.error(f"VirusTotal domain check failed: {e}")
            return None

    def _parse_domain_report(self, domain: str, data: Dict) -> Dict[str, Any]:
        """Parse VirusTotal domain report."""
        attributes = data.get("data", {}).get("attributes", {})
        last_analysis = attributes.get("last_analysis_stats", {})
        malicious = last_analysis.get("malicious", 0)

        return {
            "indicator": domain,
            "indicator_type": "domain",
            "source": "virustotal",
            "malicious_votes": malicious,
            "categories": attributes.get("categories", {}),
            "creation_date": attributes.get("creation_date"),
            "registrar": attributes.get("registrar", ""),
        }

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
