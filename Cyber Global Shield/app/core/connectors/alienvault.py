"""
Cyber Global Shield — AlienVault OTX Connector
Real threat intelligence feed integration with AlienVault Open Threat Exchange.
Free, unlimited API access for threat indicators.

Features:
- Pull latest pulses (threat intelligence feeds)
- Search indicators (IP, domain, URL, hash)
- Subscribe to specific threat groups
- Automatic IOC enrichment
"""

import asyncio
import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import hashlib

import httpx

logger = logging.getLogger(__name__)


class AlienVaultConnector:
    """
    AlienVault OTX (Open Threat Exchange) connector.
    
    Free tier: unlimited API requests
    Provides: IP, domain, URL, hash reputation + malware samples
    """

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._client: Optional[httpx.AsyncClient] = None
        self._cache: Dict[str, tuple] = {}
        self._cache_ttl = timedelta(hours=1)
        self._stats = {
            "total_requests": 0,
            "cache_hits": 0,
            "indicators_found": 0,
        }

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.BASE_URL,
                headers={
                    "X-OTX-API-KEY": self.api_key,
                    "Accept": "application/json",
                },
                timeout=30.0,
            )
        return self._client

    async def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check IP address against AlienVault OTX."""
        # Check cache
        cache_key = f"ip:{ip}"
        if cache_key in self._cache:
            data, timestamp = self._cache[cache_key]
            if datetime.now() - timestamp < self._cache_ttl:
                self._stats["cache_hits"] += 1
                return data

        self._stats["total_requests"] += 1

        try:
            client = await self._get_client()
            response = await client.get(f"/indicators/IPv4/{ip}/general")

            if response.status_code == 200:
                data = response.json()
                result = {
                    "ip": ip,
                    "reputation": data.get("reputation", 0),
                    "country": data.get("country_code", ""),
                    "asn": data.get("asn", ""),
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "pulses": [
                        {
                            "name": p.get("name", ""),
                            "description": p.get("description", ""),
                            "tags": p.get("tags", []),
                            "created": p.get("created", ""),
                        }
                        for p in data.get("pulse_info", {}).get("pulses", [])[:5]
                    ],
                    "malicious": data.get("pulse_info", {}).get("count", 0) > 0,
                    "source": "alienvault_otx",
                }

                # Update cache
                self._cache[cache_key] = (result, datetime.now())
                if result["malicious"]:
                    self._stats["indicators_found"] += 1

                return result

            elif response.status_code == 404:
                return {
                    "ip": ip,
                    "reputation": 0,
                    "pulse_count": 0,
                    "malicious": False,
                    "source": "alienvault_otx",
                    "not_found": True,
                }

            else:
                logger.warning(
                    "AlienVault API error",
                    status=response.status_code,
                    ip=ip,
                )
                return None

        except Exception as e:
            logger.error("AlienVault request failed", error=str(e), ip=ip)
            return None

    async def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check domain against AlienVault OTX."""
        cache_key = f"domain:{domain}"
        if cache_key in self._cache:
            data, timestamp = self._cache[cache_key]
            if datetime.now() - timestamp < self._cache_ttl:
                self._stats["cache_hits"] += 1
                return data

        self._stats["total_requests"] += 1

        try:
            client = await self._get_client()
            response = await client.get(f"/indicators/domain/{domain}/general")

            if response.status_code == 200:
                data = response.json()
                result = {
                    "domain": domain,
                    "whois": data.get("whois", ""),
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "pulses": [
                        {
                            "name": p.get("name", ""),
                            "description": p.get("description", ""),
                            "tags": p.get("tags", []),
                        }
                        for p in data.get("pulse_info", {}).get("pulses", [])[:5]
                    ],
                    "malicious": data.get("pulse_info", {}).get("count", 0) > 0,
                    "source": "alienvault_otx",
                }

                self._cache[cache_key] = (result, datetime.now())
                if result["malicious"]:
                    self._stats["indicators_found"] += 1

                return result

            elif response.status_code == 404:
                return {
                    "domain": domain,
                    "pulse_count": 0,
                    "malicious": False,
                    "source": "alienvault_otx",
                    "not_found": True,
                }

        except Exception as e:
            logger.error("AlienVault domain check failed", error=str(e), domain=domain)
            return None

    async def check_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Check file hash against AlienVault OTX."""
        hash_type = self._detect_hash_type(file_hash)
        cache_key = f"hash:{file_hash}"
        
        if cache_key in self._cache:
            data, timestamp = self._cache[cache_key]
            if datetime.now() - timestamp < self._cache_ttl:
                self._stats["cache_hits"] += 1
                return data

        self._stats["total_requests"] += 1

        try:
            client = await self._get_client()
            response = await client.get(f"/indicators/file/{file_hash}/general")

            if response.status_code == 200:
                data = response.json()
                result = {
                    "hash": file_hash,
                    "hash_type": hash_type,
                    "malware_name": data.get("malware_name", ""),
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "pulses": [
                        {
                            "name": p.get("name", ""),
                            "description": p.get("description", ""),
                            "tags": p.get("tags", []),
                        }
                        for p in data.get("pulse_info", {}).get("pulses", [])[:5]
                    ],
                    "malicious": data.get("pulse_info", {}).get("count", 0) > 0,
                    "source": "alienvault_otx",
                }

                self._cache[cache_key] = (result, datetime.now())
                if result["malicious"]:
                    self._stats["indicators_found"] += 1

                return result

        except Exception as e:
            logger.error("AlienVault hash check failed", error=str(e), hash=file_hash)
            return None

    async def get_recent_pulses(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent threat intelligence pulses."""
        try:
            client = await self._get_client()
            response = await client.get("/pulses/subscribed", params={"limit": limit})

            if response.status_code == 200:
                data = response.json()
                pulses = []
                for pulse in data.get("results", []):
                    pulses.append({
                        "id": pulse.get("id", ""),
                        "name": pulse.get("name", ""),
                        "description": pulse.get("description", ""),
                        "tags": pulse.get("tags", []),
                        "indicators_count": len(pulse.get("indicators", [])),
                        "created": pulse.get("created", ""),
                        "author": pulse.get("author", {}).get("username", ""),
                    })
                return pulses

        except Exception as e:
            logger.error("Failed to get AlienVault pulses", error=str(e))

        return []

    def _detect_hash_type(self, file_hash: str) -> str:
        """Detect hash type by length."""
        hash_len = len(file_hash)
        if hash_len == 32:
            return "MD5"
        elif hash_len == 40:
            return "SHA1"
        elif hash_len == 64:
            return "SHA256"
        else:
            return "unknown"

    async def close(self):
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    def get_stats(self) -> Dict[str, Any]:
        """Get connector statistics."""
        return {
            "total_requests": self._stats["total_requests"],
            "cache_hits": self._stats["cache_hits"],
            "indicators_found": self._stats["indicators_found"],
            "cache_size": len(self._cache),
            "status": "connected" if self._client else "disconnected",
        }
