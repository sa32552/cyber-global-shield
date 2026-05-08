"""
Cyber Global Shield — MISP Connector
Real threat intelligence feed integration with MISP (Malware Information Sharing Platform).
Open source threat intelligence platform.

Features:
- Pull events from MISP
- Search indicators
- Publish events
- Automatic IOC enrichment
"""

import asyncio
import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta

import httpx

logger = logging.getLogger(__name__)


class MISPConnector:
    """
    MISP (Malware Information Sharing Platform) connector.
    
    MISP is an open source threat intelligence platform.
    This connector allows pulling/pushing threat data.
    """

    def __init__(self, base_url: str, api_key: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self._client: Optional[httpx.AsyncClient] = None
        self._cache: Dict[str, tuple] = {}
        self._cache_ttl = timedelta(hours=1)
        self._stats = {
            "total_requests": 0,
            "cache_hits": 0,
            "events_found": 0,
        }

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={
                    "Authorization": self.api_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                verify=self.verify_ssl,
                timeout=30.0,
            )
        return self._client

    async def get_events(self, limit: int = 50, page: int = 1) -> List[Dict[str, Any]]:
        """Get recent MISP events."""
        self._stats["total_requests"] += 1

        try:
            client = await self._get_client()
            response = await client.post(
                "/events/index",
                json={
                    "limit": limit,
                    "page": page,
                    "returnFormat": "json",
                },
            )

            if response.status_code == 200:
                data = response.json()
                events = []
                for event in data.get("response", []):
                    event_data = event.get("Event", {})
                    events.append({
                        "id": event_data.get("id", ""),
                        "uuid": event_data.get("uuid", ""),
                        "info": event_data.get("info", ""),
                        "threat_level": event_data.get("threat_level_id", ""),
                        "analysis": event_data.get("analysis", ""),
                        "date": event_data.get("date", ""),
                        "published": event_data.get("published", False),
                        "tags": [
                            tag.get("name", "")
                            for tag in event_data.get("Tag", [])
                        ],
                        "attribute_count": len(event_data.get("Attribute", [])),
                        "org": event_data.get("Orgc", {}).get("name", ""),
                    })
                self._stats["events_found"] += len(events)
                return events

        except Exception as e:
            logger.error("MISP get_events failed", error=str(e))

        return []

    async def search_indicators(
        self,
        value: str,
        type_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Search for indicators in MISP."""
        cache_key = f"search:{value}:{type_filter}"
        if cache_key in self._cache:
            data, timestamp = self._cache[cache_key]
            if datetime.now() - timestamp < self._cache_ttl:
                self._stats["cache_hits"] += 1
                return data

        self._stats["total_requests"] += 1

        try:
            client = await self._get_client()
            payload = {
                "returnFormat": "json",
                "value": value,
                "searchall": 1,
            }
            if type_filter:
                payload["type"] = type_filter

            response = await client.post("/attributes/restSearch", json=payload)

            if response.status_code == 200:
                data = response.json()
                results = []
                for attr in data.get("response", {}).get("Attribute", []):
                    results.append({
                        "id": attr.get("id", ""),
                        "type": attr.get("type", ""),
                        "value": attr.get("value", ""),
                        "category": attr.get("category", ""),
                        "comment": attr.get("comment", ""),
                        "to_ids": attr.get("to_ids", False),
                        "event_id": attr.get("event_id", ""),
                        "timestamp": attr.get("timestamp", ""),
                    })

                self._cache[cache_key] = (results, datetime.now())
                return results

        except Exception as e:
            logger.error("MISP search failed", error=str(e), value=value)

        return []

    async def get_event_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific MISP event by ID."""
        cache_key = f"event:{event_id}"
        if cache_key in self._cache:
            data, timestamp = self._cache[cache_key]
            if datetime.now() - timestamp < self._cache_ttl:
                self._stats["cache_hits"] += 1
                return data

        self._stats["total_requests"] += 1

        try:
            client = await self._get_client()
            response = await client.get(f"/events/{event_id}")

            if response.status_code == 200:
                data = response.json()
                event = data.get("response", {}).get("Event", {})
                result = {
                    "id": event.get("id", ""),
                    "uuid": event.get("uuid", ""),
                    "info": event.get("info", ""),
                    "threat_level": event.get("threat_level_id", ""),
                    "analysis": event.get("analysis", ""),
                    "date": event.get("date", ""),
                    "published": event.get("published", False),
                    "tags": [
                        tag.get("name", "")
                        for tag in event.get("Tag", [])
                    ],
                    "attributes": [
                        {
                            "id": attr.get("id", ""),
                            "type": attr.get("type", ""),
                            "value": attr.get("value", ""),
                            "category": attr.get("category", ""),
                            "comment": attr.get("comment", ""),
                        }
                        for attr in event.get("Attribute", [])
                    ],
                    "org": event.get("Orgc", {}).get("name", ""),
                }

                self._cache[cache_key] = (result, datetime.now())
                return result

        except Exception as e:
            logger.error("MISP get_event failed", error=str(e), event_id=event_id)

        return None

    async def get_tags(self) -> List[str]:
        """Get all tags from MISP."""
        self._stats["total_requests"] += 1

        try:
            client = await self._get_client()
            response = await client.get("/tags")

            if response.status_code == 200:
                data = response.json()
                return [
                    tag.get("name", "")
                    for tag in data.get("response", [])
                ]

        except Exception as e:
            logger.error("MISP get_tags failed", error=str(e))

        return []

    async def get_galaxies(self) -> List[Dict[str, Any]]:
        """Get all galaxies (threat actor groups, techniques)."""
        self._stats["total_requests"] += 1

        try:
            client = await self._get_client()
            response = await client.get("/galaxies")

            if response.status_code == 200:
                data = response.json()
                galaxies = []
                for galaxy in data.get("response", []):
                    galaxies.append({
                        "id": galaxy.get("Galaxy", {}).get("id", ""),
                        "name": galaxy.get("Galaxy", {}).get("name", ""),
                        "type": galaxy.get("Galaxy", {}).get("type", ""),
                        "description": galaxy.get("Galaxy", {}).get("description", ""),
                    })
                return galaxies

        except Exception as e:
            logger.error("MISP get_galaxies failed", error=str(e))

        return []

    async def check_health(self) -> bool:
        """Check if MISP server is reachable."""
        try:
            client = await self._get_client()
            response = await client.get("/servers/health")
            return response.status_code == 200
        except Exception:
            return False

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
            "events_found": self._stats["events_found"],
            "cache_size": len(self._cache),
            "status": "connected" if self._client else "disconnected",
            "base_url": self.base_url,
        }
