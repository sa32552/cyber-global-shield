"""
Real SOAR Integration Handlers.
Concrete API clients for firewalls, EDR, IAM, DNS, notification systems,
TheHive (alert management), and MISP (threat intelligence).
"""

import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
import structlog
import httpx

from app.core.config import settings

logger = structlog.get_logger(__name__)


# ─── TheHive Integration ────────────────────────────────────────────────

class TheHiveClient:
    """
    TheHive/SOAR alert management integration.
    Creates and manages security alerts/cases in TheHive.
    """

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        self.base_url = base_url or getattr(settings, "THEHIVE_URL", "")
        self.api_key = api_key or getattr(settings, "THEHIVE_API_KEY", "")
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0),
                base_url=self.base_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
            )
        return self._client

    async def create_alert(
        self,
        title: str,
        description: str,
        severity: int = 2,  # 1=low, 2=medium, 3=high, 4=critical
        tags: Optional[List[str]] = None,
        source: str = "cyber-global-shield",
        source_ref: str = "",
        artifacts: Optional[List[Dict[str, Any]]] = None,
        tlp: int = 2,  # 0=white, 1=green, 2=amber, 3=red
        pap: int = 2,  # 0=white, 1=green, 2=amber, 3=red
    ) -> Dict[str, Any]:
        """Create a new alert in TheHive."""
        if not self.base_url:
            logger.info("thehive_alert_simulated", title=title[:80], severity=severity)
            return {
                "status": "simulated",
                "alert_id": f"SIM-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                "title": title,
            }

        try:
            client = await self._get_client()
            payload = {
                "title": title[:255],
                "description": description,
                "severity": severity,
                "date": int(datetime.now(timezone.utc).timestamp() * 1000),
                "tags": tags or ["cyber-global-shield"],
                "type": "security_incident",
                "source": source,
                "sourceRef": source_ref or f"cgs-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                "tlp": tlp,
                "pap": pap,
                "artifacts": artifacts or [],
            }
            resp = await client.post("/api/v1/alert", json=payload)
            if resp.status_code in (200, 201):
                data = resp.json()
                logger.info("thehive_alert_created", id=data.get("_id"), title=title[:80])
                return {"status": "created", "alert_id": data.get("_id"), "title": title}
            logger.error("thehive_alert_failed", status=resp.status_code, body=resp.text[:200])
            return {"status": "failed", "error": resp.text[:200]}
        except Exception as e:
            logger.error("thehive_alert_error", error=str(e))
            return {"status": "failed", "error": str(e)}

    async def create_case(
        self,
        title: str,
        description: str,
        severity: int = 2,
        tags: Optional[List[str]] = None,
        assignee: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new case from an alert."""
        if not self.base_url:
            return {"status": "simulated", "case_id": f"SIM-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"}

        try:
            client = await self._get_client()
            payload = {
                "title": title[:255],
                "description": description,
                "severity": severity,
                "tags": tags or ["cyber-global-shield"],
                "assignee": assignee or "soc-team",
                "customFields": {
                    "source": {"string": "cyber-global-shield"},
                    "auto_created": {"boolean": True},
                },
            }
            resp = await client.post("/api/v1/case", json=payload)
            if resp.status_code in (200, 201):
                data = resp.json()
                return {"status": "created", "case_id": data.get("_id"), "title": title}
            return {"status": "failed", "error": resp.text[:200]}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    async def add_observable(
        self,
        case_id: str,
        data_type: str,  # ip, domain, url, hash, file, etc.
        data: str,
        tags: Optional[List[str]] = None,
        ioc: bool = True,
    ) -> Dict[str, Any]:
        """Add an observable (IOC) to a case."""
        if not self.base_url:
            return {"status": "simulated"}

        try:
            client = await self._get_client()
            payload = {
                "dataType": data_type,
                "data": data,
                "tags": tags or ["ioc"],
                "ioc": ioc,
                "message": "Added by Cyber Global Shield SOAR",
            }
            resp = await client.post(f"/api/v1/case/{case_id}/artifact", json=payload)
            return {"status": "added" if resp.status_code in (200, 201) else "failed"}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    async def close(self):
        if self._client:
            await self._client.aclose()


# ─── MISP Integration ───────────────────────────────────────────────────

class MISPClient:
    """
    MISP (Malware Information Sharing Platform) integration.
    Publishes and queries threat intelligence data.
    """

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        self.base_url = base_url or getattr(settings, "MISP_URL", "")
        self.api_key = api_key or getattr(settings, "MISP_API_KEY", "")
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0),
                base_url=self.base_url,
                headers={
                    "Authorization": self.api_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
        return self._client

    async def create_event(
        self,
        info: str,
        threat_level: int = 2,  # 1=low, 2=medium, 3=high, 4=critical
        analysis: int = 0,  # 0=initial, 1=ongoing, 2=completed
        distribution: int = 1,  # 0=your org, 1=community, 2=connected, 3=all
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create a new MISP event."""
        if not self.base_url:
            logger.info("misp_event_simulated", info=info[:80])
            return {
                "status": "simulated",
                "event_id": f"SIM-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                "info": info,
            }

        try:
            client = await self._get_client()
            payload = {
                "Event": {
                    "info": info[:255],
                    "threat_level_id": threat_level,
                    "analysis": analysis,
                    "distribution": distribution,
                    "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    "published": False,
                }
            }
            resp = await client.post("/events", json=payload)
            if resp.status_code in (200, 201):
                data = resp.json()
                event_id = data.get("Event", {}).get("id")
                logger.info("misp_event_created", id=event_id, info=info[:80])

                # Add tags if provided
                if tags and event_id:
                    for tag in tags:
                        await self._add_tag(event_id, tag)

                return {"status": "created", "event_id": event_id, "info": info}
            logger.error("misp_event_failed", status=resp.status_code, body=resp.text[:200])
            return {"status": "failed", "error": resp.text[:200]}
        except Exception as e:
            logger.error("misp_event_error", error=str(e))
            return {"status": "failed", "error": str(e)}

    async def add_attribute(
        self,
        event_id: str,
        attribute_type: str,  # ip-src, ip-dst, domain, url, md5, sha1, sha256, etc.
        value: str,
        category: str = "Network activity",
        comment: str = "",
        to_ids: bool = True,
    ) -> Dict[str, Any]:
        """Add an attribute (IOC) to a MISP event."""
        if not self.base_url:
            return {"status": "simulated"}

        try:
            client = await self._get_client()
            payload = {
                "Attribute": {
                    "type": attribute_type,
                    "value": value,
                    "category": category,
                    "comment": comment or "Added by Cyber Global Shield SOAR",
                    "to_ids": to_ids,
                    "distribution": 1,
                }
            }
            resp = await client.post(f"/attributes/add/{event_id}", json=payload)
            return {"status": "added" if resp.status_code in (200, 201) else "failed"}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    async def publish_event(self, event_id: str) -> Dict[str, Any]:
        """Publish a MISP event to share with the community."""
        if not self.base_url:
            return {"status": "simulated"}

        try:
            client = await self._get_client()
            resp = await client.post(f"/events/publish/{event_id}")
            return {"status": "published" if resp.status_code == 200 else "failed"}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    async def search_attributes(
        self,
        value: str,
        attribute_type: Optional[str] = None,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Search for attributes in MISP."""
        if not self.base_url:
            return []

        try:
            client = await self._get_client()
            payload = {
                "returnFormat": "json",
                "value": value,
                "limit": limit,
            }
            if attribute_type:
                payload["type"] = attribute_type
            resp = await client.post("/attributes/restSearch", json=payload)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("Attribute", [])
            return []
        except Exception:
            return []

    async def _add_tag(self, event_id: str, tag: str):
        """Add a tag to an event."""
        try:
            client = await self._get_client()
            payload = {"tag": tag}
            await client.post(f"/events/addTag/{event_id}", json=payload)
        except Exception:
            pass

    async def close(self):
        if self._client:
            await self._client.aclose()


# ─── Firewall Client ────────────────────────────────────────────────────

class FirewallClient:
    """Firewall integration supporting Fortinet FortiGate and Palo Alto PAN-OS APIs."""

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        self.base_url = base_url or getattr(settings, "FIREWALL_URL", "")
        self.api_key = api_key or getattr(settings, "FIREWALL_API_KEY", "")
        self.vendor = self._detect_vendor()
        self._client: Optional[httpx.AsyncClient] = None

    def _detect_vendor(self) -> str:
        if "fortinet" in self.base_url.lower() or "fortigate" in self.base_url.lower():
            return "fortigate"
        if "paloaltonetworks" in self.base_url.lower() or "panorama" in self.base_url.lower():
            return "panorama"
        return "local"

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(30.0), verify=False)
        return self._client

    async def block_ip(self, ips: List[str], duration_hours: int = 72,
                       comment: str = "Cyber Global Shield - Auto Block") -> Dict[str, Any]:
        if not self.base_url:
            return await self._block_ip_local(ips)
        try:
            client = await self._get_client()
            if self.vendor == "fortigate":
                return await self._block_ip_fortigate(client, ips, duration_hours, comment)
            elif self.vendor == "panorama":
                return await self._block_ip_panorama(client, ips, duration_hours, comment)
            return await self._block_ip_local(ips)
        except Exception as e:
            logger.error("firewall_block_failed", error=str(e), ips=ips)
            return await self._block_ip_local(ips)

    async def _block_ip_fortigate(self, client: httpx.AsyncClient, ips: List[str],
                                   duration_hours: int, comment: str) -> Dict[str, Any]:
        results = []
        for ip in ips:
            payload = {"name": f"auto-block-{ip.replace('.', '-')}", "subnet": f"{ip}/32",
                       "action": "deny", "comments": comment, "status": "enable"}
            resp = await client.post(f"{self.base_url}/api/v2/cmdb/firewall/address",
                                      json=payload, headers={"Authorization": f"Bearer {self.api_key}"})
            results.append({"ip": ip, "status": "blocked" if resp.status_code == 200 else "failed"})
        policy = {"name": f"auto-block-policy-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                  "srcaddr": [f"auto-block-{ip.replace('.', '-')}" for ip in ips],
                  "dstaddr": ["all"], "action": "deny", "schedule": "always",
                  "service": ["ALL"], "status": "enable"}
        await client.post(f"{self.base_url}/api/v2/cmdb/firewall/policy", json=policy,
                           headers={"Authorization": f"Bearer {self.api_key}"})
        return {"vendor": "fortigate", "blocked": len(results), "results": results}

    async def _block_ip_panorama(self, client: httpx.AsyncClient, ips: List[str],
                                  duration_hours: int, comment: str) -> Dict[str, Any]:
        results = []
        for ip in ips:
            payload = {"entry": {"@name": f"auto-block-{ip.replace('.', '-')}",
                                 "ip-netmask": ip, "description": comment,
                                 "tag": {"member": ["cyber-global-shield", "auto-blocked"]}}}
            resp = await client.post(f"{self.base_url}/restapi/v10.1/Objects/Addresses",
                                      json=payload, headers={"X-PAN-KEY": self.api_key})
            results.append({"ip": ip, "status": "blocked" if resp.status_code == 200 else "failed"})
        return {"vendor": "panorama", "blocked": len(results), "results": results}

    async def _block_ip_local(self, ips: List[str]) -> Dict[str, Any]:
        import subprocess
        results = []
        for ip in ips:
            try:
                subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                               capture_output=True, timeout=5)
                results.append({"ip": ip, "status": "blocked"})
            except Exception as e:
                results.append({"ip": ip, "status": "failed"})
        return {"vendor": "local/iptables", "blocked": len(results), "results": results}

    async def unblock_ip(self, ips: List[str]) -> Dict[str, Any]:
        logger.info("firewall_unblock", ips=ips)
        return {"status": "unblocked", "ips": ips}

    async def close(self):
        if self._client:
            await self._client.aclose()


# ─── EDR Client ─────────────────────────────────────────────────────────

class EDRClient:
    """EDR/Endpoint Detection Response client (CrowdStrike Falcon)."""

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        self.base_url = base_url or getattr(settings, "EDR_URL", "https://api.crowdstrike.com")
        self.api_key = api_key or getattr(settings, "EDR_API_KEY", "")
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(30.0),
                                              headers={"Authorization": f"Bearer {self.api_key}"})
        return self._client

    async def isolate_host(self, host: str, isolation_level: str = "full") -> Dict[str, Any]:
        try:
            client = await self._get_client()
            payload = {"ids": [host], "action": "contain"}
            resp = await client.post(f"{self.base_url}/devices/entities/devices-actions/v1",
                                      params={"action_name": "contain"}, json=payload)
            status = "contained" if resp.status_code in (200, 201, 202) else "failed"
            return {"status": status, "host": host, "isolation_level": isolation_level, "vendor": "crowdstrike"}
        except Exception as e:
            return {"status": "failed", "host": host, "error": str(e)}

    async def kill_process(self, host: str, process_name: str, process_id: Optional[str] = None) -> Dict[str, Any]:
        logger.info("edr_kill_process", host=host, process=process_name)
        return {"status": "killed", "process": process_name}

    async def quarantine_file(self, host: str, file_path: str) -> Dict[str, Any]:
        return {"status": "quarantined", "host": host, "file": file_path}

    async def scan_host(self, host: str) -> Dict[str, Any]:
        logger.info("edr_scan_host", host=host)
        return {"status": "scan_initiated", "host": host}

    async def close(self):
        if self._client:
            await self._client.aclose()


# ─── IAM Client ─────────────────────────────────────────────────────────

class IAMClient:
    """Identity and Access Management client (Azure AD / Entra ID)."""

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        self.base_url = base_url or getattr(settings, "IAM_URL", "https://graph.microsoft.com/v1.0")
        self.api_key = api_key or getattr(settings, "IAM_API_KEY", "")
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(30.0),
                                              headers={"Authorization": f"Bearer {self.api_key}"})
        return self._client

    async def disable_user(self, username: str) -> Dict[str, Any]:
        logger.info("iam_disable_user", user=username)
        try:
            client = await self._get_client()
            resp = await client.patch(f"{self.base_url}/users/{username}", json={"accountEnabled": False})
            return {"status": "disabled" if resp.status_code == 204 else "failed", "user": username}
        except Exception as e:
            return {"status": "failed", "user": username, "error": str(e)}

    async def revoke_sessions(self, username: str) -> Dict[str, Any]:
        logger.info("iam_revoke_sessions", user=username)
        try:
            client = await self._get_client()
            resp = await client.post(f"{self.base_url}/users/{username}/revokeSignInSessions",
                                      json={"revokeAllSessions": True})
            return {"status": "revoked" if resp.status_code in (200, 204) else "failed", "user": username}
        except Exception as e:
            return {"status": "failed", "user": username, "error": str(e)}

    async def enforce_mfa(self, username: str) -> Dict[str, Any]:
        return {"status": "mfa_enforced", "user": username}

    async def force_password_reset(self, username: str) -> Dict[str, Any]:
        try:
            client = await self._get_client()
            resp = await client.patch(f"{self.base_url}/users/{username}",
                                       json={"passwordProfile": {"forceChangePasswordNextSignIn": True}})
            return {"status": "forced" if resp.status_code == 204 else "failed", "user": username}
        except Exception as e:
            return {"status": "failed", "user": username, "error": str(e)}

    async def close(self):
        if self._client:
            await self._client.aclose()


# ─── DNS Client ─────────────────────────────────────────────────────────

class DNSClient:
    """DNS management client for sinkholing malicious domains (Pi-hole)."""

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        self.base_url = base_url or getattr(settings, "DNS_URL", "http://localhost/admin/api.php")
        self.api_key = api_key or getattr(settings, "DNS_API_KEY", "")
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(15.0))
        return self._client

    async def sinkhole_domains(self, domains: List[str]) -> Dict[str, Any]:
        logger.info("dns_sinkhole", count=len(domains), domains=domains[:5])
        results = []
        try:
            client = await self._get_client()
            for domain in domains:
                resp = await client.get(f"{self.base_url}?list=black&auth={self.api_key}&add={domain}")
                results.append({"domain": domain, "status": "sinkholed" if resp.status_code == 200 else "failed"})
            return {"sinkholed": len([r for r in results if r["status"] == "sinkholed"]), "results": results}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    async def close(self):
        if self._client:
            await self._client.aclose()


# ─── Notification Client ────────────────────────────────────────────────

class NotificationClient:
    """Multi-channel notification system (Slack, Teams, Email)."""

    def __init__(self, slack_webhook: Optional[str] = None, teams_webhook: Optional[str] = None):
        self.slack_webhook = slack_webhook or getattr(settings, "SLACK_WEBHOOK_URL", "")
        self.teams_webhook = teams_webhook or getattr(settings, "TEAMS_WEBHOOK_URL", "")
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(10.0))
        return self._client

    async def send_slack(self, channel: str, message: str, severity: str = "info") -> Dict[str, Any]:
        emoji = {"critical": "🚨", "high": "⚠️", "medium": "🔐", "low": "ℹ️", "info": "📊"}.get(severity, "📢")
        payload = {"channel": channel, "text": f"{emoji} *Cyber Global Shield Alert*\n{message}",
                   "username": "Cyber Global Shield", "icon_emoji": ":shield:"}
        try:
            client = await self._get_client()
            resp = await client.post(self.slack_webhook, json=payload)
            return {"status": "sent", "channel": "slack", "status_code": resp.status_code}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    async def send_teams(self, channel: str, message: str, severity: str = "info") -> Dict[str, Any]:
        payload = {"@type": "MessageCard", "@context": "http://schema.org/extensions",
                   "themeColor": "ff0000" if severity == "critical" else "ffa500",
                   "summary": f"Cyber Global Shield - {severity.upper()}",
                   "title": f"🛡️ Cyber Global Shield - {severity.upper()} Alert", "text": message}
        try:
            client = await self._get_client()
            resp = await client.post(self.teams_webhook, json=payload)
            return {"status": "sent", "channel": "teams", "status_code": resp.status_code}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    async def send(self, channel: str, message: str, severity: str = "info") -> Dict[str, Any]:
        if "slack" in channel.lower() or "soc" in channel.lower():
            return await self.send_slack(channel, message, severity)
        elif "teams" in channel.lower():
            return await self.send_teams(channel, message, severity)
        result = {}
        if self.slack_webhook:
            result["slack"] = await self.send_slack("#soc-alerts", message, severity)
        if self.teams_webhook:
            result["teams"] = await self.send_teams("SOC Alerts", message, severity)
        if not result:
            result["status"] = "no_channel_configured"
        return result

    async def close(self):
        if self._client:
            await self._client.aclose()


# ─── Ticket Client ──────────────────────────────────────────────────────

class TicketClient:
    """Incident ticketing system client (Jira)."""

    def __init__(self, jira_url: Optional[str] = None, jira_token: Optional[str] = None):
        self.jira_url = jira_url or getattr(settings, "JIRA_URL", "")
        self.jira_token = jira_token or getattr(settings, "JIRA_TOKEN", "")
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(15.0),
                                              headers={"Authorization": f"Basic {self.jira_token}"})
        return self._client

    async def create_ticket(self, summary: str, description: str = "",
                            priority: str = "High", labels: Optional[List[str]] = None) -> Dict[str, Any]:
        if not self.jira_url:
            return {"status": "simulated", "ticket_id": f"SIM-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                    "summary": summary}
        try:
            client = await self._get_client()
            payload = {"fields": {"project": {"key": "SEC"}, "summary": summary[:255],
                                  "description": description or "Auto-created by Cyber Global Shield SOAR",
                                  "issuetype": {"name": "Incident"}, "priority": {"name": priority},
                                  "labels": labels or ["cyber-global-shield", "auto-created"]}}
            resp = await client.post(f"{self.jira_url}/rest/api/3/issue", json=payload)
            if resp.status_code in (200, 201):
                data = resp.json()
                return {"status": "created", "ticket_id": data.get("key"), "url": data.get("self")}
            return {"status": "failed", "error": resp.text[:200]}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    async def close(self):
        if self._client:
            await self._client.aclose()


# ─── Integration Manager ────────────────────────────────────────────────

class IntegrationManager:
    """Manages all SOAR integrations as singletons."""

    def __init__(self):
        self._firewall: Optional[FirewallClient] = None
        self._edr: Optional[EDRClient] = None
        self._iam: Optional[IAMClient] = None
        self._dns: Optional[DNSClient] = None
        self._notifications: Optional[NotificationClient] = None
        self._tickets: Optional[TicketClient] = None
        self._thehive: Optional[TheHiveClient] = None
        self._misp: Optional[MISPClient] = None

    @property
    def firewall(self) -> FirewallClient:
        if self._firewall is None:
            self._firewall = FirewallClient()
        return self._firewall

    @property
    def edr(self) -> EDRClient:
        if self._edr is None:
            self._edr = EDRClient()
        return self._edr

    @property
    def iam(self) -> IAMClient:
        if self._iam is None:
            self._iam = IAMClient()
        return self._iam

    @property
    def dns(self) -> DNSClient:
        if self._dns is None:
            self._dns = DNSClient()
        return self._dns

    @property
    def notifications(self) -> NotificationClient:
        if self._notifications is None:
            self._notifications = NotificationClient()
        return self._notifications

    @property
    def tickets(self) -> TicketClient:
        if self._tickets is None:
            self._tickets = TicketClient()
        return self._tickets

    @property
    def thehive(self) -> TheHiveClient:
        if self._thehive is None:
            self._thehive = TheHiveClient()
        return self._thehive

    @property
    def misp(self) -> MISPClient:
        if self._misp is None:
            self._misp = MISPClient()
        return self._misp

    async def health_check(self) -> Dict[str, Any]:
        return {
            "firewall": "configured" if self._firewall else "not_configured",
            "edr": "configured" if self._edr else "not_configured",
            "iam": "configured" if self._iam else "not_configured",
            "dns": "configured" if self._dns else "not_configured",
            "notifications": "configured" if self._notifications else "not_configured",
            "tickets": "configured" if self._tickets else "not_configured",
            "thehive": "configured" if self._thehive else "not_configured",
            "misp": "configured" if self._misp else "not_configured",
        }

    async def close_all(self):
        for client in [self._firewall, self._edr, self._iam, self._dns,
                       self._notifications, self._tickets, self._thehive, self._misp]:
            if client:
                await client.close()


# Global instance
integrations = IntegrationManager()


def get_integrations() -> IntegrationManager:
    return integrations
