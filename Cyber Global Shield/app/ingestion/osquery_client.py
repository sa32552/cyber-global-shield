"""
Cyber Global Shield - Osquery Client
Real-time endpoint telemetry via osqueryd TLS API
Collects process, network, file, and registry data from endpoints
"""

import json
import hashlib
import structlog
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from dataclasses import dataclass, field

logger = structlog.get_logger(__name__)


@dataclass
class OsqueryEndpoint:
    """Represents a single endpoint running osquery."""
    hostname: str
    ip_address: str
    os_version: str
    osquery_version: str
    last_checkin: datetime
    enrolled_at: datetime
    tags: List[str] = field(default_factory=list)
    status: str = "active"  # active, stale, offline


class OsqueryClient:
    """
    Osquery TLS API client for endpoint telemetry.
    
    Collects in real-time:
    - Running processes (MITRE T1057)
    - Network connections (MITRE T1049)
    - File system changes (MITRE T1070)
    - Registry modifications (MITRE T1112)
    - Scheduled tasks (MITRE T1053)
    - Services (MITRE T1569)
    - Kernel modules (MITRE T1014)
    - User accounts (MITRE T1087)
    - DNS cache (MITRE T1012)
    - ARP table (MITRE T1016)
    """

    def __init__(self, api_url: str = "https://osquery:443", api_key: str = ""):
        self.api_url = api_url
        self.api_key = api_key
        self._endpoints: Dict[str, OsqueryEndpoint] = {}
        self._session = None
        self._queries = self._load_queries()

    def _load_queries(self) -> Dict[str, str]:
        """Load osquery SQL queries for security monitoring."""
        return {
            # Process monitoring
            "processes": """
                SELECT pid, name, path, cmdline, parent, uid, gid, 
                       start_time, state, wired_size, resident_size, total_size
                FROM processes
                WHERE name NOT LIKE '[system]'
                ORDER BY resident_size DESC
                LIMIT 500
            """,
            "listening_ports": """
                SELECT pid, port, protocol, address, fd, socket, net_namespace
                FROM listening_ports
                WHERE port NOT IN (0, 1)
                ORDER BY port
            """,
            "process_open_sockets": """
                SELECT pid, fd, socket, protocol, local_address, local_port,
                       remote_address, remote_port, state, net_namespace
                FROM process_open_sockets
                WHERE remote_address NOT IN ('0.0.0.0', '::', '127.0.0.1', '::1')
                ORDER BY remote_address
            """,
            
            # Network monitoring
            "arp_cache": """
                SELECT address, mac, interface, permanent
                FROM arp_cache
                WHERE permanent = 0
            """,
            "dns_resolvers": """
                SELECT id, type, address, netmask, options
                FROM dns_resolvers
            """,
            "routes": """
                SELECT destination, netmask, gateway, source, flags, interface, metric
                FROM routes
                WHERE destination NOT IN ('0.0.0.0', '::')
            """,
            "curl_certificates": """
                SELECT hostname, common_name, issuer, organization, 
                       not_valid_before, not_valid_after, sha256
                FROM curl_certificate
            """,
            
            # File monitoring
            "file_events": """
                SELECT target_path, category, action, transaction_id, 
                       inode, uid, gid, mode, size, atime, mtime, ctime
                FROM file_events
                ORDER BY time DESC
                LIMIT 100
            """,
            "file_hashes": """
                SELECT path, directory, filename, md5, sha1, sha256, 
                       size, type, permissions
                FROM file
                WHERE path LIKE '/etc/%%' 
                   OR path LIKE '/usr/bin/%%'
                   OR path LIKE '/usr/local/bin/%%'
                LIMIT 1000
            """,
            
            # Registry monitoring (Windows)
            "registry_events": """
                SELECT target_path, action, transaction_id, 
                       key, value, data, time
                FROM registry_events
                WHERE action IN ('CREATE', 'WRITE', 'DELETE')
                ORDER BY time DESC
                LIMIT 100
            """,
            "registry_keys": """
                SELECT key, path, name, type, data, mtime
                FROM registry
                WHERE key LIKE 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%%'
                   OR key LIKE 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services%%'
                LIMIT 500
            """,
            
            # Persistence monitoring
            "scheduled_tasks": """
                SELECT name, path, enabled, state, type, 
                       next_run_time, last_run_time, last_run_message, action
                FROM scheduled_tasks
                WHERE enabled = 1
            """,
            "startup_items": """
                SELECT name, path, args, type, source, status
                FROM startup_items
            """,
            "services": """
                SELECT name, path, pid, status, service_type, 
                       module_path, description, user_account
                FROM services
                WHERE status = 'RUNNING'
            """,
            
            # Security monitoring
            "kernel_modules": """
                SELECT name, size, used_by, status, address, linked_modules
                FROM kernel_modules
                WHERE status != 'Live'
            """,
            "user_accounts": """
                SELECT uid, gid, username, description, shell, 
                       is_hidden, directory, uuid
                FROM users
                WHERE is_hidden = 0
            """,
            "logged_in_users": """
                SELECT user, tty, host, time, pid, type
                FROM logged_in_users
            """,
            "authorized_keys": """
                SELECT uid, algorithm, key, file, comment
                FROM authorized_keys
            """,
            "sudoers": """
                SELECT header, rule, user, runas, host, command
                FROM sudoers
            """,
            
            # System info
            "os_version": """
                SELECT name, version, major, minor, patch, build, 
                       platform, platform_like, codename, install_date
                FROM os_version
            """,
            "system_info": """
                SELECT hostname, cpu_brand, cpu_logical_cores, cpu_physical_cores,
                       physical_memory, hardware_vendor, hardware_model, 
                       hardware_serial, uuid
                FROM system_info
            """,
            "uptime": """
                SELECT days, hours, minutes, seconds, total_seconds
                FROM uptime
            """,
            
            # Docker monitoring
            "docker_containers": """
                SELECT id, name, image, image_id, command, state, 
                       status, pid, path, ports, created
                FROM docker_containers
            """,
            "docker_processes": """
                SELECT id, pid, name, cmdline, user, time, elapsed
                FROM docker_processes
            """,
            
            # YARA scanning
            "yara_scan": """
                SELECT path, matches, count, strings, tags
                FROM yara
                WHERE matches != ''
                LIMIT 100
            """,
        }

    async def query_endpoint(self, hostname: str, query_name: str) -> List[Dict[str, Any]]:
        """
        Execute a named query on a specific endpoint.
        Returns list of result rows.
        """
        if query_name not in self._queries:
            logger.error("unknown_query", query=query_name)
            return []

        endpoint = self._endpoints.get(hostname)
        if not endpoint:
            logger.error("endpoint_not_found", hostname=hostname)
            return []

        sql = self._queries[query_name]
        
        # In production, this would make an HTTPS request to osqueryd TLS endpoint
        # For now, return simulated data for testing
        results = self._simulate_query(query_name, endpoint)
        
        logger.debug(
            "osquery_executed",
            hostname=hostname,
            query=query_name,
            results=len(results),
        )
        
        return results

    async def query_all(self, query_name: str) -> Dict[str, List[Dict[str, Any]]]:
        """Execute a query on all active endpoints."""
        results = {}
        for hostname, endpoint in self._endpoints.items():
            if endpoint.status == "active":
                try:
                    results[hostname] = await self.query_endpoint(hostname, query_name)
                except Exception as e:
                    logger.error("query_failed", hostname=hostname, error=str(e))
                    results[hostname] = []
        return results

    async def detect_anomalies(self) -> List[Dict[str, Any]]:
        """
        Run security anomaly detection queries across all endpoints.
        Returns list of suspicious findings.
        """
        findings = []
        
        # Check for suspicious processes
        all_procs = await self.query_all("processes")
        for hostname, procs in all_procs.items():
            for proc in procs:
                name = proc.get("name", "").lower()
                cmdline = proc.get("cmdline", "").lower()
                
                # Suspicious process names
                suspicious_names = [
                    "mimikatz", "pwdump", "gsecdump", "wce", "cain",
                    "nc.exe", "netcat", "ncat", "socat",
                    "plink", "putty", "winscp",
                    "psexec", "paexec", "remcom",
                    "powershell.exe -enc", "powershell -window hidden",
                    "rundll32.exe javascript:", "regsvr32.exe /s /u /i:",
                    "mshta.exe javascript:", "certutil.exe -urlcache",
                    "bitsadmin.exe /transfer", "cscript.exe //nologo",
                    "wscript.exe //nologo", "msiexec.exe /quiet",
                ]
                
                for suspicious in suspicious_names:
                    if suspicious in cmdline or suspicious in name:
                        findings.append({
                            "hostname": hostname,
                            "type": "suspicious_process",
                            "severity": "high",
                            "detail": f"Suspicious process: {name} ({cmdline})",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "mitre_tactic": "TA0002",
                            "mitre_technique": "T1059",
                        })
                        break
        
        # Check for suspicious network connections
        all_sockets = await self.query_all("process_open_sockets")
        for hostname, sockets in all_sockets.items():
            for sock in sockets:
                remote = sock.get("remote_address", "")
                port = sock.get("remote_port", 0)
                
                # Known bad ports
                if port in [4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 54321]:
                    findings.append({
                        "hostname": hostname,
                        "type": "suspicious_connection",
                        "severity": "high",
                        "detail": f"Connection to suspicious port {port}: {remote}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "mitre_tactic": "TA0011",
                        "mitre_technique": "T1071",
                    })
        
        # Check for unauthorized SSH keys
        all_keys = await self.query_all("authorized_keys")
        for hostname, keys in all_keys.items():
            for key in keys:
                if key.get("file", "").startswith("/tmp") or key.get("file", "").startswith("/dev/shm"):
                    findings.append({
                        "hostname": hostname,
                        "type": "unauthorized_ssh_key",
                        "severity": "critical",
                        "detail": f"SSH key in suspicious location: {key.get('file')}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "mitre_tactic": "TA0003",
                        "mitre_technique": "T1098",
                    })
        
        return findings

    def _simulate_query(self, query_name: str, endpoint: OsqueryEndpoint) -> List[Dict[str, Any]]:
        """Simulate osquery results for testing."""
        import random
        
        if query_name == "processes":
            return [
                {"pid": 1, "name": "init", "path": "/sbin/init", "cmdline": "init", "uid": 0, "resident_size": 1024},
                {"pid": 100, "name": "sshd", "path": "/usr/sbin/sshd", "cmdline": "sshd -D", "uid": 0, "resident_size": 2048},
                {"pid": 200, "name": "nginx", "path": "/usr/sbin/nginx", "cmdline": "nginx -g daemon off;", "uid": 33, "resident_size": 4096},
                {"pid": 300, "name": "python3", "path": "/usr/bin/python3", "cmdline": "python3 /app/main.py", "uid": 1000, "resident_size": 8192},
            ]
        elif query_name == "listening_ports":
            return [
                {"pid": 200, "port": 80, "protocol": 6, "address": "0.0.0.0"},
                {"pid": 200, "port": 443, "protocol": 6, "address": "0.0.0.0"},
                {"pid": 100, "port": 22, "protocol": 6, "address": "0.0.0.0"},
            ]
        elif query_name == "logged_in_users":
            return [
                {"user": "admin", "tty": "pts/0", "host": "10.0.0.1", "time": int(datetime.now().timestamp()), "pid": 500},
            ]
        elif query_name == "os_version":
            return [{"name": "Ubuntu", "version": "22.04", "major": 22, "minor": 4, "platform": "ubuntu"}]
        elif query_name == "system_info":
            return [{"hostname": endpoint.hostname, "cpu_brand": "Intel(R) Xeon(R)", "physical_memory": 16384}]
        elif query_name == "uptime":
            return [{"days": 15, "hours": 3, "minutes": 25, "total_seconds": 1300000}]
        elif query_name == "docker_containers":
            return [
                {"id": "abc123", "name": "cyber-shield-api", "image": "cyber-shield:latest", "state": "running", "status": "Up 2 days"},
                {"id": "def456", "name": "kafka", "image": "confluentinc/cp-kafka:latest", "state": "running", "status": "Up 2 days"},
            ]
        else:
            return []

    def register_endpoint(self, hostname: str, ip: str, os_version: str, osquery_version: str) -> OsqueryEndpoint:
        """Register a new endpoint."""
        endpoint = OsqueryEndpoint(
            hostname=hostname,
            ip_address=ip,
            os_version=os_version,
            osquery_version=osquery_version,
            last_checkin=datetime.now(timezone.utc),
            enrolled_at=datetime.now(timezone.utc),
        )
        self._endpoints[hostname] = endpoint
        logger.info("endpoint_registered", hostname=hostname, ip=ip)
        return endpoint

    def get_endpoints(self) -> Dict[str, OsqueryEndpoint]:
        """Get all registered endpoints."""
        return self._endpoints

    def get_stats(self) -> Dict[str, Any]:
        """Get osquery client statistics."""
        active = sum(1 for e in self._endpoints.values() if e.status == "active")
        stale = sum(1 for e in self._endpoints.values() if e.status == "stale")
        offline = sum(1 for e in self._endpoints.values() if e.status == "offline")
        
        return {
            "total_endpoints": len(self._endpoints),
            "active": active,
            "stale": stale,
            "offline": offline,
            "queries_available": len(self._queries),
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }


# Global instance
osquery_client = OsqueryClient()


def get_osquery_client() -> OsqueryClient:
    return osquery_client
