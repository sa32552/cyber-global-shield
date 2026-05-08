"""
Synthetic Network Security Dataset Generator.
Produces realistic network logs with both normal traffic and attack patterns
for training the Transformer Autoencoder anomaly detector.
"""

import numpy as np
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime, timezone, timedelta
import random
import json


class NetworkLogGenerator:
    """
    Generates synthetic network security logs mimicking real traffic patterns.
    Covers normal operations + 10+ attack types across the cyber kill chain.
    """

    # Normal network behavior profiles
    NORMAL_PROFILES = {
        "workstation": {
            "typical_ports": [80, 443, 53, 22, 3389],
            "hourly_traffic_mean": 50,
            "hourly_traffic_std": 15,
            "typical_protocols": ["tcp", "udp", "icmp"],
            "typical_destinations": ["internal", "cdn", "saas"],
        },
        "server": {
            "typical_ports": [443, 22, 3306, 5432, 6379, 8080],
            "hourly_traffic_mean": 500,
            "hourly_traffic_std": 100,
            "typical_protocols": ["tcp", "udp"],
            "typical_destinations": ["any"],
        },
        "iot_device": {
            "typical_ports": [80, 443, 5683, 1883],
            "hourly_traffic_mean": 10,
            "hourly_traffic_std": 5,
            "typical_protocols": ["tcp", "udp", "mqtt"],
            "typical_destinations": ["cloud", "internal"],
        },
        "domain_controller": {
            "typical_ports": [88, 389, 636, 3268, 3269, 53, 445],
            "hourly_traffic_mean": 200,
            "hourly_traffic_std": 30,
            "typical_protocols": ["tcp", "udp"],
            "typical_destinations": ["internal"],
        },
    }

    # Attack patterns with realistic traffic signatures
    ATTACK_PATTERNS = {
        "port_scan": {
            "type": "reconnaissance",
            "kill_chain": "Reconnaissance",
            "mitre": ("TA0043", "T1046"),
            "description": "Network service discovery via port scanning",
            "features": {
                "event_type": "scan",
                "protocol": "tcp",
                "dst_port_range": (1, 10000),
                "src_port_range": (40000, 60000),
                "packets_per_target": 1,
                "targets_per_scan": (50, 500),
                "scan_rate": (50, 200),  # ports per second
                "inter_arrival_time_ms": (5, 20),
            },
        },
        "brute_force_ssh": {
            "type": "credential_access",
            "kill_chain": "Exploitation",
            "mitre": ("TA0006", "T1110"),
            "description": "SSH brute force attack",
            "features": {
                "event_type": "brute_force",
                "protocol": "tcp",
                "dst_port": 22,
                "auth_failures": (100, 5000),
                "unique_usernames": (1, 50),
                "attempts_per_second": (1, 50),
            },
        },
        "brute_force_rdp": {
            "type": "credential_access",
            "kill_chain": "Exploitation",
            "mitre": ("TA0006", "T1110"),
            "description": "RDP brute force attack",
            "features": {
                "event_type": "brute_force",
                "protocol": "tcp",
                "dst_port": 3389,
                "auth_failures": (20, 2000),
                "unique_usernames": (1, 20),
            },
        },
        "dga_dns": {
            "type": "command_and_control",
            "kill_chain": "Command & Control",
            "mitre": ("TA0011", "T1568"),
            "description": "Domain Generation Algorithm for C2 communication",
            "features": {
                "event_type": "c2_communication",
                "protocol": "udp",
                "dst_port": 53,
                "unique_domains": (50, 5000),
                "domain_entropy": (3.5, 4.5),  # High entropy = random-looking
                "nxdomain_rate": (0.3, 0.9),
            },
        },
        "dns_exfiltration": {
            "type": "exfiltration",
            "kill_chain": "Actions on Objectives",
            "mitre": ("TA0010", "T1048"),
            "description": "Data exfiltration via DNS tunneling",
            "features": {
                "event_type": "data_exfiltration",
                "protocol": "udp",
                "dst_port": 53,
                "query_length": (200, 300),  # Abnormally long DNS queries
                "packets_per_second": (5, 50),
                "total_bytes": (10000, 1000000),
            },
        },
        "http_exfiltration": {
            "type": "exfiltration",
            "kill_chain": "Actions on Objectives",
            "mitre": ("TA0010", "T1041"),
            "description": "Data exfiltration over HTTP/HTTPS",
            "features": {
                "event_type": "data_exfiltration",
                "protocol": "tcp",
                "dst_port": 443,
                "upload_bytes": (500000, 50000000),  # 500KB to 50MB
                "unusual_hour": True,
                "connection_duration": (60, 600),
            },
        },
        "lateral_movement_smb": {
            "type": "lateral_movement",
            "kill_chain": "Lateral Movement",
            "mitre": ("TA0008", "T1021"),
            "description": "Lateral movement via SMB/Windows admin shares",
            "features": {
                "event_type": "lateral_movement",
                "protocol": "tcp",
                "dst_port": 445,
                "unique_targets": (3, 50),
                "connection_interval": (1, 30),
                "auth_type": "pass_the_hash",
            },
        },
        "lateral_movement_wmi": {
            "type": "lateral_movement",
            "kill_chain": "Lateral Movement",
            "mitre": ("TA0008", "T1047"),
            "description": "Lateral movement via WMI",
            "features": {
                "event_type": "lateral_movement",
                "protocol": "tcp",
                "dst_port_range": (135, 49152),
                "unique_targets": (2, 30),
            },
        },
        "ransomware_activity": {
            "type": "impact",
            "kill_chain": "Actions on Objectives",
            "mitre": ("TA0040", "T1486"),
            "description": "Ransomware file encryption activity",
            "features": {
                "event_type": "ransomware_activity",
                "protocol": "tcp",
                "dst_port": 445,
                "files_modified": (100, 100000),
                "encryption_rate": (10, 500),  # files per second
                "file_extensions": [".encrypted", ".locked", ".crypt", ".ransom"],
                "network_share_access": True,
            },
        },
        "c2_beacon": {
            "type": "command_and_control",
            "kill_chain": "Command & Control",
            "mitre": ("TA0011", "T1071"),
            "description": "Periodic C2 beaconing",
            "features": {
                "event_type": "c2_communication",
                "protocol": "tcp",
                "dst_port": 443,
                "beacon_interval_ms": (30000, 86400000),  # 30s to 24h
                "packet_size": (40, 200),
                "jitter": (0.0, 0.3),
            },
        },
        "privilege_escalation": {
            "type": "privilege_escalation",
            "kill_chain": "Privilege Escalation",
            "mitre": ("TA0004", "T1068"),
            "description": "Exploitation for privilege escalation",
            "features": {
                "event_type": "privilege_escalation",
                "protocol": "tcp",
                "dst_port": 445,
                "new_process_user": "SYSTEM",
                "parent_process": "cmd.exe",
                "child_process": "powershell.exe",
            },
        },
        "phishing_callback": {
            "type": "initial_access",
            "kill_chain": "Delivery",
            "mitre": ("TA0001", "T1566"),
            "description": "Phishing email callback to C2",
            "features": {
                "event_type": "c2_communication",
                "protocol": "tcp",
                "dst_port": 443,
                "connection_to_new_domain": True,
                "user_agent_spoof": True,
            },
        },
    }

    def __init__(self, seed: int = 42):
        self.rng = np.random.RandomState(seed)
        random.seed(seed)
        self.internal_range = "10.0.0.0/8"
        self.external_ranges = [
            "45.0.0.0/8", "91.0.0.0/8", "103.0.0.0/8",
            "185.0.0.0/8", "198.0.0.0/8", "203.0.0.0/8",
            "5.0.0.0/8", "37.0.0.0/8", "77.0.0.0/8",
        ]
        self.ip_pool = self._generate_ip_pool(1000)

    def _generate_ip_pool(self, size: int) -> List[str]:
        """Generate a pool of IP addresses."""
        ips = []
        for _ in range(size):
            if random.random() < 0.7:  # 70% internal
                ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            else:
                ext_range = random.choice(self.external_ranges)
                prefix = int(ext_range.split(".")[0])
                ip = f"{prefix}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            ips.append(ip)
        return ips

    def _random_ip(self, internal: bool = True) -> str:
        if internal or random.random() < 0.7:
            return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        ext_range = random.choice(self.external_ranges)
        prefix = int(ext_range.split(".")[0])
        return f"{prefix}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    def _random_port(self, normal_ports: List[int]) -> int:
        if random.random() < 0.9:
            return random.choice(normal_ports)
        return random.randint(1, 65535)

    def generate_normal_log(
        self,
        profile: str = "workstation",
        timestamp: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Generate a single normal network log entry."""
        prof = self.NORMAL_PROFILES[profile]
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        src_ip = self._random_ip(internal=True)
        dst_ip = self._random_ip(internal=random.random() < 0.6)
        protocol = random.choice(prof["typical_protocols"])
        dst_port = self._random_port(prof["typical_ports"])

        return {
            "org_id": "org-synthetic",
            "source": random.choice(["zeek", "suricata", "osquery"]),
            "event_type": random.choice(["connection", "dns_query", "http_request", "auth_success"]),
            "severity": "info",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": random.randint(49152, 65535),
            "dst_port": dst_port,
            "protocol": protocol,
            "hostname": f"host-{random.randint(1,200)}.internal",
            "user": f"user_{random.randint(1,50)}",
            "process_name": random.choice(["chrome.exe", "svchost.exe", "explorer.exe", "outlook.exe"]),
            "tags": [],
            "bytes_sent": int(self.rng.exponential(1000)),
            "bytes_received": int(self.rng.exponential(5000)),
            "packets_sent": int(self.rng.exponential(10)),
            "packets_received": int(self.rng.exponential(20)),
            "timestamp": timestamp.isoformat(),
            "raw_payload": {"normal_operation": True},
        }

    def generate_attack_log(
        self,
        attack_type: str,
        timestamp: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Generate a single attack log entry."""
        if attack_type not in self.ATTACK_PATTERNS:
            raise ValueError(f"Unknown attack type: {attack_type}")

        pattern = self.ATTACK_PATTERNS[attack_type]
        feat = pattern["features"]
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        src_ip = self._random_ip(internal=False)
        dst_ip = self._random_ip(internal=True)

        # Default attack log
        log = {
            "org_id": "org-synthetic",
            "source": random.choice(["zeek", "suricata"]),
            "event_type": feat["event_type"],
            "severity": random.choice(["high", "critical"]),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(self.rng.uniform(
                feat.get("src_port_range", (40000, 60000))[0],
                feat.get("src_port_range", (40000, 60000))[1],
            )),
            "dst_port": feat.get("dst_port", random.randint(1, 65535)),
            "protocol": feat.get("protocol", "tcp"),
            "hostname": f"host-{random.randint(1,200)}.internal",
            "user": f"user_{random.randint(1,50)}",
            "process_name": random.choice(["powershell.exe", "cmd.exe", "wscript.exe"]),
            "tags": [attack_type, pattern["type"]],
            "timestamp": timestamp.isoformat(),
            "raw_payload": {
                "attack_type": attack_type,
                "kill_chain_phase": pattern["kill_chain"],
                "mitre_tactic": pattern["mitre"][0],
                "mitre_technique": pattern["mitre"][1],
            },
        }

        # Attack-specific features
        if attack_type == "port_scan":
            log["bytes_sent"] = int(feat["scan_rate"][0] * 40)
            log["bytes_received"] = int(feat["scan_rate"][0] * 20)
            log["packets_sent"] = int(feat["scan_rate"][0] * 2)
            log["packets_received"] = int(feat["scan_rate"][0])
            log["dst_port"] = self.rng.randint(*feat["dst_port_range"])

        elif attack_type in ["brute_force_ssh", "brute_force_rdp"]:
            log["bytes_sent"] = int(self.rng.exponential(200))
            log["bytes_received"] = int(self.rng.exponential(150))
            log["packets_sent"] = int(self.rng.exponential(5))
            log["raw_payload"]["auth_failures"] = int(self.rng.uniform(*feat["auth_failures"]))
            log["dst_port"] = feat["dst_port"]

        elif attack_type == "dga_dns":
            log["bytes_sent"] = int(self.rng.exponential(100))
            log["bytes_received"] = int(self.rng.exponential(50))
            log["packets_sent"] = 1
            log["dst_port"] = 53
            log["raw_payload"]["unique_domains"] = int(self.rng.uniform(*feat["unique_domains"]))

        elif attack_type in ["dns_exfiltration", "http_exfiltration"]:
            log["bytes_sent"] = int(self.rng.uniform(100000, 1000000))
            log["bytes_received"] = int(self.rng.exponential(100))
            log["packets_sent"] = int(self.rng.exponential(50))
            if attack_type == "dns_exfiltration":
                log["dst_port"] = 53
            else:
                log["dst_port"] = 443

        elif attack_type in ["lateral_movement_smb", "lateral_movement_wmi"]:
            log["bytes_sent"] = int(self.rng.exponential(1000))
            log["bytes_received"] = int(self.rng.exponential(500))
            log["packets_sent"] = int(self.rng.exponential(20))
            log["dst_port"] = 445 if "smb" in attack_type else 135

        elif attack_type == "ransomware_activity":
            log["bytes_sent"] = int(self.rng.uniform(10000, 1000000))
            log["bytes_received"] = int(self.rng.exponential(100))
            log["packets_sent"] = int(self.rng.exponential(100))
            log["dst_port"] = 445

        elif attack_type == "c2_beacon":
            log["bytes_sent"] = int(self.rng.uniform(40, 200))
            log["bytes_received"] = int(self.rng.uniform(40, 200))
            log["packets_sent"] = 1
            log["dst_port"] = 443

        elif attack_type == "privilege_escalation":
            log["bytes_sent"] = int(self.rng.exponential(500))
            log["bytes_received"] = int(self.rng.exponential(200))
            log["packets_sent"] = int(self.rng.exponential(10))
            log["raw_payload"]["new_process_user"] = "SYSTEM"

        return log

    def generate_dataset(
        self,
        total_logs: int = 100000,
        attack_ratio: float = 0.05,
        time_window_hours: int = 24,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Generate a complete dataset with normal and attack logs.
        
        Args:
            total_logs: Total number of log entries
            attack_ratio: Fraction of logs that are attacks (0.0 to 1.0)
            time_window_hours: Time span for the dataset
            
        Returns:
            Tuple of (all_logs_labeled, normal_logs_only)
        """
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(hours=time_window_hours)

        normal_count = int(total_logs * (1 - attack_ratio))
        attack_count = int(total_logs * attack_ratio)

        normal_logs = []
        attack_logs = []

        # Generate normal traffic with temporal patterns
        for i in range(normal_count):
            # More traffic during business hours
            hour_offset = random.random() * time_window_hours
            if 8 <= now.hour + hour_offset % 24 <= 18:
                hour_offset = random.random() * 10  # Concentrer sur 8-18h

            ts = start_time + timedelta(hours=hour_offset)
            profile = random.choice(list(self.NORMAL_PROFILES.keys()))
            log = self.generate_normal_log(profile, timestamp=ts)
            log["is_attack"] = False
            normal_logs.append(log)

        # Generate attacks in bursts (realistic attack patterns)
        current_ts = start_time
        attacks_remaining = attack_count
        while attacks_remaining > 0:
            attack_type = random.choice(list(self.ATTACK_PATTERNS.keys()))
            burst_size = min(
                self.rng.randint(10, 200),
                attacks_remaining,
            )
            burst_interval_ms = self.ATTACK_PATTERNS[attack_type]["features"].get(
                "inter_arrival_time_ms", (10, 100)
            )

            for j in range(burst_size):
                # Advance time slightly within the burst
                ms_delta = self.rng.uniform(burst_interval_ms[0], burst_interval_ms[1])
                current_ts = min(current_ts + timedelta(milliseconds=ms_delta), now)
                log = self.generate_attack_log(attack_type, timestamp=current_ts)
                log["is_attack"] = True
                attack_logs.append(log)
                attacks_remaining -= 1

            # Gap between attack bursts (minutes to hours)
            gap_minutes = self.rng.uniform(5, 120)
            current_ts = current_ts + timedelta(minutes=gap_minutes)

        # Combine and shuffle
        all_logs = normal_logs + attack_logs
        random.shuffle(all_logs)

        return all_logs, normal_logs

    def generate_sequences(
        self,
        num_sequences: int = 10000,
        seq_length: int = 64,
        anomaly_probability: float = 0.1,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generate sequences optimized for training the Transformer Autoencoder.
        
        Returns:
            X: Array of shape (num_sequences, seq_length, 128) - preprocessed features
            y: Array of shape (num_sequences,) - 0=normal, 1=anomaly
        """
        from app.ml.anomaly_detector import create_default_detector

        detector = create_default_detector()
        X = np.zeros((num_sequences, seq_length, 128))
        y = np.zeros(num_sequences)

        for i in range(num_sequences):
            is_anomaly = random.random() < anomaly_probability
            logs = []

            if is_anomaly:
                # Generate attack sequence (burst of related attacks)
                attack_type = random.choice(list(self.ATTACK_PATTERNS.keys()))
                burst_size = min(self.rng.randint(5, seq_length), seq_length)
                for _ in range(burst_size):
                    logs.append(self.generate_attack_log(attack_type))
                # Pad with normal if needed
                while len(logs) < seq_length:
                    logs.append(self.generate_normal_log())
            else:
                # Normal sequence
                for _ in range(seq_length):
                    profiles = random.choices(
                        list(self.NORMAL_PROFILES.keys()),
                        weights=[0.4, 0.2, 0.1, 0.3],
                    )
                    logs.append(self.generate_normal_log(profile=profiles[0]))

            # Preprocess to tensor
            tensor = detector.preprocess(logs, seq_len=seq_length)
            X[i] = tensor.squeeze(0).numpy()
            y[i] = 1 if is_anomaly else 0

        return X, y


def generate_and_save(
    output_dir: str = "data",
    total_logs: int = 100000,
    attack_ratio: float = 0.05,
):
    """Generate dataset and save to files."""
    import os
    import json

    os.makedirs(output_dir, exist_ok=True)

    generator = NetworkLogGenerator(seed=42)
    all_logs, normal_logs = generator.generate_dataset(
        total_logs=total_logs,
        attack_ratio=attack_ratio,
    )

    # Save as JSON lines
    with open(f"{output_dir}/all_logs.jsonl", "w") as f:
        for log in all_logs:
            f.write(json.dumps(log, default=str) + "\n")

    with open(f"{output_dir}/normal_logs.jsonl", "w") as f:
        for log in normal_logs:
            f.write(json.dumps(log, default=str) + "\n")

    # Generate training sequences
    X, y = generator.generate_sequences(
        num_sequences=5000,
        seq_length=64,
        anomaly_probability=0.1,
    )

    np.save(f"{output_dir}/X_train.npy", X[:4000])
    np.save(f"{output_dir}/y_train.npy", y[:4000])
    np.save(f"{output_dir}/X_val.npy", X[4000:])
    np.save(f"{output_dir}/y_val.npy", y[4000:])

    print(f"Dataset generated: {len(all_logs)} logs ({len(normal_logs)} normal, {len(all_logs) - len(normal_logs)} attacks)")
    print(f"Training sequences: {X.shape}")
    print(f"Normal: {np.sum(y == 0)}, Anomalies: {np.sum(y == 1)}")

    return all_logs, X, y


if __name__ == "__main__":
    generate_and_save()