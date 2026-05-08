"""
Cyber Global Shield — Network Traffic Analyzer
Analyse de trafic réseau en temps réel.
Détection d'anomalies, protocoles, et patterns malveillants.
"""

import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class TrafficFlow:
    """A network traffic flow."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_sent: int
    packets: int
    duration: float
    flags: List[str]


class NetworkTrafficAnalyzer:
    """
    Analyseur de trafic réseau.
    
    Analyse:
    - Protocoles (HTTP, DNS, SMB, RDP, SSH)
    - Anomalies de volume
    - Patterns C2 (beaconing)
    - Data exfiltration
    - Port scanning
    - DDoS patterns
    - DNS tunneling
    """

    def __init__(self):
        self._flows: List[TrafficFlow] = []
        self._alerts: List[Dict] = []
        self._baseline = self._create_baseline()

    def _create_baseline(self) -> Dict:
        """Create traffic baseline."""
        return {
            "avg_bytes_per_flow": 1024,
            "avg_packets_per_flow": 10,
            "avg_duration": 30.0,
            "common_ports": [80, 443, 53, 22, 3389],
            "common_protocols": ["TCP", "UDP", "ICMP"],
            "max_connections_per_ip": 100,
            "max_bytes_per_second": 1000000,
        }

    def analyze_flow(self, flow_data: Dict) -> TrafficFlow:
        """Analyze a network traffic flow."""
        flow = TrafficFlow(
            flow_id=f"FLOW-{len(self._flows)+1}",
            src_ip=flow_data.get("src_ip", "0.0.0.0"),
            dst_ip=flow_data.get("dst_ip", "0.0.0.0"),
            src_port=flow_data.get("src_port", 0),
            dst_port=flow_data.get("dst_port", 0),
            protocol=flow_data.get("protocol", "TCP"),
            bytes_sent=flow_data.get("bytes", 0),
            packets=flow_data.get("packets", 0),
            duration=flow_data.get("duration", 0),
            flags=flow_data.get("flags", []),
        )

        self._flows.append(flow)
        
        # Analyze for anomalies
        anomalies = self._detect_anomalies(flow)
        if anomalies:
            alert = {
                "flow_id": flow.flow_id,
                "timestamp": datetime.utcnow().isoformat(),
                "anomalies": anomalies,
                "severity": "high" if len(anomalies) > 2 else "medium",
            }
            self._alerts.append(alert)
            logger.warning(f"🚨 Traffic anomaly detected: {anomalies}")

        return flow

    def _detect_anomalies(self, flow: TrafficFlow) -> List[str]:
        """Detect traffic anomalies."""
        anomalies = []

        # 1. Beaconing detection (C2)
        if self._is_beaconing(flow):
            anomalies.append("C2_beaconing_pattern")

        # 2. Data exfiltration
        if self._is_data_exfiltration(flow):
            anomalies.append("potential_data_exfiltration")

        # 3. Port scan
        if self._is_port_scan(flow):
            anomalies.append("port_scanning")

        # 4. DNS tunneling
        if self._is_dns_tunneling(flow):
            anomalies.append("dns_tunneling")

        # 5. Unusual protocol
        if self._is_unusual_protocol(flow):
            anomalies.append("unusual_protocol")

        # 6. Volume anomaly
        if self._is_volume_anomaly(flow):
            anomalies.append("volume_anomaly")

        return anomalies

    def _is_beaconing(self, flow: TrafficFlow) -> bool:
        """Detect C2 beaconing pattern."""
        # Check for regular intervals (simulated)
        if len(self._flows) >= 3:
            recent = self._flows[-3:]
            intervals = [
                (recent[i+1].duration - recent[i].duration)
                for i in range(len(recent)-1)
            ]
            if intervals and all(abs(i - intervals[0]) < 1.0 for i in intervals):
                return True
        return False

    def _is_data_exfiltration(self, flow: TrafficFlow) -> bool:
        """Detect potential data exfiltration."""
        # Large outbound data transfer
        if flow.bytes_sent > self._baseline["max_bytes_per_second"] * 10:
            return True
        
        # Data to unusual destination
        if flow.dst_port not in [80, 443, 53] and flow.bytes_sent > 100000:
            return True

        return False

    def _is_port_scan(self, flow: TrafficFlow) -> bool:
        """Detect port scanning."""
        # Multiple connections to different ports from same source
        recent_from_src = [
            f for f in self._flows[-50:]
            if f.src_ip == flow.src_ip
        ]
        unique_ports = set(f.dst_port for f in recent_from_src)
        if len(unique_ports) > 20:
            return True
        return False

    def _is_dns_tunneling(self, flow: TrafficFlow) -> bool:
        """Detect DNS tunneling."""
        if flow.protocol == "UDP" and flow.dst_port == 53:
            # Large DNS queries suggest tunneling
            if flow.bytes_sent > 512:  # Normal DNS < 512 bytes
                return True
        return False

    def _is_unusual_protocol(self, flow: TrafficFlow) -> bool:
        """Detect unusual protocol usage."""
        unusual_ports = [445, 135, 139, 1433, 3306, 5900, 6379]
        if flow.dst_port in unusual_ports and flow.bytes_sent > 10000:
            return True
        return False

    def _is_volume_anomaly(self, flow: TrafficFlow) -> bool:
        """Detect volume anomalies."""
        if flow.bytes_sent > self._baseline["avg_bytes_per_flow"] * 100:
            return True
        if flow.packets > self._baseline["avg_packets_per_flow"] * 100:
            return True
        return False

    def get_traffic_summary(self) -> Dict[str, Any]:
        """Get traffic analysis summary."""
        recent = self._flows[-100:] if len(self._flows) > 100 else self._flows
        
        return {
            "total_flows": len(self._flows),
            "recent_flows": len(recent),
            "total_alerts": len(self._alerts),
            "protocols": dict(
                (p, len([f for f in recent if f.protocol == p]))
                for p in set(f.protocol for f in recent)
            ),
            "top_sources": self._get_top_n("src_ip", recent, 5),
            "top_destinations": self._get_top_n("dst_ip", recent, 5),
            "avg_flow_size": sum(f.bytes_sent for f in recent) / len(recent) if recent else 0,
            "status": "MONITORING",
        }

    def _get_top_n(self, attr: str, flows: List[TrafficFlow], n: int) -> List[Dict]:
        """Get top N items by attribute."""
        counts = {}
        for flow in flows:
            val = getattr(flow, attr)
            counts[val] = counts.get(val, 0) + 1
        sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)
        return [{"address": k, "connections": v} for k, v in sorted_items[:n]]

    def get_stats(self) -> Dict[str, Any]:
        """Get network analyzer statistics."""
        return {
            "total_flows_analyzed": len(self._flows),
            "alerts_generated": len(self._alerts),
            "anomaly_rate": (
                len(self._alerts) / len(self._flows) * 100
                if self._flows else 0
            ),
            "status": "CAPTURING",
        }


network_traffic_analyzer = NetworkTrafficAnalyzer()
