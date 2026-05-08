"""
Real-time log file watcher for Zeek and Suricata.
Directly tails log files and ingests into the Cyber Global Shield pipeline.
Fallback when Vector is not available.
"""

import asyncio
import json
import os
from typing import Optional, Dict, Any, List
from pathlib import Path
from datetime import datetime, timezone
import structlog

from app.ingestion.kafka_client import get_producer
from app.ingestion.clickhouse_client import get_clickhouse
from app.core.config import settings

logger = structlog.get_logger(__name__)


class LogWatcher:
    """
    Tails log files (Zeek TSV, Suricata JSON) and ingests them in real-time.
    Supports automatic recovery from file rotation.
    """

    # Zeek log format definitions (field names per log type)
    ZEEK_FIELDS = {
        "conn": [
            "ts", "uid", "id_orig_h", "id_orig_p", "id_resp_h", "id_resp_p",
            "proto", "service", "duration", "orig_bytes", "resp_bytes",
            "conn_state", "local_orig", "local_resp", "missed_bytes",
            "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
            "tunnel_parents"
        ],
        "dns": [
            "ts", "uid", "id_orig_h", "id_orig_p", "id_resp_h", "id_resp_p",
            "proto", "trans_id", "rtt", "query", "qclass", "qclass_name",
            "qtype", "qtype_name", "rcode", "rcode_name", "AA", "TC", "RD",
            "RA", "Z", "answers", "TTLs", "rejected"
        ],
        "http": [
            "ts", "uid", "id_orig_h", "id_orig_p", "id_resp_h", "id_resp_p",
            "trans_depth", "method", "host", "uri", "referrer", "version",
            "user_agent", "origin", "request_body_len", "response_body_len",
            "status_code", "status_msg", "info_code", "info_msg",
            "resp_fuids", "resp_mime_types", "resp_filenames"
        ],
        "notice": [
            "ts", "uid", "id_orig_h", "id_orig_p", "id_resp_h", "id_resp_p",
            "fuid", "file_mime_type", "file_desc", "proto", "note", "msg",
            "sub", "src", "dst", "p", "n", "peer_descr", "actions",
            "suppress_for", "remote_location_country_code",
            "remote_location_region", "remote_location_city",
            "remote_location_latitude", "remote_location_longitude"
        ],
        "ssh": [
            "ts", "uid", "id_orig_h", "id_orig_p", "id_resp_h", "id_resp_p",
            "version", "auth_success", "auth_attempts", "direction",
            "client", "server", "cipher_alg", "mac_alg", "compression_alg",
            "kex_alg", "host_key_alg", "host_key"
        ],
        "smb_files": [
            "ts", "uid", "id_orig_h", "id_orig_p", "id_resp_h", "id_resp_p",
            "action", "path", "name", "size", "prev_name",
            "times_modified", "times_accessed", "times_created", "times_changed"
        ],
        "smb_mapping": [
            "ts", "uid", "id_orig_h", "id_orig_p", "id_resp_h", "id_resp_p",
            "path", "service", "native_file_system", "share_type"
        ],
        "files": [
            "ts", "fuid", "tx_hosts", "rx_hosts", "conn_uids", "source",
            "depth", "analyzers", "mime_type", "filename", "duration",
            "local_orig", "is_orig", "seen_bytes", "total_bytes",
            "missing_bytes", "overflow_bytes", "timedout", "parent_fuid",
            "md5", "sha1", "sha256", "extracted", "extracted_cutoff", "extracted_size"
        ],
    }

    def __init__(
        self,
        zeek_log_dir: str = "/usr/local/zeek/logs/current",
        suricata_eve_path: str = "/var/log/suricata/eve.json",
    ):
        self.zeek_log_dir = Path(zeek_log_dir)
        self.suricata_eve_path = Path(suricata_eve_path)
        self.producer = get_producer()
        self.clickhouse = get_clickhouse()
        self._running = False
        self._seek_positions: Dict[str, int] = {}
        self._batch_buffer: List[Dict[str, Any]] = []
        self._batch_size = 100
        self._flush_interval = 1.0  # seconds

    def _parse_zeek_line(self, line: str, log_type: str) -> Optional[Dict[str, Any]]:
        """Parse a Zeek TSV line into a normalized log entry."""
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        fields = self.ZEEK_FIELDS.get(log_type)
        if not fields:
            return None

        # Zeek uses tab-separated values
        parts = line.split("\t")
        if len(parts) < len(fields):
            return None

        data = dict(zip(fields, parts))

        # Normalize to Cyber Global Shield format
        log = {
            "org_id": "default",
            "source": "zeek",
            "event_type": log_type,
            "severity": "info",
            "src_ip": data.get("id_orig_h", ""),
            "dst_ip": data.get("id_resp_h", ""),
            "src_port": int(float(data.get("id_orig_p", "0") or "0")),
            "dst_port": int(float(data.get("id_resp_p", "0") or "0")),
            "protocol": data.get("proto", "unknown"),
            "hostname": "",
            "user": "",
            "process_name": "",
            "tags": ["zeek", log_type],
            "bytes_sent": int(float(data.get("orig_bytes", "0") or "0")),
            "bytes_received": int(float(data.get("resp_bytes", "0") or "0")),
            "packets_sent": int(float(data.get("orig_pkts", "0") or "0")),
            "packets_received": int(float(data.get("resp_pkts", "0") or "0")),
            "timestamp": data.get("ts", datetime.now(timezone.utc).isoformat()),
            "raw_payload": data,
        }

        # Determine severity based on log type
        if log_type == "notice":
            log["severity"] = "high"
            log["event_type"] = "alert"
        elif log_type == "ssh" and data.get("auth_success", "T") == "F":
            log["severity"] = "high"
            log["event_type"] = "brute_force"
        elif log_type in ["smb_files", "smb_mapping"]:
            log["event_type"] = "smb_activity"
            log["tags"].append("lateral_movement")
        elif log_type == "files":
            log["event_type"] = "file_activity"

        return log

    def _parse_suricata_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a Suricata EVE JSON line."""
        line = line.strip()
        if not line:
            return None

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        event_type = data.get("event_type", "unknown")
        severity = "info"

        # Determine severity from Suricata alert
        if event_type == "alert":
            alert = data.get("alert", {})
            severity = str(alert.get("severity", 2))
            sev_map = {"1": "critical", "2": "high", "3": "medium"}
            severity = sev_map.get(severity, "medium")

        log = {
            "org_id": "default",
            "source": "suricata",
            "event_type": event_type,
            "severity": severity,
            "src_ip": data.get("src_ip", ""),
            "dst_ip": data.get("dest_ip", ""),
            "src_port": data.get("src_port", 0),
            "dst_port": data.get("dest_port", 0),
            "protocol": data.get("proto", data.get("app_proto", "unknown")),
            "hostname": data.get("hostname", ""),
            "user": "",
            "process_name": "",
            "tags": ["suricata", event_type],
            "timestamp": data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "raw_payload": data,
        }

        # Add alert-specific fields
        if event_type == "alert":
            alert = data.get("alert", {})
            log["alert_signature"] = alert.get("signature", "")
            log["alert_category"] = alert.get("category", "")
            log["tags"].append(alert.get("signature", ""))

        # Flow data
        if "flow" in data:
            flow = data["flow"]
            log["bytes_sent"] = flow.get("bytes_toserver", 0)
            log["bytes_received"] = flow.get("bytes_toclient", 0)
            log["packets_sent"] = flow.get("pkts_toserver", 0)
            log["packets_received"] = flow.get("pkts_toclient", 0)

        # File hashes
        if "fileinfo" in data:
            log["hash_sha256"] = data["fileinfo"].get("sha256", "")
            log["hash_md5"] = data["fileinfo"].get("md5", "")

        # TLS info
        if "tls" in data:
            log["hostname"] = data["tls"].get("sni", data["tls"].get("subject", ""))

        # HTTP info
        if "http" in data:
            log["hostname"] = data["http"].get("hostname", "")
            log["user"] = data["http"].get("http_user_agent", "")

        return log

    async def watch_zeek_log(self, log_type: str, file_pattern: Optional[str] = None):
        """Watch a Zeek log file for new entries."""
        log_file = self.zeek_log_dir / f"{log_type}.log"
        if not log_file.exists():
            logger.warning("zeek_log_not_found", path=str(log_file))
            return

        logger.info("watching_zeek_log", type=log_type, path=str(log_file))
        position_key = f"zeek_{log_type}"

        while self._running:
            try:
                with open(log_file, "r") as f:
                    # Seek to last known position
                    f.seek(self._seek_positions.get(position_key, 0))

                    for line in f:
                        parsed = self._parse_zeek_line(line, log_type)
                        if parsed:
                            await self._handle_log(parsed)

                    # Update position
                    self._seek_positions[position_key] = f.tell()

            except FileNotFoundError:
                logger.warning("zeek_log_disappeared", type=log_type)
                await asyncio.sleep(5)
                continue
            except Exception as e:
                logger.error("zeek_watch_error", type=log_type, error=str(e))

            await asyncio.sleep(0.1)

    async def watch_suricata_eve(self):
        """Watch the Suricata EVE JSON log."""
        if not self.suricata_eve_path.exists():
            logger.warning("suricata_log_not_found", path=str(self.suricata_eve_path))
            return

        logger.info("watching_suricata_log", path=str(self.suricata_eve_path))
        position_key = "suricata_eve"

        while self._running:
            try:
                with open(self.suricata_eve_path, "r") as f:
                    f.seek(self._seek_positions.get(position_key, 0))

                    for line in f:
                        parsed = self._parse_suricata_line(line)
                        if parsed:
                            await self._handle_log(parsed)

                    self._seek_positions[position_key] = f.tell()

            except FileNotFoundError:
                await asyncio.sleep(5)
                continue
            except Exception as e:
                logger.error("suricata_watch_error", error=str(e))

            await asyncio.sleep(0.1)

    async def _handle_log(self, log: Dict[str, Any]):
        """Process a parsed log entry: buffer + flush to Kafka/ClickHouse."""
        self._batch_buffer.append(log)

        if len(self._batch_buffer) >= self._batch_size:
            await self._flush_batch()

    async def _flush_batch(self):
        """Flush the batch buffer to Kafka and ClickHouse."""
        if not self._batch_buffer:
            return

        batch = self._batch_buffer.copy()
        self._batch_buffer.clear()

        # Send high-severity to alerts topic, all to raw_logs
        for log in batch:
            self.producer.produce_async(
                topic=settings.KAFKA_TOPIC_LOGS,
                key=log.get("org_id", "default"),
                value=log,
            )
            if log.get("severity") in ("high", "critical"):
                self.producer.produce_async(
                    topic=settings.KAFKA_TOPIC_ALERTS,
                    key=log.get("org_id", "default"),
                    value=log,
                )

        # Async insert to ClickHouse
        try:
            self.clickhouse.insert_logs_batch(batch)
        except Exception as e:
            logger.error("clickhouse_batch_failed", error=str(e))

        logger.debug("log_batch_flushed", count=len(batch))

    async def start(self):
        """Start watching all log sources."""
        self._running = True
        logger.info("log_watcher_starting")

        tasks = []

        # Watch Zeek logs
        for log_type in self.ZEEK_FIELDS.keys():
            task = asyncio.create_task(self.watch_zeek_log(log_type))
            tasks.append(task)

        # Watch Suricata
        task = asyncio.create_task(self.watch_suricata_eve())
        tasks.append(task)

        # Periodic flush
        task = asyncio.create_task(self._periodic_flush())
        tasks.append(task)

        logger.info("log_watcher_started", watchers=len(tasks))

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("log_watcher_cancelled")
        finally:
            await self._flush_batch()

    async def _periodic_flush(self):
        """Flush buffer periodically."""
        while self._running:
            await asyncio.sleep(self._flush_interval)
            if self._batch_buffer:
                await self._flush_batch()

    def stop(self):
        """Stop the log watcher."""
        self._running = False
        logger.info("log_watcher_stopping")


# Global watcher instance
log_watcher = LogWatcher()


def get_watcher() -> LogWatcher:
    return log_watcher


async def run_watcher():
    """Entry point for running the log watcher as a standalone process."""
    watcher = LogWatcher(
        zeek_log_dir=os.environ.get("ZEEK_LOG_DIR", "/usr/local/zeek/logs/current"),
        suricata_eve_path=os.environ.get("SURICATA_EVE_PATH", "/var/log/suricata/eve.json"),
    )
    await watcher.start()


if __name__ == "__main__":
    asyncio.run(run_watcher())