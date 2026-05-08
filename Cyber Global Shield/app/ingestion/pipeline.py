"""
Core ingestion pipeline: Kafka -> Normalize -> Enrich -> ClickHouse.
Handles log normalization, enrichment, routing, and backpressure.
"""
import json
import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
import structlog
from app.ingestion.kafka_client import get_producer, get_consumer
from app.ingestion.clickhouse_client import get_clickhouse
from app.core.config import settings

logger = structlog.get_logger(__name__)


class BackpressureController:
    """
    Adaptive backpressure controller.
    Slows down ingestion when downstream systems are slow.
    """

    def __init__(
        self,
        max_queue_size: int = 10000,
        target_latency_ms: float = 100.0,
        cooldown_factor: float = 0.9,
    ):
        self.max_queue_size = max_queue_size
        self.target_latency_ms = target_latency_ms
        self.cooldown_factor = cooldown_factor
        self._current_delay = 0.0
        self._queue_size = 0
        self._last_latency_ms = 0.0

    def update(self, queue_size: int, latency_ms: float):
        """Update backpressure based on queue size and latency."""
        self._queue_size = queue_size
        self._last_latency_ms = latency_ms

        if queue_size > self.max_queue_size or latency_ms > self.target_latency_ms:
            # Increase delay (backpressure)
            self._current_delay = min(
                self._current_delay + 0.01,  # max 10ms additional delay
                0.1,  # max 100ms delay
            )
            logger.warning(
                "backpressure_applied",
                queue_size=queue_size,
                latency_ms=latency_ms,
                delay=self._current_delay,
            )
        else:
            # Decrease delay (cooldown)
            self._current_delay *= self.cooldown_factor

    @property
    def delay(self) -> float:
        return self._current_delay

    @property
    def queue_size(self) -> int:
        return self._queue_size

    async def wait_if_needed(self):
        """Wait if backpressure is active."""
        if self._current_delay > 0:
            await asyncio.sleep(self._current_delay)


class IngestionPipeline:
    """
    Core ingestion pipeline: Kafka -> Normalize -> Enrich -> ClickHouse.
    Handles log normalization, enrichment, routing, and backpressure.
    """

    def __init__(self):
        self.producer = get_producer()
        self.clickhouse = get_clickhouse()
        self._batch_buffer: List[Dict[str, Any]] = []
        self._batch_size = 500
        self._batch_timer: Optional[asyncio.Task] = None
        self._backpressure = BackpressureController(
            max_queue_size=10000,
            target_latency_ms=100.0,
        )
        self._total_ingested = 0
        self._total_failed = 0
        self._lock = asyncio.Lock()

    def normalize_log(self, raw_log: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize raw log from any source into standard format."""
        normalized = {
            "org_id": raw_log.get("org_id", "unknown"),
            "source": raw_log.get("source", "unknown"),
            "event_type": raw_log.get("event_type", "unknown"),
            "severity": raw_log.get("severity", "info"),
            "raw_payload": json.dumps(raw_log.get("raw_payload", raw_log)),
            "normalized_payload": json.dumps(self._extract_fields(raw_log)),
            "src_ip": raw_log.get("src_ip"),
            "dst_ip": raw_log.get("dst_ip"),
            "src_port": raw_log.get("src_port"),
            "dst_port": raw_log.get("dst_port"),
            "protocol": raw_log.get("protocol"),
            "hostname": raw_log.get("hostname"),
            "user": raw_log.get("user"),
            "process_name": raw_log.get("process_name"),
            "tags": raw_log.get("tags", []),
            "timestamp": self._parse_timestamp(raw_log.get("timestamp")),
        }
        return normalized

    def _extract_fields(self, raw_log: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key fields from raw log for indexing."""
        fields = {}
        payload = raw_log.get("raw_payload", raw_log)

        if isinstance(payload, dict):
            # Zeek/Suricata fields
            fields["uid"] = payload.get("uid")
            fields["id_orig_h"] = payload.get("id.orig_h")
            fields["id_resp_h"] = payload.get("id.resp_h")
            fields["id_orig_p"] = payload.get("id.orig_p")
            fields["id_resp_p"] = payload.get("id.resp_p")
            fields["proto"] = payload.get("proto")
            fields["service"] = payload.get("service")
            fields["duration"] = payload.get("duration")
            fields["orig_bytes"] = payload.get("orig_bytes")
            fields["resp_bytes"] = payload.get("resp_bytes")
            fields["conn_state"] = payload.get("conn_state")
            fields["history"] = payload.get("history")

        return fields

    def _parse_timestamp(self, ts) -> datetime:
        """Parse timestamp from various formats."""
        if ts is None:
            return datetime.now(timezone.utc)
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        try:
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)

    def enrich_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich log with threat intelligence and context."""
        # Determine severity based on event type
        severity_map = {
            "scan": "low",
            "auth_failure": "medium",
            "brute_force": "high",
            "malware_detected": "critical",
            "c2_communication": "critical",
            "data_exfiltration": "critical",
            "privilege_escalation": "high",
            "lateral_movement": "high",
            "ransomware_activity": "critical",
        }
        if log.get("severity") == "info" and log["event_type"] in severity_map:
            log["severity"] = severity_map[log["event_type"]]

        # Add MITRE ATT&CK mapping
        mitre_map = {
            "scan": ("TA0043", "T1595"),
            "brute_force": ("TA0006", "T1110"),
            "phishing": ("TA0001", "T1566"),
            "c2_communication": ("TA0011", "T1071"),
            "data_exfiltration": ("TA0010", "T1041"),
            "lateral_movement": ("TA0008", "T1021"),
            "privilege_escalation": ("TA0004", "T1068"),
            "ransomware_activity": ("TA0040", "T1486"),
        }
        if log["event_type"] in mitre_map:
            log["mitre_tactic"], log["mitre_technique"] = mitre_map[log["event_type"]]

        return log

    async def ingest(self, raw_log: Dict[str, Any]) -> bool:
        """Full ingestion pipeline for a single log."""
        try:
            # Apply backpressure if needed
            await self._backpressure.wait_if_needed()

            # 1. Normalize
            normalized = self.normalize_log(raw_log)

            # 2. Enrich
            enriched = self.enrich_log(normalized)

            # 3. Add to batch buffer
            async with self._lock:
                self._batch_buffer.append(enriched)

            # 4. Flush batch if full
            if len(self._batch_buffer) >= self._batch_size:
                await self.flush()

            async with self._lock:
                self._total_ingested += 1

            return True
        except Exception as e:
            async with self._lock:
                self._total_failed += 1
            logger.error("ingestion_pipeline_error", error=str(e))
            return False

    async def ingest_batch(self, raw_logs: List[Dict[str, Any]]) -> int:
        """Ingest a batch of logs."""
        count = 0
        for log in raw_logs:
            if await self.ingest(log):
                count += 1
        await self.flush()
        return count

    async def flush(self):
        """Flush the batch buffer to ClickHouse."""
        async with self._lock:
            if not self._batch_buffer:
                return

            batch = self._batch_buffer.copy()
            self._batch_buffer.clear()

        import time
        start = time.time()

        try:
            inserted = await self.clickhouse.insert_logs_batch(batch)
            latency_ms = (time.time() - start) * 1000

            # Update backpressure
            self._backpressure.update(len(self._batch_buffer), latency_ms)

            logger.info(
                "ingestion_flush",
                batch_size=len(batch),
                inserted=inserted,
                latency_ms=round(latency_ms, 2),
            )
        except Exception as e:
            latency_ms = (time.time() - start) * 1000
            logger.error("ingestion_flush_failed", error=str(e), latency_ms=round(latency_ms, 2))

            # Re-queue failed batch to Kafka via circuit breaker
            for log in batch:
                await self.producer.produce_sync(
                    topic=settings.KAFKA_TOPIC_LOGS,
                    key=log.get("org_id", "unknown"),
                    value=log,
                )

    async def start_consumer(self):
        """Start Kafka consumer to process incoming logs."""
        consumer = get_consumer()
        consumer.subscribe([settings.KAFKA_TOPIC_LOGS])

        logger.info("ingestion_consumer_started", topic=settings.KAFKA_TOPIC_LOGS)

        def handler(msg: Dict[str, Any]):
            asyncio.create_task(self._handle_message(msg))

        await consumer.consume_loop(
            handler=handler,
            batch_size=100,
            timeout=1.0,
        )

    async def _handle_message(self, msg: Dict[str, Any]):
        """Handle a single Kafka message."""
        try:
            # Clean Kafka metadata
            msg.pop("_kafka_topic", None)
            msg.pop("_kafka_partition", None)
            msg.pop("_kafka_offset", None)

            await self.ingest(msg)
        except Exception as e:
            logger.error("message_handling_error", error=str(e))

    async def get_stats(self, org_id: str, minutes: int = 60) -> Dict[str, Any]:
        """Get ingestion statistics."""
        return self.clickhouse.get_traffic_stats(org_id, minutes)

    async def health_check(self) -> Dict[str, Any]:
        """Check ingestion pipeline health."""
        async with self._lock:
            return {
                "status": "healthy",
                "batch_buffer_size": len(self._batch_buffer),
                "batch_max_size": self._batch_size,
                "kafka_topic": settings.KAFKA_TOPIC_LOGS,
                "total_ingested": self._total_ingested,
                "total_failed": self._total_failed,
                "backpressure_delay": self._backpressure.delay,
                "backpressure_queue": self._backpressure.queue_size,
            }


# Global pipeline instance
pipeline = IngestionPipeline()


def get_pipeline() -> IngestionPipeline:
    return pipeline
