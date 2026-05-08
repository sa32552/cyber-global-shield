"""
ClickHouse OLAP client with async buffering, retry, and health checks.
"""
import asyncio
import time
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone
from collections import deque
import structlog
import clickhouse_connect
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)
from app.core.config import settings

logger = structlog.get_logger(__name__)


class ClickHouseBuffer:
    """
    Async buffer for ClickHouse inserts.
    Accumulates rows and flushes periodically or when buffer is full.
    """

    def __init__(
        self,
        table: str,
        column_names: List[str],
        max_size: int = 10000,
        flush_interval: float = 2.0,
        max_retries: int = 3,
    ):
        self.table = table
        self.column_names = column_names
        self.max_size = max_size
        self.flush_interval = flush_interval
        self.max_retries = max_retries
        self._buffer: deque = deque(maxlen=max_size * 2)
        self._flush_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        self._total_inserted = 0
        self._total_failed = 0

    async def add(self, row: List[Any]):
        """Add a row to the buffer."""
        async with self._lock:
            self._buffer.append(row)
            if len(self._buffer) >= self.max_size:
                await self._flush()

    async def start_periodic_flush(self):
        """Start periodic flush task."""
        if self._flush_task is None or self._flush_task.done():
            self._flush_task = asyncio.create_task(self._periodic_flush_loop())

    async def stop_periodic_flush(self):
        """Stop periodic flush task."""
        if self._flush_task and not self._flush_task.done():
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass

    async def _periodic_flush_loop(self):
        """Periodically flush the buffer."""
        while True:
            await asyncio.sleep(self.flush_interval)
            async with self._lock:
                if self._buffer:
                    await self._flush()

    async def _flush(self):
        """Flush buffer to ClickHouse."""
        if not self._buffer:
            return

        batch = list(self._buffer)
        self._buffer.clear()

        try:
            await self._do_insert(batch)
            self._total_inserted += len(batch)
            logger.debug(
                "clickhouse_buffer_flushed",
                table=self.table,
                count=len(batch),
                total_inserted=self._total_inserted,
            )
        except Exception as e:
            self._total_failed += len(batch)
            logger.error(
                "clickhouse_buffer_flush_failed",
                table=self.table,
                count=len(batch),
                error=str(e),
                total_failed=self._total_failed,
            )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, max=5.0),
        retry=retry_if_exception_type(Exception),
        before_sleep=before_sleep_log(logger, structlog.get_log_level()),
        reraise=True,
    )
    async def _do_insert(self, rows: List[List[Any]]):
        """Insert rows with retry logic."""
        from app.ingestion.clickhouse_client import get_clickhouse
        client = get_clickhouse()
        client.client.insert(
            self.table,
            rows,
            column_names=self.column_names,
        )

    async def get_stats(self) -> Dict[str, Any]:
        """Get buffer statistics."""
        async with self._lock:
            return {
                "table": self.table,
                "buffer_size": len(self._buffer),
                "max_size": self.max_size,
                "total_inserted": self._total_inserted,
                "total_failed": self._total_failed,
                "flush_interval": self.flush_interval,
            }


class ClickHouseClient:
    """ClickHouse OLAP client for high-performance log storage and analytics."""

    def __init__(self):
        self.client = clickhouse_connect.get_client(
            host=settings.CLICKHOUSE_HOST,
            port=settings.CLICKHOUSE_PORT,
            username=settings.CLICKHOUSE_USER,
            password=settings.CLICKHOUSE_PASSWORD,
            database=settings.CLICKHOUSE_DATABASE,
            compress=True,
            settings={
                "max_insert_block_size": 100000,
                "async_insert": 1,
                "wait_for_async_insert": 0,
            },
        )
        self._ensure_database()

        # Async buffers for each table
        self._buffers: Dict[str, ClickHouseBuffer] = {}
        self._buffer_task: Optional[asyncio.Task] = None

    def _ensure_database(self):
        """Create database and tables if they don't exist."""
        self.client.command(
            f"CREATE DATABASE IF NOT EXISTS {settings.CLICKHOUSE_DATABASE}"
        )

        # Raw logs table - partitioned by day, ordered by timestamp
        self.client.command("""
            CREATE TABLE IF NOT EXISTS raw_logs (
                org_id String,
                source LowCardinality(String),
                event_type LowCardinality(String),
                severity LowCardinality(String),
                raw_payload String,
                normalized_payload String,
                src_ip Nullable(IPv6),
                dst_ip Nullable(IPv6),
                src_port Nullable(UInt16),
                dst_port Nullable(UInt16),
                protocol Nullable(String),
                hostname Nullable(String),
                user Nullable(String),
                process_name Nullable(String),
                tags Array(String),
                timestamp DateTime64(3),
                ingested_at DateTime64(3) DEFAULT now64(3)
            )
            ENGINE = MergeTree()
            PARTITION BY toYYYYMMDD(timestamp)
            ORDER BY (org_id, timestamp, source, event_type)
            TTL timestamp + INTERVAL 90 DAY
            SETTINGS index_granularity = 8192
        """)

        # Network flows table
        self.client.command("""
            CREATE TABLE IF NOT EXISTS network_flows (
                org_id String,
                src_ip IPv6,
                dst_ip IPv6,
                src_port UInt16,
                dst_port UInt16,
                protocol LowCardinality(String),
                bytes_sent UInt64,
                bytes_received UInt64,
                packets_sent UInt64,
                packets_received UInt64,
                duration_seconds Float64,
                flow_start DateTime64(3),
                flow_end Nullable(DateTime64(3)),
                is_anomalous UInt8,
                anomaly_score Nullable(Float64)
            )
            ENGINE = MergeTree()
            PARTITION BY toYYYYMMDD(flow_start)
            ORDER BY (org_id, flow_start, src_ip, dst_ip)
            TTL flow_start + INTERVAL 30 DAY
        """)

        # Alerts table
        self.client.command("""
            CREATE TABLE IF NOT EXISTS alerts_analytics (
                org_id String,
                alert_type LowCardinality(String),
                severity LowCardinality(String),
                confidence Float64,
                threat_score Float64,
                status LowCardinality(String),
                mitre_tactic Nullable(String),
                mitre_technique Nullable(String),
                auto_resolved UInt8,
                created_at DateTime64(3),
                resolved_at Nullable(DateTime64(3))
            )
            ENGINE = MergeTree()
            PARTITION BY toYYYYMM(created_at)
            ORDER BY (org_id, created_at, severity, alert_type)
            TTL created_at + INTERVAL 365 DAY
        """)

        # Anomaly scores table for ML analytics
        self.client.command("""
            CREATE TABLE IF NOT EXISTS anomaly_scores_analytics (
                org_id String,
                model_id String,
                model_version String,
                anomaly_score Float64,
                reconstruction_error Nullable(Float64),
                is_anomaly UInt8,
                inference_time_ms Nullable(Float64),
                created_at DateTime64(3)
            )
            ENGINE = MergeTree()
            PARTITION BY toYYYYMM(created_at)
            ORDER BY (org_id, created_at, is_anomaly)
            TTL created_at + INTERVAL 90 DAY
        """)

        # Materialized views for real-time aggregation
        self.client.command("""
            CREATE MATERIALIZED VIEW IF NOT EXISTS alerts_per_minute
            ENGINE = AggregatingMergeTree()
            PARTITION BY toYYYYMM(minute)
            ORDER BY (org_id, minute, severity)
            AS SELECT
                org_id,
                toStartOfMinute(created_at) AS minute,
                severity,
                count() AS alert_count,
                avg(confidence) AS avg_confidence,
                max(threat_score) AS max_threat_score
            FROM alerts_analytics
            GROUP BY org_id, minute, severity
        """)

    def _get_buffer(self, table: str, column_names: List[str]) -> ClickHouseBuffer:
        """Get or create an async buffer for a table."""
        if table not in self._buffers:
            self._buffers[table] = ClickHouseBuffer(
                table=table,
                column_names=column_names,
                max_size=10000,
                flush_interval=2.0,
            )
        return self._buffers[table]

    async def start_buffers(self):
        """Start all async buffers."""
        for buffer in self._buffers.values():
            await buffer.start_periodic_flush()

    async def stop_buffers(self):
        """Stop all async buffers and flush remaining data."""
        for buffer in self._buffers.values():
            await buffer.stop_periodic_flush()

    async def insert_logs_batch(self, logs: List[Dict[str, Any]]) -> int:
        """Insert a batch of raw logs. Returns number of rows inserted."""
        if not logs:
            return 0

        rows = []
        for log in logs:
            rows.append([
                log.get("org_id", ""),
                log.get("source", "unknown"),
                log.get("event_type", "unknown"),
                log.get("severity", "info"),
                log.get("raw_payload", "{}"),
                log.get("normalized_payload", "{}"),
                log.get("src_ip"),
                log.get("dst_ip"),
                log.get("src_port"),
                log.get("dst_port"),
                log.get("protocol"),
                log.get("hostname"),
                log.get("user"),
                log.get("process_name"),
                log.get("tags", []),
                log.get("timestamp", datetime.now(timezone.utc)),
                datetime.now(timezone.utc),
            ])

        column_names = [
            "org_id", "source", "event_type", "severity",
            "raw_payload", "normalized_payload", "src_ip", "dst_ip",
            "src_port", "dst_port", "protocol", "hostname", "user",
            "process_name", "tags", "timestamp", "ingested_at",
        ]

        # Use async buffer
        buffer = self._get_buffer("raw_logs", column_names)
        for row in rows:
            await buffer.add(row)

        return len(rows)

    async def insert_flows_batch(self, flows: List[Dict[str, Any]]) -> int:
        """Insert a batch of network flows."""
        if not flows:
            return 0

        rows = []
        for flow in flows:
            rows.append([
                flow.get("org_id", ""),
                flow.get("src_ip"),
                flow.get("dst_ip"),
                flow.get("src_port"),
                flow.get("dst_port"),
                flow.get("protocol", "tcp"),
                flow.get("bytes_sent", 0),
                flow.get("bytes_received", 0),
                flow.get("packets_sent", 0),
                flow.get("packets_received", 0),
                flow.get("duration_seconds", 0.0),
                flow.get("flow_start", datetime.now(timezone.utc)),
                flow.get("flow_end"),
                int(flow.get("is_anomalous", False)),
                flow.get("anomaly_score"),
            ])

        column_names = [
            "org_id", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "bytes_sent", "bytes_received", "packets_sent",
            "packets_received", "duration_seconds", "flow_start",
            "flow_end", "is_anomalous", "anomaly_score",
        ]

        buffer = self._get_buffer("network_flows", column_names)
        for row in rows:
            await buffer.add(row)

        return len(rows)

    def query_logs(
        self,
        org_id: str,
        start_time: datetime,
        end_time: Optional[datetime] = None,
        limit: int = 10000,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Query raw logs with time range and filters."""
        if end_time is None:
            end_time = datetime.now(timezone.utc)

        query = """
            SELECT org_id, source, event_type, severity, src_ip, dst_ip,
                   src_port, dst_port, protocol, hostname, user,
                   process_name, tags, timestamp
            FROM raw_logs
            WHERE org_id = {org_id:String}
              AND timestamp >= {start:DateTime64(3)}
              AND timestamp <= {end:DateTime64(3)}
        """

        params = {
            "org_id": org_id,
            "start": start_time,
            "end": end_time,
        }

        if filters:
            for key, value in filters.items():
                if key in ["source", "event_type", "severity", "protocol"]:
                    query += f" AND {key} = {{{key}:String}}"
                    params[key] = value

        query += f" ORDER BY timestamp DESC LIMIT {limit}"

        result = self.client.query(query, parameters=params)
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    def get_traffic_stats(
        self, org_id: str, minutes: int = 60
    ) -> Dict[str, Any]:
        """Get traffic statistics for dashboard."""
        start = datetime.now(timezone.utc).replace(
            second=0, microsecond=0
        ) - __import__("datetime").timedelta(minutes=minutes)

        # Log volume
        volume = self.client.query(
            """
            SELECT
                toStartOfMinute(timestamp) AS minute,
                count() AS event_count,
                uniqExact(src_ip) AS unique_src_ips,
                uniqExact(dst_ip) AS unique_dst_ips
            FROM raw_logs
            WHERE org_id = {org_id:String} AND timestamp >= {start:DateTime64(3)}
            GROUP BY minute ORDER BY minute
            """,
            parameters={"org_id": org_id, "start": start},
        )

        # Alert stats
        alerts = self.client.query(
            """
            SELECT
                severity,
                count() AS count,
                avg(confidence) AS avg_confidence,
                max(threat_score) AS max_threat_score
            FROM alerts_analytics
            WHERE org_id = {org_id:String} AND created_at >= {start:DateTime64(3)}
            GROUP BY severity ORDER BY severity
            """,
            parameters={"org_id": org_id, "start": start},
        )

        # Anomaly rate
        anomalies = self.client.query(
            """
            SELECT
                countIf(is_anomaly = 1) AS anomaly_count,
                count() AS total_count,
                anomaly_count / total_count AS anomaly_rate
            FROM anomaly_scores_analytics
            WHERE org_id = {org_id:String} AND created_at >= {start:DateTime64(3)}
            """,
            parameters={"org_id": org_id, "start": start},
        )

        return {
            "volume": [dict(zip(volume.column_names, row)) for row in volume.result_rows],
            "alerts": [dict(zip(alerts.column_names, row)) for row in alerts.result_rows],
            "anomalies": [dict(zip(anomalies.column_names, row)) for row in anomalies.result_rows],
        }

    async def health_check(self) -> Dict[str, Any]:
        """Detailed ClickHouse health check."""
        import time
        start = time.time()

        try:
            result = self.client.query("SELECT 1")
            latency_ms = (time.time() - start) * 1000

            # Get buffer stats
            buffer_stats = {}
            for name, buf in self._buffers.items():
                buffer_stats[name] = await buf.get_stats()

            return {
                "status": "healthy",
                "latency_ms": round(latency_ms, 2),
                "database": settings.CLICKHOUSE_DATABASE,
                "buffers": buffer_stats,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            latency_ms = (time.time() - start) * 1000
            logger.error("clickhouse_health_check_failed", error=str(e))
            return {
                "status": "unhealthy",
                "error": str(e),
                "latency_ms": round(latency_ms, 2),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    def close(self):
        self.client.close()


# Global instance
clickhouse_client = ClickHouseClient()


def get_clickhouse() -> ClickHouseClient:
    return clickhouse_client
