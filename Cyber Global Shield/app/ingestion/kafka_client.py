"""
Kafka client with circuit breaker, dead letter queue, and OpenTelemetry tracing.
"""
import json
import asyncio
import time
from typing import Optional, Dict, Any, Callable, List
from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass, field
import structlog
from confluent_kafka import Producer, Consumer, KafkaError, KafkaException
from app.core.config import settings

logger = structlog.get_logger(__name__)


# ─── Circuit Breaker ────────────────────────────────────────────────────

class CircuitState(Enum):
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # Failing, reject requests
    HALF_OPEN = "half_open" # Testing if service recovered


@dataclass
class CircuitBreakerStats:
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[float] = None
    last_success_time: Optional[float] = None
    total_failures: int = 0
    total_successes: int = 0


class CircuitBreaker:
    """
    Circuit breaker for Kafka producer.
    Prevents cascading failures when Kafka is unavailable.
    """

    def __init__(
        self,
        name: str = "kafka",
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_requests: int = 3,
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_requests = half_open_max_requests
        self._state = CircuitState.CLOSED
        self._stats = CircuitBreakerStats()
        self._half_open_requests = 0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def stats(self) -> CircuitBreakerStats:
        return self._stats

    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute a function with circuit breaker protection."""
        async with self._lock:
            if self._state == CircuitState.OPEN:
                if time.time() - self._stats.last_failure_time >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_requests = 0
                    logger.info("circuit_half_open", name=self.name)
                else:
                    raise CircuitBreakerOpenError(
                        f"Circuit breaker '{self.name}' is OPEN. "
                        f"Retry after {self.recovery_timeout - (time.time() - self._stats.last_failure_time):.0f}s"
                    )

            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_requests >= self.half_open_max_requests:
                    raise CircuitBreakerOpenError(
                        f"Circuit breaker '{self.name}' is HALF_OPEN and at max test requests"
                    )
                self._half_open_requests += 1

        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)

            async with self._lock:
                self._stats.success_count += 1
                self._stats.total_successes += 1
                self._stats.last_success_time = time.time()

                if self._state == CircuitState.HALF_OPEN:
                    self._state = CircuitState.CLOSED
                    self._stats.failure_count = 0
                    logger.info("circuit_closed", name=self.name, message="Service recovered")

            return result

        except Exception as e:
            async with self._lock:
                self._stats.failure_count += 1
                self._stats.total_failures += 1
                self._stats.last_failure_time = time.time()

                if self._state == CircuitState.CLOSED and self._stats.failure_count >= self.failure_threshold:
                    self._state = CircuitState.OPEN
                    logger.warning(
                        "circuit_opened",
                        name=self.name,
                        failures=self._stats.failure_count,
                        threshold=self.failure_threshold,
                    )
                elif self._state == CircuitState.HALF_OPEN:
                    self._state = CircuitState.OPEN
                    logger.warning("circuit_reopened", name=self.name)

            raise


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open."""
    pass


# ─── Dead Letter Queue ──────────────────────────────────────────────────

@dataclass
class DeadLetterMessage:
    topic: str
    key: str
    value: Dict[str, Any]
    error: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    retry_count: int = 0


class DeadLetterQueue:
    """
    Dead letter queue for messages that failed processing.
    Stores failed messages in memory with optional periodic retry.
    """

    def __init__(self, max_size: int = 10000, max_retries: int = 3):
        self.max_size = max_size
        self.max_retries = max_retries
        self._messages: List[DeadLetterMessage] = []
        self._lock = asyncio.Lock()

    async def add(self, message: DeadLetterMessage):
        """Add a message to the dead letter queue."""
        async with self._lock:
            if len(self._messages) >= self.max_size:
                # Remove oldest message
                self._messages.pop(0)
            self._messages.append(message)
            logger.warning(
                "dlq_message_added",
                topic=message.topic,
                error=message.error,
                retry_count=message.retry_count,
                queue_size=len(self._messages),
            )

    async def get_pending_retries(self) -> List[DeadLetterMessage]:
        """Get messages that are eligible for retry."""
        async with self._lock:
            retryable = [m for m in self._messages if m.retry_count < self.max_retries]
            return retryable

    async def retry_failed(self, producer_func: Callable) -> int:
        """Retry all failed messages. Returns number of successful retries."""
        retryable = await self.get_pending_retries()
        success_count = 0

        for msg in retryable:
            try:
                producer_func(msg.topic, msg.key, msg.value)
                async with self._lock:
                    self._messages.remove(msg)
                success_count += 1
                logger.info("dlq_retry_success", topic=msg.topic, key=msg.key)
            except Exception as e:
                msg.retry_count += 1
                msg.error = str(e)
                logger.warning(
                    "dlq_retry_failed",
                    topic=msg.topic,
                    key=msg.key,
                    retry_count=msg.retry_count,
                    error=str(e),
                )

        return success_count

    async def get_stats(self) -> Dict[str, Any]:
        """Get dead letter queue statistics."""
        async with self._lock:
            return {
                "total_messages": len(self._messages),
                "pending_retries": len([m for m in self._messages if m.retry_count < self.max_retries]),
                "max_retries": self.max_retries,
                "max_size": self.max_size,
            }


# ─── Kafka Producer ─────────────────────────────────────────────────────

class KafkaProducerClient:
    """High-throughput Kafka producer with circuit breaker and DLQ."""

    def __init__(self):
        self.config = {
            "bootstrap.servers": settings.KAFKA_BOOTSTRAP_SERVERS,
            "acks": "all",
            "retries": 5,
            "retry.backoff.ms": 100,
            "compression.type": "lz4",
            "linger.ms": 5,
            "batch.size": 65536,  # 64KB
            "max.in.flight.requests.per.connection": 5,
            "client.id": "cyber-global-shield-producer",
        }
        self.producer = Producer(self.config)
        self.circuit_breaker = CircuitBreaker(
            name="kafka-producer",
            failure_threshold=5,
            recovery_timeout=30.0,
        )
        self.dead_letter_queue = DeadLetterQueue(max_size=10000, max_retries=3)

    def delivery_callback(self, err, msg):
        if err:
            logger.error("kafka_delivery_failed", error=str(err))
        else:
            logger.debug(
                "kafka_delivery_success",
                topic=msg.topic(),
                partition=msg.partition(),
                offset=msg.offset(),
            )

    async def produce_sync(self, topic: str, key: str, value: Dict[str, Any]) -> bool:
        """Synchronous produce with circuit breaker protection."""
        try:
            await self.circuit_breaker.call(
                self._do_produce_sync, topic, key, value
            )
            return True
        except CircuitBreakerOpenError as e:
            logger.error("circuit_open_dropping_message", topic=topic, error=str(e))
            await self.dead_letter_queue.add(DeadLetterMessage(
                topic=topic, key=key, value=value, error=str(e)
            ))
            return False
        except Exception as e:
            logger.error("kafka_produce_failed", topic=topic, error=str(e))
            await self.dead_letter_queue.add(DeadLetterMessage(
                topic=topic, key=key, value=value, error=str(e)
            ))
            return False

    def _do_produce_sync(self, topic: str, key: str, value: Dict[str, Any]):
        """Internal synchronous produce (no circuit breaker wrapper)."""
        self.producer.produce(
            topic=topic,
            key=key.encode("utf-8"),
            value=json.dumps(value, default=str).encode("utf-8"),
            callback=self.delivery_callback,
        )
        self.producer.flush(timeout=10)

    def produce_async(self, topic: str, key: str, value: Dict[str, Any]):
        """Fire-and-forget async produce for high-throughput."""
        try:
            self.producer.produce(
                topic=topic,
                key=key.encode("utf-8"),
                value=json.dumps(value, default=str).encode("utf-8"),
                callback=self.delivery_callback,
            )
        except Exception as e:
            logger.error("kafka_async_produce_failed", topic=topic, error=str(e))
            # Add to DLQ as fallback
            asyncio.create_task(self.dead_letter_queue.add(DeadLetterMessage(
                topic=topic, key=key, value=value, error=str(e)
            )))

    def produce_batch(
        self, topic: str, messages: List[tuple], flush_after: int = 1000
    ):
        """Batch produce multiple messages."""
        for i, (key, value) in enumerate(messages):
            try:
                self.producer.produce(
                    topic=topic,
                    key=key.encode("utf-8"),
                    value=json.dumps(value, default=str).encode("utf-8"),
                    callback=self.delivery_callback,
                )
            except Exception as e:
                logger.error("kafka_batch_produce_failed", topic=topic, error=str(e))
                asyncio.create_task(self.dead_letter_queue.add(DeadLetterMessage(
                    topic=topic, key=key, value=value, error=str(e)
                )))

            if i > 0 and i % flush_after == 0:
                self.producer.poll(0)

        self.producer.flush(timeout=30)

    async def retry_dead_letters(self) -> int:
        """Retry all messages in the dead letter queue."""
        return await self.dead_letter_queue.retry_failed(self._do_produce_sync)

    def close(self):
        self.producer.flush(timeout=30)


# ─── Kafka Consumer ─────────────────────────────────────────────────────

class KafkaConsumerClient:
    """Kafka consumer for processing log streams."""

    def __init__(self, group_id: Optional[str] = None):
        self.config = {
            "bootstrap.servers": settings.KAFKA_BOOTSTRAP_SERVERS,
            "group.id": group_id or settings.KAFKA_CONSUMER_GROUP,
            "auto.offset.reset": "latest",
            "enable.auto.commit": False,
            "max.poll.interval.ms": 300000,
            "session.timeout.ms": 30000,
            "heartbeat.interval.ms": 10000,
        }
        self.consumer = Consumer(self.config)
        self.running = False

    def subscribe(self, topics: List[str]):
        self.consumer.subscribe(topics)

    async def consume_loop(
        self,
        handler: Callable[[Dict[str, Any]], None],
        batch_size: int = 100,
        timeout: float = 1.0,
    ):
        """Async consume loop with batch processing."""
        self.running = True
        batch = []

        try:
            while self.running:
                msg = self.consumer.poll(timeout=timeout)

                if msg is None:
                    # Process any remaining batch
                    if batch:
                        await self._process_batch(batch, handler)
                        batch = []
                    continue

                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    logger.error(
                        "kafka_consumer_error",
                        error=msg.error().str(),
                        topic=msg.topic(),
                    )
                    continue

                try:
                    value = json.loads(msg.value().decode("utf-8"))
                    value["_kafka_topic"] = msg.topic()
                    value["_kafka_partition"] = msg.partition()
                    value["_kafka_offset"] = msg.offset()
                    batch.append(value)

                    if len(batch) >= batch_size:
                        await self._process_batch(batch, handler)
                        self.consumer.commit(asynchronous=True)
                        batch = []

                except json.JSONDecodeError as e:
                    logger.error("kafka_decode_error", error=str(e))
                    self.consumer.commit(asynchronous=True)

        except KafkaException as e:
            logger.error("kafka_fatal_error", error=str(e))
        finally:
            if batch:
                await self._process_batch(batch, handler)
                self.consumer.commit()
            self.close()

    async def _process_batch(
        self, batch: List[Dict[str, Any]], handler: Callable[[Dict[str, Any]], None]
    ):
        """Process a batch of messages concurrently."""
        tasks = []
        for msg in batch:
            task = asyncio.create_task(self._safe_handle(msg, handler))
            tasks.append(task)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _safe_handle(
        self, msg: Dict[str, Any], handler: Callable[[Dict[str, Any]], None]
    ):
        """Safely handle a single message, catching exceptions."""
        try:
            if asyncio.iscoroutinefunction(handler):
                await handler(msg)
            else:
                handler(msg)
        except Exception as e:
            logger.error("message_handler_error", error=str(e))

    def stop(self):
        self.running = False

    def close(self):
        try:
            self.consumer.close()
        except Exception:
            pass


# ─── Global instances ───────────────────────────────────────────────────

producer_client = KafkaProducerClient()


def get_producer() -> KafkaProducerClient:
    return producer_client


def get_consumer(group_id: Optional[str] = None) -> KafkaConsumerClient:
    return KafkaConsumerClient(group_id=group_id)
