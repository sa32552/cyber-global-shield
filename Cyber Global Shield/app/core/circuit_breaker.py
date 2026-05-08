"""
╔══════════════════════════════════════════════════════════════╗
║  Cyber Global Shield — Circuit Breaker                      ║
║  Protection contre les défaillances en cascade              ║
║  États: CLOSED → OPEN → HALF_OPEN → CLOSED                  ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    breaker = CircuitBreaker("redis", failure_threshold=5, recovery_timeout=30)
    
    async with breaker:
        result = await redis_client.get("key")
"""

import os
import time
import asyncio
import structlog
from enum import Enum
from typing import Dict, Any, Optional, Callable, TypeVar, Awaitable
from dataclasses import dataclass, field
from functools import wraps

logger = structlog.get_logger(__name__)

T = TypeVar("T")


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"        # Normal operation
    OPEN = "open"            # Circuit open, requests blocked
    HALF_OPEN = "half_open"  # Testing recovery


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is OPEN."""
    pass


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    half_open_max_requests: int = 3
    success_threshold: int = 2
    name: str = "default"


class CircuitBreaker:
    """
    Circuit Breaker pattern with HALF_OPEN state.
    
    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Circuit open, requests blocked immediately
    - HALF_OPEN: Testing if service recovered
    
    Thread-safe with asyncio.Lock.
    """

    def __init__(self, name: str = "default", config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig(name=name)
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = 0.0
        self.half_open_requests = 0
        self._lock = asyncio.Lock()
        self._stats = {
            "total_calls": 0,
            "successful_calls": 0,
            "failed_calls": 0,
            "rejected_calls": 0,
            "state_changes": 0,
        }

    async def __aenter__(self):
        """Async context manager entry."""
        await self._check_state()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if exc_type is None:
            await self._on_success()
        elif exc_type is not CircuitBreakerOpenError:
            await self._on_failure()
        # Don't suppress exceptions
        return False

    async def call(self, func: Callable[..., Awaitable[T]], *args, **kwargs) -> T:
        """
        Execute an async function with circuit breaker protection.
        
        Args:
            func: Async function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            Function result
            
        Raises:
            CircuitBreakerOpenError: If circuit is OPEN
        """
        await self._check_state()

        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except CircuitBreakerOpenError:
            raise
        except Exception as e:
            await self._on_failure()
            raise

    async def call_sync(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute a sync function with circuit breaker protection.
        
        Args:
            func: Sync function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            Function result
            
        Raises:
            CircuitBreakerOpenError: If circuit is OPEN
        """
        await self._check_state()

        try:
            result = func(*args, **kwargs)
            await self._on_success()
            return result
        except CircuitBreakerOpenError:
            raise
        except Exception as e:
            await self._on_failure()
            raise

    async def _check_state(self):
        """Check and potentially transition circuit state."""
        async with self._lock:
            self._stats["total_calls"] += 1

            if self.state == CircuitState.OPEN:
                # Check if recovery timeout has elapsed
                if time.time() - self.last_failure_time >= self.config.recovery_timeout:
                    logger.info(
                        "circuit_half_open",
                        circuit=self.name,
                        recovery_time=self.config.recovery_timeout,
                    )
                    self.state = CircuitState.HALF_OPEN
                    self.half_open_requests = 0
                    self.success_count = 0
                    self._stats["state_changes"] += 1
                else:
                    self._stats["rejected_calls"] += 1
                    remaining = self.config.recovery_timeout - (time.time() - self.last_failure_time)
                    raise CircuitBreakerOpenError(
                        f"Circuit '{self.name}' is OPEN. "
                        f"Retry in {remaining:.1f}s"
                    )

            if self.state == CircuitState.HALF_OPEN:
                if self.half_open_requests >= self.config.half_open_max_requests:
                    self._stats["rejected_calls"] += 1
                    raise CircuitBreakerOpenError(
                        f"Circuit '{self.name}' is HALF_OPEN. "
                        f"Max test requests ({self.config.half_open_max_requests}) reached."
                    )
                self.half_open_requests += 1

    async def _on_success(self):
        """Handle successful call."""
        async with self._lock:
            self._stats["successful_calls"] += 1

            if self.state == CircuitState.HALF_OPEN:
                self.success_count += 1
                if self.success_count >= self.config.success_threshold:
                    logger.info(
                        "circuit_closed",
                        circuit=self.name,
                        successes=self.success_count,
                    )
                    self.state = CircuitState.CLOSED
                    self.failure_count = 0
                    self.success_count = 0
                    self._stats["state_changes"] += 1

    async def _on_failure(self):
        """Handle failed call."""
        async with self._lock:
            self._stats["failed_calls"] += 1
            self.failure_count += 1
            self.last_failure_time = time.time()

            if self.state == CircuitState.HALF_OPEN:
                # Failed during recovery test, go back to OPEN
                logger.warning(
                    "circuit_reopened",
                    circuit=self.name,
                    failures=self.failure_count,
                )
                self.state = CircuitState.OPEN
                self.success_count = 0
                self._stats["state_changes"] += 1
            elif self.failure_count >= self.config.failure_threshold:
                logger.warning(
                    "circuit_opened",
                    circuit=self.name,
                    failures=self.failure_count,
                    threshold=self.config.failure_threshold,
                )
                self.state = CircuitState.OPEN
                self.success_count = 0
                self._stats["state_changes"] += 1

    def force_state(self, state: CircuitState):
        """Force circuit breaker state (for testing)."""
        self.state = state
        self._stats["state_changes"] += 1
        logger.info("circuit_force_state", circuit=self.name, state=state.value)

    def reset(self):
        """Reset circuit breaker to CLOSED state."""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.half_open_requests = 0
        self._stats["state_changes"] += 1
        logger.info("circuit_reset", circuit=self.name)

    def get_state(self) -> Dict[str, Any]:
        """Get current circuit breaker state."""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "half_open_requests": self.half_open_requests,
            "last_failure_time": self.last_failure_time,
            "time_since_last_failure": time.time() - self.last_failure_time if self.last_failure_time else 0,
            "config": {
                "failure_threshold": self.config.failure_threshold,
                "recovery_timeout": self.config.recovery_timeout,
                "half_open_max_requests": self.config.half_open_max_requests,
                "success_threshold": self.config.success_threshold,
            },
            "stats": self._stats,
        }


# =============================================================================
# Circuit Breaker Registry
# =============================================================================

class CircuitBreakerRegistry:
    """
    Registry of circuit breakers for all services.
    Provides centralized management and monitoring.
    """

    def __init__(self):
        self._breakers: Dict[str, CircuitBreaker] = {}

    def get_or_create(self, name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
        """Get or create a circuit breaker."""
        if name not in self._breakers:
            self._breakers[name] = CircuitBreaker(name, config)
            logger.info("circuit_breaker_created", name=name)
        return self._breakers[name]

    def get(self, name: str) -> Optional[CircuitBreaker]:
        """Get a circuit breaker by name."""
        return self._breakers.get(name)

    def get_all_states(self) -> Dict[str, Dict[str, Any]]:
        """Get states of all circuit breakers."""
        return {
            name: breaker.get_state()
            for name, breaker in self._breakers.items()
        }

    def reset_all(self):
        """Reset all circuit breakers."""
        for breaker in self._breakers.values():
            breaker.reset()
        logger.info("all_circuit_breakers_reset")

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all circuit breakers."""
        states = self.get_all_states()
        return {
            "total": len(states),
            "closed": sum(1 for s in states.values() if s["state"] == "closed"),
            "open": sum(1 for s in states.values() if s["state"] == "open"),
            "half_open": sum(1 for s in states.values() if s["state"] == "half_open"),
            "total_calls": sum(s["stats"]["total_calls"] for s in states.values()),
            "total_rejected": sum(s["stats"]["rejected_calls"] for s in states.values()),
            "total_failures": sum(s["stats"]["failed_calls"] for s in states.values()),
        }


# =============================================================================
# Decorator
# =============================================================================

def circuit_breaker(name: str = "default", config: Optional[CircuitBreakerConfig] = None):
    """
    Decorator that wraps a function with circuit breaker protection.
    
    Usage:
        @circuit_breaker("redis")
        async def get_from_redis(key):
            return await redis.get(key)
    
        @circuit_breaker("database", CircuitBreakerConfig(failure_threshold=3))
        def query_db(sql):
            return cursor.execute(sql)
    """
    breaker = CircuitBreaker(name, config)

    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await breaker.call(func, *args, **kwargs)

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            return breaker.call_sync(func, *args, **kwargs)

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


# Global registry
circuit_breakers = CircuitBreakerRegistry()
