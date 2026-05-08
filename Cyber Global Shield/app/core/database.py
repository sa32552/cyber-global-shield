"""
Database module: async SQLAlchemy engine with retry logic and health checks.
"""
from typing import AsyncGenerator, Optional, Dict, Any
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)
import structlog

from app.core.config import settings

logger = structlog.get_logger(__name__)

# Supabase uses PostgreSQL under the hood
DATABASE_URL = (
    settings.SUPABASE_URL.replace("https://", "postgresql+asyncpg://")
    if settings.SUPABASE_URL
    else "sqlite+aiosqlite:///./cyber_shield.db"
)

engine = create_async_engine(
    DATABASE_URL,
    echo=settings.DEBUG,
    pool_size=50,
    max_overflow=25,
    pool_pre_ping=True,
    pool_recycle=3600,
    pool_use_lifo=True,  # LIFO for better connection reuse
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    pass


# ─── Retry configuration ────────────────────────────────────────────────

# Retry on connection-level errors (operational errors, timeouts)
DB_RETRY_ATTEMPTS = 3
DB_RETRY_MIN_WAIT = 1.0  # seconds
DB_RETRY_MAX_WAIT = 10.0  # seconds


def is_retryable_error(exception: Exception) -> bool:
    """Determine if a database error is retryable."""
    error_msg = str(exception).lower()
    retryable_patterns = [
        "connection refused",
        "connection reset",
        "timeout",
        "deadlock",
        "could not connect",
        "server closed connection",
        "database is locked",  # SQLite specific
        "database connection",
        "operationalerror",
        "interfaceerror",
    ]
    return any(pattern in error_msg for pattern in retryable_patterns)


# ─── Database initialization ────────────────────────────────────────────

@retry(
    stop=stop_after_attempt(DB_RETRY_ATTEMPTS),
    wait=wait_exponential(multiplier=DB_RETRY_MIN_WAIT, max=DB_RETRY_MAX_WAIT),
    retry=retry_if_exception_type(Exception),
    before_sleep=before_sleep_log(logger, structlog.get_log_level()),
    reraise=True,
)
async def init_db():
    """Initialize database tables with retry logic."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("database_initialized", url=DATABASE_URL.split("@")[-1] if "@" in DATABASE_URL else "local")


# ─── Session management ─────────────────────────────────────────────────

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Get a database session with automatic commit/rollback.
    Usage:
        async with get_db() as session:
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ─── Health check ───────────────────────────────────────────────────────

@retry(
    stop=stop_after_attempt(2),
    wait=wait_exponential(multiplier=0.5, max=2.0),
    retry=retry_if_exception_type(Exception),
    reraise=False,
)
async def check_db_health() -> Dict[str, Any]:
    """
    Detailed database health check.
    Returns a dict with status, latency, and pool stats.
    """
    import time
    start = time.time()

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(text("SELECT 1"))
            latency_ms = (time.time() - start) * 1000

            # Get pool status
            pool = engine.pool
            pool_status = {
                "size": pool.size(),
                "checked_in": pool.checkedin(),
                "checked_out": pool.checkedout(),
                "overflow": pool.overflow(),
            }

            return {
                "status": "healthy",
                "latency_ms": round(latency_ms, 2),
                "pool": pool_status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
    except Exception as e:
        latency_ms = (time.time() - start) * 1000
        logger.error("db_health_check_failed", error=str(e), latency_ms=latency_ms)
        return {
            "status": "unhealthy",
            "error": str(e),
            "latency_ms": round(latency_ms, 2),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# ─── Utility: execute with retry ────────────────────────────────────────

async def execute_with_retry(
    stmt,
    params: Optional[Dict[str, Any]] = None,
    max_attempts: int = DB_RETRY_ATTEMPTS,
) -> Any:
    """
    Execute a SQL statement with automatic retry on transient errors.
    Usage:
        result = await execute_with_retry(
            text("SELECT * FROM logs WHERE id = :id"),
            {"id": log_id},
        )
    """
    last_error = None
    for attempt in range(1, max_attempts + 1):
        try:
            async with AsyncSessionLocal() as session:
                if params:
                    result = await session.execute(stmt, params)
                else:
                    result = await session.execute(stmt)
                await session.commit()
                return result
        except Exception as e:
            last_error = e
            if attempt < max_attempts and is_retryable_error(e):
                wait_time = DB_RETRY_MIN_WAIT * (2 ** (attempt - 1))
                logger.warning(
                    "db_retry_attempt",
                    attempt=attempt,
                    max_attempts=max_attempts,
                    wait_seconds=wait_time,
                    error=str(e),
                )
                import asyncio
                await asyncio.sleep(min(wait_time, DB_RETRY_MAX_WAIT))
            else:
                raise

    raise last_error  # Should not reach here
