"""
Application configuration with environment variable validation.
Uses pydantic-settings for type-safe configuration.
"""
from pydantic_settings import BaseSettings
from pydantic import field_validator, model_validator, Field
from typing import Optional, List, Dict, Any
from functools import lru_cache
import re
import structlog

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    # ─── Application ────────────────────────────────────────────────────
    APP_NAME: str = "Cyber Global Shield"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = Field(default="production", pattern="^(development|staging|production)$")

    # ─── Server ─────────────────────────────────────────────────────────
    HOST: str = Field(default="0.0.0.0", pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^localhost$")
    PORT: int = Field(default=8000, ge=1024, le=65535)
    WORKERS: int = Field(default=4, ge=1, le=32)

    # ─── Security ───────────────────────────────────────────────────────
    SECRET_KEY: str = Field(default="change-me-in-production-use-aws-secrets", min_length=16)
    ALGORITHM: str = Field(default="HS256", pattern="^(HS256|HS384|HS512|RS256)$")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, ge=1, le=1440)

    # ─── Admin Credentials (override via .env) ──────────────────────────
    ADMIN_USERNAME: str = Field(default="admin", min_length=1)
    ADMIN_PASSWORD: str = Field(default="cybershield2024", min_length=8)
    ADMIN_ORG_ID: str = Field(default="global", min_length=1)
    ADMIN_ROLE: str = Field(default="admin", min_length=1)

    # ─── Supabase ───────────────────────────────────────────────────────
    SUPABASE_URL: str = ""
    SUPABASE_KEY: str = ""
    SUPABASE_JWT_SECRET: str = ""

    # ─── Redis ──────────────────────────────────────────────────────────
    REDIS_URL: str = Field(default="redis://localhost:6379/0", pattern=r"^redis://")
    REDIS_MAX_CONNECTIONS: int = Field(default=100, ge=1, le=1000)

    # ─── Kafka ──────────────────────────────────────────────────────────
    KAFKA_BOOTSTRAP_SERVERS: str = Field(default="localhost:9092", min_length=3)
    KAFKA_TOPIC_LOGS: str = Field(default="raw_logs", min_length=1)
    KAFKA_TOPIC_ALERTS: str = Field(default="alerts", min_length=1)
    KAFKA_TOPIC_THREATS: str = Field(default="threats", min_length=1)
    KAFKA_CONSUMER_GROUP: str = Field(default="cyber-global-shield", min_length=1)

    # ─── ClickHouse ─────────────────────────────────────────────────────
    CLICKHOUSE_HOST: str = Field(default="localhost", min_length=1)
    CLICKHOUSE_PORT: int = Field(default=8123, ge=1, le=65535)
    CLICKHOUSE_USER: str = Field(default="default", min_length=1)
    CLICKHOUSE_PASSWORD: str = ""
    CLICKHOUSE_DATABASE: str = Field(default="cyber_shield", min_length=1)

    # ─── Ray ────────────────────────────────────────────────────────────
    RAY_ADDRESS: str = Field(default="auto", pattern=r"^(auto|ray://|localhost)")
    RAY_NAMESPACE: str = "cyber_shield"
    RAY_NUM_CPUS: int = Field(default=4, ge=1, le=256)
    RAY_NUM_GPUS: int = Field(default=0, ge=0, le=64)

    # ─── Flower (Federated Learning) ────────────────────────────────────
    FLOWER_SERVER_ADDRESS: str = Field(default="0.0.0.0:8080", min_length=5)
    FLOWER_NUM_ROUNDS: int = Field(default=10, ge=1, le=1000)
    FLOWER_MIN_CLIENTS: int = Field(default=2, ge=1, le=100)

    # ─── CrewAI Agents ──────────────────────────────────────────────────
    CREWAI_MODEL: str = Field(default="gpt-4-turbo", min_length=3)
    CREWAI_TEMPERATURE: float = Field(default=0.1, ge=0.0, le=2.0)
    CREWAI_MAX_TOKENS: int = Field(default=4096, ge=256, le=128000)

    # ─── OpenAI / LLM ───────────────────────────────────────────────────
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = Field(default="gpt-4-turbo", min_length=3)
    LLM_PROVIDER: str = Field(default="openai", pattern="^(openai|anthropic|local)$")

    # ─── MISP ───────────────────────────────────────────────────────────
    MISP_URL: str = ""
    MISP_API_KEY: str = ""
    MISP_VERIFY_SSL: bool = False

    # ─── Cortex ─────────────────────────────────────────────────────────
    CORTEX_URL: str = ""
    CORTEX_API_KEY: str = ""

    # ─── SOAR ───────────────────────────────────────────────────────────
    SOAR_WEBHOOK_URL: str = ""
    SOAR_TIMEOUT: int = Field(default=30, ge=5, le=300)

    # ─── SOAR Integrations - Firewall ───────────────────────────────────
    FIREWALL_URL: str = ""
    FIREWALL_API_KEY: str = ""

    # ─── SOAR Integrations - EDR (CrowdStrike/SentinelOne) ──────────────
    EDR_URL: str = ""
    EDR_API_KEY: str = ""
    EDR_API_SECRET: str = ""

    # ─── SOAR Integrations - IAM (Azure AD/Entra ID) ────────────────────
    IAM_URL: str = ""
    IAM_API_KEY: str = ""

    # ─── SOAR Integrations - DNS (Pi-hole) ──────────────────────────────
    DNS_URL: str = ""
    DNS_API_KEY: str = ""

    # ─── SOAR Integrations - Notifications ──────────────────────────────
    SLACK_WEBHOOK_URL: str = ""
    TEAMS_WEBHOOK_URL: str = ""

    # ─── SOAR Integrations - Ticketing ──────────────────────────────────
    JIRA_URL: str = ""
    JIRA_TOKEN: str = ""

    # ─── Observability ──────────────────────────────────────────────────
    PROMETHEUS_PORT: int = Field(default=9090, ge=1024, le=65535)
    OTEL_EXPORTER_ENDPOINT: str = ""

    # ─── Rate Limiting ──────────────────────────────────────────────────
    RATE_LIMIT_PER_SECOND: int = Field(default=10000, ge=1, le=1000000)
    RATE_LIMIT_BURST: int = Field(default=50000, ge=1, le=2000000)

    # ─── Alerting Thresholds ────────────────────────────────────────────
    ANOMALY_THRESHOLD: float = Field(default=0.95, ge=0.0, le=1.0)
    THREAT_SCORE_THRESHOLD: float = Field(default=0.7, ge=0.0, le=1.0)
    MAX_ALERTS_PER_SECOND: int = Field(default=1000, ge=1, le=100000)

    # ─── Validators ─────────────────────────────────────────────────────

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """Warn if using default secret key in production."""
        if v == "change-me-in-production-use-aws-secrets":
            logger.warning("using_default_secret_key", environment=cls.ENVIRONMENT if hasattr(cls, 'ENVIRONMENT') else "unknown")
        return v

    @field_validator("SUPABASE_URL")
    @classmethod
    def validate_supabase_url(cls, v: str) -> str:
        """Validate Supabase URL format if provided."""
        if v and not v.startswith("https://"):
            raise ValueError("SUPABASE_URL must start with https://")
        return v

    @field_validator("KAFKA_BOOTSTRAP_SERVERS")
    @classmethod
    def validate_kafka_servers(cls, v: str) -> str:
        """Validate Kafka bootstrap servers format."""
        servers = v.split(",")
        for server in servers:
            server = server.strip()
            if ":" not in server:
                raise ValueError(f"Kafka server '{server}' must include port (e.g., localhost:9092)")
            host, port = server.rsplit(":", 1)
            if not port.isdigit() or not (1 <= int(port) <= 65535):
                raise ValueError(f"Invalid port in Kafka server '{server}'")
        return v

    @field_validator("REDIS_URL")
    @classmethod
    def validate_redis_url(cls, v: str) -> str:
        """Validate Redis URL format."""
        if v and not v.startswith("redis://") and not v.startswith("rediss://"):
            raise ValueError("REDIS_URL must start with redis:// or rediss://")
        return v

    @field_validator("CLICKHOUSE_PORT")
    @classmethod
    def validate_clickhouse_port(cls, v: int) -> int:
        """Validate ClickHouse port (HTTP: 8123, Native: 9000)."""
        if v not in (8123, 9000, 8443, 9440):
            logger.warning("non_standard_clickhouse_port", port=v)
        return v

    @model_validator(mode="after")
    def validate_production_settings(self) -> "Settings":
        """Cross-field validation for production environment."""
        if self.ENVIRONMENT == "production":
            # Warn if using default secret key
            if self.SECRET_KEY == "change-me-in-production-use-aws-secrets":
                logger.warning("production_with_default_secret_key")

            # Warn if no LLM provider configured
            if not self.OPENAI_API_KEY and self.LLM_PROVIDER == "openai":
                logger.warning("production_no_openai_api_key")

        return self

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "validate_default": True,
        "extra": "ignore",  # Ignore extra env vars
    }


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    settings = Settings()
    logger.info(
        "settings_loaded",
        environment=settings.ENVIRONMENT,
        debug=settings.DEBUG,
    )
    return settings


settings = get_settings()
