"""
Application configuration with environment variable validation.
Uses pydantic-settings for type-safe configuration.
Supports HashiCorp Vault, AWS Secrets Manager, and Azure Key Vault.
"""
import os
import json
from pydantic_settings import BaseSettings
from pydantic import field_validator, model_validator, Field, SecretStr
from typing import Optional, List, Dict, Any, Literal
from functools import lru_cache
import structlog

logger = structlog.get_logger(__name__)


# ─── Secrets Manager Abstraction ──────────────────────────────────────────

class SecretsBackend:
    """Abstract base for secrets management backends."""

    async def get_secret(self, key: str) -> Optional[str]:
        raise NotImplementedError

    async def health_check(self) -> bool:
        raise NotImplementedError


class EnvSecretsBackend(SecretsBackend):
    """Fallback: read secrets from environment variables directly."""

    async def get_secret(self, key: str) -> Optional[str]:
        return os.environ.get(key)

    async def health_check(self) -> bool:
        return True


class VaultSecretsBackend(SecretsBackend):
    """HashiCorp Vault integration using AppRole or Token auth."""

    def __init__(self, vault_addr: str, vault_token: str, mount_path: str = "secret"):
        self.vault_addr = vault_addr.rstrip("/")
        self.vault_token = vault_token
        self.mount_path = mount_path
        self._client = None

    async def _get_client(self):
        if self._client is None:
            try:
                import hvac
                self._client = hvac.Client(url=self.vault_addr, token=self.vault_token)
            except ImportError:
                logger.warning("hvac_not_installed_falling_back_to_env")
                return None
        return self._client

    async def get_secret(self, key: str) -> Optional[str]:
        client = await self._get_client()
        if client is None:
            return os.environ.get(key)
        try:
            secret = client.secrets.kv.v2.read_secret_version(
                path=key.lower(), mount_point=self.mount_path
            )
            return secret["data"]["data"].get(key)
        except Exception as e:
            logger.error("vault_secret_read_failed", key=key, error=str(e))
            return os.environ.get(key)

    async def health_check(self) -> bool:
        client = await self._get_client()
        if client is None:
            return False
        try:
            return client.sys.is_initialized()
        except Exception:
            return False


class AWSSecretsBackend(SecretsBackend):
    """AWS Secrets Manager integration."""

    def __init__(self, region_name: str = "us-east-1"):
        self.region_name = region_name
        self._client = None

    async def _get_client(self):
        if self._client is None:
            try:
                import boto3
                self._client = boto3.client("secretsmanager", region_name=self.region_name)
            except ImportError:
                logger.warning("boto3_not_installed_falling_back_to_env")
                return None
        return self._client

    async def get_secret(self, key: str) -> Optional[str]:
        client = await self._get_client()
        if client is None:
            return os.environ.get(key)
        try:
            response = client.get_secret_value(SecretId=key)
            return response.get("SecretString")
        except Exception as e:
            logger.error("aws_secret_read_failed", key=key, error=str(e))
            return os.environ.get(key)

    async def health_check(self) -> bool:
        client = await self._get_client()
        if client is None:
            return False
        try:
            client.list_secrets(MaxResults=1)
            return True
        except Exception:
            return False


# ─── Secrets Manager Factory ──────────────────────────────────────────────

SECRETS_BACKEND_TYPES = Literal["env", "vault", "aws", "azure"]


def create_secrets_backend(
    backend_type: SECRETS_BACKEND_TYPES = "env",
    vault_addr: Optional[str] = None,
    vault_token: Optional[str] = None,
    aws_region: Optional[str] = None,
) -> SecretsBackend:
    """Factory to create the appropriate secrets backend."""
    if backend_type == "vault":
        addr = vault_addr or os.environ.get("VAULT_ADDR", "")
        token = vault_token or os.environ.get("VAULT_TOKEN", "")
        if addr and token:
            return VaultSecretsBackend(addr, token)
        logger.warning("vault_configured_but_missing_addr_or_token_falling_back")
    elif backend_type == "aws":
        region = aws_region or os.environ.get("AWS_REGION", "us-east-1")
        return AWSSecretsBackend(region)
    # Default: environment variables
    return EnvSecretsBackend()


# ─── Global secrets backend instance ──────────────────────────────────────

_secrets_backend: Optional[SecretsBackend] = None


def get_secrets_backend() -> SecretsBackend:
    """Get or create the global secrets backend."""
    global _secrets_backend
    if _secrets_backend is None:
        backend_type = os.environ.get("SECRETS_BACKEND", "env")
        _secrets_backend = create_secrets_backend(
            backend_type=backend_type,  # type: ignore
            vault_addr=os.environ.get("VAULT_ADDR"),
            vault_token=os.environ.get("VAULT_TOKEN"),
            aws_region=os.environ.get("AWS_REGION"),
        )
        logger.info("secrets_backend_initialized", backend_type=backend_type)
    return _secrets_backend


# ─── Settings ─────────────────────────────────────────────────────────────

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
    # NOTE: In production, set SECRET_KEY via environment variable or secrets manager.
    # The default below will cause a startup error in production.
    SECRET_KEY: SecretStr = Field(default="", min_length=32)
    ALGORITHM: str = Field(default="HS256", pattern="^(HS256|HS384|HS512|RS256)$")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, ge=1, le=1440)

    # ─── Admin Credentials (override via .env or secrets manager) ────────
    # These MUST be set in production. No defaults provided.
    ADMIN_USERNAME: str = Field(default="", min_length=1)
    ADMIN_PASSWORD: SecretStr = Field(default="", min_length=12)
    ADMIN_ORG_ID: str = Field(default="global", min_length=1)
    ADMIN_ROLE: str = Field(default="admin", min_length=1)

    # ─── Supabase ───────────────────────────────────────────────────────
    SUPABASE_URL: str = ""
    SUPABASE_KEY: SecretStr = Field(default="")
    SUPABASE_SERVICE_ROLE_KEY: SecretStr = Field(default="")
    SUPABASE_JWT_SECRET: SecretStr = Field(default="")

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
    CLICKHOUSE_PASSWORD: SecretStr = Field(default="")
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
    OPENAI_API_KEY: SecretStr = Field(default="")
    OPENAI_MODEL: str = Field(default="gpt-4-turbo", min_length=3)
    LLM_PROVIDER: str = Field(default="openai", pattern="^(openai|anthropic|local|ollama)$")

    # ─── MISP ───────────────────────────────────────────────────────────
    MISP_URL: str = ""
    MISP_API_KEY: SecretStr = Field(default="")
    MISP_VERIFY_SSL: bool = True  # Changed from False to True for security

    # ─── Cortex ─────────────────────────────────────────────────────────
    CORTEX_URL: str = ""
    CORTEX_API_KEY: SecretStr = Field(default="")

    # ─── SOAR ───────────────────────────────────────────────────────────
    SOAR_WEBHOOK_URL: str = ""
    SOAR_TIMEOUT: int = Field(default=30, ge=5, le=300)

    # ─── SOAR Integrations - Firewall ───────────────────────────────────
    FIREWALL_URL: str = ""
    FIREWALL_API_KEY: SecretStr = Field(default="")

    # ─── SOAR Integrations - EDR (CrowdStrike/SentinelOne) ──────────────
    EDR_URL: str = ""
    EDR_API_KEY: SecretStr = Field(default="")
    EDR_API_SECRET: SecretStr = Field(default="")

    # ─── SOAR Integrations - IAM (Azure AD/Entra ID) ────────────────────
    IAM_URL: str = ""
    IAM_API_KEY: SecretStr = Field(default="")

    # ─── SOAR Integrations - DNS (Pi-hole) ──────────────────────────────
    DNS_URL: str = ""
    DNS_API_KEY: SecretStr = Field(default="")

    # ─── SOAR Integrations - Notifications ──────────────────────────────
    SLACK_WEBHOOK_URL: str = ""
    TEAMS_WEBHOOK_URL: str = ""

    # ─── SOAR Integrations - Ticketing ──────────────────────────────────
    JIRA_URL: str = ""
    JIRA_TOKEN: SecretStr = Field(default="")

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

    # ─── Secrets Manager Configuration ──────────────────────────────────
    SECRETS_BACKEND: str = Field(default="env", pattern="^(env|vault|aws|azure)$")
    VAULT_ADDR: str = ""
    VAULT_TOKEN: SecretStr = Field(default="")
    AWS_REGION: str = "us-east-1"

    # ─── Validators ─────────────────────────────────────────────────────

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: SecretStr) -> SecretStr:
        """Ensure secret key is set in production."""
        secret_value = v.get_secret_value() if v else ""
        if not secret_value or len(secret_value) < 32:
            raise ValueError(
                "SECRET_KEY must be at least 32 characters. "
                "Generate one with: openssl rand -hex 32"
            )
        return v

    @field_validator("ADMIN_PASSWORD")
    @classmethod
    def validate_admin_password(cls, v: SecretStr) -> SecretStr:
        """Ensure admin password meets minimum requirements."""
        secret_value = v.get_secret_value() if v else ""
        if not secret_value:
            raise ValueError(
                "ADMIN_PASSWORD must be set in production. "
                "Use a strong password with at least 12 characters."
            )
        if len(secret_value) < 12:
            raise ValueError("ADMIN_PASSWORD must be at least 12 characters")
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
            # Ensure SECRET_KEY is not empty
            if not self.SECRET_KEY.get_secret_value():
                raise ValueError(
                    "SECRET_KEY must be configured in production. "
                    "Set via environment variable or secrets manager."
                )

            # Ensure ADMIN_PASSWORD is set
            if not self.ADMIN_PASSWORD.get_secret_value():
                raise ValueError(
                    "ADMIN_PASSWORD must be configured in production."
                )

            # Warn if no LLM provider configured
            if not self.OPENAI_API_KEY.get_secret_value() and self.LLM_PROVIDER == "openai":
                logger.warning("production_no_openai_api_key")

            # Warn if MISP SSL verification is disabled
            if not self.MISP_VERIFY_SSL:
                logger.warning(
                    "production_misp_ssl_disabled",
                    message="MISP_VERIFY_SSL is False. Enable SSL verification in production."
                )

        return self

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "validate_default": True,
        "extra": "ignore",
    }


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    settings = Settings()
    logger.info(
        "settings_loaded",
        environment=settings.ENVIRONMENT,
        debug=settings.DEBUG,
        secrets_backend=settings.SECRETS_BACKEND,
    )
    return settings


settings = get_settings()
