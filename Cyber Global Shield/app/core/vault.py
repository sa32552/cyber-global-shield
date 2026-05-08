"""
╔══════════════════════════════════════════════════════════════╗
║  Cyber Global Shield — Vault Manager                        ║
║  Gestionnaire de secrets centralisé multi-cloud             ║
║  HashiCorp Vault → AWS Secrets Manager → Azure Key Vault    ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    vault = VaultManager()
    api_key = await vault.get_secret("OPENAI_API_KEY")
"""

import os
import time
import json
import structlog
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

logger = structlog.get_logger(__name__)


class SecretNotFoundError(Exception):
    """Raised when a secret is not found in any provider."""
    pass


class SecretExpiredError(Exception):
    """Raised when a cached secret has expired."""
    pass


@dataclass
class CachedSecret:
    """A cached secret with expiry."""
    value: str
    expires_at: float
    source: str = ""


class SecretProvider(ABC):
    """Abstract base class for secret providers."""

    @abstractmethod
    async def get_secret(self, key: str) -> Optional[str]:
        """Retrieve a secret by key."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the provider is healthy."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name for logging."""
        pass


class HashiCorpVaultProvider(SecretProvider):
    """HashiCorp Vault provider using hvac."""

    def __init__(self):
        self._client = None
        self._mount_point = os.getenv("VAULT_MOUNT_POINT", "secret")
        self._path = os.getenv("VAULT_PATH", "cyber-global-shield")
        self._initialized = False

    async def _ensure_client(self):
        """Lazy initialize Vault client."""
        if not self._initialized:
            try:
                import hvac
                self._client = hvac.Client(
                    url=os.getenv("VAULT_ADDR", "http://localhost:8200"),
                    token=os.getenv("VAULT_TOKEN", ""),
                )
                self._initialized = self._client.is_authenticated()
                if self._initialized:
                    logger.info("vault_authenticated", url=os.getenv("VAULT_ADDR"))
                else:
                    logger.warning("vault_auth_failed")
            except ImportError:
                logger.warning("hvac_not_installed")
                self._initialized = False

    async def get_secret(self, key: str) -> Optional[str]:
        await self._ensure_client()
        if not self._client or not self._initialized:
            return None
        try:
            secret = self._client.secrets.kv.v2.read_secret_version(
                path=f"{self._path}/{key}",
                mount_point=self._mount_point,
            )
            return secret["data"]["data"].get(key)
        except Exception as e:
            logger.debug("vault_get_failed", key=key, error=str(e))
            return None

    async def health_check(self) -> bool:
        await self._ensure_client()
        if not self._client:
            return False
        try:
            return self._client.is_authenticated()
        except Exception:
            return False

    @property
    def name(self) -> str:
        return "hashicorp_vault"


class AWSSecretsProvider(SecretProvider):
    """AWS Secrets Manager provider."""

    def __init__(self):
        self._client = None
        self._region = os.getenv("AWS_SECRETS_REGION", "us-east-1")

    async def _ensure_client(self):
        if not self._client:
            try:
                import boto3
                self._client = boto3.client(
                    "secretsmanager",
                    region_name=self._region,
                )
            except ImportError:
                logger.warning("boto3_not_installed")

    async def get_secret(self, key: str) -> Optional[str]:
        await self._ensure_client()
        if not self._client:
            return None
        try:
            response = self._client.get_secret_value(SecretId=key)
            if "SecretString" in response:
                return response["SecretString"]
            return response["SecretBinary"].decode("utf-8")
        except Exception as e:
            logger.debug("aws_secrets_get_failed", key=key, error=str(e))
            return None

    async def health_check(self) -> bool:
        await self._ensure_client()
        if not self._client:
            return False
        try:
            self._client.list_secrets(MaxResults=1)
            return True
        except Exception:
            return False

    @property
    def name(self) -> str:
        return "aws_secrets_manager"


class AzureKeyVaultProvider(SecretProvider):
    """Azure Key Vault provider."""

    def __init__(self):
        self._client = None
        self._vault_url = os.getenv("AZURE_KEY_VAULT_URL", "")

    async def _ensure_client(self):
        if not self._client and self._vault_url:
            try:
                from azure.identity import DefaultAzureCredential
                from azure.keyvault.secrets import SecretClient
                credential = DefaultAzureCredential()
                self._client = SecretClient(
                    vault_url=self._vault_url,
                    credential=credential,
                )
            except ImportError:
                logger.warning("azure_identity_not_installed")

    async def get_secret(self, key: str) -> Optional[str]:
        await self._ensure_client()
        if not self._client:
            return None
        try:
            secret = self._client.get_secret(key)
            return secret.value
        except Exception as e:
            logger.debug("azure_vault_get_failed", key=key, error=str(e))
            return None

    async def health_check(self) -> bool:
        await self._ensure_client()
        return self._client is not None

    @property
    def name(self) -> str:
        return "azure_key_vault"


class EnvFallbackProvider(SecretProvider):
    """Fallback to environment variables (development only)."""

    async def get_secret(self, key: str) -> Optional[str]:
        return os.getenv(key)

    async def health_check(self) -> bool:
        return True

    @property
    def name(self) -> str:
        return "env_fallback"


class VaultManager:
    """
    Gestionnaire de secrets centralisé avec cache et rotation automatique.
    
    Ordre de priorité des providers:
    1. HashiCorp Vault
    2. AWS Secrets Manager
    3. Azure Key Vault
    4. .env (fallback développement)
    """

    def __init__(self):
        self._cache: Dict[str, CachedSecret] = {}
        self._providers: List[SecretProvider] = []
        self._default_ttl = 3600  # 1 hour default cache TTL
        self._stats = {
            "cache_hits": 0,
            "cache_misses": 0,
            "provider_hits": 0,
            "provider_misses": 0,
            "errors": 0,
        }

        # Initialize providers in priority order
        self._init_providers()

    def _init_providers(self):
        """Initialize available secret providers."""
        if os.getenv("VAULT_ADDR"):
            self._providers.append(HashiCorpVaultProvider())
            logger.info("vault_provider_enabled")

        if os.getenv("AWS_SECRETS_REGION"):
            self._providers.append(AWSSecretsProvider())
            logger.info("aws_secrets_provider_enabled")

        if os.getenv("AZURE_KEY_VAULT_URL"):
            self._providers.append(AzureKeyVaultProvider())
            logger.info("azure_vault_provider_enabled")

        # Always add env fallback as last resort
        self._providers.append(EnvFallbackProvider())

        if len(self._providers) == 1:
            logger.warning("no_vault_provider_configured_using_env_only")

    async def get_secret(self, key: str, ttl: Optional[int] = None) -> str:
        """
        Retrieve a secret with caching.
        
        Args:
            key: Secret key to retrieve
            ttl: Cache TTL in seconds (default: 3600)
            
        Returns:
            Secret value as string
            
        Raises:
            SecretNotFoundError: If secret not found in any provider
        """
        ttl = ttl or self._default_ttl

        # Check cache first
        if key in self._cache:
            cached = self._cache[key]
            if time.time() < cached.expires_at:
                self._stats["cache_hits"] += 1
                return cached.value
            else:
                del self._cache[key]

        self._stats["cache_misses"] += 1

        # Try each provider in order
        for provider in self._providers:
            try:
                value = await provider.get_secret(key)
                if value is not None:
                    self._stats["provider_hits"] += 1
                    # Cache the result
                    self._cache[key] = CachedSecret(
                        value=value,
                        expires_at=time.time() + ttl,
                        source=provider.name,
                    )
                    logger.debug("secret_retrieved", key=key, source=provider.name)
                    return value
            except Exception as e:
                self._stats["errors"] += 1
                logger.warning(
                    "secret_provider_error",
                    key=key,
                    provider=provider.name,
                    error=str(e),
                )

        self._stats["provider_misses"] += 1
        raise SecretNotFoundError(
            f"Secret '{key}' not found in any provider. "
            f"Checked: {[p.name for p in self._providers]}"
        )

    async def set_secret(self, key: str, value: str, provider_index: int = 0):
        """
        Store a secret in the primary provider.
        
        Args:
            key: Secret key
            value: Secret value
            provider_index: Provider index (0 = primary)
        """
        if not self._providers or provider_index >= len(self._providers):
            raise SecretNotFoundError("No writable provider available")

        provider = self._providers[provider_index]
        
        # Update cache
        self._cache[key] = CachedSecret(
            value=value,
            expires_at=time.time() + self._default_ttl,
            source=provider.name,
        )

        # Store in provider (implementation varies by provider)
        if isinstance(provider, HashiCorpVaultProvider):
            await provider._ensure_client()
            if provider._client:
                provider._client.secrets.kv.v2.create_or_update_secret(
                    path=f"{provider._path}/{key}",
                    secret={key: value},
                    mount_point=provider._mount_point,
                )
        elif isinstance(provider, AWSSecretsProvider):
            await provider._ensure_client()
            if provider._client:
                provider._client.create_secret(
                    Name=key,
                    SecretString=value,
                )

        logger.info("secret_stored", key=key, provider=provider.name)

    async def rotate_secret(self, key: str, new_value: str):
        """
        Rotate a secret (update + invalidate cache).
        
        Args:
            key: Secret key to rotate
            new_value: New secret value
        """
        # Invalidate cache
        if key in self._cache:
            del self._cache[key]

        # Store new value
        await self.set_secret(key, new_value)

        logger.info("secret_rotated", key=key)

    async def delete_secret(self, key: str):
        """Delete a secret from cache and all providers."""
        # Remove from cache
        self._cache.pop(key, None)

        # Remove from providers (best effort)
        for provider in self._providers:
            try:
                if isinstance(provider, HashiCorpVaultProvider):
                    await provider._ensure_client()
                    if provider._client:
                        provider._client.secrets.kv.v2.delete_metadata_and_all_versions(
                            path=f"{provider._path}/{key}",
                            mount_point=provider._mount_point,
                        )
                elif isinstance(provider, AWSSecretsProvider):
                    await provider._ensure_client()
                    if provider._client:
                        provider._client.delete_secret(SecretId=key)
            except Exception as e:
                logger.debug("secret_delete_failed", key=key, provider=provider.name, error=str(e))

        logger.info("secret_deleted", key=key)

    async def health_check(self) -> Dict[str, Any]:
        """Check health of all providers."""
        results = {}
        for provider in self._providers:
            try:
                healthy = await provider.health_check()
                results[provider.name] = {
                    "healthy": healthy,
                    "status": "connected" if healthy else "disconnected",
                }
            except Exception as e:
                results[provider.name] = {
                    "healthy": False,
                    "status": "error",
                    "error": str(e),
                }
        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get vault manager statistics."""
        total = self._stats["cache_hits"] + self._stats["cache_misses"]
        return {
            "cache_hit_rate": round(self._stats["cache_hits"] / max(total, 1) * 100, 2),
            "cache_size": len(self._cache),
            "providers": [p.name for p in self._providers],
            "provider_hits": self._stats["provider_hits"],
            "provider_misses": self._stats["provider_misses"],
            "errors": self._stats["errors"],
        }

    async def warmup(self):
        """Pre-warm cache with critical secrets."""
        critical_keys = [
            "OPENAI_API_KEY",
            "SUPABASE_URL",
            "SUPABASE_KEY",
            "SECRET_KEY",
            "REDIS_URL",
            "KAFKA_BOOTSTRAP_SERVERS",
        ]
        for key in critical_keys:
            try:
                await self.get_secret(key, ttl=300)  # Short TTL for warmup
            except SecretNotFoundError:
                pass
        logger.info("vault_warmup_complete", keys_loaded=len(self._cache))


# Global vault manager instance
vault = VaultManager()
