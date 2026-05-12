"""
Cyber Global Shield — Supabase Client Module
Centralized Supabase client for Admin API operations (user management, DB queries).
Uses service_role key for backend-to-Supabase operations.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

import structlog
from supabase import create_client, Client as SupabaseClient
from postgrest import APIError

from app.core.config import settings

logger = structlog.get_logger(__name__)


class SupabaseManager:
    """
    Manages Supabase Admin client for backend operations.
    Uses SERVICE_ROLE_KEY for privileged operations (user creation, RLS bypass).
    """

    def __init__(self):
        self._client: Optional[SupabaseClient] = None
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the Supabase client with service role key."""
        if self._initialized:
            return

        supabase_url = settings.SUPABASE_URL
        service_key = settings.SUPABASE_SERVICE_ROLE_KEY.get_secret_value() if settings.SUPABASE_SERVICE_ROLE_KEY else ""

        if not supabase_url or not service_key:
            logger.warning(
                "supabase_not_configured",
                message="SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not set. "
                        "Supabase features will be unavailable.",
            )
            self._initialized = False
            return

        try:
            self._client = create_client(supabase_url, service_key)
            self._initialized = True
            logger.info("supabase_client_initialized", url=supabase_url)
        except Exception as e:
            logger.error("supabase_client_init_failed", error=str(e))
            self._initialized = False

    @property
    def client(self) -> Optional[SupabaseClient]:
        """Get the Supabase client instance."""
        return self._client

    @property
    def is_ready(self) -> bool:
        """Check if Supabase client is initialized."""
        return self._initialized and self._client is not None

    # ─── User Management ────────────────────────────────────────────────

    async def create_user(
        self,
        email: str,
        password: str,
        user_metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Create a new user via Supabase Auth Admin API."""
        if not self.is_ready:
            logger.error("supabase_not_ready")
            return None

        try:
            result = self._client.auth.admin.create_user({
                "email": email,
                "password": password,
                "email_confirm": True,
                "user_metadata": user_metadata or {},
            })
            logger.info("supabase_user_created", email=email)
            return result.user.dict() if hasattr(result, "user") else result
        except APIError as e:
            logger.error("supabase_user_create_failed", email=email, error=str(e))
            return None

    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user details by ID."""
        if not self.is_ready:
            return None

        try:
            result = self._client.auth.admin.get_user_by_id(user_id)
            return result.user.dict() if hasattr(result, "user") else result
        except APIError as e:
            logger.error("supabase_user_get_failed", user_id=user_id, error=str(e))
            return None

    async def list_users(self) -> List[Dict[str, Any]]:
        """List all users (paginated)."""
        if not self.is_ready:
            return []

        try:
            result = self._client.auth.admin.list_users()
            users = result.users if hasattr(result, "users") else []
            return [u.dict() if hasattr(u, "dict") else u for u in users]
        except APIError as e:
            logger.error("supabase_users_list_failed", error=str(e))
            return []

    async def delete_user(self, user_id: str) -> bool:
        """Delete a user by ID."""
        if not self.is_ready:
            return False

        try:
            self._client.auth.admin.delete_user(user_id)
            logger.info("supabase_user_deleted", user_id=user_id)
            return True
        except APIError as e:
            logger.error("supabase_user_delete_failed", user_id=user_id, error=str(e))
            return False

    # ─── Organization Management ─────────────────────────────────────────

    async def create_organization(
        self, name: str, slug: str, tier: str = "free"
    ) -> Optional[Dict[str, Any]]:
        """Create a new organization."""
        if not self.is_ready:
            return None

        try:
            result = (
                self._client.table("organizations")
                .insert({
                    "name": name,
                    "slug": slug,
                    "tier": tier,
                    "settings": {},
                })
                .execute()
            )
            org = result.data[0] if result.data else None
            logger.info("organization_created", name=name, slug=slug)
            return org
        except APIError as e:
            logger.error("organization_create_failed", name=name, error=str(e))
            return None

    async def get_organization(self, org_id: str) -> Optional[Dict[str, Any]]:
        """Get organization by ID."""
        if not self.is_ready:
            return None

        try:
            result = (
                self._client.table("organizations")
                .select("*")
                .eq("id", org_id)
                .execute()
            )
            return result.data[0] if result.data else None
        except APIError as e:
            logger.error("organization_get_failed", org_id=org_id, error=str(e))
            return None

    async def get_organization_by_slug(self, slug: str) -> Optional[Dict[str, Any]]:
        """Get organization by slug."""
        if not self.is_ready:
            return None

        try:
            result = (
                self._client.table("organizations")
                .select("*")
                .eq("slug", slug)
                .execute()
            )
            return result.data[0] if result.data else None
        except APIError as e:
            logger.error("organization_get_by_slug_failed", slug=slug, error=str(e))
            return None

    # ─── Profile Management ─────────────────────────────────────────────

    async def create_profile(
        self,
        user_id: str,
        org_id: str,
        full_name: str = "",
        role: str = "analyst",
        permissions: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Create a user profile linked to an organization."""
        if not self.is_ready:
            return None

        try:
            result = (
                self._client.table("profiles")
                .insert({
                    "id": user_id,
                    "org_id": org_id,
                    "full_name": full_name,
                    "role": role,
                    "permissions": permissions or [],
                    "is_active": True,
                })
                .execute()
            )
            profile = result.data[0] if result.data else None
            logger.info("profile_created", user_id=user_id, org_id=org_id, role=role)
            return profile
        except APIError as e:
            logger.error("profile_create_failed", user_id=user_id, error=str(e))
            return None

    async def get_profile(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user profile by user ID."""
        if not self.is_ready:
            return None

        try:
            result = (
                self._client.table("profiles")
                .select("*, organizations(*)")
                .eq("id", user_id)
                .execute()
            )
            return result.data[0] if result.data else None
        except APIError as e:
            logger.error("profile_get_failed", user_id=user_id, error=str(e))
            return None

    async def update_profile(
        self,
        user_id: str,
        updates: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Update user profile."""
        if not self.is_ready:
            return None

        try:
            updates["updated_at"] = datetime.now(timezone.utc).isoformat()
            result = (
                self._client.table("profiles")
                .update(updates)
                .eq("id", user_id)
                .execute()
            )
            return result.data[0] if result.data else None
        except APIError as e:
            logger.error("profile_update_failed", user_id=user_id, error=str(e))
            return None

    # ─── API Key Management ─────────────────────────────────────────────

    async def store_api_key(
        self,
        key_hash: str,
        user_id: str,
        org_id: str,
        expires_at: Optional[str] = None,
    ) -> bool:
        """Store an API key hash."""
        if not self.is_ready:
            return False

        try:
            self._client.table("api_keys").insert({
                "key_hash": key_hash,
                "user_id": user_id,
                "org_id": org_id,
                "expires_at": expires_at,
            }).execute()
            return True
        except APIError as e:
            logger.error("api_key_store_failed", error=str(e))
            return False

    async def verify_api_key(self, key_hash: str) -> Optional[Dict[str, Any]]:
        """Verify and return API key details."""
        if not self.is_ready:
            return None

        try:
            result = (
                self._client.table("api_keys")
                .select("*, profiles(*)")
                .eq("key_hash", key_hash)
                .gte("expires_at", datetime.now(timezone.utc).isoformat())
                .execute()
            )
            return result.data[0] if result.data else None
        except APIError as e:
            logger.error("api_key_verify_failed", error=str(e))
            return None

    # ─── Health Check ───────────────────────────────────────────────────

    async def health_check(self) -> Dict[str, Any]:
        """Check Supabase connectivity."""
        if not self.is_ready:
            return {"status": "unavailable", "error": "Supabase not configured"}

        try:
            # Simple query to verify connectivity
            result = self._client.table("organizations").select("count", count="exact").limit(1).execute()
            return {
                "status": "healthy",
                "url": settings.SUPABASE_URL,
                "org_count": result.count if hasattr(result, "count") else None,
            }
        except APIError as e:
            return {"status": "unhealthy", "error": str(e)}


# Global singleton
supabase_manager = SupabaseManager()


async def get_supabase() -> SupabaseManager:
    """Dependency: get Supabase manager instance."""
    if not supabase_manager.is_ready:
        await supabase_manager.initialize()
    return supabase_manager
