"""
Cyber Global Shield — SSO/SAML/OAuth Authentication
Support pour l'authentification via Google, Microsoft, Okta, GitHub.
"""

import os
import json
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/sso", tags=["sso"])


class SSOProvider(BaseModel):
    """SSO provider configuration."""
    name: str
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    scopes: list = ["openid", "email", "profile"]
    redirect_uri: str = ""
    enabled: bool = True


class SSOUser(BaseModel):
    """User info from SSO provider."""
    provider: str
    provider_id: str
    email: str
    name: str
    avatar_url: Optional[str] = None
    org_id: Optional[str] = None
    role: str = "viewer"


# SSO Provider configurations
SSO_PROVIDERS = {
    "google": SSOProvider(
        name="google",
        client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET", ""),
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        userinfo_url="https://www.googleapis.com/oauth2/v2/userinfo",
        scopes=["openid", "email", "profile"],
    ),
    "microsoft": SSOProvider(
        name="microsoft",
        client_id=os.getenv("MICROSOFT_CLIENT_ID", ""),
        client_secret=os.getenv("MICROSOFT_CLIENT_SECRET", ""),
        authorize_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
        userinfo_url="https://graph.microsoft.com/v1.0/me",
        scopes=["User.Read", "email", "openid", "profile"],
    ),
    "github": SSOProvider(
        name="github",
        client_id=os.getenv("GITHUB_CLIENT_ID", ""),
        client_secret=os.getenv("GITHUB_CLIENT_SECRET", ""),
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        userinfo_url="https://api.github.com/user",
        scopes=["read:user", "user:email"],
    ),
    "okta": SSOProvider(
        name="okta",
        client_id=os.getenv("OKTA_CLIENT_ID", ""),
        client_secret=os.getenv("OKTA_CLIENT_SECRET", ""),
        authorize_url=os.getenv("OKTA_AUTHORIZE_URL", ""),
        token_url=os.getenv("OKTA_TOKEN_URL", ""),
        userinfo_url=os.getenv("OKTA_USERINFO_URL", ""),
        scopes=["openid", "email", "profile", "groups"],
    ),
}


class SSOService:
    """
    SSO authentication service.
    Supports Google, Microsoft, GitHub, Okta, and custom SAML providers.
    """

    def __init__(self):
        self._sessions: Dict[str, Dict] = {}
        self._http_client = httpx.AsyncClient(timeout=30.0)

    def get_provider(self, name: str) -> Optional[SSOProvider]:
        """Get SSO provider configuration."""
        return SSO_PROVIDERS.get(name)

    def list_providers(self) -> list:
        """List enabled SSO providers."""
        return [
            {"name": p.name, "enabled": p.enabled and bool(p.client_id)}
            for p in SSO_PROVIDERS.values()
        ]

    def get_authorize_url(self, provider_name: str, redirect_uri: str) -> str:
        """Get the authorization URL for a provider."""
        provider = self.get_provider(provider_name)
        if not provider:
            raise HTTPException(status_code=404, detail=f"Provider {provider_name} not found")

        if not provider.client_id:
            raise HTTPException(
                status_code=501,
                detail=f"Provider {provider_name} is not configured",
            )

        params = {
            "client_id": provider.client_id,
            "redirect_uri": redirect_uri or provider.redirect_uri,
            "response_type": "code",
            "scope": " ".join(provider.scopes),
            "state": os.urandom(16).hex(),
            "access_type": "offline",
            "prompt": "consent",
        }

        # Store state for CSRF protection
        self._sessions[params["state"]] = {
            "provider": provider_name,
            "redirect_uri": redirect_uri,
            "created_at": datetime.utcnow(),
        }

        return f"{provider.authorize_url}?{urlencode(params)}"

    async def handle_callback(
        self,
        provider_name: str,
        code: str,
        state: str,
        redirect_uri: str,
    ) -> SSOUser:
        """Handle OAuth callback and get user info."""
        # Verify state
        session = self._sessions.pop(state, None)
        if not session:
            raise HTTPException(status_code=400, detail="Invalid state parameter")

        provider = self.get_provider(provider_name)
        if not provider:
            raise HTTPException(status_code=404, detail=f"Provider {provider_name} not found")

        # Exchange code for token
        token_data = {
            "client_id": provider.client_id,
            "client_secret": provider.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri or session.get("redirect_uri", ""),
        }

        try:
            # Get access token
            token_response = await self._http_client.post(
                provider.token_url,
                data=token_data,
                headers={"Accept": "application/json"},
            )
            token_response.raise_for_status()
            token_json = token_response.json()
            access_token = token_json.get("access_token")

            if not access_token:
                raise HTTPException(
                    status_code=400,
                    detail="Failed to get access token",
                )

            # Get user info
            user_response = await self._http_client.get(
                provider.userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            user_response.raise_for_status()
            user_data = user_response.json()

            # Map user data based on provider
            if provider_name == "google":
                return SSOUser(
                    provider="google",
                    provider_id=user_data.get("id"),
                    email=user_data.get("email"),
                    name=user_data.get("name"),
                    avatar_url=user_data.get("picture"),
                )
            elif provider_name == "microsoft":
                return SSOUser(
                    provider="microsoft",
                    provider_id=user_data.get("id"),
                    email=user_data.get("mail") or user_data.get("userPrincipalName"),
                    name=user_data.get("displayName"),
                )
            elif provider_name == "github":
                # Get primary email
                emails_response = await self._http_client.get(
                    "https://api.github.com/user/emails",
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                emails = emails_response.json()
                primary_email = next(
                    (e["email"] for e in emails if e.get("primary")),
                    user_data.get("email", ""),
                )

                return SSOUser(
                    provider="github",
                    provider_id=str(user_data.get("id")),
                    email=primary_email,
                    name=user_data.get("name") or user_data.get("login"),
                    avatar_url=user_data.get("avatar_url"),
                )
            elif provider_name == "okta":
                return SSOUser(
                    provider="okta",
                    provider_id=user_data.get("sub"),
                    email=user_data.get("email"),
                    name=user_data.get("name"),
                )
            else:
                return SSOUser(
                    provider=provider_name,
                    provider_id=user_data.get("sub", user_data.get("id")),
                    email=user_data.get("email", ""),
                    name=user_data.get("name", ""),
                )

        except httpx.HTTPError as e:
            logger.error(f"SSO callback error for {provider_name}: {e}")
            raise HTTPException(
                status_code=502,
                detail=f"SSO provider error: {str(e)}",
            )

    async def get_user_info(self, provider_name: str, token: str) -> SSOUser:
        """Get user info from provider using an existing token."""
        provider = self.get_provider(provider_name)
        if not provider:
            raise HTTPException(status_code=404, detail=f"Provider {provider_name} not found")

        try:
            response = await self._http_client.get(
                provider.userinfo_url,
                headers={"Authorization": f"Bearer {token}"},
            )
            response.raise_for_status()
            user_data = response.json()

            return SSOUser(
                provider=provider_name,
                provider_id=user_data.get("sub", user_data.get("id")),
                email=user_data.get("email", ""),
                name=user_data.get("name", ""),
            )
        except httpx.HTTPError as e:
            logger.error(f"SSO userinfo error: {e}")
            raise HTTPException(status_code=502, detail=str(e))


# Global SSO service
sso_service = SSOService()


# API Routes
@router.get("/providers")
async def list_providers():
    """List available SSO providers."""
    return {"providers": sso_service.list_providers()}


@router.get("/login/{provider}")
async def sso_login(provider: str, redirect_uri: str = ""):
    """Initiate SSO login."""
    authorize_url = sso_service.get_authorize_url(provider, redirect_uri)
    return RedirectResponse(url=authorize_url)


@router.get("/callback/{provider}")
async def sso_callback(
    provider: str,
    code: str = "",
    state: str = "",
    redirect_uri: str = "",
):
    """Handle SSO callback."""
    user = await sso_service.handle_callback(provider, code, state, redirect_uri)

    # Generate JWT token for the user
    from app.core.auth import create_access_token
    token = create_access_token(
        data={
            "sub": user.email,
            "provider": user.provider,
            "provider_id": user.provider_id,
            "name": user.name,
            "avatar": user.avatar_url or "",
            "org_id": user.org_id or "default",
            "role": user.role,
        },
    )

    # Redirect to frontend with token
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
    redirect = f"{frontend_url}/auth/callback?token={token}&provider={provider}"

    return RedirectResponse(url=redirect)
