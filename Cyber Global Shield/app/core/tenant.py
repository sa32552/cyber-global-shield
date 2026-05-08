"""
Cyber Global Shield — Multi-Tenant Isolation Layer
Assure l'isolation complète des données entre organisations (org_id).
"""

import re
from typing import Optional, List, Dict, Any
from fastapi import Request, HTTPException, Depends
from pydantic import BaseModel


class TenantContext(BaseModel):
    """Tenant context extracted from request."""
    org_id: str
    user_id: str
    role: str
    is_admin: bool = False


def extract_tenant(request: Request) -> TenantContext:
    """
    Extract tenant context from JWT token in request.
    Every request must have a valid org_id.
    """
    # Try to get from Authorization header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        try:
            import jwt
            payload = jwt.decode(
                token,
                options={"verify_signature": False},  # Will be verified by auth middleware
            )
            org_id = payload.get("org_id", "")
            user_id = payload.get("sub", "")
            role = payload.get("role", "viewer")
            is_admin = role == "admin"

            if not org_id:
                raise HTTPException(
                    status_code=403,
                    detail="Missing org_id in token",
                )

            return TenantContext(
                org_id=org_id,
                user_id=user_id,
                role=role,
                is_admin=is_admin,
            )
        except Exception as e:
            raise HTTPException(
                status_code=403,
                detail=f"Invalid token: {str(e)}",
            )

    # Fallback: try X-Org-ID header (for development)
    org_id = request.headers.get("X-Org-ID", "")
    user_id = request.headers.get("X-User-ID", "anonymous")
    role = request.headers.get("X-User-Role", "viewer")

    if not org_id:
        raise HTTPException(
            status_code=403,
            detail="Missing tenant context (org_id)",
        )

    return TenantContext(
        org_id=org_id,
        user_id=user_id,
        role=role,
        is_admin=role == "admin",
    )


def get_tenant(request: Request) -> TenantContext:
    """Dependency injection for tenant context."""
    return extract_tenant(request)


class TenantFilter:
    """
    Adds org_id filter to all database queries.
    Ensures data isolation between tenants.
    """

    def __init__(self, org_id: str):
        self.org_id = org_id

    def apply_to_query(self, query: str) -> str:
        """Add WHERE org_id = ? to any query."""
        if "WHERE" in query.upper():
            return query.replace("WHERE", f"WHERE org_id = '{self.org_id}' AND")
        else:
            return f"{query} WHERE org_id = '{self.org_id}'"

    def apply_to_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add org_id to a dictionary."""
        data["org_id"] = self.org_id
        return data

    def verify_access(self, data_org_id: str):
        """Verify that the data belongs to the tenant."""
        if data_org_id != self.org_id:
            raise HTTPException(
                status_code=403,
                detail="Access denied: data belongs to another organization",
            )


# Decorator for tenant-aware endpoints
def tenant_aware(func):
    """Decorator that ensures tenant context is available."""
    async def wrapper(*args, **kwargs):
        request = kwargs.get("request")
        if request:
            tenant = extract_tenant(request)
            kwargs["tenant"] = tenant
        return await func(*args, **kwargs)
    return wrapper


# Tenant-aware ClickHouse queries
TENANT_QUERIES = {
    "list_logs": """
        SELECT * FROM logs
        WHERE org_id = '{org_id}'
        ORDER BY timestamp DESC
        LIMIT {limit} OFFSET {offset}
    """,
    "list_alerts": """
        SELECT * FROM alerts
        WHERE org_id = '{org_id}'
        ORDER BY created_at DESC
        LIMIT {limit} OFFSET {offset}
    """,
    "list_anomalies": """
        SELECT * FROM anomalies
        WHERE org_id = '{org_id}'
        ORDER BY timestamp DESC
        LIMIT {limit} OFFSET {offset}
    """,
    "list_soar_executions": """
        SELECT * FROM soar_executions
        WHERE org_id = '{org_id}'
        ORDER BY created_at DESC
        LIMIT {limit} OFFSET {offset}
    """,
    "list_fl_rounds": """
        SELECT * FROM fl_rounds
        WHERE org_id = '{org_id}'
        ORDER BY round DESC
        LIMIT {limit} OFFSET {offset}
    """,
    "list_threat_intel": """
        SELECT * FROM threat_intel
        WHERE org_id = '{org_id}'
        ORDER BY created_at DESC
        LIMIT {limit} OFFSET {offset}
    """,
    "list_audit_log": """
        SELECT * FROM audit_log
        WHERE org_id = '{org_id}'
        ORDER BY timestamp DESC
        LIMIT {limit} OFFSET {offset}
    """,
    "count_logs": """
        SELECT COUNT(*) FROM logs WHERE org_id = '{org_id}'
    """,
    "count_alerts": """
        SELECT COUNT(*) FROM alerts WHERE org_id = '{org_id}'
    """,
    "count_anomalies": """
        SELECT COUNT(*) FROM anomalies WHERE org_id = '{org_id}'
    """,
    "stats_by_org": """
        SELECT
            org_id,
            COUNT(*) as total_logs,
            COUNT(DISTINCT src_ip) as unique_ips,
            MAX(timestamp) as last_event
        FROM logs
        WHERE org_id = '{org_id}'
        GROUP BY org_id
    """,
}
