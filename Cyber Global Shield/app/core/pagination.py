"""
Cyber Global Shield — Pagination Standardisée
Fournit une pagination complète et cohérente pour toutes les API.
"""

from typing import Optional, List, Dict, Any, Generic, TypeVar
from math import ceil
from fastapi import Query
from pydantic import BaseModel

T = TypeVar("T")


class PaginationParams(BaseModel):
    """Standard pagination parameters."""
    page: int = 1
    page_size: int = 50
    sort_by: Optional[str] = None
    sort_order: str = "desc"  # asc or desc
    search: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    org_id: Optional[str] = None


class PaginatedResponse(BaseModel, Generic[T]):
    """Standard paginated response."""
    items: List[T]
    total: int
    page: int
    page_size: int
    total_pages: int
    has_next: bool
    has_prev: bool
    next_page: Optional[int] = None
    prev_page: Optional[int] = None
    sort_by: Optional[str] = None
    sort_order: str = "desc"

    class Config:
        arbitrary_types_allowed = True


class Paginator:
    """
    Generic paginator for any data source.
    Supports ClickHouse, PostgreSQL, and in-memory data.
    """

    def __init__(self, page: int = 1, page_size: int = 50):
        self.page = max(1, page)
        self.page_size = min(max(1, page_size), 1000)  # Max 1000 per page
        self.offset = (self.page - 1) * self.page_size

    def paginate(self, items: List[Any], total: int) -> PaginatedResponse:
        """Paginate a list of items."""
        total_pages = max(1, ceil(total / self.page_size))

        return PaginatedResponse(
            items=items,
            total=total,
            page=self.page,
            page_size=self.page_size,
            total_pages=total_pages,
            has_next=self.page < total_pages,
            has_prev=self.page > 1,
            next_page=self.page + 1 if self.page < total_pages else None,
            prev_page=self.page - 1 if self.page > 1 else None,
        )

    def get_sql_limit_offset(self) -> str:
        """Generate SQL LIMIT/OFFSET clause."""
        return f"LIMIT {self.page_size} OFFSET {self.offset}"

    def get_clickhouse_query(self, base_query: str, count_query: str) -> tuple:
        """
        Generate paginated ClickHouse query.
        Returns (paginated_query, count_query)
        """
        paginated = f"{base_query} {self.get_sql_limit_offset()}"
        return paginated, count_query


# FastAPI dependency for pagination
async def get_pagination(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=1000, description="Items per page"),
    sort_by: Optional[str] = Query(None, description="Sort field"),
    sort_order: str = Query("desc", regex="^(asc|desc)$"),
    search: Optional[str] = Query(None, description="Search query"),
    start_date: Optional[str] = Query(None, description="Start date filter"),
    end_date: Optional[str] = Query(None, description="End date filter"),
    status: Optional[str] = Query(None, description="Status filter"),
    severity: Optional[str] = Query(None, description="Severity filter"),
) -> PaginationParams:
    """FastAPI dependency for standard pagination."""
    return PaginationParams(
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_order=sort_order,
        search=search,
        start_date=start_date,
        end_date=end_date,
        status=status,
        severity=severity,
    )


# Utility functions for common pagination patterns
def paginate_clickhouse(
    client,
    base_query: str,
    count_query: str,
    params: PaginationParams,
    tenant_filter: Optional[str] = None,
) -> PaginatedResponse:
    """
    Paginate a ClickHouse query with tenant isolation.
    """
    paginator = Paginator(params.page, params.page_size)

    # Add tenant filter if provided
    if tenant_filter:
        if "WHERE" in base_query.upper():
            base_query = base_query.replace("WHERE", f"WHERE {tenant_filter} AND")
            count_query = count_query.replace("WHERE", f"WHERE {tenant_filter} AND")
        else:
            base_query = f"{base_query} WHERE {tenant_filter}"
            count_query = f"{count_query} WHERE {tenant_filter}"

    # Add sorting
    if params.sort_by:
        safe_sort = params.sort_by.replace(";", "").replace("'", "")
        base_query = f"{base_query} ORDER BY {safe_sort} {params.sort_order}"

    # Add search filter
    if params.search and params.sort_by:
        safe_search = params.search.replace("'", "\\'")
        base_query = base_query.replace(
            "WHERE",
            f"WHERE {params.sort_by} ILIKE '%{safe_search}%' AND",
        )
        count_query = count_query.replace(
            "WHERE",
            f"WHERE {params.sort_by} ILIKE '%{safe_search}%' AND",
        )

    # Add date filters
    if params.start_date:
        date_filter = f"timestamp >= '{params.start_date}'"
        if "WHERE" in base_query.upper():
            base_query = base_query.replace("WHERE", f"WHERE {date_filter} AND")
            count_query = count_query.replace("WHERE", f"WHERE {date_filter} AND")
        else:
            base_query = f"{base_query} WHERE {date_filter}"
            count_query = f"{count_query} WHERE {date_filter}"

    if params.end_date:
        date_filter = f"timestamp <= '{params.end_date}'"
        if "WHERE" in base_query.upper():
            base_query = base_query.replace("WHERE", f"WHERE {date_filter} AND")
            count_query = count_query.replace("WHERE", f"WHERE {date_filter} AND")
        else:
            base_query = f"{base_query} WHERE {date_filter}"
            count_query = f"{count_query} WHERE {date_filter}"

    # Execute count
    total = client.execute(count_query)[0][0]

    # Execute paginated query
    paginated_query = f"{base_query} {paginator.get_sql_limit_offset()}"
    items = client.execute(paginated_query)

    return paginator.paginate(items, total)


def paginate_in_memory(
    items: List[Any],
    params: PaginationParams,
) -> PaginatedResponse:
    """
    Paginate an in-memory list.
    """
    paginator = Paginator(params.page, params.page_size)
    total = len(items)

    # Apply sorting
    if params.sort_by:
        reverse = params.sort_order == "desc"
        items.sort(key=lambda x: getattr(x, params.sort_by, ""), reverse=reverse)

    # Apply slicing
    start = paginator.offset
    end = start + paginator.page_size
    page_items = items[start:end]

    return paginator.paginate(page_items, total)
