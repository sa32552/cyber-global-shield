"""
Cyber Global Shield — Full-Text Search Engine
Recherche full-text sur les logs, alertes, anomalies avec Elasticsearch.
"""

import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class SearchResult(BaseModel):
    """A search result."""
    id: str
    index: str  # "logs", "alerts", "anomalies", "threat_intel"
    score: float
    source: Dict[str, Any]
    highlights: Dict[str, List[str]] = {}


class SearchResponse(BaseModel):
    """Search response with results and metadata."""
    results: List[SearchResult]
    total: int
    took_ms: int
    page: int
    page_size: int
    query: str


class SearchService:
    """
    Full-text search service.
    Supports Elasticsearch backend with ClickHouse fallback.
    """

    def __init__(self, es_client=None, clickhouse_client=None):
        self._es = es_client
        self._ch = clickhouse_client
        self._indices = {
            "logs": {
                "fields": ["src_ip", "dst_ip", "event_type", "message", "protocol"],
                "boosted_fields": ["message^3", "src_ip^2", "dst_ip^2"],
            },
            "alerts": {
                "fields": ["type", "description", "source", "status"],
                "boosted_fields": ["description^3", "type^2"],
            },
            "anomalies": {
                "fields": ["model_version", "feature_values"],
                "boosted_fields": [],
            },
            "threat_intel": {
                "fields": ["ip", "source", "threat_type", "description"],
                "boosted_fields": ["ip^3", "description^2"],
            },
        }

    async def search(
        self,
        query: str,
        indices: Optional[List[str]] = None,
        page: int = 1,
        page_size: int = 20,
        org_id: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> SearchResponse:
        """
        Search across multiple indices.
        Uses Elasticsearch if available, falls back to ClickHouse.
        """
        if indices is None:
            indices = list(self._indices.keys())

        start_time = datetime.utcnow()

        if self._es:
            results = await self._search_elasticsearch(
                query, indices, page, page_size, org_id, filters,
            )
        elif self._ch:
            results = await self._search_clickhouse(
                query, indices, page, page_size, org_id, filters,
            )
        else:
            results = SearchResponse(
                results=[],
                total=0,
                took_ms=0,
                page=page,
                page_size=page_size,
                query=query,
            )

        took_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        results.took_ms = took_ms

        return results

    async def _search_elasticsearch(
        self, query: str, indices: List[str],
        page: int, page_size: int,
        org_id: Optional[str], filters: Optional[Dict],
    ) -> SearchResponse:
        """Search using Elasticsearch."""
        must_conditions = [
            {"multi_match": {
                "query": query,
                "fields": ["*"],
                "type": "best_fields",
                "fuzziness": "AUTO",
            }}
        ]

        if org_id:
            must_conditions.append({"term": {"org_id": org_id}})

        if filters:
            for field, value in filters.items():
                must_conditions.append({"term": {field: value}})

        body = {
            "query": {
                "bool": {
                    "must": must_conditions,
                }
            },
            "from": (page - 1) * page_size,
            "size": page_size,
            "highlight": {
                "fields": {
                    "*": {"number_of_fragments": 3, "fragment_size": 150}
                }
            },
        }

        try:
            response = await self._es.search(
                index=",".join(indices),
                body=body,
            )

            hits = response["hits"]
            results = []
            for hit in hits["hits"]:
                results.append(SearchResult(
                    id=hit["_id"],
                    index=hit["_index"],
                    score=hit["_score"],
                    source=hit["_source"],
                    highlights=hit.get("highlight", {}),
                ))

            return SearchResponse(
                results=results,
                total=hits["total"]["value"],
                took_ms=response["took"],
                page=page,
                page_size=page_size,
                query=query,
            )

        except Exception as e:
            logger.error(f"Elasticsearch search error: {e}")
            return SearchResponse(
                results=[], total=0, took_ms=0,
                page=page, page_size=page_size, query=query,
            )

    async def _search_clickhouse(
        self, query: str, indices: List[str],
        page: int, page_size: int,
        org_id: Optional[str], filters: Optional[Dict],
    ) -> SearchResponse:
        """Search using ClickHouse (fallback)."""
        results = []
        total = 0

        for index in indices:
            index_results, index_total = await self._search_index_clickhouse(
                index, query, page, page_size, org_id, filters,
            )
            results.extend(index_results)
            total += index_total

        # Sort by relevance (simple match count)
        results.sort(key=lambda r: r.score, reverse=True)

        # Paginate combined results
        start = (page - 1) * page_size
        end = start + page_size
        page_results = results[start:end]

        return SearchResponse(
            results=page_results,
            total=total,
            took_ms=0,
            page=page,
            page_size=page_size,
            query=query,
        )

    async def _search_index_clickhouse(
        self, index: str, query: str,
        page: int, page_size: int,
        org_id: Optional[str], filters: Optional[Dict],
    ) -> tuple:
        """Search a single index in ClickHouse."""
        config = self._indices.get(index)
        if not config:
            return [], 0

        conditions = []
        for field in config["fields"]:
            conditions.append(f"{field} ILIKE '%{query}%'")

        where = " OR ".join(conditions)
        params = []

        if org_id:
            where = f"(org_id = '{org_id}') AND ({where})"

        if filters:
            for field, value in filters.items():
                where = f"({field} = '{value}') AND ({where})"

        # Count query
        count_query = f"SELECT COUNT(*) FROM {index} WHERE {where}"
        try:
            count_result = self._ch.execute(count_query)
            total = count_result[0][0] if count_result else 0
        except Exception as e:
            logger.error(f"ClickHouse count error for {index}: {e}")
            return [], 0

        # Data query
        offset = (page - 1) * page_size
        data_query = f"""
            SELECT *
            FROM {index}
            WHERE {where}
            ORDER BY timestamp DESC
            LIMIT {page_size} OFFSET {offset}
        """

        try:
            data_result = self._ch.execute(data_query)
            results = []
            for row in data_result:
                # Calculate simple relevance score
                score = sum(
                    1 for field in config["fields"]
                    if query.lower() in str(row).lower()
                )

                results.append(SearchResult(
                    id=str(hash(str(row))),
                    index=index,
                    score=score,
                    source={"row": list(row)},
                ))

            return results, total

        except Exception as e:
            logger.error(f"ClickHouse search error for {index}: {e}")
            return [], 0

    async def index_document(
        self, index: str, doc_id: str, document: Dict[str, Any],
    ):
        """Index a document for search."""
        if self._es:
            try:
                await self._es.index(
                    index=index,
                    id=doc_id,
                    body=document,
                    refresh="wait_for",
                )
            except Exception as e:
                logger.error(f"Elasticsearch indexing error: {e}")

    async def bulk_index(
        self, index: str, documents: List[Dict[str, Any]],
    ):
        """Bulk index documents."""
        if self._es:
            try:
                body = ""
                for doc in documents:
                    action = {"index": {"_index": index, "_id": doc.get("id")}}
                    body += json.dumps(action) + "\n"
                    body += json.dumps(doc) + "\n"

                await self._es.bulk(body=body, refresh="wait_for")
            except Exception as e:
                logger.error(f"Elasticsearch bulk indexing error: {e}")

    async def delete_index(self, index: str):
        """Delete a search index."""
        if self._es:
            try:
                await self._es.indices.delete(index=index, ignore_unavailable=True)
            except Exception as e:
                logger.error(f"Elasticsearch delete index error: {e}")


# Global search service
search_service = SearchService()
