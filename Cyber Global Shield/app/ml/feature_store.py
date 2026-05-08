"""
Cyber Global Shield — Feature Store
Stockage et gestion centralisés des features ML avec cache Redis.
Évite de recalculer les features à chaque entraînement.
"""

import json
import hashlib
import logging
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from pydantic import BaseModel
import numpy as np

logger = logging.getLogger(__name__)


class FeatureDefinition(BaseModel):
    """Definition of a feature."""
    name: str
    description: str
    data_type: str  # "float", "int", "categorical", "timestamp"
    source: str  # "log", "alert", "threat_intel", "derived"
    aggregation: Optional[str] = None  # "count", "avg", "max", "min", "std"
    window: Optional[str] = None  # "1h", "24h", "7d"
    nullable: bool = False
    default_value: Any = 0.0


class FeatureGroup(BaseModel):
    """Group of related features."""
    name: str
    description: str
    features: List[FeatureDefinition]
    version: str = "1.0.0"
    created_at: datetime = datetime.utcnow()


class FeatureStore:
    """
    Centralized feature store with Redis caching.
    Features are computed once and cached for reuse.
    """

    def __init__(self, redis_client=None):
        self._redis = redis_client
        self._feature_groups: Dict[str, FeatureGroup] = {}
        self._cache_ttl = 3600  # 1 hour default cache
        self._local_cache: Dict[str, np.ndarray] = {}

        # Register default feature groups
        self._register_default_groups()

    def _register_default_groups(self):
        """Register default feature groups for network security."""
        network_features = FeatureGroup(
            name="network_traffic",
            description="Network traffic features from logs",
            features=[
                FeatureDefinition(
                    name="bytes_sent", description="Bytes sent",
                    data_type="int", source="log", aggregation="sum", window="1h",
                ),
                FeatureDefinition(
                    name="bytes_received", description="Bytes received",
                    data_type="int", source="log", aggregation="sum", window="1h",
                ),
                FeatureDefinition(
                    name="packet_count", description="Number of packets",
                    data_type="int", source="log", aggregation="count", window="1h",
                ),
                FeatureDefinition(
                    name="unique_dst_ips", description="Unique destination IPs",
                    data_type="int", source="log", aggregation="count", window="1h",
                ),
                FeatureDefinition(
                    name="unique_ports", description="Unique ports contacted",
                    data_type="int", source="log", aggregation="count", window="1h",
                ),
                FeatureDefinition(
                    name="connection_duration_avg", description="Average connection duration",
                    data_type="float", source="log", aggregation="avg", window="1h",
                ),
                FeatureDefinition(
                    name="connection_duration_std", description="Std dev of connection duration",
                    data_type="float", source="log", aggregation="std", window="1h",
                ),
                FeatureDefinition(
                    name="failed_connections", description="Failed connection count",
                    data_type="int", source="log", aggregation="count", window="1h",
                ),
                FeatureDefinition(
                    name="bytes_per_second", description="Bytes per second throughput",
                    data_type="float", source="derived", aggregation="avg", window="1h",
                ),
                FeatureDefinition(
                    name="packets_per_connection", description="Average packets per connection",
                    data_type="float", source="derived", aggregation="avg", window="1h",
                ),
            ],
        )

        alert_features = FeatureGroup(
            name="alert_history",
            description="Alert history features",
            features=[
                FeatureDefinition(
                    name="alert_count", description="Number of alerts",
                    data_type="int", source="alert", aggregation="count", window="24h",
                ),
                FeatureDefinition(
                    name="critical_alert_count", description="Critical alert count",
                    data_type="int", source="alert", aggregation="count", window="24h",
                ),
                FeatureDefinition(
                    name="unique_alert_types", description="Unique alert types",
                    data_type="int", source="alert", aggregation="count", window="24h",
                ),
                FeatureDefinition(
                    name="alert_severity_avg", description="Average alert severity",
                    data_type="float", source="alert", aggregation="avg", window="24h",
                ),
                FeatureDefinition(
                    name="time_since_last_alert", description="Seconds since last alert",
                    data_type="float", source="alert", aggregation="max", window="24h",
                ),
            ],
        )

        threat_intel_features = FeatureGroup(
            name="threat_intel",
            description="Threat intelligence features",
            features=[
                FeatureDefinition(
                    name="threat_score", description="Threat intelligence score",
                    data_type="float", source="threat_intel", aggregation="max", window="24h",
                ),
                FeatureDefinition(
                    name="known_malicious_ips", description="Known malicious IPs count",
                    data_type="int", source="threat_intel", aggregation="count", window="24h",
                ),
                FeatureDefinition(
                    name="reputation_score", description="IP reputation score",
                    data_type="float", source="threat_intel", aggregation="avg", window="24h",
                ),
            ],
        )

        self.register_group(network_features)
        self.register_group(alert_features)
        self.register_group(threat_intel_features)

    def register_group(self, group: FeatureGroup):
        """Register a feature group."""
        self._feature_groups[group.name] = group
        logger.info(f"Feature group registered: {group.name} (v{group.version})")

    def get_group(self, name: str) -> Optional[FeatureGroup]:
        """Get a feature group by name."""
        return self._feature_groups.get(name)

    def list_groups(self) -> List[str]:
        """List all registered feature groups."""
        return list(self._feature_groups.keys())

    def get_all_features(self) -> List[FeatureDefinition]:
        """Get all features from all groups."""
        features = []
        for group in self._feature_groups.values():
            features.extend(group.features)
        return features

    def get_feature_names(self) -> List[str]:
        """Get all feature names."""
        return [f.name for f in self.get_all_features()]

    def get_feature_dimension(self) -> int:
        """Get total feature dimension."""
        return len(self.get_all_features())

    def _make_cache_key(self, org_id: str, group_name: str) -> str:
        """Generate cache key for a feature group."""
        return f"features:{org_id}:{group_name}"

    async def compute_features(
        self,
        org_id: str,
        group_name: str,
        clickhouse_client=None,
        force_recompute: bool = False,
    ) -> Optional[np.ndarray]:
        """
        Compute features for an organization.
        Returns cached features if available.
        """
        cache_key = self._make_cache_key(org_id, group_name)

        # Check Redis cache
        if not force_recompute and self._redis:
            cached = await self._redis.get(cache_key)
            if cached:
                data = json.loads(cached)
                return np.array(data["features"])

        # Check local cache
        if not force_recompute and cache_key in self._local_cache:
            return self._local_cache[cache_key]

        # Compute features from ClickHouse
        if clickhouse_client:
            features = await self._compute_from_clickhouse(
                org_id, group_name, clickhouse_client,
            )
        else:
            # Return default features
            group = self.get_group(group_name)
            if not group:
                return None
            features = np.zeros(len(group.features))

        # Cache the result
        if self._redis:
            await self._redis.setex(
                cache_key,
                self._cache_ttl,
                json.dumps({"features": features.tolist()}),
            )
        self._local_cache[cache_key] = features

        return features

    async def _compute_from_clickhouse(
        self,
        org_id: str,
        group_name: str,
        client,
    ) -> np.ndarray:
        """Compute features from ClickHouse data."""
        group = self.get_group(group_name)
        if not group:
            return np.array([])

        feature_values = []

        for feature in group.features:
            try:
                if feature.source == "log":
                    value = await self._compute_log_feature(
                        org_id, feature, client,
                    )
                elif feature.source == "alert":
                    value = await self._compute_alert_feature(
                        org_id, feature, client,
                    )
                elif feature.source == "threat_intel":
                    value = await self._compute_threat_intel_feature(
                        org_id, feature, client,
                    )
                else:
                    value = feature.default_value

                feature_values.append(float(value))
            except Exception as e:
                logger.warning(f"Feature computation failed: {feature.name}: {e}")
                feature_values.append(feature.default_value)

        return np.array(feature_values)

    async def _compute_log_feature(
        self, org_id: str, feature: FeatureDefinition, client,
    ) -> float:
        """Compute a feature from log data."""
        window_hours = 1
        if feature.window:
            window_hours = int(feature.window.replace("h", "").replace("d", ""))

        queries = {
            ("bytes_sent", "sum"): f"""
                SELECT COALESCE(SUM(bytes_sent), 0)
                FROM logs
                WHERE org_id = '{org_id}'
                AND timestamp > NOW() - INTERVAL {window_hours} HOUR
            """,
            ("bytes_received", "sum"): f"""
                SELECT COALESCE(SUM(bytes_received), 0)
                FROM logs
                WHERE org_id = '{org_id}'
                AND timestamp > NOW() - INTERVAL {window_hours} HOUR
            """,
            ("packet_count", "count"): f"""
                SELECT COUNT(*)
                FROM logs
                WHERE org_id = '{org_id}'
                AND timestamp > NOW() - INTERVAL {window_hours} HOUR
            """,
            ("unique_dst_ips", "count"): f"""
                SELECT COUNT(DISTINCT dst_ip)
                FROM logs
                WHERE org_id = '{org_id}'
                AND timestamp > NOW() - INTERVAL {window_hours} HOUR
            """,
            ("unique_ports", "count"): f"""
                SELECT COUNT(DISTINCT port)
                FROM logs
                WHERE org_id = '{org_id}'
                AND timestamp > NOW() - INTERVAL {window_hours} HOUR
            """,
            ("failed_connections", "count"): f"""
                SELECT COUNT(*)
                FROM logs
                WHERE org_id = '{org_id}'
                AND action = 'block'
                AND timestamp > NOW() - INTERVAL {window_hours} HOUR
            """,
        }

        query_key = (feature.name, feature.aggregation)
        query = queries.get(query_key)
        if query:
            result = client.execute(query)
            return float(result[0][0]) if result else 0.0

        return feature.default_value

    async def _compute_alert_feature(
        self, org_id: str, feature: FeatureDefinition, client,
    ) -> float:
        """Compute a feature from alert data."""
        window_hours = 24
        if feature.window:
            window_hours = int(feature.window.replace("h", "").replace("d", ""))

        queries = {
            ("alert_count", "count"): f"""
                SELECT COUNT(*)
                FROM alerts
                WHERE org_id = '{org_id}'
                AND created_at > NOW() - INTERVAL {window_hours} HOUR
            """,
            ("critical_alert_count", "count"): f"""
                SELECT COUNT(*)
                FROM alerts
                WHERE org_id = '{org_id}'
                AND severity = 'critical'
                AND created_at > NOW() - INTERVAL {window_hours} HOUR
            """,
        }

        query_key = (feature.name, feature.aggregation)
        query = queries.get(query_key)
        if query:
            result = client.execute(query)
            return float(result[0][0]) if result else 0.0

        return feature.default_value

    async def _compute_threat_intel_feature(
        self, org_id: str, feature: FeatureDefinition, client,
    ) -> float:
        """Compute a feature from threat intelligence data."""
        window_hours = 24
        if feature.window:
            window_hours = int(feature.window.replace("h", "").replace("d", ""))

        queries = {
            ("known_malicious_ips", "count"): f"""
                SELECT COUNT(DISTINCT ip)
                FROM threat_intel
                WHERE org_id = '{org_id}'
                AND is_malicious = 1
                AND created_at > NOW() - INTERVAL {window_hours} HOUR
            """,
        }

        query_key = (feature.name, feature.aggregation)
        query = queries.get(query_key)
        if query:
            result = client.execute(query)
            return float(result[0][0]) if result else 0.0

        return feature.default_value

    def get_feature_vector(
        self,
        org_id: str,
        group_names: Optional[List[str]] = None,
    ) -> np.ndarray:
        """Get combined feature vector for all groups."""
        if group_names is None:
            group_names = list(self._feature_groups.keys())

        vectors = []
        for group_name in group_names:
            cache_key = self._make_cache_key(org_id, group_name)
            if cache_key in self._local_cache:
                vectors.append(self._local_cache[cache_key])

        if vectors:
            return np.concatenate(vectors)
        return np.array([])

    def invalidate_cache(self, org_id: str, group_name: Optional[str] = None):
        """Invalidate cached features."""
        if group_name:
            cache_key = self._make_cache_key(org_id, group_name)
            self._local_cache.pop(cache_key, None)
        else:
            keys_to_remove = [
                k for k in self._local_cache if k.startswith(f"features:{org_id}")
            ]
            for k in keys_to_remove:
                self._local_cache.pop(k, None)


# Global feature store instance
feature_store = FeatureStore()
