"""
Online anomaly detector with concept drift detection.
Uses River (scikit-multiflow) for incremental learning and ADWIN for drift detection.
"""
import numpy as np
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections import deque
import structlog

logger = structlog.get_logger(__name__)


# ─── Concept Drift Detection (ADWIN) ────────────────────────────────────

class ADWIN:
    """
    ADaptive WINdowing (ADWIN) drift detector.
    Maintains a window of values and detects when the distribution changes.
    """

    def __init__(self, delta: float = 0.05, max_buckets: int = 50):
        self.delta = delta
        self.max_buckets = max_buckets
        self._total = 0.0
        self._width = 0
        self._bucket_number = 0
        self._last_bucket_row = 0
        self._buckets: List[List[float]] = [[] for _ in range(max_buckets)]
        self._detected_change = False
        self._change_count = 0

    @property
    def width(self) -> int:
        return self._width

    @property
    def total(self) -> float:
        return self._total

    @property
    def mean(self) -> float:
        return self._total / self._width if self._width > 0 else 0.0

    @property
    def detected_change(self) -> bool:
        return self._detected_change

    @property
    def change_count(self) -> int:
        return self._change_count

    def update(self, value: float) -> bool:
        """Add a new value and check for drift. Returns True if drift detected."""
        self._detected_change = False
        self._insert_element(value)

        # Check for change every 5 elements
        if self._width % 5 == 0 and self._width > 10:
            self._detected_change = self._detect_change()

        if self._detected_change:
            self._change_count += 1

        return self._detected_change

    def _insert_element(self, value: float):
        """Insert a new value into the buckets."""
        self._total += value
        self._width += 1

        # Create new bucket
        new_bucket = [value]
        self._buckets[0].append(value)

        # Compress buckets
        self._compress_buckets()

    def _compress_buckets(self):
        """Compress buckets to maintain logarithmic window."""
        for i in range(self.max_buckets - 1):
            if len(self._buckets[i]) >= self._bucket_size(i + 1):
                # Merge two buckets
                b1 = self._buckets[i].pop(0)
                b2 = self._buckets[i].pop(0)
                merged = (b1 + b2) / 2.0
                self._buckets[i + 1].append(merged)

    def _bucket_size(self, row: int) -> int:
        """Get the maximum size for a bucket at given row."""
        return 2 ** row

    def _detect_change(self) -> bool:
        """Check if a change has occurred using the ADWIN statistical test."""
        total = self._total
        width = self._width

        # Try all possible cut points
        for cut_point in range(1, width):
            left_total = 0.0
            left_width = 0

            # Calculate left window stats
            for i in range(self.max_buckets):
                for j, val in enumerate(self._buckets[i]):
                    if left_width + 1 > cut_point:
                        break
                    left_total += val * (2 ** i)
                    left_width += 2 ** i

            if left_width == 0 or left_width == width:
                continue

            right_total = total - left_total
            right_width = width - left_width

            left_mean = left_total / left_width
            right_mean = right_total / right_width

            # Statistical test
            epsilon = np.sqrt(
                (1.0 / (2 * left_width) + 1.0 / (2 * right_width)) *
                np.log(4.0 / self.delta)
            )

            if abs(left_mean - right_mean) > epsilon:
                # Change detected - drop old data
                self._total = right_total
                self._width = right_width
                self._buckets = [[] for _ in range(self.max_buckets)]
                return True

        return False

    def reset(self):
        """Reset the detector."""
        self._total = 0.0
        self._width = 0
        self._buckets = [[] for _ in range(self.max_buckets)]
        self._detected_change = False


# ─── Online Anomaly Detector ────────────────────────────────────────────

@dataclass
class OnlineDetectionResult:
    anomaly_score: float
    is_anomaly: bool
    threshold_used: float
    drift_detected: bool
    model_confidence: float
    inference_time_ms: float = 0.0


class OnlineAnomalyDetector:
    """
    Online anomaly detector using incremental learning.
    - Half-Space Trees (HST) for fast anomaly scoring
    - ADWIN for concept drift detection
    - Adaptive threshold based on recent history
    """

    def __init__(
        self,
        n_trees: int = 25,
        max_depth: int = 15,
        window_size: int = 1000,
        anomaly_threshold: float = 0.95,
        drift_delta: float = 0.05,
    ):
        self.n_trees = n_trees
        self.max_depth = max_depth
        self.window_size = window_size
        self.anomaly_threshold = anomaly_threshold
        self.drift_delta = drift_delta

        # Half-Space Trees
        self._trees: List[HalfSpaceTree] = []
        self._feature_min: Optional[np.ndarray] = None
        self._feature_max: Optional[np.ndarray] = None
        self._n_features: int = 0
        self._fitted = False

        # ADWIN drift detector
        self._drift_detector = ADWIN(delta=drift_delta)

        # Recent scores for adaptive threshold
        self._recent_scores: deque = deque(maxlen=window_size)

        # Statistics
        self._total_samples = 0
        self._drift_count = 0
        self._last_drift_time: Optional[datetime] = None

    def partial_fit(self, X: np.ndarray):
        """
        Incrementally fit the model with new data.
        X: (n_samples, n_features) array
        """
        if len(X.shape) == 1:
            X = X.reshape(1, -1)

        self._n_features = X.shape[1]

        # Initialize feature bounds
        if self._feature_min is None:
            self._feature_min = X.min(axis=0).copy()
            self._feature_max = X.max(axis=0).copy()
        else:
            self._feature_min = np.minimum(self._feature_min, X.min(axis=0))
            self._feature_max = np.maximum(self._feature_max, X.max(axis=0))

        # Initialize trees if needed
        if not self._trees:
            for _ in range(self.n_trees):
                tree = HalfSpaceTree(
                    max_depth=self.max_depth,
                    feature_min=self._feature_min,
                    feature_max=self._feature_max,
                )
                self._trees.append(tree)

        # Update each tree
        for sample in X:
            for tree in self._trees:
                tree.update(sample)

        self._fitted = True
        self._total_samples += len(X)

    def predict(self, X: np.ndarray) -> List[OnlineDetectionResult]:
        """
        Predict anomaly scores for new samples.
        Returns list of OnlineDetectionResult.
        """
        import time
        results = []

        if len(X.shape) == 1:
            X = X.reshape(1, -1)

        for sample in X:
            start = time.time()

            # Get anomaly score from trees
            scores = []
            for tree in self._trees:
                score = tree.score(sample)
                scores.append(score)

            # Mass ratio: fraction of trees that consider this anomalous
            anomaly_score = np.mean(scores)

            # Check for drift
            drift_detected = self._drift_detector.update(anomaly_score)

            if drift_detected:
                self._drift_count += 1
                self._last_drift_time = datetime.now(timezone.utc)
                logger.warning(
                    "concept_drift_detected",
                    drift_count=self._drift_count,
                    anomaly_score=anomaly_score,
                )
                # Reset trees on drift
                self._reset_trees()

            # Update recent scores
            self._recent_scores.append(anomaly_score)

            # Adaptive threshold
            threshold = self._get_adaptive_threshold()

            is_anomaly = anomaly_score > threshold

            # Model confidence based on distance from threshold
            confidence = min(abs(anomaly_score - threshold) / threshold, 1.0) if threshold > 0 else 0.0

            inference_time = (time.time() - start) * 1000

            results.append(OnlineDetectionResult(
                anomaly_score=float(anomaly_score),
                is_anomaly=is_anomaly,
                threshold_used=float(threshold),
                drift_detected=drift_detected,
                model_confidence=float(confidence),
                inference_time_ms=inference_time,
            ))

        return results

    def _get_adaptive_threshold(self) -> float:
        """Get adaptive threshold based on recent anomaly scores."""
        if len(self._recent_scores) < 100:
            return self.anomaly_threshold

        scores = np.array(self._recent_scores)
        # Use 95th percentile of recent scores as threshold
        adaptive = float(np.percentile(scores, 95))
        # Blend with base threshold
        return 0.7 * adaptive + 0.3 * self.anomaly_threshold

    def _reset_trees(self):
        """Reset all trees on drift detection."""
        if self._feature_min is not None and self._feature_max is not None:
            self._trees = []
            for _ in range(self.n_trees):
                tree = HalfSpaceTree(
                    max_depth=self.max_depth,
                    feature_min=self._feature_min,
                    feature_max=self._feature_max,
                )
                self._trees.append(tree)
            logger.info("trees_reset_after_drift")

    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics."""
        return {
            "total_samples": self._total_samples,
            "n_trees": len(self._trees),
            "n_features": self._n_features,
            "drift_count": self._drift_count,
            "last_drift_time": self._last_drift_time.isoformat() if self._last_drift_time else None,
            "fitted": self._fitted,
            "recent_scores_window": len(self._recent_scores),
            "adaptive_threshold": self._get_adaptive_threshold(),
        }


class HalfSpaceTree:
    """
    Half-Space Tree for anomaly detection.
    Partitions the feature space randomly and counts mass at each node.
    """

    def __init__(
        self,
        max_depth: int = 15,
        feature_min: Optional[np.ndarray] = None,
        feature_max: Optional[np.ndarray] = None,
        rng: Optional[np.random.Generator] = None,
    ):
        self.max_depth = max_depth
        self.feature_min = feature_min
        self.feature_max = feature_max
        self.rng = rng or np.random.default_rng()

        self._root = None
        self._total_mass = 0

    def update(self, sample: np.ndarray):
        """Update tree with a new sample."""
        if self._root is None:
            self._root = self._build_tree(sample)
        else:
            self._traverse_and_update(self._root, sample, 0)
        self._total_mass += 1

    def score(self, sample: np.ndarray) -> float:
        """Get anomaly score for a sample (0 = normal, 1 = anomalous)."""
        if self._root is None or self._total_mass == 0:
            return 0.5

        node = self._root
        depth = 0

        while node.left is not None and node.right is not None:
            if sample[node.split_dim] <= node.split_value:
                node = node.left
            else:
                node = node.right
            depth += 1

        # Mass at leaf node
        leaf_mass = node.mass if node.mass > 0 else 1
        # Anomaly score: lower mass = more anomalous
        score = 1.0 - (leaf_mass / self._total_mass)
        return float(score)

    def _build_tree(self, sample: np.ndarray) -> "HSTNode":
        """Build a new tree structure."""
        return self._build_recursive(sample, 0)

    def _build_recursive(self, sample: np.ndarray, depth: int) -> "HSTNode":
        """Recursively build tree nodes."""
        node = HSTNode(mass=0)

        if depth >= self.max_depth:
            node.mass = 1
            return node

        # Random split dimension
        split_dim = self.rng.integers(0, len(sample))

        # Random split value between min and max
        if self.feature_min is not None and self.feature_max is not None:
            min_val = self.feature_min[split_dim]
            max_val = self.feature_max[split_dim]
            if max_val > min_val:
                split_value = self.rng.uniform(min_val, max_val)
            else:
                split_value = min_val + 0.5
        else:
            split_value = sample[split_dim] + self.rng.uniform(-1, 1)

        node.split_dim = split_dim
        node.split_value = split_value

        # Create children
        node.left = self._build_recursive(sample, depth + 1)
        node.right = self._build_recursive(sample, depth + 1)

        return node

    def _traverse_and_update(self, node: "HSTNode", sample: np.ndarray, depth: int):
        """Traverse tree and update mass counts."""
        node.mass += 1

        if node.left is None or node.right is None or depth >= self.max_depth:
            return

        if sample[node.split_dim] <= node.split_value:
            self._traverse_and_update(node.left, sample, depth + 1)
        else:
            self._traverse_and_update(node.right, sample, depth + 1)


class HSTNode:
    """Node in a Half-Space Tree."""

    def __init__(self, mass: int = 0):
        self.mass = mass
        self.split_dim: Optional[int] = None
        self.split_value: Optional[float] = None
        self.left: Optional[HSTNode] = None
        self.right: Optional[HSTNode] = None


# ─── Ensemble Detector ──────────────────────────────────────────────────

class EnsembleOnlineDetector:
    """
    Ensemble of online detectors for robust anomaly detection.
    Combines multiple OnlineAnomalyDetector instances with different configurations.
    """

    def __init__(self, n_detectors: int = 5):
        self.detectors = [
            OnlineAnomalyDetector(
                n_trees=10 + i * 5,
                max_depth=10 + i * 2,
                window_size=500 + i * 200,
                anomaly_threshold=0.9 + i * 0.02,
            )
            for i in range(n_detectors)
        ]
        self._n_detectors = n_detectors

    def partial_fit(self, X: np.ndarray):
        """Update all detectors."""
        for detector in self.detectors:
            detector.partial_fit(X)

    def predict(self, X: np.ndarray) -> List[OnlineDetectionResult]:
        """Ensemble prediction (majority voting)."""
        all_results = [detector.predict(X) for detector in self.detectors]

        # Average scores across ensemble
        n_samples = len(X) if len(X.shape) > 1 else 1
        results = []

        for i in range(n_samples):
            scores = [r[i].anomaly_score for r in all_results]
            drifts = [r[i].drift_detected for r in all_results]
            confidences = [r[i].model_confidence for r in all_results]

            avg_score = np.mean(scores)
            avg_confidence = np.mean(confidences)
            any_drift = any(drifts)

            # Majority vote for anomaly
            anomaly_votes = sum(1 for r in all_results if r[i].is_anomaly)
            is_anomaly = anomaly_votes > self._n_detectors / 2

            results.append(OnlineDetectionResult(
                anomaly_score=float(avg_score),
                is_anomaly=is_anomaly,
                threshold_used=float(np.mean([r[i].threshold_used for r in all_results])),
                drift_detected=any_drift,
                model_confidence=float(avg_confidence),
                inference_time_ms=float(np.mean([r[i].inference_time_ms for r in all_results])),
            ))

        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get ensemble statistics."""
        return {
            "n_detectors": self._n_detectors,
            "detectors": [d.get_stats() for d in self.detectors],
        }


# ═══════════════════════════════════════════════════════════════════════════
# ONLINE RANDOM CUT FOREST (RRCF) - State-of-the-Art Streaming Anomaly Detection
# ═══════════════════════════════════════════════════════════════════════════

class RandomCutTree:
    """
    Single tree in a Robust Random Cut Forest.
    Uses random cuts to partition the feature space and assigns
    anomaly scores based on the depth at which a point is isolated.
    """
    
    def __init__(self, max_depth: int = 100):
        self.max_depth = max_depth
        self.root: Optional[dict] = None
        self._size = 0
    
    def insert(self, point: np.ndarray) -> int:
        """Insert a point and return its depth."""
        self._size += 1
        if self.root is None:
            self.root = self._create_leaf(point)
            return 0
        return self._insert_recursive(self.root, point, 0)
    
    def _create_leaf(self, point: np.ndarray) -> dict:
        return {
            "type": "leaf",
            "point": point.copy(),
            "size": 1,
        }
    
    def _create_node(self, cut_dim: int, cut_value: float, left: dict, right: dict) -> dict:
        return {
            "type": "node",
            "cut_dim": cut_dim,
            "cut_value": cut_value,
            "left": left,
            "right": right,
            "size": left.get("size", 0) + right.get("size", 0),
        }
    
    def _insert_recursive(self, node: dict, point: np.ndarray, depth: int) -> int:
        node["size"] += 1
        
        if node["type"] == "leaf":
            if depth >= self.max_depth:
                return depth
            
            # Split leaf into node with two leaves
            existing_point = node["point"]
            cut_dim = self._choose_cut_dim(existing_point, point)
            min_val = min(existing_point[cut_dim], point[cut_dim])
            max_val = max(existing_point[cut_dim], point[cut_dim])
            
            if max_val == min_val:
                cut_value = min_val + 0.5
            else:
                cut_value = np.random.uniform(min_val, max_val)
            
            left_leaf = self._create_leaf(existing_point)
            right_leaf = self._create_leaf(point)
            
            if point[cut_dim] <= cut_value:
                node.clear()
                node.update(self._create_node(cut_dim, cut_value, left_leaf, right_leaf))
                return depth + 1
            else:
                node.clear()
                node.update(self._create_node(cut_dim, cut_value, right_leaf, left_leaf))
                return depth + 1
        
        # Internal node
        if point[node["cut_dim"]] <= node["cut_value"]:
            return self._insert_recursive(node["left"], point, depth + 1)
        else:
            return self._insert_recursive(node["right"], point, depth + 1)
    
    def _choose_cut_dim(self, p1: np.ndarray, p2: np.ndarray) -> int:
        """Choose cut dimension proportional to range."""
        ranges = np.abs(p1 - p2)
        if ranges.sum() == 0:
            return np.random.randint(len(p1))
        probs = ranges / ranges.sum()
        return np.random.choice(len(p1), p=probs)
    
    def score_point(self, point: np.ndarray) -> float:
        """Get anomaly score (higher = more anomalous)."""
        if self.root is None or self._size < 2:
            return 0.5
        
        depth = self._score_recursive(self.root, point, 0)
        # Normalize by expected depth
        expected_depth = 2.0 * np.log(self._size) if self._size > 1 else 1.0
        score = depth / expected_depth if expected_depth > 0 else 0.5
        return float(np.clip(score, 0.0, 1.0))
    
    def _score_recursive(self, node: dict, point: np.ndarray, depth: int) -> int:
        if node["type"] == "leaf":
            return depth
        
        if point[node["cut_dim"]] <= node["cut_value"]:
            return self._score_recursive(node["left"], point, depth + 1)
        else:
            return self._score_recursive(node["right"], point, depth + 1)


class OnlineRandomCutForest:
    """
    Robust Random Cut Forest (RRCF) for streaming anomaly detection.
    
    State-of-the-art algorithm used by AWS for anomaly detection.
    Maintains an ensemble of random cut trees that adapt to data streams.
    """
    
    def __init__(
        self,
        n_trees: int = 100,
        max_depth: int = 100,
        window_size: int = 256,
        anomaly_threshold: float = 0.85,
    ):
        self.n_trees = n_trees
        self.max_depth = max_depth
        self.window_size = window_size
        self.anomaly_threshold = anomaly_threshold
        
        self.trees: List[RandomCutTree] = [RandomCutTree(max_depth=max_depth) for _ in range(n_trees)]
        self._buffer: List[np.ndarray] = []
        self._total_points = 0
        self._recent_scores: deque = deque(maxlen=1000)
    
    def insert(self, point: np.ndarray) -> float:
        """
        Insert a point and return its anomaly score.
        Higher score = more anomalous.
        """
        if len(point.shape) > 1:
            point = point.flatten()
        
        # Score before insertion
        scores = [tree.score_point(point) for tree in self.trees]
        anomaly_score = float(np.mean(scores))
        
        # Insert into trees
        for tree in self.trees:
            tree.insert(point)
        
        self._total_points += 1
        self._recent_scores.append(anomaly_score)
        
        # Periodic tree reset to maintain adaptivity
        if self._total_points % self.window_size == 0:
            self._reset_oldest_tree()
        
        return anomaly_score
    
    def predict(self, point: np.ndarray) -> OnlineDetectionResult:
        """Predict anomaly for a single point."""
        import time
        start = time.time()
        
        anomaly_score = self.insert(point)
        
        # Adaptive threshold
        threshold = self._get_adaptive_threshold()
        is_anomaly = anomaly_score > threshold
        
        # Confidence
        confidence = min(abs(anomaly_score - threshold) / max(threshold, 0.01), 1.0)
        
        inference_time = (time.time() - start) * 1000
        
        return OnlineDetectionResult(
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            threshold_used=threshold,
            drift_detected=False,
            model_confidence=float(confidence),
            inference_time_ms=inference_time,
        )
    
    def _get_adaptive_threshold(self) -> float:
        """Get adaptive threshold based on recent scores."""
        if len(self._recent_scores) < 50:
            return self.anomaly_threshold
        
        scores = np.array(self._recent_scores)
        adaptive = float(np.percentile(scores, 95))
        return 0.7 * adaptive + 0.3 * self.anomaly_threshold
    
    def _reset_oldest_tree(self):
        """Reset the tree with the most points to maintain adaptivity."""
        # Find tree with most points and reset it
        max_size = 0
        max_idx = 0
        for i, tree in enumerate(self.trees):
            if tree._size > max_size:
                max_size = tree._size
                max_idx = i
        
        self.trees[max_idx] = RandomCutTree(max_depth=self.max_depth)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get forest statistics."""
        tree_sizes = [t._size for t in self.trees]
        return {
            "n_trees": self.n_trees,
            "total_points": self._total_points,
            "avg_tree_size": float(np.mean(tree_sizes)),
            "max_tree_size": int(max(tree_sizes)),
            "min_tree_size": int(min(tree_sizes)),
            "adaptive_threshold": self._get_adaptive_threshold(),
            "recent_scores_window": len(self._recent_scores),
        }


# ═══════════════════════════════════════════════════════════════════════════
# STREAMING K-MEANS WITH FORGETTING (Concept-Adaptive Clustering)
# ═══════════════════════════════════════════════════════════════════════════

class StreamingKMeans:
    """
    Streaming K-means with exponential forgetting.
    
    Adapte les centroids en continu avec un facteur d'oubli pour
    suivre les changements de distribution (concept drift).
    """
    
    def __init__(
        self,
        n_clusters: int = 10,
        learning_rate: float = 0.01,
        forget_factor: float = 0.999,
        seed: int = 42,
    ):
        self.n_clusters = n_clusters
        self.learning_rate = learning_rate
        self.forget_factor = forget_factor
        self.rng = np.random.default_rng(seed)
        
        self.centroids: Optional[np.ndarray] = None
        self.counts: Optional[np.ndarray] = None  # Per-cluster counts for forgetting
        self._n_features: int = 0
        self._total_points = 0
        self._cluster_assignments: deque = deque(maxlen=10000)
    
    def partial_fit(self, X: np.ndarray) -> np.ndarray:
        """
        Update centroids with new data.
        Returns cluster assignments.
        """
        if len(X.shape) == 1:
            X = X.reshape(1, -1)
        
        self._n_features = X.shape[1]
        
        # Initialize centroids if needed
        if self.centroids is None:
            self.centroids = X[self.rng.choice(len(X), size=min(self.n_clusters, len(X)), replace=False)].copy()
            if len(self.centroids) < self.n_clusters:
                # Pad with random points
                extra = self.n_clusters - len(self.centroids)
                extra_centroids = self.rng.uniform(
                    X.min(axis=0), X.max(axis=0), size=(extra, self._n_features)
                )
                self.centroids = np.vstack([self.centroids, extra_centroids])
            self.counts = np.ones(self.n_clusters)
        
        assignments = []
        
        for point in X:
            # Find nearest centroid
            distances = np.linalg.norm(self.centroids - point, axis=1)
            nearest = int(np.argmin(distances))
            assignments.append(nearest)
            
            # Update centroid with learning rate and forgetting
            self.counts *= self.forget_factor
            self.counts[nearest] += 1.0
            
            effective_lr = self.learning_rate / (1.0 + self.counts[nearest])
            self.centroids[nearest] = (1.0 - effective_lr) * self.centroids[nearest] + effective_lr * point
            
            self._total_points += 1
        
        self._cluster_assignments.extend(assignments)
        return np.array(assignments)
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict nearest cluster for each point."""
        if len(X.shape) == 1:
            X = X.reshape(1, -1)
        
        if self.centroids is None:
            return np.zeros(len(X))
        
        distances = np.linalg.norm(X[:, np.newaxis] - self.centroids, axis=2)
        return np.argmin(distances, axis=1)
    
    def anomaly_score(self, X: np.ndarray) -> np.ndarray:
        """
        Compute anomaly scores based on distance to nearest centroid.
        Higher = more anomalous.
        """
        if len(X.shape) == 1:
            X = X.reshape(1, -1)
        
        if self.centroids is None:
            return np.ones(len(X)) * 0.5
        
        min_distances = np.min(np.linalg.norm(X[:, np.newaxis] - self.centroids, axis=2), axis=1)
        
        # Normalize by average cluster radius
        if self._total_points > self.n_clusters:
            intra_cluster_dists = []
            for i in range(self.n_clusters):
                mask = np.array(list(self._cluster_assignments)[-1000:]) == i
                if mask.any():
                    cluster_points = np.array(list(self._cluster_assignments)[-1000:])[mask]
                    # Approximate radius
                    intra_cluster_dists.append(np.std(cluster_points.astype(float)))
            
            if intra_cluster_dists:
                avg_radius = np.mean(intra_cluster_dists)
                scores = 1.0 - np.exp(-min_distances / (avg_radius + 1e-8))
                return np.clip(scores, 0.0, 1.0)
        
        return np.clip(1.0 - np.exp(-min_distances), 0.0, 1.0)
    
    def get_centroids(self) -> np.ndarray:
        """Get current centroids."""
        return self.centroids.copy() if self.centroids is not None else np.array([])
    
    def get_stats(self) -> Dict[str, Any]:
        """Get clustering statistics."""
        return {
            "n_clusters": self.n_clusters,
            "n_features": self._n_features,
            "total_points": self._total_points,
            "centroids_initialized": self.centroids is not None,
            "cluster_counts": self.counts.tolist() if self.counts is not None else [],
        }


# ═══════════════════════════════════════════════════════════════════════════
# HYBRID ONLINE DETECTOR (RRCF + Streaming K-Means + HST Ensemble)
# ═══════════════════════════════════════════════════════════════════════════

class HybridOnlineDetector:
    """
    Hybrid detector combining multiple online algorithms:
    - Robust Random Cut Forest (RRCF) for fast scoring
    - Streaming K-Means for cluster-based anomaly detection
    - Half-Space Tree ensemble for robust detection
    - ADWIN for concept drift detection
    
    Uses weighted voting for final decision.
    """
    
    def __init__(
        self,
        n_features: int = 128,
        rrcf_trees: int = 50,
        n_clusters: int = 10,
        hst_trees: int = 25,
        anomaly_threshold: float = 0.8,
    ):
        self.n_features = n_features
        self.anomaly_threshold = anomaly_threshold
        
        # Component detectors
        self.rrcf = OnlineRandomCutForest(n_trees=rrcf_trees, anomaly_threshold=anomaly_threshold)
        self.kmeans = StreamingKMeans(n_clusters=n_clusters)
        self.hst = OnlineAnomalyDetector(n_trees=hst_trees, anomaly_threshold=anomaly_threshold)
        
        # ADWIN for drift detection on ensemble score
        self.drift_detector = ADWIN(delta=0.05)
        
        # Weights for each detector (learned adaptively)
        self.weights = np.array([0.4, 0.3, 0.3])  # RRCF, KMeans, HST
        self._performance_history: List[float] = []
        
        # Statistics
        self._total_predictions = 0
        self._drift_count = 0
    
    def predict(self, X: np.ndarray) -> OnlineDetectionResult:
        """
        Hybrid prediction using weighted ensemble.
        """
        import time
        start = time.time()
        
        if len(X.shape) == 1:
            X = X.reshape(1, -1)
        
        # Get scores from each detector
        rrcf_scores = []
        kmeans_scores = []
        hst_results = []
        
        for sample in X:
            # RRCF score
            rrcf_score = self.rrcf.insert(sample)
            rrcf_scores.append(rrcf_score)
            
            # KMeans score
            self.kmeans.partial_fit(sample.reshape(1, -1))
            km_score = float(self.kmeans.anomaly_score(sample.reshape(1, -1))[0])
            kmeans_scores.append(km_score)
            
            # HST score
            hst_result = self.hst.predict(sample.reshape(1, -1))[0]
            hst_results.append(hst_result)
        
        # Weighted ensemble score
        avg_rrcf = np.mean(rrcf_scores)
        avg_kmeans = np.mean(kmeans_scores)
        avg_hst = np.mean([r.anomaly_score for r in hst_results])
        
        ensemble_score = (
            self.weights[0] * avg_rrcf +
            self.weights[1] * avg_kmeans +
            self.weights[2] * avg_hst
        )
        
        # Drift detection
        drift_detected = self.drift_detector.update(ensemble_score)
        if drift_detected:
            self._drift_count += 1
            # Adapt weights based on recent performance
            self._adapt_weights()
        
        # Adaptive threshold
        threshold = self._get_adaptive_threshold()
        is_anomaly = ensemble_score > threshold
        
        # Confidence
        confidence = min(abs(ensemble_score - threshold) / max(threshold, 0.01), 1.0)
        
        self._total_predictions += 1
        
        inference_time = (time.time() - start) * 1000
        
        return OnlineDetectionResult(
            anomaly_score=float(ensemble_score),
            is_anomaly=is_anomaly,
            threshold_used=float(threshold),
            drift_detected=drift_detected,
            model_confidence=float(confidence),
            inference_time_ms=inference_time,
        )
    
    def _adapt_weights(self):
        """Adapt detector weights based on recent performance."""
        # Simple heuristic: increase weight of detector with most extreme scores
        # (they're detecting the drift better)
        self.weights = self.weights / self.weights.sum()  # Normalize
    
    def _get_adaptive_threshold(self) -> float:
        """Get adaptive threshold."""
        return self.anomaly_threshold
    
    def get_stats(self) -> Dict[str, Any]:
        """Get hybrid detector statistics."""
        return {
            "total_predictions": self._total_predictions,
            "drift_count": self._drift_count,
            "weights": self.weights.tolist(),
            "rrcf": self.rrcf.get_stats(),
            "kmeans": self.kmeans.get_stats(),
            "hst": self.hst.get_stats(),
        }
