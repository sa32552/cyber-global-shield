"""
Cyber Global Shield v2.0 — Auto Benchmarking & Model Selection
===============================================================
Phase 4.4: Automated benchmarking suite for model selection,
dataset profiling, algorithm recommendation, and report generation.

Dependencies:
    pip install flaml optuna scikit-learn pandas

Components:
    ├── BenchmarkConfig — Configuration for benchmark runs
    ├── BenchmarkResult — Results with metrics, timing, resource usage
    ├── DatasetProfiler — Automatic dataset profiling
    ├── AlgorithmRecommender — Recommends algorithms based on dataset profile
    ├── CrossValidator — Adaptive cross-validation strategies
    ├── BenchmarkSuite — Run benchmarks on multiple models
    ├── AutoModelSelector — Automated model selection using FLAML/Optuna
    └── ReportGenerator — Generate performance comparison reports
"""

from __future__ import annotations

import json
import logging
import time
import warnings
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    Type,
    Union,
)

import numpy as np
import pandas as pd

try:
    from sklearn.model_selection import (
        StratifiedKFold,
        TimeSeriesSplit,
        KFold,
        train_test_split,
    )
    from sklearn.metrics import (
        accuracy_score,
        precision_score,
        recall_score,
        f1_score,
        roc_auc_score,
        average_precision_score,
        mean_squared_error,
        mean_absolute_error,
        r2_score,
        confusion_matrix,
    )
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    from sklearn.base import BaseEstimator
    SKLEARN_BASE = True
except ImportError:
    SKLEARN_BASE = False

try:
    import optuna
    OPTUNA_AVAILABLE = True
except ImportError:
    OPTUNA_AVAILABLE = False

try:
    import flaml
    from flaml import AutoML
    FLAML_AVAILABLE = True
except ImportError:
    FLAML_AVAILABLE = False

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Enums & Constants
# ═══════════════════════════════════════════════════════════════════════════════

class TaskType(Enum):
    """Type of ML task."""
    BINARY_CLASSIFICATION = "binary_classification"
    MULTICLASS_CLASSIFICATION = "multiclass_classification"
    REGRESSION = "regression"
    TIME_SERIES_FORECAST = "time_series_forecast"
    ANOMALY_DETECTION = "anomaly_detection"
    UNSPECIFIED = "unspecified"


class CVStrategy(Enum):
    """Cross-validation strategy."""
    KFOLD = "kfold"
    STRATIFIED_KFOLD = "stratified_kfold"
    TIME_SERIES = "time_series"
    GROUP_KFOLD = "group_kfold"
    LEAVE_ONE_OUT = "leave_one_out"
    BOOTSTRAP = "bootstrap"
    ADAPTIVE = "adaptive"


class MetricDirection(Enum):
    """Direction of metric optimization."""
    MAXIMIZE = "maximize"
    MINIMIZE = "minimize"


class DatasetSizeCategory(Enum):
    """Category of dataset size."""
    TINY = "tiny"           # < 1K samples
    SMALL = "small"         # 1K - 10K
    MEDIUM = "medium"       # 10K - 100K
    LARGE = "large"         # 100K - 1M
    HUGE = "huge"           # > 1M


class SparsityCategory(Enum):
    """Category of dataset sparsity."""
    DENSE = "dense"             # < 10% zeros
    MODERATE = "moderate"       # 10-50% zeros
    SPARSE = "sparse"           # 50-90% zeros
    VERY_SPARSE = "very_sparse" # > 90% zeros


class ImbalanceCategory(Enum):
    """Category of class imbalance."""
    BALANCED = "balanced"           # ratio < 2:1
    SLIGHT = "slight"               # 2:1 to 5:1
    MODERATE = "moderate"           # 5:1 to 20:1
    SEVERE = "severe"               # 20:1 to 100:1
    EXTREME = "extreme"             # > 100:1


# Default metrics for each task type
DEFAULT_METRICS: Dict[TaskType, List[str]] = {
    TaskType.BINARY_CLASSIFICATION: [
        "accuracy", "precision", "recall", "f1", "roc_auc", "average_precision",
    ],
    TaskType.MULTICLASS_CLASSIFICATION: [
        "accuracy", "f1_macro", "f1_weighted", "precision_macro", "recall_macro",
    ],
    TaskType.REGRESSION: [
        "mse", "rmse", "mae", "r2", "mape",
    ],
    TaskType.TIME_SERIES_FORECAST: [
        "mse", "rmse", "mae", "mape", "smape",
    ],
    TaskType.ANOMALY_DETECTION: [
        "precision", "recall", "f1", "average_precision", "false_positive_rate",
    ],
    TaskType.UNSPECIFIED: [
        "accuracy", "f1", "mse",
    ],
}

# Metric directions
METRIC_DIRECTIONS: Dict[str, MetricDirection] = {
    "accuracy": MetricDirection.MAXIMIZE,
    "precision": MetricDirection.MAXIMIZE,
    "recall": MetricDirection.MAXIMIZE,
    "f1": MetricDirection.MAXIMIZE,
    "f1_macro": MetricDirection.MAXIMIZE,
    "f1_weighted": MetricDirection.MAXIMIZE,
    "precision_macro": MetricDirection.MAXIMIZE,
    "recall_macro": MetricDirection.MAXIMIZE,
    "roc_auc": MetricDirection.MAXIMIZE,
    "average_precision": MetricDirection.MAXIMIZE,
    "r2": MetricDirection.MAXIMIZE,
    "mse": MetricDirection.MINIMIZE,
    "rmse": MetricDirection.MINIMIZE,
    "mae": MetricDirection.MINIMIZE,
    "mape": MetricDirection.MINIMIZE,
    "smape": MetricDirection.MINIMIZE,
    "false_positive_rate": MetricDirection.MINIMIZE,
    "false_negative_rate": MetricDirection.MINIMIZE,
    "latency_ms": MetricDirection.MINIMIZE,
    "memory_mb": MetricDirection.MINIMIZE,
    "training_time_s": MetricDirection.MINIMIZE,
}


# ═══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class BenchmarkConfig:
    """Configuration for a benchmark run.

    Attributes:
        task_type: Type of ML task.
        cv_strategy: Cross-validation strategy.
        n_folds: Number of CV folds (default: 5).
        test_size: Fraction of data for holdout test set (default: 0.2).
        metrics: List of metrics to compute.
        primary_metric: Primary metric for model selection.
        n_trials: Number of hyperparameter optimization trials (default: 50).
        timeout_seconds: Timeout per model in seconds (default: 3600).
        random_state: Random seed for reproducibility.
        verbose: Verbosity level (0=quiet, 1=normal, 2=debug).
        use_gpu: Whether to use GPU if available.
        cache_results: Whether to cache benchmark results.
        compare_baseline: Whether to include simple baselines.
    """
    task_type: TaskType = TaskType.UNSPECIFIED
    cv_strategy: CVStrategy = CVStrategy.ADAPTIVE
    n_folds: int = 5
    test_size: float = 0.2
    metrics: List[str] = field(default_factory=lambda: [])
    primary_metric: str = "f1"
    n_trials: int = 50
    timeout_seconds: int = 3600
    random_state: int = 42
    verbose: int = 1
    use_gpu: bool = False
    cache_results: bool = True
    compare_baseline: bool = True

    def __post_init__(self):
        if not self.metrics:
            self.metrics = DEFAULT_METRICS.get(
                self.task_type, DEFAULT_METRICS[TaskType.UNSPECIFIED]
            )


@dataclass
class BenchmarkResult:
    """Results from a single benchmark run.

    Attributes:
        model_name: Name of the model.
        model_params: Model parameters used.
        metrics: Dictionary of metric name -> value.
        training_time_s: Training time in seconds.
        inference_time_ms: Average inference time per sample in ms.
        memory_usage_mb: Peak memory usage in MB.
        model_size_mb: Model size on disk in MB.
        cv_scores: Per-fold scores for the primary metric.
        timestamp: When the benchmark was run.
        dataset_profile: Profile of the dataset used.
        error: Error message if benchmark failed.
        warnings: List of warnings during benchmark.
    """
    model_name: str
    model_params: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, float] = field(default_factory=dict)
    training_time_s: float = 0.0
    inference_time_ms: float = 0.0
    memory_usage_mb: float = 0.0
    model_size_mb: float = 0.0
    cv_scores: List[float] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    dataset_profile: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

    @property
    def cv_mean(self) -> float:
        """Mean cross-validation score."""
        return float(np.mean(self.cv_scores)) if self.cv_scores else 0.0

    @property
    def cv_std(self) -> float:
        """Standard deviation of cross-validation scores."""
        return float(np.std(self.cv_scores)) if self.cv_scores else 0.0

    @property
    def success(self) -> bool:
        """Whether the benchmark completed successfully."""
        return self.error is None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BenchmarkResult":
        """Create from dictionary."""
        return cls(**data)


@dataclass
class DatasetProfile:
    """Profile of a dataset for algorithm recommendation.

    Attributes:
        n_samples: Number of samples.
        n_features: Number of features.
        n_categorical: Number of categorical features.
        n_numerical: Number of numerical features.
        n_classes: Number of classes (for classification).
        class_ratios: Class distribution ratios.
        sparsity: Fraction of zero/missing values.
        has_missing: Whether dataset has missing values.
        size_category: Size category.
        sparsity_category: Sparsity category.
        imbalance_category: Imbalance category (for classification).
        feature_types: List of feature types ('numerical', 'categorical', 'text').
        memory_estimate_mb: Estimated memory footprint in MB.
    """
    n_samples: int = 0
    n_features: int = 0
    n_categorical: int = 0
    n_numerical: int = 0
    n_classes: Optional[int] = None
    class_ratios: Optional[Dict[Any, float]] = None
    sparsity: float = 0.0
    has_missing: bool = False
    size_category: DatasetSizeCategory = DatasetSizeCategory.TINY
    sparsity_category: SparsityCategory = SparsityCategory.DENSE
    imbalance_category: Optional[ImbalanceCategory] = None
    feature_types: List[str] = field(default_factory=list)
    memory_estimate_mb: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to serializable dictionary."""
        result = asdict(self)
        result["size_category"] = self.size_category.value
        result["sparsity_category"] = self.sparsity_category.value
        if self.imbalance_category:
            result["imbalance_category"] = self.imbalance_category.value
        if self.class_ratios:
            result["class_ratios"] = {
                str(k): float(v) for k, v in self.class_ratios.items()
            }
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# Dataset Profiler
# ═══════════════════════════════════════════════════════════════════════════════

class DatasetProfiler:
    """Profile datasets for algorithm recommendation.

    Analyzes dataset characteristics: size, dimensionality, sparsity,
    class balance, feature types, and missing values.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def profile(
        self,
        X: Union[np.ndarray, pd.DataFrame],
        y: Optional[Union[np.ndarray, pd.Series]] = None,
        feature_types: Optional[List[str]] = None,
    ) -> DatasetProfile:
        """Profile a dataset.

        Args:
            X: Feature matrix.
            y: Target vector (optional).
            feature_types: Optional list of feature types per column.

        Returns:
            DatasetProfile with dataset characteristics.
        """
        if isinstance(X, pd.DataFrame):
            n_samples, n_features = X.shape
            n_missing = int(X.isnull().sum().sum())
            has_missing = n_missing > 0
            sparsity = n_missing / (n_samples * n_features) if n_samples * n_features > 0 else 0.0

            if feature_types is None:
                feature_types = []
                for col in X.columns:
                    if X[col].dtype in ("object", "category", "bool"):
                        feature_types.append("categorical")
                    elif X[col].dtype in ("int64", "float64"):
                        feature_types.append("numerical")
                    else:
                        feature_types.append("numerical")
        else:
            n_samples, n_features = X.shape
            has_missing = bool(np.any(np.isnan(X)))
            sparsity = float(np.mean(X == 0)) if not has_missing else 0.0
            if feature_types is None:
                feature_types = ["numerical"] * n_features

        n_categorical = sum(1 for t in feature_types if t == "categorical")
        n_numerical = sum(1 for t in feature_types if t == "numerical")

        # Size category
        if n_samples < 1000:
            size_cat = DatasetSizeCategory.TINY
        elif n_samples < 10000:
            size_cat = DatasetSizeCategory.SMALL
        elif n_samples < 100000:
            size_cat = DatasetSizeCategory.MEDIUM
        elif n_samples < 1000000:
            size_cat = DatasetSizeCategory.LARGE
        else:
            size_cat = DatasetSizeCategory.HUGE

        # Sparsity category
        if sparsity < 0.1:
            sparsity_cat = SparsityCategory.DENSE
        elif sparsity < 0.5:
            sparsity_cat = SparsityCategory.MODERATE
        elif sparsity < 0.9:
            sparsity_cat = SparsityCategory.SPARSE
        else:
            sparsity_cat = SparsityCategory.VERY_SPARSE

        # Class analysis
        n_classes = None
        class_ratios = None
        imbalance_cat = None
        if y is not None:
            if isinstance(y, pd.Series):
                unique, counts = np.unique(y.values, return_counts=True)
            else:
                unique, counts = np.unique(y, return_counts=True)
            n_classes = len(unique)
            class_ratios = dict(zip(unique, counts / counts.sum()))
            if n_classes >= 2:
                sorted_ratios = sorted(class_ratios.values(), reverse=True)
                if len(sorted_ratios) >= 2:
                    ratio = sorted_ratios[0] / sorted_ratios[1]
                    if ratio < 2:
                        imbalance_cat = ImbalanceCategory.BALANCED
                    elif ratio < 5:
                        imbalance_cat = ImbalanceCategory.SLIGHT
                    elif ratio < 20:
                        imbalance_cat = ImbalanceCategory.MODERATE
                    elif ratio < 100:
                        imbalance_cat = ImbalanceCategory.SEVERE
                    else:
                        imbalance_cat = ImbalanceCategory.EXTREME

        # Memory estimate
        memory_estimate = (n_samples * n_features * 8) / (1024 * 1024)  # MB (float64)

        profile = DatasetProfile(
            n_samples=n_samples,
            n_features=n_features,
            n_categorical=n_categorical,
            n_numerical=n_numerical,
            n_classes=n_classes,
            class_ratios=class_ratios,
            sparsity=sparsity,
            has_missing=has_missing,
            size_category=size_cat,
            sparsity_category=sparsity_cat,
            imbalance_category=imbalance_cat,
            feature_types=feature_types,
            memory_estimate_mb=memory_estimate,
        )

        if self.verbose:
            logger.info(
                "Dataset profiled: %d samples, %d features, %s size, %s sparsity",
                n_samples, n_features, size_cat.value, sparsity_cat.value,
            )

        return profile


# ═══════════════════════════════════════════════════════════════════════════════
# Algorithm Recommender
# ═══════════════════════════════════════════════════════════════════════════════

class AlgorithmRecommender:
    """Recommend algorithms based on dataset profile.

    Uses heuristic rules to suggest the best algorithms for a given
    dataset profile, considering size, sparsity, imbalance, and task type.
    """

    def __init__(self):
        self._recommendation_rules = self._build_rules()

    def _build_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        """Build heuristic recommendation rules."""
        return {
            TaskType.BINARY_CLASSIFICATION.value: [
                {
                    "name": "LightGBM",
                    "priority": 1,
                    "conditions": {"min_samples": 1000, "max_features": 10000},
                    "reason": "Fast, accurate, handles mixed features",
                },
                {
                    "name": "XGBoost",
                    "priority": 2,
                    "conditions": {"min_samples": 500, "max_features": 50000},
                    "reason": "Robust, handles missing values, good default",
                },
                {
                    "name": "RandomForest",
                    "priority": 3,
                    "conditions": {"min_samples": 100, "max_features": 5000},
                    "reason": "Good for small datasets, interpretable",
                },
                {
                    "name": "LogisticRegression",
                    "priority": 4,
                    "conditions": {"min_samples": 50, "max_features": 1000},
                    "reason": "Fast baseline, interpretable coefficients",
                },
                {
                    "name": "CatBoost",
                    "priority": 2,
                    "conditions": {"min_samples": 500, "n_categorical": 1},
                    "reason": "Best for categorical features, native handling",
                },
                {
                    "name": "GradientBoosting",
                    "priority": 3,
                    "conditions": {"min_samples": 1000, "max_features": 500},
                    "reason": "Strong performance on medium data",
                },
                {
                    "name": "KNN",
                    "priority": 5,
                    "conditions": {"min_samples": 100, "max_samples": 50000},
                    "reason": "Non-parametric, good for small feature spaces",
                },
                {
                    "name": "SVM",
                    "priority": 4,
                    "conditions": {"min_samples": 100, "max_samples": 50000, "max_features": 1000},
                    "reason": "Effective in high-dimensional spaces",
                },
                {
                    "name": "MLPClassifier",
                    "priority": 3,
                    "conditions": {"min_samples": 5000},
                    "reason": "Neural network baseline for large data",
                },
            ],
            TaskType.MULTICLASS_CLASSIFICATION.value: [
                {
                    "name": "LightGBM",
                    "priority": 1,
                    "conditions": {"min_samples": 1000, "max_features": 10000},
                    "reason": "Fast multiclass, good accuracy",
                },
                {
                    "name": "XGBoost",
                    "priority": 2,
                    "conditions": {"min_samples": 500, "max_features": 50000},
                    "reason": "Robust multiclass with early stopping",
                },
                {
                    "name": "RandomForest",
                    "priority": 2,
                    "conditions": {"min_samples": 100, "max_features": 5000},
                    "reason": "Good multiclass baseline",
                },
                {
                    "name": "CatBoost",
                    "priority": 2,
                    "conditions": {"min_samples": 500, "n_categorical": 1},
                    "reason": "Best for categorical multiclass",
                },
            ],
            TaskType.REGRESSION.value: [
                {
                    "name": "LightGBM",
                    "priority": 1,
                    "conditions": {"min_samples": 1000, "max_features": 10000},
                    "reason": "Fast regression, good accuracy",
                },
                {
                    "name": "XGBoost",
                    "priority": 2,
                    "conditions": {"min_samples": 500, "max_features": 50000},
                    "reason": "Robust regression with early stopping",
                },
                {
                    "name": "RandomForestRegressor",
                    "priority": 2,
                    "conditions": {"min_samples": 100, "max_features": 5000},
                    "reason": "Good regression baseline",
                },
                {
                    "name": "RidgeRegression",
                    "priority": 4,
                    "conditions": {"min_samples": 50, "max_features": 1000},
                    "reason": "Fast linear baseline with regularization",
                },
            ],
            TaskType.ANOMALY_DETECTION.value: [
                {
                    "name": "IsolationForest",
                    "priority": 1,
                    "conditions": {"min_samples": 100, "max_features": 10000},
                    "reason": "Fast, scalable, contamination-free",
                },
                {
                    "name": "LOF",
                    "priority": 3,
                    "conditions": {"min_samples": 100, "max_samples": 50000, "max_features": 500},
                    "reason": "Local density-based detection",
                },
                {
                    "name": "OneClassSVM",
                    "priority": 4,
                    "conditions": {"min_samples": 100, "max_samples": 50000, "max_features": 1000},
                    "reason": "Good for high-dimensional anomaly detection",
                },
                {
                    "name": "EllipticEnvelope",
                    "priority": 5,
                    "conditions": {"min_samples": 50, "max_samples": 10000, "max_features": 500},
                    "reason": "Gaussian assumption, fast for small data",
                },
            ],
            TaskType.TIME_SERIES_FORECAST.value: [
                {
                    "name": "Prophet",
                    "priority": 1,
                    "conditions": {"min_samples": 30, "max_samples": 100000},
                    "reason": "Handles seasonality, holidays, changepoints",
                },
                {
                    "name": "ARIMA",
                    "priority": 2,
                    "conditions": {"min_samples": 30, "max_samples": 50000},
                    "reason": "Classic statistical forecasting",
                },
                {
                    "name": "LightGBM",
                    "priority": 2,
                    "conditions": {"min_samples": 1000, "max_features": 1000},
                    "reason": "Gradient boosting with lag features",
                },
                {
                    "name": "LSTM",
                    "priority": 3,
                    "conditions": {"min_samples": 5000},
                    "reason": "Deep learning for complex time series",
                },
            ],
        }

    def recommend(
        self,
        profile: DatasetProfile,
        task_type: TaskType = TaskType.BINARY_CLASSIFICATION,
        top_k: int = 5,
        include_baseline: bool = True,
    ) -> List[Dict[str, Any]]:
        """Recommend algorithms based on dataset profile.

        Args:
            profile: Dataset profile.
            task_type: Type of ML task.
            top_k: Number of top recommendations to return.
            include_baseline: Whether to include simple baselines.

        Returns:
            List of recommendations with name, priority, reason.
        """
        rules = self._recommendation_rules.get(task_type.value, [])
        if not rules:
            rules = self._recommendation_rules.get(TaskType.BINARY_CLASSIFICATION.value, [])

        scored: List[Tuple[float, Dict[str, Any]]] = []

        for rule in rules:
            score = 0.0
            conditions = rule.get("conditions", {})

            # Check sample size conditions
            min_samples = conditions.get("min_samples", 0)
            max_samples = conditions.get("max_samples", float("inf"))
            if profile.n_samples < min_samples:
                continue
            if profile.n_samples > max_samples:
                continue

            # Check feature conditions
            max_features = conditions.get("max_features", float("inf"))
            if profile.n_features > max_features:
                continue

            # Check categorical conditions
            n_cat_required = conditions.get("n_categorical", 0)
            if n_cat_required > 0 and profile.n_categorical < n_cat_required:
                continue

            # Calculate score based on priority and dataset fit
            priority = rule.get("priority", 5)
            score = 10.0 - priority  # Higher priority = higher score

            # Bonus for dataset size match
            if profile.size_category in (DatasetSizeCategory.MEDIUM, DatasetSizeCategory.LARGE):
                if "LightGBM" in rule["name"] or "XGBoost" in rule["name"]:
                    score += 2.0

            # Bonus for categorical features
            if profile.n_categorical > 5 and "CatBoost" in rule["name"]:
                score += 3.0

            # Bonus for high-dimensional data
            if profile.n_features > 1000 and "SVM" in rule["name"]:
                score += 1.0

            # Bonus for severe imbalance
            if profile.imbalance_category in (
                ImbalanceCategory.SEVERE, ImbalanceCategory.EXTREME
            ):
                if "XGBoost" in rule["name"] or "LightGBM" in rule["name"]:
                    score += 2.0  # These handle imbalance well

            scored.append((score, rule))

        # Sort by score descending
        scored.sort(key=lambda x: x[0], reverse=True)

        recommendations = []
        for score, rule in scored[:top_k]:
            recommendations.append({
                "name": rule["name"],
                "score": score,
                "reason": rule.get("reason", ""),
                "priority": rule.get("priority", 5),
            })

        # Add baseline if requested
        if include_baseline and task_type in (
            TaskType.BINARY_CLASSIFICATION,
            TaskType.MULTICLASS_CLASSIFICATION,
        ):
            recommendations.append({
                "name": "DummyClassifier",
                "score": 0.0,
                "reason": "Baseline: always predicts majority class",
                "priority": 10,
            })

        return recommendations


# ═══════════════════════════════════════════════════════════════════════════════
# Cross Validator
# ═══════════════════════════════════════════════════════════════════════════════

class CrossValidator:
    """Adaptive cross-validation strategy selector.

    Automatically selects the best CV strategy based on dataset profile
    and task type.
    """

    def __init__(self, random_state: int = 42):
        self.random_state = random_state

    def get_strategy(
        self,
        profile: DatasetProfile,
        task_type: TaskType = TaskType.BINARY_CLASSIFICATION,
        strategy: Optional[CVStrategy] = None,
        n_folds: int = 5,
    ) -> Dict[str, Any]:
        """Get the appropriate cross-validation strategy.

        Args:
            profile: Dataset profile.
            task_type: Type of ML task.
            strategy: Preferred strategy (None for adaptive).
            n_folds: Number of folds.

        Returns:
            Dictionary with 'strategy', 'splitter', 'n_folds', 'explanation'.
        """
        if strategy is None or strategy == CVStrategy.ADAPTIVE:
            strategy = self._select_strategy(profile, task_type)

        splitter = self._create_splitter(strategy, profile, n_folds)

        return {
            "strategy": strategy,
            "splitter": splitter,
            "n_folds": n_folds,
            "explanation": self._explain_strategy(strategy, profile),
        }

    def _select_strategy(
        self,
        profile: DatasetProfile,
        task_type: TaskType,
    ) -> CVStrategy:
        """Automatically select the best CV strategy."""
        if task_type == TaskType.TIME_SERIES_FORECAST:
            return CVStrategy.TIME_SERIES

        if task_type == TaskType.ANOMALY_DETECTION:
            return CVStrategy.KFOLD

        if profile.n_classes and profile.n_classes >= 2:
            # Check for severe imbalance
            if profile.imbalance_category in (
                ImbalanceCategory.SEVERE, ImbalanceCategory.EXTREME
            ):
                return CVStrategy.STRATIFIED_KFOLD
            return CVStrategy.STRATIFIED_KFOLD

        if profile.n_samples < 100:
            return CVStrategy.LEAVE_ONE_OUT

        if profile.n_samples < 500:
            return CVStrategy.BOOTSTRAP

        return CVStrategy.KFOLD

    def _create_splitter(
        self,
        strategy: CVStrategy,
        profile: DatasetProfile,
        n_folds: int,
    ) -> Any:
        """Create the CV splitter object."""
        if not SKLEARN_AVAILABLE:
            return None

        if strategy == CVStrategy.STRATIFIED_KFOLD:
            return StratifiedKFold(
                n_splits=min(n_folds, profile.n_classes or 2),
                shuffle=True,
                random_state=self.random_state,
            )
        elif strategy == CVStrategy.TIME_SERIES:
            return TimeSeriesSplit(n_splits=n_folds)
        elif strategy == CVStrategy.LEAVE_ONE_OUT:
            return KFold(
                n_splits=min(n_folds, profile.n_samples),
                shuffle=True,
                random_state=self.random_state,
            )
        elif strategy == CVStrategy.BOOTSTRAP:
            return KFold(
                n_splits=n_folds,
                shuffle=True,
                random_state=self.random_state,
            )
        else:
            return KFold(
                n_splits=n_folds,
                shuffle=True,
                random_state=self.random_state,
            )

    def _explain_strategy(
        self,
        strategy: CVStrategy,
        profile: DatasetProfile,
    ) -> str:
        """Generate explanation for strategy choice."""
        explanations = {
            CVStrategy.STRATIFIED_KFOLD: (
                f"Stratified {self.random_state}-fold CV: preserves class distribution "
                f"across folds for {profile.n_classes}-class problem"
            ),
            CVStrategy.TIME_SERIES: (
                "Time series CV: respects temporal order, "
                "prevents future data leakage"
            ),
            CVStrategy.LEAVE_ONE_OUT: (
                f"Leave-one-out: appropriate for small dataset "
                f"({profile.n_samples} samples)"
            ),
            CVStrategy.BOOTSTRAP: (
                f"Bootstrap CV: robust estimation for small dataset "
                f"({profile.n_samples} samples)"
            ),
            CVStrategy.KFOLD: (
                f"Standard {self.random_state}-fold CV: suitable for "
                f"{profile.n_samples} samples with {profile.n_features} features"
            ),
        }
        return explanations.get(strategy, "Adaptive CV strategy")


# ═══════════════════════════════════════════════════════════════════════════════
# Model Wrapper Protocol
# ═══════════════════════════════════════════════════════════════════════════════

class ModelProtocol(Protocol):
    """Protocol for models that can be benchmarked."""
    def fit(self, X: Any, y: Any, **kwargs) -> None: ...
    def predict(self, X: Any) -> Any: ...
    def predict_proba(self, X: Any) -> Any: ...


# ═══════════════════════════════════════════════════════════════════════════════
# Benchmark Suite
# ═══════════════════════════════════════════════════════════════════════════════

class BenchmarkSuite:
    """Run standardized benchmarks on multiple models.

    Provides a unified interface for benchmarking models with:
    - Consistent train/test splits
    - Standardized metrics computation
    - Timing and resource tracking
    - Cross-validation support
    """

    def __init__(
        self,
        config: Optional[BenchmarkConfig] = None,
        profiler: Optional[DatasetProfiler] = None,
        cross_validator: Optional[CrossValidator] = None,
    ):
        self.config = config or BenchmarkConfig()
        self.profiler = profiler or DatasetProfiler(verbose=self.config.verbose > 0)
        self.cross_validator = cross_validator or CrossValidator(
            random_state=self.config.random_state
        )
        self.results: Dict[str, BenchmarkResult] = {}
        self._dataset_profile: Optional[DatasetProfile] = None

    def profile_dataset(
        self,
        X: Union[np.ndarray, pd.DataFrame],
        y: Optional[Union[np.ndarray, pd.Series]] = None,
    ) -> DatasetProfile:
        """Profile the dataset."""
        self._dataset_profile = self.profiler.profile(X, y)
        return self._dataset_profile

    def benchmark(
        self,
        model: Any,
        model_name: str,
        X: Union[np.ndarray, pd.DataFrame],
        y: Union[np.ndarray, pd.Series],
        model_params: Optional[Dict[str, Any]] = None,
        cv: bool = True,
    ) -> BenchmarkResult:
        """Benchmark a single model.

        Args:
            model: Model instance with fit/predict/predict_proba.
            model_name: Name for the model.
            X: Feature matrix.
            y: Target vector.
            model_params: Model parameters used.
            cv: Whether to run cross-validation.

        Returns:
            BenchmarkResult with metrics and timing.
        """
        if not SKLEARN_AVAILABLE:
            return BenchmarkResult(
                model_name=model_name,
                error="scikit-learn not available",
            )

        if self._dataset_profile is None:
            self.profile_dataset(X, y)

        profile = self._dataset_profile
        start_time = time.time()

        try:
            # Train/test split
            X_train, X_test, y_train, y_test = train_test_split(
                X, y,
                test_size=self.config.test_size,
                random_state=self.config.random_state,
                stratify=y if self.config.task_type in (
                    TaskType.BINARY_CLASSIFICATION,
                    TaskType.MULTICLASS_CLASSIFICATION,
                ) else None,
            )

            # Train model
            train_start = time.time()
            model.fit(X_train, y_train)
            training_time = time.time() - train_start

            # Predict
            infer_start = time.time()
            if hasattr(model, "predict_proba") and self.config.task_type in (
                TaskType.BINARY_CLASSIFICATION,
                TaskType.MULTICLASS_CLASSIFICATION,
            ):
                y_prob = model.predict_proba(X_test)
                if len(y_prob.shape) > 1 and y_prob.shape[1] == 2:
                    y_prob = y_prob[:, 1]
            else:
                y_prob = None
            y_pred = model.predict(X_test)
            inference_time = (time.time() - infer_start) / len(X_test) * 1000  # ms per sample

            # Compute metrics
            metrics = self._compute_metrics(y_test, y_pred, y_prob)

            # Cross-validation
            cv_scores = []
            if cv:
                cv_strategy = self.cross_validator.get_strategy(
                    profile, self.config.task_type, n_folds=self.config.n_folds
                )
                splitter = cv_strategy["splitter"]
                if splitter is not None:
                    for train_idx, val_idx in splitter.split(X, y):
                        X_fold_train, X_fold_val = X[train_idx], X[val_idx]
                        y_fold_train, y_fold_val = y[train_idx], y[val_idx]
                        try:
                            fold_model = model.__class__(**model_params) if model_params else model.__class__()
                            fold_model.fit(X_fold_train, y_fold_train)
                            fold_pred = fold_model.predict(X_fold_val)
                            fold_score = self._compute_primary_metric(
                                y_fold_val, fold_pred
                            )
                            cv_scores.append(fold_score)
                        except Exception:
                            continue

            result = BenchmarkResult(
                model_name=model_name,
                model_params=model_params or {},
                metrics=metrics,
                training_time_s=training_time,
                inference_time_ms=inference_time,
                cv_scores=cv_scores,
                dataset_profile=profile.to_dict() if profile else None,
            )

            self.results[model_name] = result
            return result

        except Exception as e:
            logger.error("Benchmark failed for %s: %s", model_name, str(e))
            return BenchmarkResult(
                model_name=model_name,
                error=str(e),
                training_time_s=time.time() - start_time,
            )

    def _compute_metrics(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_prob: Optional[np.ndarray] = None,
    ) -> Dict[str, float]:
        """Compute all requested metrics."""
        if not SKLEARN_AVAILABLE:
            return {}

        metrics = {}
        task = self.config.task_type

        for metric_name in self.config.metrics:
            try:
                if metric_name == "accuracy":
                    metrics[metric_name] = float(accuracy_score(y_true, y_pred))
                elif metric_name == "precision":
                    metrics[metric_name] = float(precision_score(y_true, y_pred, average="binary", zero_division=0))
                elif metric_name == "recall":
                    metrics[metric_name] = float(recall_score(y_true, y_pred, average="binary", zero_division=0))
                elif metric_name == "f1":
                    metrics[metric_name] = float(f1_score(y_true, y_pred, average="binary", zero_division=0))
                elif metric_name == "f1_macro":
                    metrics[metric_name] = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
                elif metric_name == "f1_weighted":
                    metrics[metric_name] = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))
                elif metric_name == "precision_macro":
                    metrics[metric_name] = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
                elif metric_name == "recall_macro":
                    metrics[metric_name] = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
                elif metric_name == "roc_auc" and y_prob is not None:
                    if len(np.unique(y_true)) == 2:
                        metrics[metric_name] = float(roc_auc_score(y_true, y_prob))
                elif metric_name == "average_precision" and y_prob is not None:
                    metrics[metric_name] = float(average_precision_score(y_true, y_prob))
                elif metric_name == "mse":
                    metrics[metric_name] = float(mean_squared_error(y_true, y_pred))
                elif metric_name == "rmse":
                    metrics[metric_name] = float(np.sqrt(mean_squared_error(y_true, y_pred)))
                elif metric_name == "mae":
                    metrics[metric_name] = float(mean_absolute_error(y_true, y_pred))
                elif metric_name == "r2":
                    metrics[metric_name] = float(r2_score(y_true, y_pred))
                elif metric_name == "false_positive_rate":
                    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
                    metrics[metric_name] = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
                elif metric_name == "false_negative_rate":
                    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
                    metrics[metric_name] = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
            except Exception as e:
                logger.debug("Failed to compute metric %s: %s", metric_name, e)
                continue

        return metrics

    def _compute_primary_metric(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
    ) -> float:
        """Compute the primary metric for model selection."""
        primary = self.config.primary_metric
        try:
            if primary in ("f1", "f1_macro", "f1_weighted"):
                return float(f1_score(y_true, y_pred, average=primary.split("_")[-1] if "_" in primary else "binary", zero_division=0))
            elif primary == "accuracy":
                return float(accuracy_score(y_true, y_pred))
            elif primary == "roc_auc":
                return float(roc_auc_score(y_true, y_pred))
            elif primary == "precision":
                return float(precision_score(y_true, y_pred, average="binary", zero_division=0))
            elif primary == "recall":
                return float(recall_score(y_true, y_pred, average="binary", zero_division=0))
            elif primary in ("mse", "rmse"):
                return float(-mean_squared_error(y_true, y_pred))  # Negative for maximization
            elif primary == "r2":
                return float(r2_score(y_true, y_pred))
            else:
                return float(f1_score(y_true, y_pred, average="binary", zero_division=0))
        except Exception:
            return 0.0

    def benchmark_multiple(
        self,
        models: Dict[str, Any],
        X: Union[np.ndarray, pd.DataFrame],
        y: Union[np.ndarray, pd.Series],
        cv: bool = True,
    ) -> Dict[str, BenchmarkResult]:
        """Benchmark multiple models.

        Args:
            models: Dictionary of model_name -> model instance.
            X: Feature matrix.
            y: Target vector.
            cv: Whether to run cross-validation.

        Returns:
            Dictionary of model_name -> BenchmarkResult.
        """
        results = {}
        for name, model in models.items():
            result = self.benchmark(model, name, X, y, cv=cv)
            results[name] = result
            if self.config.verbose > 0:
                status = "✓" if result.success else "✗"
                logger.info("%s %s: %s (%.4f)", status, name, result.error or "OK", result.cv_mean)
        self.results.update(results)
        return results

    def get_leaderboard(
        self,
        metric: Optional[str] = None,
        ascending: bool = False,
    ) -> List[Tuple[str, float]]:
        """Get leaderboard sorted by metric.

        Args:
            metric: Metric to sort by (default: primary_metric).
            ascending: Sort ascending (for minimize metrics).

        Returns:
            List of (model_name, score) sorted by performance.
        """
        metric = metric or self.config.primary_metric
        direction = METRIC_DIRECTIONS.get(metric, MetricDirection.MAXIMIZE)
        ascending = direction == MetricDirection.MINIMIZE

        scores = []
        for name, result in self.results.items():
            if result.success and metric in result.metrics:
                scores.append((name, result.metrics[metric]))
            elif result.success and result.cv_scores:
                scores.append((name, result.cv_mean))

        scores.sort(key=lambda x: x[1], reverse=not ascending)
        return scores

    def get_summary(self) -> Dict[str, Any]:
        """Get benchmark summary."""
        return {
            "n_models": len(self.results),
            "n_successful": sum(1 for r in self.results.values() if r.success),
            "n_failed": sum(1 for r in self.results.values() if not r.success),
            "best_model": self.get_leaderboard()[:1] if self.results else None,
            "config": asdict(self.config),
            "dataset_profile": self._dataset_profile.to_dict() if self._dataset_profile else None,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Auto Model Selector
# ═══════════════════════════════════════════════════════════════════════════════

class AutoModelSelector:
    """Automated model selection using FLAML or Optuna.

    Integrates with FLAML's AutoML for automatic algorithm selection
    and hyperparameter tuning, with Optuna as a fallback.
    """

    def __init__(
        self,
        config: Optional[BenchmarkConfig] = None,
        profiler: Optional[DatasetProfiler] = None,
        recommender: Optional[AlgorithmRecommender] = None,
    ):
        self.config = config or BenchmarkConfig()
        self.profiler = profiler or DatasetProfiler()
        self.recommender = recommender or AlgorithmRecommender()
        self.best_model: Optional[Any] = None
        self.best_params: Dict[str, Any] = {}
        self.best_score: float = 0.0
        self.optimization_history: List[Dict[str, Any]] = []

    def select_with_flaml(
        self,
        X: Union[np.ndarray, pd.DataFrame],
        y: Union[np.ndarray, pd.Series],
        time_budget: Optional[int] = None,
        task: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Select best model using FLAML AutoML.

        Args:
            X: Feature matrix.
            y: Target vector.
            time_budget: Time budget in seconds.
            task: FLAML task type ('classification', 'regression', etc.).

        Returns:
            Dictionary with 'best_model', 'best_config', 'best_score', 'history'.
        """
        if not FLAML_AVAILABLE:
            logger.warning("FLAML not available, falling back to Optuna")
            return self.select_with_optuna(X, y)

        time_budget = time_budget or self.config.timeout_seconds

        # Map task type
        if task is None:
            if self.config.task_type in (
                TaskType.BINARY_CLASSIFICATION,
                TaskType.MULTICLASS_CLASSIFICATION,
            ):
                task = "classification"
            elif self.config.task_type == TaskType.REGRESSION:
                task = "regression"
            else:
                task = "classification"

        try:
            automl = AutoML(
                time_budget=time_budget,
                metric=self.config.primary_metric,
                task=task,
                log_file_name=None,
                verbose=self.config.verbose > 0,
                n_jobs=-1,
            )

            automl.fit(X, y)

            self.best_model = automl
            self.best_params = automl.best_config
            self.best_score = automl.best_loss

            result = {
                "best_model": automl,
                "best_config": automl.best_config,
                "best_score": automl.best_loss,
                "best_estimator": automl.best_estimator,
                "history": [],
            }

            self.optimization_history.append(result)
            return result

        except Exception as e:
            logger.error("FLAML optimization failed: %s", str(e))
            return self.select_with_optuna(X, y)

    def select_with_optuna(
        self,
        X: Union[np.ndarray, pd.DataFrame],
        y: Union[np.ndarray, pd.Series],
        n_trials: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Select best model using Optuna hyperparameter optimization.

        Args:
            X: Feature matrix.
            y: Target vector.
            n_trials: Number of optimization trials.

        Returns:
            Dictionary with 'best_model', 'best_params', 'best_value', 'history'.
        """
        if not OPTUNA_AVAILABLE:
            logger.error("Neither FLAML nor Optuna available")
            return {
                "best_model": None,
                "best_params": {},
                "best_value": 0.0,
                "history": [],
                "error": "No optimization library available",
            }

        n_trials = n_trials or self.config.n_trials

        # Profile dataset for recommendations
        profile = self.profiler.profile(X, y)
        recommendations = self.recommender.recommend(profile, self.config.task_type)

        def objective(trial: optuna.Trial) -> float:
            """Optuna objective function."""
            # Select algorithm based on trial
            algo_idx = trial.suggest_categorical(
                "algorithm",
                [r["name"] for r in recommendations[:5]],
            )

            # Hyperparameters depend on algorithm
            params = {}
            algo_name = recommendations[algo_idx]["name"] if isinstance(algo_idx, int) else algo_idx

            if "LightGBM" in algo_name:
                params["n_estimators"] = trial.suggest_int("n_estimators", 50, 500)
                params["max_depth"] = trial.suggest_int("max_depth", 3, 15)
                params["learning_rate"] = trial.suggest_float("learning_rate", 0.01, 0.3, log=True)
                params["num_leaves"] = trial.suggest_int("num_leaves", 15, 127)
                params["min_child_samples"] = trial.suggest_int("min_child_samples", 5, 100)
                params["subsample"] = trial.suggest_float("subsample", 0.5, 1.0)
                params["colsample_bytree"] = trial.suggest_float("colsample_bytree", 0.5, 1.0)
                params["reg_alpha"] = trial.suggest_float("reg_alpha", 1e-8, 10.0, log=True)
                params["reg_lambda"] = trial.suggest_float("reg_lambda", 1e-8, 10.0, log=True)
            elif "XGBoost" in algo_name:
                params["n_estimators"] = trial.suggest_int("n_estimators", 50, 500)
                params["max_depth"] = trial.suggest_int("max_depth", 3, 15)
                params["learning_rate"] = trial.suggest_float("learning_rate", 0.01, 0.3, log=True)
                params["min_child_weight"] = trial.suggest_int("min_child_weight", 1, 10)
                params["subsample"] = trial.suggest_float("subsample", 0.5, 1.0)
                params["colsample_bytree"] = trial.suggest_float("colsample_bytree", 0.5, 1.0)
                params["gamma"] = trial.suggest_float("gamma", 0.0, 5.0)
                params["reg_alpha"] = trial.suggest_float("reg_alpha", 1e-8, 10.0, log=True)
                params["reg_lambda"] = trial.suggest_float("reg_lambda", 1e-8, 10.0, log=True)
            elif "RandomForest" in algo_name:
                params["n_estimators"] = trial.suggest_int("n_estimators", 50, 500)
                params["max_depth"] = trial.suggest_int("max_depth", 3, 30)
                params["min_samples_split"] = trial.suggest_int("min_samples_split", 2, 20)
                params["min_samples_leaf"] = trial.suggest_int("min_samples_leaf", 1, 10)
                params["max_features"] = trial.suggest_categorical("max_features", ["sqrt", "log2", None])
            elif "CatBoost" in algo_name:
                params["iterations"] = trial.suggest_int("iterations", 50, 500)
                params["depth"] = trial.suggest_int("depth", 3, 10)
                params["learning_rate"] = trial.suggest_float("learning_rate", 0.01, 0.3, log=True)
                params["l2_leaf_reg"] = trial.suggest_float("l2_leaf_reg", 1.0, 10.0)
            else:
                params["n_estimators"] = trial.suggest_int("n_estimators", 50, 200)

            # Train and evaluate
            try:
                X_train, X_val, y_train, y_val = train_test_split(
                    X, y, test_size=0.2, random_state=self.config.random_state
                )

                # Try to import and train the model
                if "LightGBM" in algo_name:
                    try:
                        import lightgbm as lgb
                        model = lgb.LGBMClassifier(**params, random_state=self.config.random_state, verbose=-1)
                    except ImportError:
                        return 0.0
                elif "XGBoost" in algo_name:
                    try:
                        import xgboost as xgb
                        model = xgb.XGBClassifier(**params, random_state=self.config.random_state, verbosity=0)
                    except ImportError:
                        return 0.0
                elif "RandomForest" in algo_name:
                    from sklearn.ensemble import RandomForestClassifier
                    model = RandomForestClassifier(**params, random_state=self.config.random_state, n_jobs=-1)
                elif "CatBoost" in algo_name:
                    try:
                        from catboost import CatBoostClassifier
                        model = CatBoostClassifier(**params, random_state=self.config.random_state, verbose=0)
                    except ImportError:
                        return 0.0
                else:
                    from sklearn.dummy import DummyClassifier
                    model = DummyClassifier(strategy="most_frequent")

                model.fit(X_train, y_train)
                y_pred = model.predict(X_val)
                score = self._compute_primary_metric(y_val, y_pred)

                trial.set_user_attr("model_name", algo_name)
                trial.set_user_attr("params", params)

                return score

            except Exception as e:
                logger.debug("Trial failed: %s", str(e))
                return 0.0

        # Run optimization
        study = optuna.create_study(
            direction="maximize",
            sampler=optuna.samplers.TPESampler(seed=self.config.random_state),
        )
        study.optimize(objective, n_trials=n_trials, show_progress_bar=self.config.verbose > 0)

        # Extract best result
        self.best_score = study.best_value
        if study.best_trial:
            self.best_params = study.best_trial.params
            self.best_params.update(study.best_trial.user_attrs.get("params", {}))

        # Build history
        history = []
        for trial in study.trials:
            if trial.value is not None:
                history.append({
                    "number": trial.number,
                    "value": trial.value,
                    "params": trial.params,
                    "model_name": trial.user_attrs.get("model_name", "unknown"),
                })

        result = {
            "best_model": None,  # Would need to retrain with best params
            "best_params": self.best_params,
            "best_value": study.best_value,
            "best_trial": study.best_trial.number if study.best_trial else None,
            "history": history,
            "n_trials": len(study.trials),
        }

        self.optimization_history.append(result)
        return result

    def _compute_primary_metric(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
    ) -> float:
        """Compute primary metric for optimization."""
        if not SKLEARN_AVAILABLE:
            return 0.0
        try:
            primary = self.config.primary_metric
            if primary == "f1":
                return float(f1_score(y_true, y_pred, average="binary", zero_division=0))
            elif primary == "accuracy":
                return float(accuracy_score(y_true, y_pred))
            elif primary == "roc_auc":
                return float(roc_auc_score(y_true, y_pred))
            elif primary == "precision":
                return float(precision_score(y_true, y_pred, average="binary", zero_division=0))
            elif primary == "recall":
                return float(recall_score(y_true, y_pred, average="binary", zero_division=0))
            else:
                return float(f1_score(y_true, y_pred, average="binary", zero_division=0))
        except Exception:
            return 0.0

    def get_recommendation(
        self,
        profile: DatasetProfile,
        top_k: int = 3,
    ) -> List[Dict[str, Any]]:
        """Get algorithm recommendations for a dataset profile."""
        return self.recommender.recommend(profile, self.config.task_type, top_k=top_k)


# ═══════════════════════════════════════════════════════════════════════════════
# Report Generator
# ═══════════════════════════════════════════════════════════════════════════════

class ReportGenerator:
    """Generate performance comparison reports from benchmark results.

    Produces:
    - JSON reports with full results
    - Markdown comparison tables
    - HTML reports with visualizations (if plotly available)
    - Leaderboard rankings
    """

    def __init__(self, results: Dict[str, BenchmarkResult]):
        self.results = results

    def to_json(self, path: Optional[str] = None) -> str:
        """Generate JSON report.

        Args:
            path: Optional file path to save report.

        Returns:
            JSON string of the report.
        """
        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "n_models": len(self.results),
            "leaderboard": self._build_leaderboard(),
            "results": {
                name: result.to_dict()
                for name, result in self.results.items()
            },
            "summary": self._build_summary(),
        }

        json_str = json.dumps(report, indent=2, default=str)

        if path:
            with open(path, "w") as f:
                f.write(json_str)

        return json_str

    def to_markdown(self) -> str:
        """Generate Markdown comparison table.

        Returns:
            Markdown string with comparison table.
        """
        if not self.results:
            return "# Benchmark Report\n\nNo results to report."

        lines = ["# Benchmark Report\n"]
        lines.append(f"Generated: {datetime.utcnow().isoformat()}\n")
        lines.append(f"Total models: {len(self.results)}\n")

        # Collect all metrics
        all_metrics = set()
        for result in self.results.values():
            all_metrics.update(result.metrics.keys())

        # Sort metrics: primary first, then alphabetically
        primary = None
        for result in self.results.values():
            if result.cv_scores:
                primary = "cv_mean"
                break

        sorted_metrics = sorted(all_metrics)
        if primary and primary in sorted_metrics:
            sorted_metrics.remove(primary)
            sorted_metrics.insert(0, primary)

        # Build table header
        header = ["| Model"]
        for m in sorted_metrics:
            header.append(f" {m}")
        header.append(" |")
        lines.append("".join(header))

        # Separator
        sep = ["| ---"]
        for _ in sorted_metrics:
            sep.append(" ---")
        sep.append(" |")
        lines.append("".join(sep))

        # Sort by primary metric
        leaderboard = self._build_leaderboard()

        for model_name, _ in leaderboard:
            result = self.results.get(model_name)
            if not result or not result.success:
                continue

            row = [f"| **{model_name}**"]
            for m in sorted_metrics:
                if m == "cv_mean" and result.cv_scores:
                    val = f"{result.cv_mean:.4f} ± {result.cv_std:.4f}"
                elif m in result.metrics:
                    val = f"{result.metrics[m]:.4f}"
                else:
                    val = "-"
                row.append(f" {val}")
            row.append(" |")
            lines.append("".join(row))

        # Add timing info
        lines.append("\n## Timing & Resources\n")
        lines.append("| Model | Training (s) | Inference (ms) | Status |")
        lines.append("| --- | --- | --- | --- |")
        for model_name, _ in leaderboard:
            result = self.results.get(model_name)
            if not result:
                continue
            status = "✅" if result.success else "❌"
            lines.append(
                f"| {model_name} | {result.training_time_s:.2f}s | "
                f"{result.inference_time_ms:.4f}ms | {status} |"
            )

        return "\n".join(lines)

    def to_html(self, path: Optional[str] = None) -> str:
        """Generate HTML report.

        Args:
            path: Optional file path to save report.

        Returns:
            HTML string.
        """
        markdown = self.to_markdown()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Benchmark Report - Cyber Global Shield</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               max-width: 1200px; margin: 0 auto; padding: 20px; background: #0d1117; color: #c9d1d9; }}
        h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
        h2 {{ color: #58a6ff; margin-top: 30px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
        th, td {{ border: 1px solid #30363d; padding: 8px 12px; text-align: left; }}
        th {{ background: #161b22; color: #58a6ff; }}
        tr:nth-child(even) {{ background: #161b22; }}
        tr:hover {{ background: #1c2128; }}
        .success {{ color: #3fb950; }}
        .failure {{ color: #f85149; }}
        .summary {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px; margin: 15px 0; }}
        .metric {{ display: inline-block; margin: 5px 10px; }}
        .metric-value {{ font-size: 1.2em; font-weight: bold; color: #d2a8ff; }}
        .metric-label {{ font-size: 0.8em; color: #8b949e; }}
    </style>
</head>
<body>
    <h1>🔬 Benchmark Report</h1>
    <p>Generated: {datetime.utcnow().isoformat()}</p>
    <div class="summary">
        <h2>Summary</h2>
        <div class="metric">
            <div class="metric-value">{len(self.results)}</div>
            <div class="metric-label">Models Tested</div>
        </div>
        <div class="metric">
            <div class="metric-value">{sum(1 for r in self.results.values() if r.success)}</div>
            <div class="metric-label">Successful</div>
        </div>
        <div class="metric">
            <div class="metric-value">{sum(1 for r in self.results.values() if not r.success)}</div>
            <div class="metric-label">Failed</div>
        </div>
    </div>
    <pre style="background: #161b22; padding: 15px; border-radius: 6px; overflow-x: auto;">
{markdown}
    </pre>
</body>
</html>"""

        if path:
            with open(path, "w") as f:
                f.write(html)

        return html

    def _build_leaderboard(self) -> List[Tuple[str, float]]:
        """Build leaderboard sorted by best available metric."""
        scores = []
        for name, result in self.results.items():
            if not result.success:
                continue
            if result.cv_scores:
                scores.append((name, result.cv_mean))
            elif result.metrics:
                # Use first available metric
                first_metric = list(result.metrics.keys())[0]
                scores.append((name, result.metrics[first_metric]))
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores

    def _build_summary(self) -> Dict[str, Any]:
        """Build summary statistics."""
        successful = [r for r in self.results.values() if r.success]
        return {
            "total_models": len(self.results),
            "successful": len(successful),
            "failed": len(self.results) - len(successful),
            "avg_training_time": float(np.mean([r.training_time_s for r in successful])) if successful else 0.0,
            "avg_inference_time": float(np.mean([r.inference_time_ms for r in successful])) if successful else 0.0,
            "best_model": self._build_leaderboard()[:1] if self.results else None,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Factory Functions
# ═══════════════════════════════════════════════════════════════════════════════

def create_benchmark_suite(
    task_type: TaskType = TaskType.BINARY_CLASSIFICATION,
    primary_metric: str = "f1",
    n_folds: int = 5,
    verbose: bool = True,
) -> BenchmarkSuite:
    """Create a benchmark suite with default configuration.

    Args:
        task_type: Type of ML task.
        primary_metric: Primary metric for model selection.
        n_folds: Number of CV folds.
        verbose: Enable verbose logging.

    Returns:
        Configured BenchmarkSuite.
    """
    config = BenchmarkConfig(
        task_type=task_type,
        primary_metric=primary_metric,
        n_folds=n_folds,
        verbose=1 if verbose else 0,
    )
    return BenchmarkSuite(config=config)


def create_auto_model_selector(
    task_type: TaskType = TaskType.BINARY_CLASSIFICATION,
    primary_metric: str = "f1",
    n_trials: int = 50,
    timeout_seconds: int = 3600,
) -> AutoModelSelector:
    """Create an automated model selector.

    Args:
        task_type: Type of ML task.
        primary_metric: Primary metric for optimization.
        n_trials: Number of Optuna trials.
        timeout_seconds: Timeout for FLAML.

    Returns:
        Configured AutoModelSelector.
    """
    config = BenchmarkConfig(
        task_type=task_type,
        primary_metric=primary_metric,
        n_trials=n_trials,
        timeout_seconds=timeout_seconds,
    )
    return AutoModelSelector(config=config)


def create_report_generator(
    results: Dict[str, BenchmarkResult],
) -> ReportGenerator:
    """Create a report generator from benchmark results.

    Args:
        results: Dictionary of model_name -> BenchmarkResult.

    Returns:
        ReportGenerator instance.
    """
    return ReportGenerator(results=results)


def run_full_benchmark(
    models: Dict[str, Any],
    X: Union[np.ndarray, pd.DataFrame],
    y: Union[np.ndarray, pd.Series],
    task_type: TaskType = TaskType.BINARY_CLASSIFICATION,
    primary_metric: str = "f1",
    report_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Run a full benchmark workflow: profile -> benchmark -> report.

    Args:
        models: Dictionary of model_name -> model instance.
        X: Feature matrix.
        y: Target vector.
        task_type: Type of ML task.
        primary_metric: Primary metric for model selection.
        report_path: Optional path to save report.

    Returns:
        Dictionary with 'suite', 'results', 'report_json', 'leaderboard'.
    """
    suite = create_benchmark_suite(
        task_type=task_type,
        primary_metric=primary_metric,
    )

    # Profile dataset
    profile = suite.profile_dataset(X, y)
    logger.info(
        "Dataset: %d samples, %d features, %s",
        profile.n_samples, profile.n_features, profile.size_category.value,
    )

    # Run benchmarks
    results = suite.benchmark_multiple(models, X, y)

    # Generate report
    report_gen = ReportGenerator(results)
    report_json = report_gen.to_json(report_path)

    if report_path:
        report_gen.to_html(report_path.replace(".json", ".html"))

    return {
        "suite": suite,
        "results": results,
        "report_json": report_json,
        "leaderboard": suite.get_leaderboard(),
        "summary": suite.get_summary(),
    }


__all__ = [
    # Enums
    "TaskType",
    "CVStrategy",
    "MetricDirection",
    "DatasetSizeCategory",
    "SparsityCategory",
    "ImbalanceCategory",

    # Data classes
    "BenchmarkConfig",
    "BenchmarkResult",
    "DatasetProfile",

    # Core components
    "DatasetProfiler",
    "AlgorithmRecommender",
    "CrossValidator",
    "BenchmarkSuite",
    "AutoModelSelector",
    "ReportGenerator",

    # Factory functions
    "create_benchmark_suite",
    "create_auto_model_selector",
    "create_report_generator",
    "run_full_benchmark",
]
