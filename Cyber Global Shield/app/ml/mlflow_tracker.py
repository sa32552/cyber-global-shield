"""
Cyber Global Shield — MLflow Experiment Tracking & Model Drift Detection
Track experiments, log metrics, detect data drift, and manage model versions.
"""

import os
import json
import time
import hashlib
import tempfile
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, field

import numpy as np
import structlog
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score

from app.core.config import settings

logger = structlog.get_logger(__name__)

# Try to import MLflow (optional dependency)
try:
    import mlflow
    import mlflow.pytorch
    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False
    logger.warning("mlflow_not_available", message="Install mlflow: pip install mlflow")


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class ExperimentRun:
    """Represents a single ML experiment run."""
    run_id: str
    experiment_name: str
    start_time: str
    end_time: Optional[str] = None
    status: str = "running"
    params: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, float] = field(default_factory=dict)
    artifacts: List[str] = field(default_factory=list)
    model_path: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    dataset_hash: Optional[str] = None
    git_commit: Optional[str] = None

@dataclass
class DriftReport:
    """Data drift detection report."""
    timestamp: str
    feature_name: str
    drift_score: float
    drift_detected: bool
    reference_mean: float
    current_mean: float
    reference_std: float
    current_std: float
    ks_statistic: Optional[float] = None
    psi_value: Optional[float] = None
    sample_size_reference: int = 0
    sample_size_current: int = 0


# =============================================================================
# MLflow Tracker
# =============================================================================

class MLflowTracker:
    """
    ML experiment tracking with MLflow.
    Falls back to local JSON logging if MLflow is not available.
    """

    def __init__(self, experiment_name: str = "cyber_global_shield"):
        self.experiment_name = experiment_name
        self.current_run: Optional[ExperimentRun] = None
        self._runs: Dict[str, ExperimentRun] = {}
        self._local_log_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "data", "mlflow_logs"
        )
        os.makedirs(self._local_log_path, exist_ok=True)

        if MLFLOW_AVAILABLE:
            try:
                mlflow.set_tracking_uri(
                    os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5000")
                )
                mlflow.set_experiment(experiment_name)
                logger.info("mlflow_initialized", experiment=experiment_name)
            except Exception as e:
                logger.warning("mlflow_init_failed", error=str(e))

    def start_run(
        self,
        run_name: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        dataset_hash: Optional[str] = None,
    ) -> str:
        """Start a new experiment run."""
        run_id = hashlib.sha256(
            f"{self.experiment_name}_{time.time()}_{np.random.rand()}".encode()
        ).hexdigest()[:16]

        run = ExperimentRun(
            run_id=run_id,
            experiment_name=self.experiment_name,
            start_time=datetime.now(timezone.utc).isoformat(),
            params=params or {},
            tags=tags or {},
            dataset_hash=dataset_hash,
        )

        self.current_run = run
        self._runs[run_id] = run

        # MLflow integration
        if MLFLOW_AVAILABLE:
            try:
                with mlflow.start_run(run_name=run_name or run_id) as active_run:
                    if tags:
                        mlflow.set_tags(tags)
                    if params:
                        mlflow.log_params(params)
                    run.run_id = active_run.info.run_id
            except Exception as e:
                logger.warning("mlflow_start_run_failed", error=str(e))

        logger.info(
            "experiment_run_started",
            run_id=run_id,
            experiment=self.experiment_name,
            params=params,
        )

        return run_id

    def log_metric(self, key: str, value: float, step: Optional[int] = None):
        """Log a metric for the current run."""
        if self.current_run:
            self.current_run.metrics[key] = value

            if MLFLOW_AVAILABLE:
                try:
                    mlflow.log_metric(key, value, step=step or 0)
                except Exception:
                    pass

    def log_metrics(self, metrics: Dict[str, float], step: Optional[int] = None):
        """Log multiple metrics."""
        for key, value in metrics.items():
            self.log_metric(key, value, step=step)

    def log_params(self, params: Dict[str, Any]):
        """Log parameters."""
        if self.current_run:
            self.current_run.params.update(params)

            if MLFLOW_AVAILABLE:
                try:
                    mlflow.log_params(params)
                except Exception:
                    pass

    def log_artifact(self, local_path: str, artifact_path: Optional[str] = None):
        """Log an artifact file."""
        if self.current_run:
            self.current_run.artifacts.append(local_path)

            if MLFLOW_AVAILABLE:
                try:
                    mlflow.log_artifact(local_path, artifact_path=artifact_path)
                except Exception:
                    pass

    def log_model(self, model, model_name: str = "anomaly_detector"):
        """Log a PyTorch model."""
        if self.current_run and MLFLOW_AVAILABLE:
            try:
                mlflow.pytorch.log_model(model, model_name)
                self.current_run.model_path = model_name
                logger.info("model_logged_to_mlflow", model_name=model_name)
            except Exception as e:
                logger.warning("mlflow_log_model_failed", error=str(e))

    def end_run(self, status: str = "completed"):
        """End the current run."""
        if self.current_run:
            self.current_run.end_time = datetime.now(timezone.utc).isoformat()
            self.current_run.status = status

            # Save local log
            self._save_local_log(self.current_run)

            if MLFLOW_AVAILABLE:
                try:
                    mlflow.end_run(status=status)
                except Exception:
                    pass

            logger.info(
                "experiment_run_ended",
                run_id=self.current_run.run_id,
                status=status,
                metrics=self.current_run.metrics,
            )

            self.current_run = None

    def get_run(self, run_id: str) -> Optional[ExperimentRun]:
        """Get a run by ID."""
        return self._runs.get(run_id)

    def get_best_run(self, metric: str = "validation_loss", minimize: bool = True) -> Optional[ExperimentRun]:
        """Get the best run based on a metric."""
        completed_runs = [
            r for r in self._runs.values()
            if r.status == "completed" and metric in r.metrics
        ]
        if not completed_runs:
            return None

        return min(completed_runs, key=lambda r: r.metrics[metric]) if minimize \
            else max(completed_runs, key=lambda r: r.metrics[metric])

    def list_runs(self, status: Optional[str] = None) -> List[ExperimentRun]:
        """List all runs, optionally filtered by status."""
        if status:
            return [r for r in self._runs.values() if r.status == status]
        return list(self._runs.values())

    def _save_local_log(self, run: ExperimentRun):
        """Save run data to local JSON file."""
        filepath = os.path.join(self._local_log_path, f"run_{run.run_id}.json")
        with open(filepath, "w") as f:
            json.dump({
                "run_id": run.run_id,
                "experiment_name": run.experiment_name,
                "start_time": run.start_time,
                "end_time": run.end_time,
                "status": run.status,
                "params": run.params,
                "metrics": run.metrics,
                "artifacts": run.artifacts,
                "model_path": run.model_path,
                "tags": run.tags,
                "dataset_hash": run.dataset_hash,
            }, f, indent=2)


# Global MLflow tracker instance
mlflow_tracker = MLflowTracker()


# =============================================================================
# Data Drift Detector
# =============================================================================

class DataDriftDetector:
    """
    Detects data drift between reference and current data distributions.
    Uses statistical tests: KS-test, PSI (Population Stability Index).
    """

    def __init__(self, drift_threshold: float = 0.1):
        self.drift_threshold = drift_threshold
        self._reference_stats: Dict[str, Dict[str, float]] = {}
        self._drift_reports: List[DriftReport] = []
        self._concept_drift_count = 0

    def set_reference(self, data: np.ndarray, feature_names: Optional[List[str]] = None):
        """
        Set the reference distribution (training data).
        data: shape (n_samples, n_features)
        """
        if len(data.shape) == 1:
            data = data.reshape(-1, 1)

        n_features = data.shape[1]
        names = feature_names or [f"feature_{i}" for i in range(n_features)]

        for i in range(n_features):
            self._reference_stats[names[i]] = {
                "mean": float(np.mean(data[:, i])),
                "std": float(np.std(data[:, i])),
                "min": float(np.min(data[:, i])),
                "max": float(np.max(data[:, i])),
                "p5": float(np.percentile(data[:, i], 5)),
                "p25": float(np.percentile(data[:, i], 25)),
                "p50": float(np.percentile(data[:, i], 50)),
                "p75": float(np.percentile(data[:, i], 75)),
                "p95": float(np.percentile(data[:, i], 95)),
                "samples": data.shape[0],
            }

        logger.info(
            "reference_distribution_set",
            n_features=n_features,
            n_samples=data.shape[0],
        )

    def detect_drift(
        self,
        current_data: np.ndarray,
        feature_names: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Detect drift in current data compared to reference.
        Returns a comprehensive drift report.
        """
        if not self._reference_stats:
            return {"error": "Reference distribution not set. Call set_reference() first."}

        if len(current_data.shape) == 1:
            current_data = current_data.reshape(-1, 1)

        n_features = current_data.shape[1]
        names = feature_names or [f"feature_{i}" for i in range(n_features)]

        drift_results = []
        overall_drift_score = 0.0
        features_with_drift = 0

        for i in range(n_features):
            feature_name = names[i] if i < len(names) else f"feature_{i}"
            ref_stats = self._reference_stats.get(feature_name)

            if ref_stats is None:
                continue

            current_feature = current_data[:, i]
            current_mean = float(np.mean(current_feature))
            current_std = float(np.std(current_feature))

            # Calculate drift score using normalized difference
            mean_diff = abs(current_mean - ref_stats["mean"])
            std_diff = abs(current_std - ref_stats["std"])

            # Normalized drift score (0 to 1+)
            drift_score = (mean_diff / (ref_stats["std"] + 1e-8)) + (std_diff / (ref_stats["std"] + 1e-8))
            drift_score = drift_score / 2  # Average of mean and std drift

            # KS statistic approximation
            ks_stat = self._calculate_ks_statistic(
                current_feature,
                ref_stats["mean"],
                ref_stats["std"],
            )

            # PSI (Population Stability Index)
            psi = self._calculate_psi(
                current_feature,
                ref_stats["mean"],
                ref_stats["std"],
                ref_stats["p5"],
                ref_stats["p95"],
            )

            drift_detected = drift_score > self.drift_threshold

            report = DriftReport(
                timestamp=datetime.now(timezone.utc).isoformat(),
                feature_name=feature_name,
                drift_score=round(drift_score, 4),
                drift_detected=drift_detected,
                reference_mean=ref_stats["mean"],
                current_mean=round(current_mean, 4),
                reference_std=ref_stats["std"],
                current_std=round(current_std, 4),
                ks_statistic=round(ks_stat, 4),
                psi_value=round(psi, 4),
                sample_size_reference=ref_stats["samples"],
                sample_size_current=len(current_feature),
            )

            self._drift_reports.append(report)
            drift_results.append(report)

            if drift_detected:
                features_with_drift += 1
                overall_drift_score += drift_score

        # Calculate overall drift
        overall_drift_score = overall_drift_score / max(len(drift_results), 1)
        concept_drift = overall_drift_score > self.drift_threshold * 2

        if concept_drift:
            self._concept_drift_count += 1
            logger.warning(
                "concept_drift_detected",
                drift_score=overall_drift_score,
                features_with_drift=features_with_drift,
                total_features=len(drift_results),
            )

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_drift_score": round(overall_drift_score, 4),
            "drift_detected": overall_drift_score > self.drift_threshold,
            "concept_drift_detected": concept_drift,
            "features_with_drift": features_with_drift,
            "total_features": len(drift_results),
            "threshold": self.drift_threshold,
            "feature_reports": [
                {
                    "feature": r.feature_name,
                    "drift_score": r.drift_score,
                    "drift_detected": r.drift_detected,
                    "reference_mean": r.reference_mean,
                    "current_mean": r.current_mean,
                    "ks_statistic": r.ks_statistic,
                    "psi_value": r.psi_value,
                }
                for r in drift_results
            ],
            "recommendation": self._get_recommendation(overall_drift_score, features_with_drift, len(drift_results)),
        }

    def get_drift_history(self, n_last: int = 10) -> List[DriftReport]:
        """Get the last N drift reports."""
        return self._drift_reports[-n_last:]

    def get_drift_summary(self) -> Dict[str, Any]:
        """Get a summary of all drift detections."""
        if not self._drift_reports:
            return {"message": "No drift checks performed yet"}

        total_checks = len(self._drift_reports)
        drift_events = sum(1 for r in self._drift_reports if r.drift_detected)
        avg_drift_score = np.mean([r.drift_score for r in self._drift_reports])

        return {
            "total_checks": total_checks,
            "drift_events": drift_events,
            "drift_rate": round(drift_events / total_checks * 100, 2),
            "average_drift_score": round(float(avg_drift_score), 4),
            "concept_drift_count": self._concept_drift_count,
            "threshold": self.drift_threshold,
            "last_check": self._drift_reports[-1].timestamp if self._drift_reports else None,
            "status": "healthy" if drift_events / max(total_checks, 1) < 0.1 else "degraded",
        }

    def _calculate_ks_statistic(self, data: np.ndarray, ref_mean: float, ref_std: float) -> float:
        """Approximate KS statistic between data and normal distribution."""
        from scipy import stats
        try:
            _, p_value = stats.ks_2samp(data, np.random.normal(ref_mean, ref_std, len(data)))
            return float(p_value)
        except Exception:
            return 0.5

    def _calculate_psi(self, data: np.ndarray, ref_mean: float, ref_std: float,
                       ref_p5: float, ref_p95: float) -> float:
        """Calculate Population Stability Index."""
        # Create bins based on reference distribution
        bins = np.linspace(ref_p5, ref_p95, 10)
        expected = np.ones(len(bins) + 1) / (len(bins) + 1)

        # Count actual observations in bins
        actual_counts, _ = np.histogram(data, bins=bins)
        actual = actual_counts / max(len(data), 1)

        # Avoid division by zero
        actual = np.clip(actual, 0.001, 1.0)
        expected = np.clip(expected, 0.001, 1.0)

        # Calculate PSI
        psi = np.sum((actual - expected) * np.log(actual / expected))
        return float(psi)

    def _get_recommendation(self, drift_score: float, drifted_features: int, total_features: int) -> str:
        """Generate recommendation based on drift analysis."""
        if drift_score > self.drift_threshold * 3:
            return (
                "CRITICAL: Significant data drift detected. "
                "Immediate model retraining recommended. "
                "Consider rolling back to previous model version."
            )
        elif drift_score > self.drift_threshold * 2:
            return (
                "WARNING: Moderate data drift detected. "
                "Schedule model retraining within 24 hours. "
                "Monitor model performance closely."
            )
        elif drift_score > self.drift_threshold:
            return (
                "INFO: Mild data drift detected. "
                "Continue monitoring. No immediate action required."
            )
        else:
            return "OK: No significant drift detected. Model is performing as expected."


# Global drift detector instance
drift_detector = DataDriftDetector()


# =============================================================================
# Model Performance Monitor
# =============================================================================

class ModelPerformanceMonitor:
    """
    Monitors model performance metrics over time.
    Tracks precision, recall, F1, ROC-AUC, and latency.
    """

    def __init__(self):
        self._predictions: List[Dict] = []
        self._latencies: List[float] = []
        self._max_history = 10000

    def log_prediction(
        self,
        y_true: float,
        y_pred: float,
        anomaly_score: float,
        latency_ms: float,
        features: Optional[Dict] = None,
    ):
        """Log a single prediction for performance tracking."""
        self._predictions.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "y_true": y_true,
            "y_pred": y_pred,
            "anomaly_score": anomaly_score,
            "latency_ms": latency_ms,
            "features": features,
        })
        self._latencies.append(latency_ms)

        # Trim history
        if len(self._predictions) > self._max_history:
            self._predictions = self._predictions[-self._max_history:]
            self._latencies = self._latencies[-self._max_history:]

    def get_performance_metrics(self, n_last: int = 1000) -> Dict[str, Any]:
        """Calculate performance metrics over the last N predictions."""
        recent = self._predictions[-n_last:] if self._predictions else []

        if len(recent) < 10:
            return {"message": "Insufficient data for performance metrics"}

        y_true = [p["y_true"] for p in recent]
        y_pred = [p["y_pred"] for p in recent]
        scores = [p["anomaly_score"] for p in recent]

        metrics = {
            "samples": len(recent),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
            "avg_anomaly_score": float(np.mean(scores)),
            "anomaly_rate": float(np.mean(y_pred)),
            "avg_latency_ms": float(np.mean(self._latencies[-n_last:])),
            "p95_latency_ms": float(np.percentile(self._latencies[-n_last:], 95)),
            "p99_latency_ms": float(np.percentile(self._latencies[-n_last:], 99)),
        }

        # Calculate ROC-AUC if we have both classes
        if len(set(y_true)) > 1:
            try:
                metrics["roc_auc"] = float(roc_auc_score(y_true, scores))
            except Exception:
                metrics["roc_auc"] = 0.0

        return metrics

    def get_latency_trend(self, window: int = 100) -> List[Dict]:
        """Get latency trend over time."""
        if len(self._latencies) < window:
            return []

        trends = []
        for i in range(0, len(self._latencies), window):
            chunk = self._latencies[i:i + window]
            trends.append({
                "window_start": i,
                "window_end": i + len(chunk),
                "avg_latency_ms": float(np.mean(chunk)),
                "p95_latency_ms": float(np.percentile(chunk, 95)),
                "max_latency_ms": float(np.max(chunk)),
            })

        return trends


# Global performance monitor instance
performance_monitor = ModelPerformanceMonitor()
