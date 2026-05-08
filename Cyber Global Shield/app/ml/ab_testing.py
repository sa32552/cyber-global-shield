"""
Cyber Global Shield — A/B Testing Framework for ML Models
Permet de comparer les performances de différents modèles en production.
"""

import json
import random
import logging
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from enum import Enum
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class ExperimentStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class ModelVariant(BaseModel):
    """A model variant in an A/B test."""
    name: str
    version: str
    weight: float  # Traffic weight (0.0 to 1.0)
    metrics: Dict[str, float] = {}
    samples: int = 0
    is_control: bool = False


class ABExperiment(BaseModel):
    """An A/B testing experiment."""
    id: str
    name: str
    description: str
    status: ExperimentStatus = ExperimentStatus.RUNNING
    variants: List[ModelVariant]
    created_at: datetime = datetime.utcnow()
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    min_samples: int = 1000
    confidence_level: float = 0.95
    metric_name: str = "f1_score"
    winner: Optional[str] = None


class ABTestingService:
    """
    A/B testing service for ML models.
    Routes traffic between model variants and evaluates performance.
    """

    def __init__(self):
        self._experiments: Dict[str, ABExperiment] = {}
        self._results: Dict[str, List[Dict]] = {}

    def create_experiment(
        self,
        name: str,
        description: str,
        variants: List[Dict[str, Any]],
        min_samples: int = 1000,
        metric_name: str = "f1_score",
    ) -> ABExperiment:
        """Create a new A/B experiment."""
        experiment_id = f"exp_{datetime.utcnow().timestamp()}"

        # Normalize weights
        total_weight = sum(v.get("weight", 1.0) for v in variants)
        model_variants = []
        for i, v in enumerate(variants):
            model_variants.append(ModelVariant(
                name=v["name"],
                version=v.get("version", "1.0.0"),
                weight=v.get("weight", 1.0) / total_weight,
                is_control=i == 0,
            ))

        experiment = ABExperiment(
            id=experiment_id,
            name=name,
            description=description,
            variants=model_variants,
            min_samples=min_samples,
            metric_name=metric_name,
            started_at=datetime.utcnow(),
        )

        self._experiments[experiment_id] = experiment
        self._results[experiment_id] = []

        logger.info(
            f"Experiment created: {name} ({experiment_id}) "
            f"with {len(variants)} variants"
        )

        return experiment

    def select_variant(self, experiment_id: str) -> Optional[ModelVariant]:
        """
        Select a variant based on traffic weights.
        Returns None if experiment is not running.
        """
        experiment = self._experiments.get(experiment_id)
        if not experiment or experiment.status != ExperimentStatus.RUNNING:
            return None

        # Weighted random selection
        r = random.random()
        cumulative = 0.0
        for variant in experiment.variants:
            cumulative += variant.weight
            if r <= cumulative:
                return variant

        return experiment.variants[-1]

    def record_result(
        self,
        experiment_id: str,
        variant_name: str,
        metrics: Dict[str, float],
    ):
        """Record a result for a variant."""
        experiment = self._experiments.get(experiment_id)
        if not experiment:
            return

        # Update variant metrics
        for variant in experiment.variants:
            if variant.name == variant_name:
                variant.samples += 1
                # Running average
                for key, value in metrics.items():
                    if key in variant.metrics:
                        n = variant.samples
                        variant.metrics[key] = (
                            (variant.metrics[key] * (n - 1) + value) / n
                        )
                    else:
                        variant.metrics[key] = value
                break

        # Store raw result
        self._results[experiment_id].append({
            "variant": variant_name,
            "metrics": metrics,
            "timestamp": datetime.utcnow().isoformat(),
        })

        # Check if experiment should be evaluated
        self._evaluate_experiment(experiment_id)

    def _evaluate_experiment(self, experiment_id: str):
        """Evaluate if experiment has enough data to determine winner."""
        experiment = self._experiments.get(experiment_id)
        if not experiment or experiment.status != ExperimentStatus.RUNNING:
            return

        # Check if all variants have minimum samples
        min_samples_met = all(
            v.samples >= experiment.min_samples
            for v in experiment.variants
        )

        if not min_samples_met:
            return

        # Find the best variant
        best_variant = max(
            experiment.variants,
            key=lambda v: v.metrics.get(experiment.metric_name, 0),
        )

        # Check if the difference is statistically significant
        if self._is_significant(experiment, best_variant):
            experiment.winner = best_variant.name
            experiment.status = ExperimentStatus.COMPLETED
            experiment.completed_at = datetime.utcnow()

            logger.info(
                f"Experiment {experiment.name} completed! "
                f"Winner: {best_variant.name} "
                f"({experiment.metric_name}: {best_variant.metrics.get(experiment.metric_name, 0):.4f})"
            )

    def _is_significant(
        self, experiment: ABExperiment, best: ModelVariant,
    ) -> bool:
        """Simple statistical significance check."""
        # Get control variant
        control = next(
            (v for v in experiment.variants if v.is_control),
            experiment.variants[0],
        )

        if control.name == best.name:
            return False

        best_metric = best.metrics.get(experiment.metric_name, 0)
        control_metric = control.metrics.get(experiment.metric_name, 0)

        if control_metric == 0:
            return best_metric > 0

        # Simple improvement threshold (5% improvement)
        improvement = (best_metric - control_metric) / control_metric
        return improvement > 0.05

    def get_experiment(self, experiment_id: str) -> Optional[ABExperiment]:
        """Get experiment details."""
        return self._experiments.get(experiment_id)

    def list_experiments(
        self, status: Optional[ExperimentStatus] = None,
    ) -> List[ABExperiment]:
        """List all experiments, optionally filtered by status."""
        if status:
            return [
                e for e in self._experiments.values()
                if e.status == status
            ]
        return list(self._experiments.values())

    def rollback_experiment(self, experiment_id: str):
        """Rollback an experiment to control variant."""
        experiment = self._experiments.get(experiment_id)
        if experiment:
            experiment.status = ExperimentStatus.ROLLED_BACK
            experiment.completed_at = datetime.utcnow()
            experiment.winner = next(
                (v.name for v in experiment.variants if v.is_control),
                experiment.variants[0].name,
            )
            logger.info(f"Experiment {experiment.name} rolled back to control")

    def get_experiment_report(self, experiment_id: str) -> Dict[str, Any]:
        """Generate a detailed report for an experiment."""
        experiment = self._experiments.get(experiment_id)
        if not experiment:
            return {"error": "Experiment not found"}

        return {
            "experiment": experiment.dict(),
            "results": self._results.get(experiment_id, []),
            "summary": {
                "total_samples": sum(v.samples for v in experiment.variants),
                "best_variant": experiment.winner,
                "status": experiment.status.value,
                "duration": (
                    str(experiment.completed_at - experiment.started_at)
                    if experiment.completed_at and experiment.started_at
                    else "running"
                ),
            },
        }


# Global A/B testing service
ab_testing_service = ABTestingService()
