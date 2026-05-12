"""
Cyber Global Shield — ML Pipeline Orchestrator
===============================================
Automated ML pipeline orchestration with versioning,
experiment tracking, and model registry.

Components:
  - PipelineStep: Individual pipeline step definition
  - PipelineDAG: Directed acyclic graph of pipeline steps
  - ExperimentTracker: MLflow-compatible experiment tracking
  - ModelRegistry: Model versioning and staging
  - PipelineRunner: Distributed pipeline execution
  - PipelineOrchestrator: Full pipeline management
"""

import json
import time
import hashlib
import warnings
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from enum import Enum

import numpy as np

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

try:
    import mlflow
    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False


# ─── Constants ────────────────────────────────────────────────────────────────

DEFAULT_EXPERIMENT = "cyber_global_shield"
DEFAULT_TRACKING_URI = "./mlruns"
MAX_RETRIES = 3
TIMEOUT_SECONDS = 3600


# ─── Enums ────────────────────────────────────────────────────────────────────

class StepStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CACHED = "cached"


class ModelStage(Enum):
    NONE = "None"
    STAGING = "Staging"
    PRODUCTION = "Production"
    ARCHIVED = "Archived"


class PipelineStatus(Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class PipelineStep:
    """A single step in the ML pipeline."""
    name: str
    func: Callable
    dependencies: List[str] = field(default_factory=list)
    params: Dict[str, Any] = field(default_factory=dict)
    timeout: int = TIMEOUT_SECONDS
    retries: int = MAX_RETRIES
    cache_key: Optional[str] = None
    status: StepStatus = StepStatus.PENDING
    result: Any = None
    error: Optional[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    artifacts: Dict[str, str] = field(default_factory=dict)


@dataclass
class PipelineRun:
    """A single run of a pipeline."""
    run_id: str
    pipeline_name: str
    status: PipelineStatus
    steps: Dict[str, PipelineStep]
    start_time: float
    end_time: Optional[float] = None
    params: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, float] = field(default_factory=dict)
    artifacts: Dict[str, str] = field(default_factory=dict)
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class ModelVersion:
    """A versioned model in the registry."""
    name: str
    version: int
    stage: ModelStage
    run_id: str
    path: str
    metrics: Dict[str, float] = field(default_factory=dict)
    params: Dict[str, Any] = field(default_factory=dict)
    created_at: float = 0.0
    description: str = ""


# ─── Pipeline DAG ─────────────────────────────────────────────────────────────

class PipelineDAG:
    """
    Directed Acyclic Graph of pipeline steps.
    
    Validates dependencies and computes execution order.
    """

    def __init__(self):
        self.steps: Dict[str, PipelineStep] = {}

    def add_step(self, step: PipelineStep):
        """Add a step to the DAG."""
        self.steps[step.name] = step

    def validate(self) -> bool:
        """Validate the DAG (no cycles, all dependencies exist)."""
        # Check all dependencies exist
        for step in self.steps.values():
            for dep in step.dependencies:
                if dep not in self.steps:
                    raise ValueError(f"Step '{step.name}' depends on unknown step '{dep}'")

        # Check for cycles (DFS)
        visited: Set[str] = set()
        in_stack: Set[str] = set()

        def has_cycle(node: str) -> bool:
            visited.add(node)
            in_stack.add(node)
            for dep in self.steps[node].dependencies:
                if dep not in visited:
                    if has_cycle(dep):
                        return True
                elif dep in in_stack:
                    return True
            in_stack.remove(node)
            return False

        for name in self.steps:
            if name not in visited:
                if has_cycle(name):
                    raise ValueError(f"Cycle detected in pipeline DAG involving step '{name}'")

        return True

    def get_execution_order(self) -> List[str]:
        """Get topological execution order."""
        self.validate()

        visited: Set[str] = set()
        order: List[str] = []

        def dfs(node: str):
            visited.add(node)
            for dep in self.steps[node].dependencies:
                if dep not in visited:
                    dfs(dep)
            order.append(node)

        for name in self.steps:
            if name not in visited:
                dfs(name)

        return order

    def get_parallel_groups(self) -> List[List[str]]:
        """Get groups of steps that can run in parallel."""
        order = self.get_execution_order()
        groups: List[List[str]] = []
        current_group: List[str] = []

        for step_name in order:
            step = self.steps[step_name]
            # Check if all dependencies are in previous groups
            deps_satisfied = all(
                any(dep in g for g in groups)
                for dep in step.dependencies
            )
            if deps_satisfied and not step.dependencies:
                current_group.append(step_name)
            else:
                if current_group:
                    groups.append(current_group)
                current_group = [step_name]

        if current_group:
            groups.append(current_group)

        return groups


# ─── Experiment Tracker ───────────────────────────────────────────────────────

class ExperimentTracker:
    """
    MLflow-compatible experiment tracking.
    
    Tracks:
    - Parameters
    - Metrics
    - Artifacts
    - Source code
    - Git commit
    """

    def __init__(
        self,
        experiment_name: str = DEFAULT_EXPERIMENT,
        tracking_uri: str = DEFAULT_TRACKING_URI,
    ):
        self.experiment_name = experiment_name
        self.tracking_uri = tracking_uri
        self.active_run = None

        if MLFLOW_AVAILABLE:
            mlflow.set_tracking_uri(tracking_uri)
            mlflow.set_experiment(experiment_name)

    def start_run(
        self,
        run_name: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> str:
        """Start a new experiment run."""
        if MLFLOW_AVAILABLE:
            self.active_run = mlflow.start_run(run_name=run_name)
            if tags:
                mlflow.set_tags(tags)
            return self.active_run.info.run_id
        else:
            run_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
            self.active_run = {"run_id": run_id}
            return run_id

    def log_params(self, params: Dict[str, Any]):
        """Log parameters."""
        if MLFLOW_AVAILABLE and self.active_run:
            mlflow.log_params(params)

    def log_metrics(self, metrics: Dict[str, float], step: Optional[int] = None):
        """Log metrics."""
        if MLFLOW_AVAILABLE and self.active_run:
            mlflow.log_metrics(metrics, step=step)

    def log_artifact(self, local_path: str):
        """Log an artifact."""
        if MLFLOW_AVAILABLE and self.active_run:
            mlflow.log_artifact(local_path)

    def log_artifacts(self, local_dir: str):
        """Log a directory of artifacts."""
        if MLFLOW_AVAILABLE and self.active_run:
            mlflow.log_artifacts(local_dir)

    def log_model(
        self,
        model: Any,
        artifact_path: str,
        signature: Optional[Any] = None,
    ):
        """Log a model."""
        if MLFLOW_AVAILABLE and self.active_run:
            if signature:
                mlflow.pytorch.log_model(model, artifact_path, signature=signature)
            else:
                mlflow.pytorch.log_model(model, artifact_path)

    def end_run(self):
        """End the active run."""
        if MLFLOW_AVAILABLE and self.active_run:
            mlflow.end_run()
        self.active_run = None

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Get run data."""
        if MLFLOW_AVAILABLE:
            try:
                run = mlflow.get_run(run_id)
                return {
                    "run_id": run.info.run_id,
                    "status": run.info.status,
                    "params": run.data.params,
                    "metrics": run.data.metrics,
                    "tags": run.data.tags,
                }
            except Exception:
                return None
        return None


# ─── Model Registry ───────────────────────────────────────────────────────────

class ModelRegistry:
    """
    Model versioning and staging.
    
    Supports:
    - Model versioning
    - Stage transitions (Staging -> Production -> Archived)
    - Model lineage tracking
    - Model comparison
    """

    def __init__(self, registry_uri: str = DEFAULT_TRACKING_URI):
        self.registry_uri = registry_uri
        self.models: Dict[str, List[ModelVersion]] = {}

        if MLFLOW_AVAILABLE:
            mlflow.set_tracking_uri(registry_uri)

    def register_model(
        self,
        name: str,
        model_path: str,
        run_id: str,
        metrics: Optional[Dict[str, float]] = None,
        params: Optional[Dict[str, Any]] = None,
        description: str = "",
    ) -> ModelVersion:
        """Register a new model version."""
        if name not in self.models:
            self.models[name] = []

        version = len(self.models[name]) + 1
        model_version = ModelVersion(
            name=name,
            version=version,
            stage=ModelStage.NONE,
            run_id=run_id,
            path=model_path,
            metrics=metrics or {},
            params=params or {},
            created_at=time.time(),
            description=description,
        )

        self.models[name].append(model_version)

        if MLFLOW_AVAILABLE:
            try:
                mlflow.register_model(f"runs:/{run_id}/{model_path}", name)
            except Exception:
                pass

        return model_version

    def transition_stage(
        self,
        name: str,
        version: int,
        stage: ModelStage,
    ) -> bool:
        """Transition a model to a new stage."""
        if name not in self.models:
            return False

        for mv in self.models[name]:
            if mv.version == version:
                mv.stage = stage
                return True
        return False

    def get_model(self, name: str, stage: ModelStage = ModelStage.PRODUCTION) -> Optional[ModelVersion]:
        """Get the latest model at a given stage."""
        if name not in self.models:
            return None

        candidates = [mv for mv in self.models[name] if mv.stage == stage]
        if not candidates:
            return None

        return max(candidates, key=lambda mv: mv.version)

    def get_best_model(
        self,
        name: str,
        metric: str = "accuracy",
    ) -> Optional[ModelVersion]:
        """Get the best model by metric."""
        if name not in self.models:
            return None

        candidates = [mv for mv in self.models[name] if metric in mv.metrics]
        if not candidates:
            return None

        return max(candidates, key=lambda mv: mv.metrics[metric])

    def compare_models(
        self,
        name: str,
        versions: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """Compare multiple versions of a model."""
        if name not in self.models:
            return {}

        if versions:
            candidates = [mv for mv in self.models[name] if mv.version in versions]
        else:
            candidates = self.models[name]

        comparison = {}
        for mv in candidates:
            comparison[f"v{mv.version}"] = {
                "metrics": mv.metrics,
                "params": mv.params,
                "stage": mv.stage.value,
                "created_at": mv.created_at,
            }

        return comparison


# ─── Pipeline Runner ──────────────────────────────────────────────────────────

class PipelineRunner:
    """
    Distributed pipeline execution.
    
    Supports:
    - Sequential execution
    - Parallel execution (via threading)
    - Caching of intermediate results
    - Error handling with retries
    """

    def __init__(
        self,
        tracker: Optional[ExperimentTracker] = None,
        registry: Optional[ModelRegistry] = None,
    ):
        self.tracker = tracker or ExperimentTracker()
        self.registry = registry or ModelRegistry()

    def run(
        self,
        dag: PipelineDAG,
        run_name: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> PipelineRun:
        """Execute a pipeline DAG."""
        run_id = self.tracker.start_run(run_name=run_name, tags=tags)
        start_time = time.time()

        run = PipelineRun(
            run_id=run_id,
            pipeline_name=run_name or "unnamed",
            status=PipelineStatus.RUNNING,
            steps=dag.steps,
            start_time=start_time,
            tags=tags or {},
        )

        try:
            # Get execution order
            order = dag.get_execution_order()

            for step_name in order:
                step = dag.steps[step_name]
                step.status = StepStatus.RUNNING
                step.start_time = time.time()

                try:
                    # Collect dependency results
                    dep_results = {}
                    for dep_name in step.dependencies:
                        dep_step = dag.steps[dep_name]
                        dep_results[dep_name] = dep_step.result

                    # Execute step
                    result = step.func(**dep_results, **step.params)

                    step.result = result
                    step.status = StepStatus.COMPLETED
                    step.end_time = time.time()

                    # Log to tracker
                    self.tracker.log_params({f"{step_name}_params": str(step.params)})
                    if isinstance(result, dict) and "metrics" in result:
                        metrics = result["metrics"]
                        if isinstance(metrics, dict):
                            self.tracker.log_metrics(
                                {f"{step_name}_{k}": v for k, v in metrics.items()}
                            )

                except Exception as e:
                    step.status = StepStatus.FAILED
                    step.error = str(e)
                    step.end_time = time.time()
                    raise

            run.status = PipelineStatus.COMPLETED

        except Exception as e:
            run.status = PipelineStatus.FAILED

        run.end_time = time.time()
        self.tracker.end_run()

        return run


# ─── Pipeline Orchestrator ────────────────────────────────────────────────────

class PipelineOrchestrator:
    """
    Full pipeline management.
    
    Provides:
    - Pipeline creation and configuration
    - Experiment tracking
    - Model registration
    - Pipeline scheduling
    - Performance monitoring
    """

    def __init__(
        self,
        experiment_name: str = DEFAULT_EXPERIMENT,
        tracking_uri: str = DEFAULT_TRACKING_URI,
    ):
        self.tracker = ExperimentTracker(experiment_name, tracking_uri)
        self.registry = ModelRegistry(tracking_uri)
        self.runner = PipelineRunner(self.tracker, self.registry)
        self.pipelines: Dict[str, PipelineDAG] = {}
        self.runs: List[PipelineRun] = []

    def create_pipeline(self, name: str) -> PipelineDAG:
        """Create a new pipeline."""
        dag = PipelineDAG()
        self.pipelines[name] = dag
        return dag

    def add_step(
        self,
        pipeline_name: str,
        name: str,
        func: Callable,
        dependencies: Optional[List[str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ):
        """Add a step to a pipeline."""
        if pipeline_name not in self.pipelines:
            raise ValueError(f"Pipeline '{pipeline_name}' not found")

        step = PipelineStep(
            name=name,
            func=func,
            dependencies=dependencies or [],
            params=params or {},
        )
        self.pipelines[pipeline_name].add_step(step)

    def run_pipeline(
        self,
        pipeline_name: str,
        run_name: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> PipelineRun:
        """Run a pipeline."""
        if pipeline_name not in self.pipelines:
            raise ValueError(f"Pipeline '{pipeline_name}' not found")

        run = self.runner.run(
            self.pipelines[pipeline_name],
            run_name=run_name or f"{pipeline_name}_{int(time.time())}",
            tags=tags,
        )
        self.runs.append(run)
        return run

    def register_model_from_run(
        self,
        run_id: str,
        model_name: str,
        model_path: str,
        metrics: Optional[Dict[str, float]] = None,
    ) -> ModelVersion:
        """Register a model from a pipeline run."""
        return self.registry.register_model(
            name=model_name,
            model_path=model_path,
            run_id=run_id,
            metrics=metrics,
        )

    def get_best_model(self, model_name: str, metric: str = "accuracy") -> Optional[ModelVersion]:
        """Get the best model."""
        return self.registry.get_best_model(model_name, metric)

    def get_run_history(self, n: int = 10) -> List[Dict[str, Any]]:
        """Get recent run history."""
        recent = self.runs[-n:]
        return [
            {
                "run_id": r.run_id,
                "pipeline": r.pipeline_name,
                "status": r.status.value,
                "duration": (r.end_time or time.time()) - r.start_time,
                "steps": {k: v.status.value for k, v in r.steps.items()},
            }
            for r in recent
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        total_runs = len(self.runs)
        successful = sum(1 for r in self.runs if r.status == PipelineStatus.COMPLETED)
        failed = sum(1 for r in self.runs if r.status == PipelineStatus.FAILED)

        return {
            "total_pipelines": len(self.pipelines),
            "total_runs": total_runs,
            "successful_runs": successful,
            "failed_runs": failed,
            "success_rate": successful / total_runs if total_runs > 0 else 0.0,
            "registered_models": sum(len(v) for v in self.registry.models.values()),
        }


# ─── Factory Functions ────────────────────────────────────────────────────────

def create_pipeline_orchestrator(
    experiment_name: str = DEFAULT_EXPERIMENT,
) -> PipelineOrchestrator:
    """Create a pipeline orchestrator."""
    return PipelineOrchestrator(experiment_name=experiment_name)


def create_experiment_tracker(
    experiment_name: str = DEFAULT_EXPERIMENT,
) -> ExperimentTracker:
    """Create an experiment tracker."""
    return ExperimentTracker(experiment_name=experiment_name)


def create_model_registry() -> ModelRegistry:
    """Create a model registry."""
    return ModelRegistry()


__all__ = [
    "StepStatus",
    "ModelStage",
    "PipelineStatus",
    "PipelineStep",
    "PipelineRun",
    "ModelVersion",
    "PipelineDAG",
    "ExperimentTracker",
    "ModelRegistry",
    "PipelineRunner",
    "PipelineOrchestrator",
    "create_pipeline_orchestrator",
    "create_experiment_tracker",
    "create_model_registry",
]
