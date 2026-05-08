"""
Ray Jobs for Cyber Global Shield.
Distributed threat detection, batch ML inference, and parallel SOAR execution
using Ray for horizontal scaling across multiple nodes.
"""

import os
import sys
import json
import time
import structlog
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone

import numpy as np

# Make app importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

logger = structlog.get_logger(__name__)

try:
    import ray
    RAY_AVAILABLE = True
except ImportError:
    RAY_AVAILABLE = False
    logger.warning("ray_not_available", message="Install with: pip install ray")


# ─── Configuration ───────────────────────────────────────────────────────

@dataclass
class RayJobConfig:
    """Configuration for Ray jobs."""
    num_cpus: int = 4
    num_gpus: int = 0
    object_store_memory: int = 2_000_000_000  # 2GB
    batch_size: int = 1000
    max_concurrent_tasks: int = 10
    timeout_seconds: int = 300


# ─── Remote Functions ────────────────────────────────────────────────────

@ray.remote(num_cpus=1)
def threat_detection_batch(
    logs: List[Dict[str, Any]],
    model_path: str,
    threshold: float = 0.95,
) -> List[Dict[str, Any]]:
    """
    Run ML anomaly detection on a batch of logs in parallel.
    
    Args:
        logs: List of log entries to analyze
        model_path: Path to trained model checkpoint
        threshold: Anomaly score threshold
        
    Returns:
        List of detection results with anomaly scores
    """
    try:
        from app.ml.anomaly_detector import AnomalyDetector

        detector = AnomalyDetector(
            model_path=model_path,
            device="cpu",
        )
        detector.threshold = threshold

        results = []
        for log in logs:
            try:
                result = detector.detect([log])
                results.append({
                    "log": log,
                    "anomaly_score": float(result.anomaly_score),
                    "is_anomaly": bool(result.is_anomaly),
                    "reconstruction_error": float(result.reconstruction_error),
                    "explanation": result.explanation,
                    "inference_time_ms": result.inference_time_ms,
                })
            except Exception as e:
                results.append({
                    "log": log,
                    "error": str(e),
                    "is_anomaly": False,
                })

        return results

    except Exception as e:
        logger.error("threat_detection_failed", error=str(e))
        return [{"log": log, "error": str(e), "is_anomaly": False} for log in logs]


@ray.remote(num_cpus=1)
def train_fl_local(
    client_id: str,
    global_params: Optional[List[np.ndarray]] = None,
    num_samples: int = 1000,
    local_epochs: int = 5,
) -> Dict[str, Any]:
    """
    Train a federated learning model on local data using Ray.
    
    Args:
        client_id: Unique client identifier
        global_params: Global model parameters from server (optional)
        num_samples: Number of local samples to use
        local_epochs: Number of local training epochs
        
    Returns:
        Dict with updated parameters and metrics
    """
    try:
        from flower_client import FlowerClient, FLConfig

        config = FLConfig(
            client_id=client_id,
            num_samples=num_samples,
            local_epochs=local_epochs,
        )
        client = FlowerClient(config)

        if global_params:
            client.set_parameters(global_params)

        params = client.get_parameters()
        updated_params, n, metrics = client.fit(params, {"local_epochs": local_epochs})

        return {
            "client_id": client_id,
            "parameters": updated_params,
            "num_samples": n,
            "metrics": metrics,
            "status": "completed",
        }

    except Exception as e:
        logger.error("fl_training_failed", client_id=client_id, error=str(e))
        return {
            "client_id": client_id,
            "status": "failed",
            "error": str(e),
        }


@ray.remote(num_cpus=1)
def soar_playbook_execution(
    playbook_name: str,
    alert: Dict[str, Any],
    context: Dict[str, Any],
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    Execute a SOAR playbook in a Ray task.
    
    Args:
        playbook_name: Name of the playbook to execute
        alert: Alert data
        context: Additional context (IOCs, etc.)
        dry_run: If True, simulate execution without side effects
        
    Returns:
        Playbook execution result
    """
    try:
        from app.soar.playbook_engine import SOAREngine
        import asyncio

        engine = SOAREngine()

        async def run():
            return await engine.execute_playbook(
                playbook_name=playbook_name,
                alert=alert,
                context=context,
                dry_run=dry_run,
            )

        result = asyncio.run(run())

        return {
            "playbook": playbook_name,
            "status": result.status.value if hasattr(result.status, 'value') else str(result.status),
            "duration_ms": result.duration_ms,
            "actions": [
                {
                    "name": a.name,
                    "status": a.status.value if hasattr(a.status, 'value') else str(a.status),
                    "duration_ms": a.duration_ms,
                }
                for a in (result.actions_results or [])
            ],
            "alert_id": alert.get("id", "unknown"),
        }

    except Exception as e:
        logger.error("soar_execution_failed", playbook=playbook_name, error=str(e))
        return {
            "playbook": playbook_name,
            "status": "failed",
            "error": str(e),
        }


@ray.remote(num_cpus=1)
def log_enrichment_batch(
    logs: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Enrich logs with MITRE ATT&CK mapping and threat intelligence in parallel.
    
    Args:
        logs: List of raw log entries
        
    Returns:
        Enriched log entries
    """
    try:
        from app.ingestion.pipeline import IngestionPipeline

        pipeline = IngestionPipeline()
        enriched = []

        for log in logs:
            try:
                normalized = pipeline.normalize_log(log)
                enriched_log = pipeline.enrich_log(normalized)
                enriched.append(enriched_log)
            except Exception as e:
                enriched.append({**log, "enrichment_error": str(e)})

        return enriched

    except Exception as e:
        logger.error("enrichment_failed", error=str(e))
        return logs


@ray.remote(num_cpus=1)
def dataset_generation(
    num_sequences: int = 1000,
    seq_length: int = 64,
    anomaly_probability: float = 0.1,
    seed: int = 42,
) -> Dict[str, Any]:
    """
    Generate synthetic network security dataset using Ray.
    
    Args:
        num_sequences: Number of sequences to generate
        seq_length: Length of each sequence
        anomaly_probability: Fraction of anomalous sequences
        seed: Random seed
        
    Returns:
        Dict with generated data shapes and stats
    """
    try:
        from app.ml.dataset_generator import NetworkLogGenerator

        generator = NetworkLogGenerator(seed=seed)
        X, y = generator.generate_sequences(
            num_sequences=num_sequences,
            seq_length=seq_length,
            anomaly_probability=anomaly_probability,
        )

        return {
            "X_shape": list(X.shape),
            "y_shape": list(y.shape),
            "num_normal": int(np.sum(y == 0)),
            "num_anomalies": int(np.sum(y == 1)),
            "anomaly_ratio": float(np.mean(y)),
            "status": "completed",
        }

    except Exception as e:
        logger.error("dataset_generation_failed", error=str(e))
        return {"status": "failed", "error": str(e)}


# ─── Job Orchestrator ────────────────────────────────────────────────────

class RayJobOrchestrator:
    """
    Orchestrates distributed Ray jobs for Cyber Global Shield.
    Manages parallel execution of threat detection, FL training,
    SOAR playbooks, and log enrichment across a Ray cluster.
    """

    def __init__(self, config: Optional[RayJobConfig] = None):
        self.config = config or RayJobConfig()
        self._initialized = False

    def initialize(self, address: Optional[str] = None):
        """Initialize Ray runtime."""
        if not RAY_AVAILABLE:
            logger.error("ray_not_available")
            return False

        if not ray.is_initialized():
            try:
                ray.init(
                    address=address,
                    num_cpus=self.config.num_cpus,
                    num_gpus=self.config.num_gpus,
                    object_store_memory=self.config.object_store_memory,
                    ignore_reinit_error=True,
                )
                logger.info(
                    "ray_initialized",
                    dashboard=ray.get_dashboard_url(),
                    nodes=len(ray.nodes()),
                )
            except Exception as e:
                logger.error("ray_init_failed", error=str(e))
                return False

        self._initialized = True
        return True

    def shutdown(self):
        """Shutdown Ray runtime."""
        if ray.is_initialized():
            ray.shutdown()
            self._initialized = False
            logger.info("ray_shutdown")

    async def run_batch_threat_detection(
        self,
        logs: List[Dict[str, Any]],
        model_path: str,
        threshold: float = 0.95,
    ) -> List[Dict[str, Any]]:
        """
        Run threat detection on logs in parallel batches.
        
        Args:
            logs: All logs to analyze
            model_path: Path to trained model
            threshold: Anomaly threshold
            
        Returns:
            Combined detection results
        """
        if not self._initialized:
            self.initialize()

        # Split into batches
        batch_size = self.config.batch_size
        batches = [
            logs[i:i + batch_size]
            for i in range(0, len(logs), batch_size)
        ]

        logger.info(
            "running_batch_detection",
            total_logs=len(logs),
            batches=len(batches),
        )

        # Launch parallel tasks
        tasks = [
            threat_detection_batch.remote(batch, model_path, threshold)
            for batch in batches
        ]

        # Gather results
        all_results = []
        for task in tasks:
            try:
                batch_results = ray.get(task, timeout=self.config.timeout_seconds)
                all_results.extend(batch_results)
            except ray.exceptions.GetTimeoutError:
                logger.error("batch_timeout")
            except Exception as e:
                logger.error("batch_failed", error=str(e))

        logger.info(
            "batch_detection_complete",
            total=len(all_results),
            anomalies=sum(1 for r in all_results if r.get("is_anomaly")),
        )

        return all_results

    async def run_parallel_soar(
        self,
        alerts: List[Dict[str, Any]],
        playbook_name: str = "brute_force_response",
        dry_run: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Execute SOAR playbooks for multiple alerts in parallel.
        
        Args:
            alerts: List of alerts to process
            playbook_name: Playbook to execute for each alert
            dry_run: If True, simulate execution
            
        Returns:
            List of execution results
        """
        if not self._initialized:
            self.initialize()

        tasks = []
        for alert in alerts:
            context = {
                "iocs": {
                    "ips": [alert.get("src_ip", "")],
                    "domains": [],
                },
                "alert": alert,
            }
            task = soar_playbook_execution.remote(
                playbook_name=playbook_name,
                alert=alert,
                context=context,
                dry_run=dry_run,
            )
            tasks.append(task)

        results = []
        for task in tasks:
            try:
                result = ray.get(task, timeout=self.config.timeout_seconds)
                results.append(result)
            except Exception as e:
                results.append({"status": "failed", "error": str(e)})

        return results

    async def run_federated_learning_round(
        self,
        client_ids: List[str],
        global_params: Optional[List[np.ndarray]] = None,
        num_samples: int = 1000,
        local_epochs: int = 5,
    ) -> Dict[str, Any]:
        """
        Run a federated learning round across multiple clients in parallel.
        
        Args:
            client_ids: List of client identifiers
            global_params: Global model parameters (optional)
            num_samples: Samples per client
            local_epochs: Epochs per client
            
        Returns:
            Aggregated FL round results
        """
        if not self._initialized:
            self.initialize()

        tasks = [
            train_fl_local.remote(
                client_id=cid,
                global_params=global_params,
                num_samples=num_samples,
                local_epochs=local_epochs,
            )
            for cid in client_ids
        ]

        client_results = []
        for task in tasks:
            try:
                result = ray.get(task, timeout=self.config.timeout_seconds)
                client_results.append(result)
            except Exception as e:
                logger.error("fl_client_failed", error=str(e))

        # Aggregate results
        successful = [r for r in client_results if r.get("status") == "completed"]
        total_samples = sum(r.get("num_samples", 0) for r in successful)

        # FedAvg: weighted average of parameters
        if successful and global_params:
            aggregated = [
                np.zeros_like(p)
                for p in global_params
            ]
            for r in successful:
                weight = r["num_samples"] / total_samples
                for i, param in enumerate(r["parameters"]):
                    aggregated[i] += weight * param
        else:
            aggregated = global_params

        return {
            "num_clients": len(client_ids),
            "successful_clients": len(successful),
            "total_samples": total_samples,
            "aggregated_parameters": aggregated,
            "client_results": [
                {
                    "client_id": r["client_id"],
                    "num_samples": r.get("num_samples", 0),
                    "loss": r.get("metrics", {}).get("loss"),
                }
                for r in successful
            ],
            "failed_clients": [
                r["client_id"]
                for r in client_results
                if r.get("status") != "completed"
            ],
        }

    def get_cluster_stats(self) -> Dict[str, Any]:
        """Get Ray cluster statistics."""
        if not ray.is_initialized():
            return {"status": "not_initialized"}

        try:
            return {
                "status": "running",
                "dashboard_url": ray.get_dashboard_url(),
                "num_nodes": len(ray.nodes()),
                "num_cpus": ray.cluster_resources().get("CPU", 0),
                "num_gpus": ray.cluster_resources().get("GPU", 0),
                "object_store_memory": ray.cluster_resources().get("object_store_memory", 0),
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}


# ─── CLI Entry Point ─────────────────────────────────────────────────────

def run_job():
    """CLI entry point for running Ray jobs."""
    import argparse

    parser = argparse.ArgumentParser(description="Cyber Global Shield Ray Jobs")
    parser.add_argument("--job", required=True, choices=[
        "threat_detection", "fl_training", "soar_execution",
        "enrichment", "dataset_gen", "cluster_info",
    ], help="Job type to run")
    parser.add_argument("--address", help="Ray cluster address")
    parser.add_argument("--input", help="Input file (JSON)")
    parser.add_argument("--output", help="Output file (JSON)")
    parser.add_argument("--dry-run", action="store_true", help="Simulate execution")
    args = parser.parse_args()

    orchestrator = RayJobOrchestrator()
    orchestrator.initialize(address=args.address)

    if args.job == "cluster_info":
        stats = orchestrator.get_cluster_stats()
        print(json.dumps(stats, indent=2))
        return

    # Load input data if provided
    input_data = None
    if args.input:
        with open(args.input, "r") as f:
            input_data = json.load(f)

    # Run the specified job
    import asyncio

    async def run():
        if args.job == "threat_detection":
            logs = input_data.get("logs", []) if input_data else []
            model_path = input_data.get("model_path", "app/ml/models/trained_model.pt") if input_data else "app/ml/models/trained_model.pt"
            threshold = input_data.get("threshold", 0.95) if input_data else 0.95
            results = await orchestrator.run_batch_threat_detection(logs, model_path, threshold)

        elif args.job == "fl_training":
            client_ids = input_data.get("client_ids", [f"client-{i:03d}" for i in range(5)]) if input_data else [f"client-{i:03d}" for i in range(5)]
            results = await orchestrator.run_federated_learning_round(client_ids)

        elif args.job == "soar_execution":
            alerts = input_data.get("alerts", []) if input_data else []
            playbook = input_data.get("playbook", "brute_force_response") if input_data else "brute_force_response"
            results = await orchestrator.run_parallel_soar(alerts, playbook, args.dry_run)

        elif args.job == "enrichment":
            logs = input_data.get("logs", []) if input_data else []
            tasks = [log_enrichment_batch.remote(logs[i:i+100]) for i in range(0, len(logs), 100)]
            results = []
            for t in tasks:
                results.extend(ray.get(t))

        elif args.job == "dataset_gen":
            num = input_data.get("num_sequences", 1000) if input_data else 1000
            result = ray.get(dataset_generation.remote(num_sequences=num))
            results = result

        # Save output
        output = {
            "job": args.job,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "results": results if isinstance(results, list) else [results],
        }

        output_path = args.output or f"ray_job_{args.job}_{int(time.time())}.json"
        with open(output_path, "w") as f:
            json.dump(output, f, indent=2, default=str)

        print(f"\n✅ Job '{args.job}' completed")
        print(f"   Output: {output_path}")
        print(f"   Results: {len(output['results'])} items")

    asyncio.run(run())
    orchestrator.shutdown()


if __name__ == "__main__":
    run_job()
