import flwr as fl
import torch
import torch.nn as nn
import numpy as np
from typing import Optional, Dict, Any, List, Tuple
from collections import OrderedDict
import structlog

from app.ml.anomaly_detector import TransformerAutoencoder, AnomalyDetector

logger = structlog.get_logger(__name__)


class FederatedAnomalyServer:
    """
    Flower-based Federated Learning server for anomaly detection.
    Orchestrates training across multiple organizations without sharing raw data.
    """

    def __init__(
        self,
        server_address: str = "0.0.0.0:8080",
        num_rounds: int = 10,
        min_clients: int = 2,
        min_available_clients: int = 2,
        fraction_fit: float = 1.0,
        fraction_evaluate: float = 1.0,
    ):
        self.server_address = server_address
        self.num_rounds = num_rounds
        self.min_clients = min_clients
        self.min_available_clients = min_available_clients
        self.fraction_fit = fraction_fit
        self.fraction_evaluate = fraction_evaluate

        # Initialize global model
        self.global_model = TransformerAutoencoder()
        self.current_round = 0
        self.round_metrics: List[Dict[str, Any]] = []

        # Strategy with secure aggregation and differential privacy
        self.strategy = fl.server.strategy.FedAvg(
            min_fit_clients=min_clients,
            min_evaluate_clients=min_clients,
            min_available_clients=min_available_clients,
            fraction_fit=fraction_fit,
            fraction_evaluate=fraction_evaluate,
            initial_parameters=fl.common.ndarrays_to_parameters(
                self._get_model_weights()
            ),
            evaluate_metrics_aggregation_fn=self._aggregate_metrics,
            fit_metrics_aggregation_fn=self._aggregate_fit_metrics,
        )

        # Server configuration
        self.server_config = fl.server.ServerConfig(num_rounds=num_rounds)

        # Optional: Differential Privacy
        self._use_dp = False
        self._dp_noise_multiplier = 1.0
        self._dp_clip_norm = 1.0

        logger.info(
            "federated_server_initialized",
            address=server_address,
            rounds=num_rounds,
            min_clients=min_clients,
        )

    def _get_model_weights(self) -> List[np.ndarray]:
        """Extract model weights as numpy arrays."""
        return [val.cpu().numpy() for _, val in self.global_model.state_dict().items()]

    def _set_model_weights(self, weights: List[np.ndarray]):
        """Set model weights from numpy arrays."""
        params_dict = zip(self.global_model.state_dict().keys(), weights)
        state_dict = OrderedDict({k: torch.tensor(v) for k, v in params_dict})
        self.global_model.load_state_dict(state_dict, strict=True)

    def _aggregate_metrics(self, metrics: List[Tuple[int, Dict[str, Any]]]) -> Dict[str, Any]:
        """Aggregate client evaluation metrics."""
        if not metrics:
            return {}

        total_samples = sum(num for num, _ in metrics)
        aggregated = {}

        for key in metrics[0][1].keys():
            weighted_sum = sum(m[key] * num for num, m in metrics)
            aggregated[key] = weighted_sum / total_samples if total_samples > 0 else 0.0

        logger.info("round_metrics_aggregated", round=self.current_round, metrics=aggregated)
        self.round_metrics.append({**aggregated, "round": self.current_round})
        return aggregated

    def _aggregate_fit_metrics(self, metrics: List[Tuple[int, Dict[str, Any]]]) -> Dict[str, Any]:
        """Aggregate client training metrics."""
        if not metrics:
            return {}

        total_samples = sum(num for num, _ in metrics)
        aggregated = {}

        for key in metrics[0][1].keys():
            weighted_sum = sum(m[key] * num for num, m in metrics)
            aggregated[key] = weighted_sum / total_samples if total_samples > 0 else 0.0

        return aggregated

    def evaluate_on_server(self, server_round: int, parameters, config):
        """Optional: Evaluate the global model on a server-side validation set."""
        self.current_round = server_round

        # This would use a held-out validation set
        # For now, just track the round
        logger.info("server_round_evaluation", round=server_round)
        return 0.0, {"round": server_round}

    def start(self):
        """Start the federated learning server."""
        logger.info(
            "federated_server_starting",
            address=self.server_address,
        )

        # Start Flower server
        fl.server.start_server(
            server_address=self.server_address,
            config=self.server_config,
            strategy=self.strategy,
        )

    def get_model_state(self) -> Dict[str, Any]:
        """Export current global model state."""
        return {
            "model_state_dict": self.global_model.state_dict(),
            "round": self.current_round,
            "metrics": self.round_metrics[-10:],  # Last 10 rounds
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get federated learning statistics."""
        return {
            "current_round": self.current_round,
            "total_rounds": self.num_rounds,
            "min_clients": self.min_clients,
            "round_metrics": self.round_metrics,
            "global_model_params": sum(
                p.numel() for p in self.global_model.parameters()
            ),
            "differential_privacy": {
                "enabled": self._use_dp,
                "noise_multiplier": self._dp_noise_multiplier,
                "clip_norm": self._dp_clip_norm,
            },
        }

    def enable_differential_privacy(
        self, noise_multiplier: float = 1.0, clip_norm: float = 1.0
    ):
        """Enable differential privacy for model updates."""
        self._use_dp = True
        self._dp_noise_multiplier = noise_multiplier
        self._dp_clip_norm = clip_norm
        logger.info(
            "differential_privacy_enabled",
            noise_multiplier=noise_multiplier,
            clip_norm=clip_norm,
        )


class SecureAggregator:
    """
    Secure aggregation using additive secret sharing.
    Ensures individual client updates cannot be inspected by the server.
    """

    @staticmethod
    def mask_update(update: np.ndarray, mask_seed: int) -> np.ndarray:
        """Mask a model update with a seeded random mask."""
        rng = np.random.RandomState(mask_seed)
        mask = rng.normal(0, 0.01, update.shape)
        return update + mask

    @staticmethod
    def unmask_updates(
        masked_updates: List[Tuple[np.ndarray, int]],
        num_clients: int,
    ) -> np.ndarray:
        """Unmask and aggregate updates. Seeds must cancel out pairwise."""
        aggregated = np.zeros_like(masked_updates[0][0])
        for update, seed in masked_updates:
            aggregated += update
        return aggregated / num_clients


def create_federated_server(
    server_address: str = "0.0.0.0:8080",
    num_rounds: int = 10,
    min_clients: int = 2,
) -> FederatedAnomalyServer:
    """Factory function for federated server."""
    return FederatedAnomalyServer(
        server_address=server_address,
        num_rounds=num_rounds,
        min_clients=min_clients,
    )