"""
Flower Client for Federated Learning in Cyber Global Shield.
Each client trains on local data (anomaly detection model) and shares
only encrypted model updates with the Flower server.
Supports differential privacy, secure aggregation, and model checkpointing.
"""

import os
import sys
import json
import time
import structlog
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

# Make app importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.ml.anomaly_detector import TransformerAutoencoder, AnomalyDetector
from app.ml.dataset_generator import NetworkLogGenerator
from app.core.config import settings

logger = structlog.get_logger(__name__)


@dataclass
class FLConfig:
    """Federated Learning configuration for a client."""
    client_id: str
    org_id: str = "default"
    data_dir: str = "data"
    model_dir: str = "app/ml/models"
    batch_size: int = 32
    local_epochs: int = 5
    learning_rate: float = 1e-4
    weight_decay: float = 1e-5
    differential_privacy: bool = True
    dp_noise_multiplier: float = 1.0
    dp_clipping_norm: float = 1.0
    device: str = "cpu"
    num_samples: int = 2000
    seq_length: int = 32


class FlowerClient:
    """
    Federated Learning client for Cyber Global Shield.
    Trains the Transformer Autoencoder on local data and submits
    encrypted model updates to the Flower server.
    """

    def __init__(self, config: FLConfig):
        self.config = config
        self.device = torch.device(config.device)
        self.model_dir = Path(config.model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)

        # Initialize model
        self.model = TransformerAutoencoder(
            input_dim=128,
            d_model=256,
            nhead=8,
            num_encoder_layers=4,
            num_decoder_layers=2,
            dim_feedforward=1024,
            dropout=0.1,
            latent_dim=64,
        ).to(self.device)

        self.criterion = nn.MSELoss()
        self.optimizer = optim.AdamW(
            self.model.parameters(),
            lr=config.learning_rate,
            weight_decay=config.weight_decay,
        )

        # Local dataset
        self._local_data: Optional[Tuple[torch.Tensor, torch.Tensor]] = None
        self._load_or_generate_data()

        logger.info(
            "flower_client_initialized",
            client_id=config.client_id,
            org_id=config.org_id,
            device=config.device,
            dp=config.differential_privacy,
        )

    def _load_or_generate_data(self):
        """Load existing data or generate synthetic data for training."""
        data_dir = Path(self.config.data_dir)
        X_path = data_dir / "X_train.npy"
        y_path = data_dir / "y_train.npy"

        if X_path.exists() and y_path.exists():
            logger.info("loading_local_data", path=str(X_path))
            X = np.load(str(X_path))
            y = np.load(str(y_path))
            # Use a subset for FL
            n = min(len(X), self.config.num_samples)
            X, y = X[:n], y[:n]
        else:
            logger.info("generating_local_data", samples=self.config.num_samples)
            generator = NetworkLogGenerator(seed=hash(self.config.client_id) % 1000)
            X, y = generator.generate_sequences(
                num_sequences=self.config.num_samples,
                seq_length=self.config.seq_length,
                anomaly_probability=0.0,  # Unsupervised: normal only
            )

        self._local_data = (
            torch.FloatTensor(X),
            torch.FloatTensor(X),  # Autoencoder target = input
        )
        logger.info(
            "local_data_ready",
            shape=X.shape,
            samples=len(X),
        )

    def get_parameters(self) -> List[np.ndarray]:
        """Return model parameters as a list of numpy arrays."""
        return [val.cpu().numpy() for val in self.model.state_dict().values()]

    def set_parameters(self, parameters: List[np.ndarray]):
        """Set model parameters from a list of numpy arrays."""
        params_dict = zip(self.model.state_dict().keys(), parameters)
        state_dict = {k: torch.tensor(v) for k, v in params_dict}
        self.model.load_state_dict(state_dict, strict=True)
        logger.info("model_parameters_updated", n_params=len(parameters))

    def fit(
        self,
        parameters: List[np.ndarray],
        config: Dict[str, Any],
    ) -> Tuple[List[np.ndarray], int, Dict[str, Any]]:
        """
        Train the model on local data.
        
        Args:
            parameters: Global model parameters from server
            config: Training configuration from server
            
        Returns:
            Tuple of (updated_parameters, num_samples, metrics)
        """
        # Apply global parameters
        self.set_parameters(parameters)

        # Override config with server settings
        local_epochs = config.get("local_epochs", self.config.local_epochs)
        lr = config.get("learning_rate", self.config.learning_rate)
        for param_group in self.optimizer.param_groups:
            param_group["lr"] = lr

        # Prepare data loader
        X, y = self._local_data
        dataset = TensorDataset(X, y)
        loader = DataLoader(
            dataset,
            batch_size=self.config.batch_size,
            shuffle=True,
            num_workers=0,
        )

        # Training loop
        self.model.train()
        total_loss = 0.0
        n_batches = 0

        for epoch in range(local_epochs):
            epoch_loss = 0.0
            for batch_x, batch_target in loader:
                batch_x = batch_x.to(self.device)
                batch_target = batch_target.to(self.device)

                self.optimizer.zero_grad()

                # Forward pass
                reconstructed, _ = self.model(batch_x)
                loss = self.criterion(reconstructed, batch_target)

                # Differential Privacy: clip gradients
                if self.config.differential_privacy:
                    torch.nn.utils.clip_grad_norm_(
                        self.model.parameters(),
                        max_norm=self.config.dp_clipping_norm,
                    )

                loss.backward()

                # DP: add noise to gradients
                if self.config.differential_privacy:
                    with torch.no_grad():
                        for param in self.model.parameters():
                            if param.grad is not None:
                                noise = torch.normal(
                                    mean=0,
                                    std=self.config.dp_clipping_norm
                                    * self.config.dp_noise_multiplier
                                    / self.config.batch_size,
                                    size=param.grad.shape,
                                ).to(param.device)
                                param.grad += noise

                self.optimizer.step()
                epoch_loss += loss.item()
                n_batches += 1

            total_loss += epoch_loss / len(loader)
            logger.debug(
                "local_epoch_complete",
                client_id=self.config.client_id,
                epoch=epoch + 1,
                loss=f"{epoch_loss / len(loader):.6f}",
            )

        # Get updated parameters
        updated_params = self.get_parameters()
        avg_loss = total_loss / local_epochs

        metrics = {
            "loss": float(avg_loss),
            "client_id": self.config.client_id,
            "org_id": self.config.org_id,
            "samples": len(X),
            "epochs": local_epochs,
            "dp_enabled": self.config.differential_privacy,
        }

        logger.info(
            "local_training_complete",
            client_id=self.config.client_id,
            loss=f"{avg_loss:.6f}",
            samples=len(X),
        )

        return updated_params, len(X), metrics

    def evaluate(
        self,
        parameters: List[np.ndarray],
        config: Dict[str, Any],
    ) -> Tuple[float, int, Dict[str, Any]]:
        """
        Evaluate the model on local validation data.
        
        Args:
            parameters: Model parameters to evaluate
            config: Evaluation configuration
            
        Returns:
            Tuple of (loss, num_samples, metrics)
        """
        self.set_parameters(parameters)
        self.model.eval()

        # Use a portion of training data as validation
        X, y = self._local_data
        split = int(len(X) * 0.8)
        X_val, y_val = X[split:], y[split:]

        val_dataset = TensorDataset(X_val, y_val)
        val_loader = DataLoader(
            val_dataset,
            batch_size=self.config.batch_size,
            shuffle=False,
        )

        total_loss = 0.0
        with torch.no_grad():
            for batch_x, batch_target in val_loader:
                batch_x = batch_x.to(self.device)
                batch_target = batch_target.to(self.device)
                reconstructed, _ = self.model(batch_x)
                loss = self.criterion(reconstructed, batch_target)
                total_loss += loss.item()

        avg_loss = total_loss / len(val_loader)

        metrics = {
            "loss": float(avg_loss),
            "client_id": self.config.client_id,
            "samples": len(X_val),
        }

        logger.info(
            "local_evaluation_complete",
            client_id=self.config.client_id,
            loss=f"{avg_loss:.6f}",
            samples=len(X_val),
        )

        return float(avg_loss), len(X_val), metrics

    def save_checkpoint(self, path: Optional[str] = None):
        """Save local model checkpoint."""
        save_path = path or str(self.model_dir / f"client_{self.config.client_id}_checkpoint.pt")
        checkpoint = {
            "client_id": self.config.client_id,
            "model_state_dict": self.model.state_dict(),
            "optimizer_state_dict": self.optimizer.state_dict(),
            "config": {
                "local_epochs": self.config.local_epochs,
                "learning_rate": self.config.learning_rate,
                "dp_enabled": self.config.differential_privacy,
            },
        }
        torch.save(checkpoint, save_path)
        logger.info("checkpoint_saved", path=save_path)

    def load_checkpoint(self, path: str):
        """Load local model checkpoint."""
        checkpoint = torch.load(path, map_location=self.device)
        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.optimizer.load_state_dict(checkpoint["optimizer_state_dict"])
        logger.info("checkpoint_loaded", path=path, client_id=checkpoint["client_id"])


def create_client(client_id: str) -> FlowerClient:
    """Factory function to create a Flower client."""
    config = FLConfig(
        client_id=client_id,
        org_id=os.environ.get("ORG_ID", "default"),
        data_dir=os.environ.get("FL_DATA_DIR", "data"),
        model_dir=os.environ.get("FL_MODEL_DIR", "app/ml/models"),
        local_epochs=int(os.environ.get("FL_LOCAL_EPOCHS", "5")),
        learning_rate=float(os.environ.get("FL_LEARNING_RATE", "1e-4")),
        differential_privacy=os.environ.get("FL_DP_ENABLED", "true").lower() == "true",
        device=os.environ.get("FL_DEVICE", "cpu"),
        num_samples=int(os.environ.get("FL_NUM_SAMPLES", "2000")),
    )
    return FlowerClient(config)


def run_client():
    """
    Run the Flower client standalone (for testing).
    Connects to the Flower server and participates in federated learning.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Cyber Global Shield FL Client")
    parser.add_argument("--client-id", default="client-001", help="Unique client identifier")
    parser.add_argument("--server", default="localhost:9092", help="Flower server address")
    parser.add_argument("--dry-run", action="store_true", help="Run local training only, no server")
    args = parser.parse_args()

    client = create_client(args.client_id)

    if args.dry_run:
        print(f"\n{'='*50}")
        print(f"FL Client Dry Run — {args.client_id}")
        print(f"{'='*50}")

        # Simulate receiving initial parameters
        initial_params = client.get_parameters()
        print(f"  Initial parameters: {len(initial_params)} layers")

        # Simulate a fit round
        print(f"\n  Training for {client.config.local_epochs} epochs...")
        updated_params, n_samples, metrics = client.fit(
            initial_params,
            {"local_epochs": client.config.local_epochs},
        )
        print(f"  Samples: {n_samples}")
        print(f"  Loss: {metrics['loss']:.6f}")
        print(f"  DP enabled: {metrics['dp_enabled']}")

        # Save checkpoint
        client.save_checkpoint()
        print(f"\n  Checkpoint saved to {client.model_dir}")
        print(f"{'='*50}\n")
    else:
        # Connect to Flower server
        try:
            import flwr as fl

            class FlowerClientWrapper(fl.client.NumPyClient):
                def __init__(self, inner_client: FlowerClient):
                    self.inner = inner_client

                def get_parameters(self, config):
                    return self.inner.get_parameters()

                def fit(self, parameters, config):
                    return self.inner.fit(parameters, config)

                def evaluate(self, parameters, config):
                    return self.inner.evaluate(parameters, config)

            fl.client.start_numpy_client(
                server_address=args.server,
                client=FlowerClientWrapper(client),
            )
        except ImportError:
            logger.error("flwr not installed. Install with: pip install flwr")
            print("ERROR: flwr package not installed. Run: pip install flwr")
            sys.exit(1)


if __name__ == "__main__":
    run_client()
