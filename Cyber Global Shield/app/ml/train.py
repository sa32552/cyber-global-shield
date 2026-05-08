"""
Training script for the Cyber Global Shield Anomaly Detector.
Trains the Transformer Autoencoder on synthetic network security data,
then calibrates detection thresholds and evaluates performance.
Includes adversarial training, early stopping, and learning rate scheduling.
"""

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path
from datetime import datetime, timezone
import json
import structlog

import sys
from pathlib import Path

# Make app package importable when running directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from app.ml.anomaly_detector import (
    TransformerAutoencoder,
    AnomalyDetector,
    AnomalyDetectionResult,
)
from app.ml.dataset_generator import NetworkLogGenerator

logger = structlog.get_logger(__name__)


# ─── Adversarial Training ───────────────────────────────────────────────

class FGSMAttack:
    """
    Fast Gradient Sign Method (FGSM) for adversarial training.
    Generates adversarial examples by adding perturbation in the gradient direction.
    """

    def __init__(self, epsilon: float = 0.01):
        self.epsilon = epsilon

    def generate(
        self, model: nn.Module, x: torch.Tensor, criterion: nn.Module
    ) -> torch.Tensor:
        """
        Generate adversarial examples using FGSM.
        x: input tensor (requires_grad=True)
        """
        x.requires_grad = True
        reconstructed, _ = model(x)
        loss = criterion(reconstructed, x)
        model.zero_grad()
        loss.backward()

        # FGSM: x_adv = x + epsilon * sign(grad)
        x_grad = x.grad.data
        x_adv = x + self.epsilon * x_grad.sign()
        x_adv = torch.clamp(x_adv, 0.0, 1.0)  # Keep in valid range

        return x_adv.detach()


class PGDAttack:
    """
    Projected Gradient Descent (PGD) attack for stronger adversarial training.
    Iterative version of FGSM with random start.
    """

    def __init__(
        self,
        epsilon: float = 0.03,
        alpha: float = 0.01,
        iterations: int = 7,
        random_start: bool = True,
    ):
        self.epsilon = epsilon
        self.alpha = alpha
        self.iterations = iterations
        self.random_start = random_start

    def generate(
        self, model: nn.Module, x: torch.Tensor, criterion: nn.Module
    ) -> torch.Tensor:
        """Generate PGD adversarial examples."""
        x_adv = x.clone().detach()

        if self.random_start:
            x_adv = x_adv + torch.empty_like(x_adv).uniform_(-self.epsilon, self.epsilon)
            x_adv = torch.clamp(x_adv, 0.0, 1.0)

        for _ in range(self.iterations):
            x_adv.requires_grad = True
            reconstructed, _ = model(x_adv)
            loss = criterion(reconstructed, x_adv)
            model.zero_grad()
            loss.backward()

            x_grad = x_adv.grad.data
            x_adv = x_adv.detach() + self.alpha * x_grad.sign()
            # Project back to epsilon ball
            perturbation = torch.clamp(x_adv - x, -self.epsilon, self.epsilon)
            x_adv = torch.clamp(x + perturbation, 0.0, 1.0)

        return x_adv.detach()


# ─── Model Trainer ──────────────────────────────────────────────────────

class ModelTrainer:
    """Handles training, evaluation, and calibration of the anomaly detector."""

    def __init__(
        self,
        device: str = "cpu",
        model_dir: str = "app/ml/models",
        data_dir: str = "data",
    ):
        self.device = torch.device(device)
        self.model_dir = Path(model_dir)
        self.data_dir = Path(data_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def prepare_data(
        self,
        num_sequences: int = 10000,
        seq_length: int = 64,
        anomaly_ratio: float = 0.1,
        val_split: float = 0.2,
    ) -> Tuple[DataLoader, DataLoader, DataLoader]:
        """
        Generate and prepare training/validation/test data.
        Training: only normal data (unsupervised)
        Validation: mixed (normal + anomalies) for threshold calibration
        Test: mixed for evaluation
        """
        logger.info("generating_training_data", sequences=num_sequences)

        generator = NetworkLogGenerator(seed=42)

        # Training: only normal sequences (unsupervised learning)
        X_train, y_train = generator.generate_sequences(
            num_sequences=int(num_sequences * 0.7),
            seq_length=seq_length,
            anomaly_probability=0.0,  # Pure normal for training
        )

        # Validation: mixed for calibration
        X_val, y_val = generator.generate_sequences(
            num_sequences=int(num_sequences * 0.15),
            seq_length=seq_length,
            anomaly_probability=anomaly_ratio,
        )

        # Test: mixed for evaluation
        X_test, y_test = generator.generate_sequences(
            num_sequences=int(num_sequences * 0.15),
            seq_length=seq_length,
            anomaly_probability=anomaly_ratio,
        )

        # Convert to tensors
        train_dataset = TensorDataset(
            torch.FloatTensor(X_train),
            torch.FloatTensor(X_train),  # Autoencoder target = input
        )
        val_dataset = TensorDataset(
            torch.FloatTensor(X_val),
            torch.LongTensor(y_val),
        )
        test_dataset = TensorDataset(
            torch.FloatTensor(X_test),
            torch.LongTensor(y_test),
        )

        train_loader = DataLoader(
            train_dataset,
            batch_size=32,
            shuffle=True,
            num_workers=0,
            pin_memory=True,
        )
        val_loader = DataLoader(val_dataset, batch_size=64, shuffle=False)
        test_loader = DataLoader(test_dataset, batch_size=64, shuffle=False)

        # Save datasets for reuse
        np.save(self.data_dir / "X_train.npy", X_train)
        np.save(self.data_dir / "y_train.npy", y_train)
        np.save(self.data_dir / "X_val.npy", X_val)
        np.save(self.data_dir / "y_val.npy", y_val)
        np.save(self.data_dir / "X_test.npy", X_test)
        np.save(self.data_dir / "y_test.npy", y_test)

        logger.info(
            "data_prepared",
            train_samples=len(X_train),
            val_samples=len(X_val),
            test_samples=len(X_test),
        )

        return train_loader, val_loader, test_loader

    def train(
        self,
        epochs: int = 50,
        learning_rate: float = 1e-4,
        weight_decay: float = 1e-5,
        early_stopping_patience: int = 10,
        use_adversarial: bool = True,
        adversarial_epsilon: float = 0.01,
        adversarial_ratio: float = 0.3,  # Fraction of batches with adversarial examples
    ) -> Dict[str, Any]:
        """
        Train the Transformer Autoencoder.
        
        Uses only normal data (unsupervised) - the model learns to reconstruct
        normal patterns. Anomalies will have high reconstruction error.
        
        Supports adversarial training with FGSM for robustness.
        """
        logger.info(
            "starting_training",
            epochs=epochs,
            lr=learning_rate,
            adversarial=use_adversarial,
        )

        # Prepare data
        train_loader, val_loader, test_loader = self.prepare_data()

        # Initialize model
        model = TransformerAutoencoder(
            input_dim=128,
            d_model=256,
            nhead=8,
            num_encoder_layers=4,
            num_decoder_layers=2,
            dim_feedforward=1024,
            dropout=0.1,
            latent_dim=64,
        ).to(self.device)

        # Loss and optimizer
        criterion = nn.MSELoss()
        optimizer = optim.AdamW(
            model.parameters(),
            lr=learning_rate,
            weight_decay=weight_decay,
        )
        scheduler = optim.lr_scheduler.CosineAnnealingWarmRestarts(
            optimizer, T_0=10, T_mult=2
        )

        # Adversarial attack
        fgsm = FGSMAttack(epsilon=adversarial_epsilon)

        # Training loop
        best_val_loss = float("inf")
        patience_counter = 0
        history = {
            "train_loss": [],
            "val_loss": [],
            "lr": [],
            "adversarial_loss": [],
        }

        for epoch in range(epochs):
            # Training
            model.train()
            train_loss = 0.0
            adv_loss_total = 0.0
            adv_batches = 0

            for batch_idx, (batch_x, batch_target) in enumerate(train_loader):
                batch_x = batch_x.to(self.device)
                batch_target = batch_target.to(self.device)

                optimizer.zero_grad()

                # Normal forward pass
                reconstructed, latent = model(batch_x)
                loss = criterion(reconstructed, batch_target)

                # Adversarial training
                if use_adversarial and np.random.random() < adversarial_ratio:
                    # Generate adversarial examples
                    x_adv = fgsm.generate(model, batch_x, criterion)
                    # Train on adversarial examples
                    reconstructed_adv, _ = model(x_adv)
                    adv_loss = criterion(reconstructed_adv, x_adv)
                    # Combine losses
                    loss = loss + 0.5 * adv_loss
                    adv_loss_total += adv_loss.item()
                    adv_batches += 1

                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                optimizer.step()

                train_loss += loss.item()

            train_loss /= len(train_loader)
            history["train_loss"].append(train_loss)
            history["adversarial_loss"].append(
                adv_loss_total / max(adv_batches, 1)
            )

            # Validation (reconstruction loss on normal data only)
            model.eval()
            val_loss = 0.0
            val_samples = 0
            with torch.no_grad():
                for batch_x, batch_y in val_loader:
                    normal_mask = batch_y == 0
                    if normal_mask.sum() == 0:
                        continue
                    batch_x = batch_x[normal_mask].to(self.device)
                    reconstructed, _ = model(batch_x)
                    loss = criterion(reconstructed, batch_x)
                    val_loss += loss.item() * len(batch_x)
                    val_samples += len(batch_x)

            val_loss = val_loss / val_samples if val_samples > 0 else float("inf")
            history["val_loss"].append(val_loss)
            history["lr"].append(optimizer.param_groups[0]["lr"])

            scheduler.step()

            # Logging
            if epoch % 5 == 0:
                logger.info(
                    "training_progress",
                    epoch=epoch,
                    train_loss=f"{train_loss:.6f}",
                    val_loss=f"{val_loss:.6f}",
                    lr=f"{scheduler.get_last_lr()[0]:.2e}",
                    adversarial_loss=f"{history['adversarial_loss'][-1]:.6f}" if use_adversarial else "N/A",
                )

            # Early stopping with patience
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                self._save_checkpoint(model, epoch, val_loss, "best_model.pt")
            else:
                patience_counter += 1
                if patience_counter >= early_stopping_patience:
                    logger.info(
                        "early_stopping_triggered",
                        epoch=epoch,
                        best_val_loss=best_val_loss,
                        patience=early_stopping_patience,
                    )
                    break

        # Load best model
        checkpoint = torch.load(self.model_dir / "best_model.pt", map_location=self.device)
        model.load_state_dict(checkpoint["model_state_dict"])

        logger.info(
            "training_complete",
            final_epoch=epoch,
            best_val_loss=f"{best_val_loss:.6f}",
        )

        return history

    def calibrate(self, model_path: Optional[str] = None) -> Tuple[float, Dict[str, float]]:
        """
        Calibrate the anomaly detection threshold.
        Uses validation data to find optimal threshold via precision-recall.
        """
        logger.info("calibrating_threshold")

        # Load model
        detector = AnomalyDetector(
            model_path=model_path or str(self.model_dir / "best_model.pt"),
            device=str(self.device),
        )

        # Load validation data
        X_val = np.load(self.data_dir / "X_val.npy")
        y_val = np.load(self.data_dir / "y_val.npy")

        # Convert back to log dictionaries for the detector
        # Since sequences are already preprocessed, we run inference directly
        val_dataset = TensorDataset(
            torch.FloatTensor(X_val), torch.LongTensor(y_val)
        )
        val_loader = DataLoader(val_dataset, batch_size=64, shuffle=False)

        # Collect reconstruction errors
        normal_errors = []
        anomaly_errors = []

        detector.model.eval()
        criterion = nn.MSELoss(reduction="none")

        with torch.no_grad():
            for batch_x, batch_y in val_loader:
                batch_x = batch_x.to(self.device)
                reconstructed, _ = detector.model(batch_x)
                errors = criterion(reconstructed, batch_x).mean(dim=(1, 2)).cpu().numpy()

                for i, y in enumerate(batch_y.numpy()):
                    if y == 0:
                        normal_errors.append(float(errors[i]))
                    else:
                        anomaly_errors.append(float(errors[i]))

        # Find optimal threshold (maximize F1)
        all_errors = normal_errors + anomaly_errors
        min_err, max_err = min(all_errors), max(all_errors)
        thresholds = np.linspace(min_err, max_err, 200)

        best_f1 = 0.0
        best_threshold = 0.95
        best_metrics = {}

        for t in thresholds:
            # Predictions
            normal_pred = np.array(normal_errors) > t
            anomaly_pred = np.array(anomaly_errors) > t

            tp = anomaly_pred.sum()
            fp = normal_pred.sum()
            fn = len(anomaly_errors) - tp
            tn = len(normal_errors) - fp

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

            if f1 > best_f1:
                best_f1 = f1
                best_threshold = t  # This is reconstruction error, convert to anomaly score
                best_metrics = {
                    "precision": float(precision),
                    "recall": float(recall),
                    "f1_score": float(f1),
                    "true_positives": int(tp),
                    "false_positives": int(fp),
                    "false_negatives": int(fn),
                    "true_negatives": int(tn),
                }

        # Convert reconstruction error threshold to anomaly score threshold
        # Anomaly score = 1 - exp(-normalized_error)
        max_err_val = max(all_errors)
        normalized_threshold = best_threshold / (max_err_val + 1e-8)
        anomaly_score_threshold = 1.0 - np.exp(-min(normalized_threshold, 10.0))

        # Save calibration
        calibration = {
            "threshold": float(anomaly_score_threshold),
            "reconstruction_error_threshold": float(best_threshold),
            "metrics": best_metrics,
            "normal_error_mean": float(np.mean(normal_errors)),
            "normal_error_std": float(np.std(normal_errors)),
            "anomaly_error_mean": float(np.mean(anomaly_errors)),
            "anomaly_error_std": float(np.std(anomaly_errors)),
            "calibration_date": datetime.now(timezone.utc).isoformat(),
        }

        with open(self.model_dir / "calibration.json", "w") as f:
            json.dump(calibration, f, indent=2)

        # Save model with threshold
        checkpoint = torch.load(self.model_dir / "best_model.pt")
        checkpoint["threshold"] = anomaly_score_threshold
        torch.save(checkpoint, self.model_dir / "trained_model.pt")

        logger.info(
            "calibration_complete",
            threshold=f"{anomaly_score_threshold:.4f}",
            f1=f"{best_f1:.4f}",
            precision=f"{best_metrics['precision']:.4f}",
            recall=f"{best_metrics['recall']:.4f}",
        )

        return anomaly_score_threshold, best_metrics

    def evaluate(self, model_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Evaluate the trained model on the test set.
        """
        logger.info("evaluating_model")

        detector = AnomalyDetector(
            model_path=model_path or str(self.model_dir / "trained_model.pt"),
            device=str(self.device),
        )

        # Load test data
        X_test = np.load(self.data_dir / "X_test.npy")
        y_test = np.load(self.data_dir / "y_test.npy")

        # Load calibration threshold
        with open(self.model_dir / "calibration.json", "r") as f:
            calibration = json.load(f)

        threshold = calibration["threshold"]
        detector.threshold = threshold

        # Convert sequences back to log-like format for the detector API
        # We pass preprocessed tensors through the model directly
        test_dataset = TensorDataset(
            torch.FloatTensor(X_test), torch.LongTensor(y_test)
        )
        test_loader = DataLoader(test_dataset, batch_size=64, shuffle=False)

        results = {
            "total": 0,
            "positive": 0,  # True anomalies
            "true_positives": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "true_negatives": 0,
            "inference_times_ms": [],
        }

        import time
        detector.model.eval()

        with torch.no_grad():
            for batch_x, batch_y in test_loader:
                batch_x = batch_x.to(self.device)

                start = time.time()
                reconstructed, _ = detector.model(batch_x)
                inference_time = (time.time() - start) * 1000 / len(batch_x)

                errors = nn.MSELoss(reduction="none")(reconstructed, batch_x).mean(dim=(1, 2))

                for i, y in enumerate(batch_y.numpy()):
                    error_val = float(errors[i].cpu())
                    # Convert to anomaly score
                    anomaly_score = 1.0 - np.exp(-min(error_val / (errors.max().item() + 1e-8), 10.0))
                    is_anomaly = anomaly_score > threshold

                    results["total"] += 1
                    if y == 1:
                        results["positive"] += 1
                        if is_anomaly:
                            results["true_positives"] += 1
                        else:
                            results["false_negatives"] += 1
                    else:
                        if is_anomaly:
                            results["false_positives"] += 1
                        else:
                            results["true_negatives"] += 1

                results["inference_times_ms"].append(inference_time)

        # Calculate metrics
        tp, fp, fn, tn = (
            results["true_positives"],
            results["false_positives"],
            results["false_negatives"],
            results["true_negatives"],
        )
        total = results["total"]

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / total if total > 0 else 0
        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0

        evaluation = {
            **results,
            "metrics": {
                "accuracy": float(accuracy),
                "precision": float(precision),
                "recall": float(recall),
                "f1_score": float(f1),
                "false_positive_rate": float(false_positive_rate),
                "avg_inference_time_ms": float(np.mean(results["inference_times_ms"])),
            },
            "threshold_used": threshold,
            "evaluation_date": datetime.now(timezone.utc).isoformat(),
        }

        with open(self.model_dir / "evaluation.json", "w") as f:
            json.dump(evaluation, f, indent=2)

        logger.info(
            "evaluation_complete",
            accuracy=f"{accuracy:.4f}",
            precision=f"{precision:.4f}",
            recall=f"{recall:.4f}",
            f1=f"{f1:.4f}",
            fpr=f"{false_positive_rate:.4f}",
            avg_inference_ms=f"{np.mean(results['inference_times_ms']):.2f}",
        )

        return evaluation

    def _save_checkpoint(
        self,
        model: nn.Module,
        epoch: int,
        val_loss: float,
        filename: str,
    ):
        """Save model checkpoint."""
        checkpoint = {
            "epoch": epoch,
            "model_state_dict": model.state_dict(),
            "val_loss": val_loss,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        torch.save(checkpoint, self.model_dir / filename)


def train_full_pipeline():
    """
    Run the complete training pipeline:
    1. Generate synthetic dataset
    2. Train Transformer Autoencoder (with adversarial training)
    3. Calibrate detection thresholds
    4. Evaluate performance
    """
    print("=" * 60)
    print("Cyber Global Shield - Model Training Pipeline")
    print("=" * 60)

    trainer = ModelTrainer(device="cpu")

    # Step 1: Train (with adversarial training)
    print("\n[1/3] Training Transformer Autoencoder (adversarial)...")
    history = trainer.train(
        epochs=50,
        learning_rate=1e-4,
        early_stopping_patience=10,
        use_adversarial=True,
        adversarial_epsilon=0.01,
        adversarial_ratio=0.3,
    )

    # Step 2: Calibrate
    print("\n[2/3] Calibrating anomaly detection threshold...")
    threshold, calib_metrics = trainer.calibrate()
    print(f"  Optimal threshold: {threshold:.4f}")
    print(f"  F1 Score: {calib_metrics['f1_score']:.4f}")
    print(f"  Precision: {calib_metrics['precision']:.4f}")
    print(f"  Recall: {calib_metrics['recall']:.4f}")

    # Step 3: Evaluate
    print("\n[3/3] Evaluating on test set...")
    evaluation = trainer.evaluate()
    metrics = evaluation["metrics"]
    print(f"  Accuracy: {metrics['accuracy']:.4f}")
    print(f"  F1 Score: {metrics['f1_score']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall: {metrics['recall']:.4f}")
    print(f"  False Positive Rate: {metrics['false_positive_rate']:.4f}")
    print(f"  Avg Inference Time: {metrics['avg_inference_time_ms']:.2f} ms")
    print(f"\n  True Positives: {evaluation['true_positives']}")
    print(f"  False Positives: {evaluation['false_positives']}")
    print(f"  False Negatives: {evaluation['false_negatives']}")
    print(f"  True Negatives: {evaluation['true_negatives']}")

    print("\n" + "=" * 60)
    print(f"Model saved to: {trainer.model_dir / 'trained_model.pt'}")
    print(f"Ready for deployment!")
    print("=" * 60)

    return history, threshold, evaluation


if __name__ == "__main__":
    train_full_pipeline()
