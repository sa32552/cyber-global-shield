"""
Quick training script — generates a usable model in ~2 minutes.
For demo/prototyping. Full training uses train.py with 50 epochs.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
from pathlib import Path
import structlog
import json

from app.ml.anomaly_detector import TransformerAutoencoder
from app.ml.dataset_generator import NetworkLogGenerator

logger = structlog.get_logger(__name__)


def quick_train():
    print("=" * 50)
    print("Cyber Global Shield — Quick Model Training")
    print("=" * 50)

    device = torch.device("cpu")
    model_dir = Path("app/ml/models")
    model_dir.mkdir(parents=True, exist_ok=True)

    # Generate small dataset (fast)
    print("\n[1] Generating mini dataset...")
    generator = NetworkLogGenerator(seed=42)
    X_train, y_train = generator.generate_sequences(
        num_sequences=2000,
        seq_length=32,  # Half sequence length = 4x faster
        anomaly_probability=0.0,
    )
    X_val, y_val = generator.generate_sequences(
        num_sequences=500,
        seq_length=32,
        anomaly_probability=0.1,
    )

    print(f"  Train: {X_train.shape}, Val: {X_val.shape}")

    # Smaller model for speed
    print("\n[2] Building model...")
    model = TransformerAutoencoder(
        input_dim=128,
        d_model=128,         # Half hidden dim
        nhead=4,             # Fewer heads
        num_encoder_layers=2,  # Fewer layers
        num_decoder_layers=1,
        dim_feedforward=512,
        latent_dim=32,
    ).to(device)

    n_params = sum(p.numel() for p in model.parameters())
    print(f"  Parameters: {n_params:,}")

    # Train
    print("\n[3] Training (10 epochs)...")
    train_dataset = TensorDataset(torch.FloatTensor(X_train), torch.FloatTensor(X_train))
    val_dataset = TensorDataset(torch.FloatTensor(X_val), torch.LongTensor(y_val))

    train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=64, shuffle=False)

    criterion = nn.MSELoss()
    optimizer = optim.AdamW(model.parameters(), lr=1e-3)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=10)

    for epoch in range(10):
        model.train()
        train_loss = 0
        for batch_x, batch_target in train_loader:
            batch_x, batch_target = batch_x.to(device), batch_target.to(device)
            optimizer.zero_grad()
            reconstructed, _ = model(batch_x)
            loss = criterion(reconstructed, batch_target)
            loss.backward()
            optimizer.step()
            train_loss += loss.item()

        scheduler.step()

        # Val loss on normal data only
        model.eval()
        val_loss = 0
        val_count = 0
        with torch.no_grad():
            for batch_x, batch_y in val_loader:
                mask = batch_y == 0
                if mask.sum() == 0:
                    continue
                batch_x_norm = batch_x[mask].to(device)
                reconstructed, _ = model(batch_x_norm)
                val_loss += criterion(reconstructed, batch_x_norm).item() * len(batch_x_norm)
                val_count += len(batch_x_norm)

        val_loss = val_loss / val_count if val_count > 0 else float("inf")
        print(f"  Epoch {epoch+1:2d}/10 | Train Loss: {train_loss/len(train_loader):.6f} | Val Loss: {val_loss:.6f}")

    # Calibrate threshold
    print("\n[4] Calibrating threshold...")
    model.eval()
    normal_errs = []
    anomaly_errs = []

    with torch.no_grad():
        for batch_x, batch_y in val_loader:
            batch_x = batch_x.to(device)
            reconstructed, _ = model(batch_x)
            errors = nn.MSELoss(reduction="none")(reconstructed, batch_x).mean(dim=(1, 2)).cpu().numpy()
            for i, y in enumerate(batch_y.numpy()):
                if y == 0:
                    normal_errs.append(float(errors[i]))
                else:
                    anomaly_errs.append(float(errors[i]))

    # Optimal threshold via F1
    all_errs = normal_errs + anomaly_errs
    thresholds = np.linspace(min(all_errs), max(all_errs), 100)
    best_f1, best_t, best_metrics = 0, 0.95, {}

    for t in thresholds:
        tp = sum(1 for e in anomaly_errs if e > t)
        fp = sum(1 for e in normal_errs if e > t)
        fn = len(anomaly_errs) - tp
        tn = len(normal_errs) - fp
        p = tp / (tp + fp) if (tp + fp) > 0 else 0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
        if f1 > best_f1:
            best_f1, best_t = f1, t
            best_metrics = {"precision": p, "recall": r, "f1_score": f1, "tp": tp, "fp": fp, "fn": fn, "tn": tn}

    max_err = max(all_errs)
    anomaly_score_threshold = 1.0 - np.exp(-min(best_t / (max_err + 1e-8), 10.0))

    # Save model
    print("\n[5] Saving model...")
    checkpoint = {
        "model_state_dict": model.state_dict(),
        "threshold": float(anomaly_score_threshold),
        "model_config": {
            "input_dim": 128, "d_model": 128, "nhead": 4,
            "num_encoder_layers": 2, "num_decoder_layers": 1,
            "dim_feedforward": 512, "latent_dim": 32,
        },
    }
    torch.save(checkpoint, model_dir / "trained_model.pt")

    # Save calibration
    calibration = {
        "threshold": float(anomaly_score_threshold),
        "reconstruction_error_threshold": float(best_t),
        "metrics": best_metrics,
        "normal_error_mean": float(np.mean(normal_errs)),
        "anomaly_error_mean": float(np.mean(anomaly_errs)),
    }
    with open(model_dir / "calibration.json", "w") as f:
        json.dump(calibration, f, indent=2)

    print(f"\n{'=' * 50}")
    print(f"✅ Model saved: {model_dir / 'trained_model.pt'}")
    print(f"   Threshold: {anomaly_score_threshold:.4f}")
    print(f"   F1 Score: {best_f1:.4f}")
    print(f"   Precision: {best_metrics['precision']:.4f}")
    print(f"   Recall: {best_metrics['recall']:.4f}")
    print(f"   Parameters: {n_params:,}")
    print(f"{'=' * 50}")


if __name__ == "__main__":
    quick_train()