#!/usr/bin/env python3
"""
Cyber Global Shield — Seed Model Generator
Génère et sauvegarde un modèle ML pré-entraîné avec des poids par défaut.
"""

import os
import sys
import json
import torch
import numpy as np
from pathlib import Path

# Ajouter le chemin racine
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.ml.anomaly_detector import AnomalyDetector
from app.ml.dataset_generator import generate_synthetic_dataset
from app.core.config import settings

MODEL_DIR = Path(__file__).parent.parent / "models"
MODEL_DIR.mkdir(exist_ok=True)


def seed_model():
    """Generate and save a pre-trained model with synthetic data."""
    print("🔄 Génération du modèle pré-entraîné...")

    # Generate synthetic dataset
    print("📊 Génération du dataset synthétique...")
    X_train, X_val, X_test, y_train, y_val, y_test = generate_synthetic_dataset(
        n_samples=50000,
        n_features=64,
        contamination=0.05,
        random_state=42,
    )

    print(f"   Train: {X_train.shape}")
    print(f"   Val:   {X_val.shape}")
    print(f"   Test:  {X_test.shape}")

    # Initialize model
    print("🧠 Initialisation du modèle...")
    model = AnomalyDetector(
        input_dim=X_train.shape[1],
        hidden_dims=[128, 64, 32],
        latent_dim=16,
        learning_rate=0.001,
    )

    # Train model
    print("🏋️ Entraînement en cours...")
    history = model.train(
        X_train,
        X_val,
        epochs=50,
        batch_size=64,
        patience=10,
        verbose=True,
    )

    # Evaluate
    print("📈 Évaluation...")
    metrics = model.evaluate(X_test, y_test)
    print(f"   Precision: {metrics['precision']:.4f}")
    print(f"   Recall:    {metrics['recall']:.4f}")
    print(f"   F1 Score:  {metrics['f1_score']:.4f}")
    print(f"   ROC-AUC:   {metrics['roc_auc']:.4f}")

    # Save model
    model_path = MODEL_DIR / "anomaly_detector.pt"
    torch.save(model.state_dict(), model_path)
    print(f"💾 Modèle sauvegardé : {model_path}")

    # Save metadata
    metadata = {
        "model": "AnomalyDetector",
        "input_dim": X_train.shape[1],
        "hidden_dims": [128, 64, 32],
        "latent_dim": 16,
        "train_samples": X_train.shape[0],
        "val_samples": X_val.shape[0],
        "test_samples": X_test.shape[0],
        "contamination": 0.05,
        "metrics": metrics,
        "training_history": {
            "train_loss": [float(l) for l in history["train_loss"]],
            "val_loss": [float(l) for l in history["val_loss"]],
        },
        "threshold": float(model.threshold),
        "created_at": str(np.datetime64("now")),
    }

    metadata_path = MODEL_DIR / "model_metadata.json"
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"📋 Métadonnées sauvegardées : {metadata_path}")

    # Save reference statistics for drift detection
    ref_stats = {
        "mean": X_train.mean(axis=0).tolist(),
        "std": X_train.std(axis=0).tolist(),
        "min": X_train.min(axis=0).tolist(),
        "max": X_train.max(axis=0).tolist(),
        "p5": np.percentile(X_train, 5, axis=0).tolist(),
        "p25": np.percentile(X_train, 25, axis=0).tolist(),
        "p50": np.percentile(X_train, 50, axis=0).tolist(),
        "p75": np.percentile(X_train, 75, axis=0).tolist(),
        "p95": np.percentile(X_train, 95, axis=0).tolist(),
        "n_samples": X_train.shape[0],
    }

    ref_path = MODEL_DIR / "reference_stats.json"
    with open(ref_path, "w") as f:
        json.dump(ref_stats, f, indent=2)
    print(f"📊 Statistiques de référence sauvegardées : {ref_path}")

    print("\n✅ Modèle pré-entraîné prêt !")
    print(f"   - Modèle : {model_path}")
    print(f"   - Métadonnées : {metadata_path}")
    print(f"   - Stats référence : {ref_path}")
    print(f"   - F1 Score: {metrics['f1_score']:.4f}")
    print(f"   - ROC-AUC: {metrics['roc_auc']:.4f}")

    return model_path


if __name__ == "__main__":
    seed_model()
