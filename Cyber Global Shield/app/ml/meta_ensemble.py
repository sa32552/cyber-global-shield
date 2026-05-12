"""
Cyber Global Shield — Meta-Ensemble & Meta-Learning Module (Niveau 11)
========================================================================

6 techniques de pointe pour combiner tous les détecteurs intelligemment :

1. Stacking (Meta-Classifier) — Apprendre à combiner les sorties
2. Bayesian Model Averaging — Pondération probabiliste
3. Mixture of Experts (MoE) — Gating network dynamique
4. Neural Architecture Search (NAS) — Combinaison optimale
5. Online Learning — Adaptation des poids en temps réel
6. Uncertainty Quantification — Monte Carlo Dropout, Deep Ensembles

Chaque technique peut fonctionner indépendamment ou en synergie.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Optional, Dict, Any, List, Tuple, Union, Callable
from dataclasses import dataclass, field
from collections import deque, defaultdict
from datetime import datetime, timezone
import structlog
import math
import warnings
from copy import deepcopy
from scipy import stats
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

logger = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class EnsembleResult:
    """Résultat d'ensemble unifié."""
    score: float
    is_malicious: bool
    confidence: float
    uncertainty: float
    method: str  # "stacking", "bayesian", "moe", "nas", "online", "uq"
    model_name: str
    explanation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    inference_time_ms: float = 0.0


@dataclass
class ModelPrediction:
    """Prédiction d'un modèle individuel."""
    model_name: str
    score: float
    confidence: float
    features: Optional[np.ndarray] = None
    timestamp: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 1: STACKING (Meta-Classifier)
# ═══════════════════════════════════════════════════════════════════════════

class StackingEnsemble:
    """
    Stacking Ensemble — Wolpert 1992.
    Apprend un meta-classifier sur les sorties des modèles de base.
    """

    def __init__(
        self,
        base_models: Dict[str, Callable],
        meta_model: str = "logistic",
        use_probas: bool = True,
        use_features: bool = False,
    ):
        self.base_models = base_models
        self.use_probas = use_probas
        self.use_features = use_features

        n_features = len(base_models) * (1 if use_probas else 0)

        if meta_model == "logistic":
            self.meta = LogisticRegression(max_iter=1000, random_state=42)
        elif meta_model == "random_forest":
            self.meta = RandomForestClassifier(
                n_estimators=100, max_depth=5, random_state=42
            )
        else:
            raise ValueError(f"Unknown meta_model: {meta_model}")

        self.is_fitted = False
        self.history: List[Dict[str, Any]] = []
        logger.info(
            "stacking_ensemble_initialized",
            n_base_models=len(base_models),
            meta_model=meta_model,
        )

    def predict(self, x: torch.Tensor) -> EnsembleResult:
        """Prédiction avec stacking."""
        # Collect base predictions
        base_scores = []
        base_confidences = []
        explanations = []

        for name, model in self.base_models.items():
            if hasattr(model, 'predict'):
                result = model.predict(x)
                base_scores.append(result.score)
                base_confidences.append(result.confidence)
                explanations.append(f"{name}: {result.score:.4f}")

        # Meta-features
        meta_features = np.array([base_scores]).T

        # Meta prediction
        if self.is_fitted:
            meta_score = float(self.meta.predict_proba(meta_features)[0, 1])
        else:
            # Fallback: weighted average
            weights = np.array(base_confidences)
            weights = weights / (weights.sum() + 1e-8)
            meta_score = float(np.average(base_scores, weights=weights))

        confidence = float(np.mean(base_confidences))
        uncertainty = float(np.std(base_scores))

        result = EnsembleResult(
            score=meta_score,
            is_malicious=meta_score > 0.5,
            confidence=confidence,
            uncertainty=uncertainty,
            method="stacking",
            model_name="StackingEnsemble",
            explanation=" | ".join(explanations),
            metadata={
                "n_models": len(base_scores),
                "individual_scores": dict(zip(self.base_models.keys(), base_scores)),
                "is_fitted": self.is_fitted,
            },
        )

        self.history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "result": result,
        })

        return result

    def fit(self, X: np.ndarray, y: np.ndarray):
        """Fit the meta-model."""
        self.meta.fit(X, y)
        self.is_fitted = True
        logger.info("stacking_ensemble_fitted", n_samples=len(X))

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "StackingEnsemble",
            "n_base_models": len(self.base_models),
            "meta_model": type(self.meta).__name__,
            "is_fitted": self.is_fitted,
            "n_predictions": len(self.history),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 2: BAYESIAN MODEL AVERAGING
# ═══════════════════════════════════════════════════════════════════════════

class BayesianModelAveraging:
    """
    Bayesian Model Averaging (BMA).
    Combine les modèles avec des poids basés sur leur vraisemblance.
    """

    def __init__(
        self,
        base_models: Dict[str, Callable],
        prior_weights: Optional[Dict[str, float]] = None,
        temperature: float = 1.0,
    ):
        self.base_models = base_models
        self.temperature = temperature

        n_models = len(base_models)
        if prior_weights is None:
            self.prior_weights = {
                name: 1.0 / n_models for name in base_models
            }
        else:
            self.prior_weights = prior_weights

        self.posterior_weights = dict(self.prior_weights)
        self.evidence: Dict[str, List[float]] = {
            name: [] for name in base_models
        }
        self.history: List[Dict[str, Any]] = []

        logger.info(
            "bayesian_averaging_initialized",
            n_models=n_models,
            prior_weights=self.prior_weights,
        )

    def update_posterior(self, model_name: str, likelihood: float):
        """Update posterior weight for a model."""
        self.evidence[model_name].append(likelihood)

        # Compute marginal likelihood
        n = len(self.evidence[model_name])
        marginal_likelihood = np.mean(self.evidence[model_name][-100:])

        # Update posterior
        total = 0.0
        for name in self.base_models:
            prior = self.prior_weights.get(name, 1.0 / len(self.base_models))
            if name == model_name:
                self.posterior_weights[name] = prior * marginal_likelihood
            total += self.posterior_weights[name]

        # Normalize
        if total > 0:
            for name in self.base_models:
                self.posterior_weights[name] /= total

    def predict(self, x: torch.Tensor) -> EnsembleResult:
        """Prédiction avec BMA."""
        weighted_score = 0.0
        total_weight = 0.0
        explanations = []
        individual_scores = {}

        for name, model in self.base_models.items():
            if hasattr(model, 'predict'):
                result = model.predict(x)
                w = self.posterior_weights.get(name, 1.0 / len(self.base_models))
                weighted_score += w * result.score
                total_weight += w
                individual_scores[name] = result.score
                explanations.append(f"{name}: {result.score:.4f} (w={w:.3f})")

                # Update evidence
                self.update_posterior(name, result.confidence)

        final_score = weighted_score / total_weight if total_weight > 0 else 0.0
        confidence = float(np.mean(list(individual_scores.values())))
        uncertainty = float(np.std(list(individual_scores.values())))

        result = EnsembleResult(
            score=final_score,
            is_malicious=final_score > 0.5,
            confidence=confidence,
            uncertainty=uncertainty,
            method="bayesian",
            model_name="BayesianModelAveraging",
            explanation=" | ".join(explanations),
            metadata={
                "posterior_weights": dict(self.posterior_weights),
                "individual_scores": individual_scores,
            },
        )

        self.history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "result": result,
        })

        return result

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "BayesianModelAveraging",
            "n_models": len(self.base_models),
            "posterior_weights": self.posterior_weights,
            "n_predictions": len(self.history),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 3: MIXTURE OF EXPERTS (MoE)
# ═══════════════════════════════════════════════════════════════════════════

class GatingNetwork(nn.Module):
    """Gating network pour Mixture of Experts."""

    def __init__(
        self,
        input_dim: int,
        n_experts: int,
        hidden_dim: int = 64,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.gate = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, n_experts),
            nn.Softmax(dim=-1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.gate(x)


class ExpertNetwork(nn.Module):
    """Expert network individuel."""

    def __init__(self, input_dim: int, hidden_dim: int = 64, dropout: float = 0.1):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, 2),  # binary classification
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class MixtureOfExperts(nn.Module):
    """
    Mixture of Experts (MoE) — Jacobs et al. 1991.
    Gating network qui apprend à router dynamiquement vers les bons experts.
    """

    def __init__(
        self,
        input_dim: int = 64,
        n_experts: int = 4,
        expert_dim: int = 64,
        gate_dim: int = 64,
        dropout: float = 0.1,
        sparsity_alpha: float = 0.01,
    ):
        super().__init__()
        self.n_experts = n_experts
        self.sparsity_alpha = sparsity_alpha

        self.gate = GatingNetwork(input_dim, n_experts, gate_dim, dropout)
        self.experts = nn.ModuleList([
            ExpertNetwork(input_dim, expert_dim, dropout)
            for _ in range(n_experts)
        ])

        self.history: List[Dict[str, Any]] = []

    def forward(
        self, x: torch.Tensor, return_gates: bool = False
    ) -> Union[torch.Tensor, Tuple[torch.Tensor, torch.Tensor]]:
        # x: (B, input_dim)
        gate_weights = self.gate(x)  # (B, n_experts)

        # Expert outputs
        expert_outputs = []
        for expert in self.experts:
            expert_outputs.append(expert(x))
        expert_outputs = torch.stack(expert_outputs, dim=1)  # (B, n_experts, 2)

        # Weighted combination
        output = torch.einsum('be,beo->bo', gate_weights, expert_outputs)

        if return_gates:
            return output, gate_weights
        return output

    def get_gate_weights(self, x: torch.Tensor) -> np.ndarray:
        """Get gate weights for interpretability."""
        with torch.no_grad():
            weights = self.gate(x).cpu().numpy()
        return weights

    def predict(self, x: torch.Tensor) -> EnsembleResult:
        """Prédiction avec MoE."""
        with torch.no_grad():
            logits, gate_weights = self.forward(x, return_gates=True)
            probs = F.softmax(logits, dim=-1)
            score = float(probs[0, 1].item())
            confidence = float(probs.max().item())

            # Uncertainty from gate distribution
            gate_entropy = float(
                -(gate_weights * torch.log(gate_weights + 1e-8)).sum(dim=1).mean().item()
            )
            uncertainty = gate_entropy / math.log(self.n_experts)

        result = EnsembleResult(
            score=score,
            is_malicious=score > 0.5,
            confidence=confidence,
            uncertainty=uncertainty,
            method="moe",
            model_name="MixtureOfExperts",
            explanation=f"MoE: score={score:.4f}, gate_entropy={gate_entropy:.4f}",
            metadata={
                "gate_weights": gate_weights.cpu().numpy().tolist(),
                "gate_entropy": gate_entropy,
                "n_experts": self.n_experts,
            },
        )

        self.history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "result": result,
        })

        return result

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "MixtureOfExperts",
            "n_experts": self.n_experts,
            "expert_dim": self.experts[0].net[0].in_features,
            "n_params": sum(p.numel() for p in self.parameters()),
            "n_predictions": len(self.history),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 4: NEURAL ARCHITECTURE SEARCH (NAS) — DARTS
# ═══════════════════════════════════════════════════════════════════════════

class DARTSCell(nn.Module):
    """DARTS cell with learnable architecture weights."""

    def __init__(
        self,
        n_nodes: int = 4,
        hidden_dim: int = 64,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.n_nodes = n_nodes
        self.hidden_dim = hidden_dim

        # Architecture weights (alpha)
        self.alpha = nn.Parameter(torch.zeros(n_nodes, n_nodes, 4))  # 4 operations

        # Operations
        self.ops = nn.ModuleDict({
            'none': nn.Identity(),
            'skip': nn.Identity(),
            'linear': nn.Linear(hidden_dim, hidden_dim),
            'relu': nn.ReLU(),
        })

        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (B, hidden_dim)
        B = x.shape[0]
        states = [x]

        for i in range(self.n_nodes):
            s = 0
            for j in range(i + 1):
                # Softmax over operations
                alpha_weights = F.softmax(self.alpha[i, j], dim=-1)

                # Apply weighted operations
                for k, (name, op) in enumerate(self.ops.items()):
                    if name == 'none':
                        continue
                    if isinstance(op, nn.Linear):
                        s += alpha_weights[k] * op(states[j])
                    elif name == 'skip':
                        s += alpha_weights[k] * states[j]
                    elif name == 'relu':
                        s += alpha_weights[k] * F.relu(states[j])

            states.append(self.dropout(s))

        return states[-1]


class DARTSNetwork(nn.Module):
    """
    Neural Architecture Search (DARTS) — Liu et al. 2018.
    Recherche automatique de l'architecture de combinaison optimale.
    """

    def __init__(
        self,
        input_dim: int = 64,
        hidden_dim: int = 64,
        n_cells: int = 3,
        n_nodes: int = 4,
        n_classes: int = 2,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.input_proj = nn.Linear(input_dim, hidden_dim)

        self.cells = nn.ModuleList([
            DARTSCell(n_nodes, hidden_dim, dropout)
            for _ in range(n_cells)
        ])

        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, n_classes),
        )

        self.history: List[Dict[str, Any]] = []

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.input_proj(x)
        for cell in self.cells:
            x = cell(x)
        logits = self.classifier(x)
        return logits

    def get_architecture(self) -> Dict[str, Any]:
        """Get the learned architecture."""
        arch = {}
        for i, cell in enumerate(self.cells):
            alpha = F.softmax(cell.alpha, dim=-1)
            arch[f"cell_{i}"] = alpha.detach().cpu().numpy().tolist()
        return arch

    def predict(self, x: torch.Tensor) -> EnsembleResult:
        """Prédiction avec NAS."""
        with torch.no_grad():
            logits = self.forward(x)
            probs = F.softmax(logits, dim=-1)
            score = float(probs[0, 1].item())
            confidence = float(probs.max().item())

        result = EnsembleResult(
            score=score,
            is_malicious=score > 0.5,
            confidence=confidence,
            uncertainty=1.0 - confidence,
            method="nas",
            model_name="DARTSNetwork",
            explanation=f"NAS: score={score:.4f}, confidence={confidence:.4f}",
            metadata={"architecture": self.get_architecture()},
        )

        self.history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "result": result,
        })

        return result

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "DARTSNetwork",
            "n_cells": len(self.cells),
            "n_nodes": self.cells[0].n_nodes,
            "n_params": sum(p.numel() for p in self.parameters()),
            "n_predictions": len(self.history),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 5: ONLINE LEARNING — Adaptive Weight Update
# ═══════════════════════════════════════════════════════════════════════════

class OnlineWeightAdapter:
    """
    Online Learning pour adaptation des poids en temps réel.
    Utilise Follow-The-Regularized-Leader (FTRL) pour mise à jour.
    """

    def __init__(
        self,
        base_models: Dict[str, Callable],
        learning_rate: float = 0.01,
        regularization: float = 0.001,
        window_size: int = 100,
    ):
        self.base_models = base_models
        self.lr = learning_rate
        self.reg = regularization
        self.window_size = window_size

        n_models = len(base_models)
        self.weights = np.ones(n_models) / n_models
        self.gradients = np.zeros(n_models)
        self.model_names = list(base_models.keys())
        self.model_index = {name: i for i, name in enumerate(self.model_names)}

        self.performance_history: Dict[str, deque] = {
            name: deque(maxlen=window_size) for name in base_models
        }
        self.history: List[Dict[str, Any]] = []

        logger.info(
            "online_adapter_initialized",
            n_models=n_models,
            learning_rate=learning_rate,
        )

    def update(self, model_name: str, error: float):
        """Update weights based on prediction error."""
        idx = self.model_index[model_name]
        self.performance_history[model_name].append(error)

        # FTRL update
        self.gradients[idx] += error
        self.weights[idx] = max(0, self.weights[idx] - self.lr * (
            self.gradients[idx] + self.reg * self.weights[idx]
        ))

        # Normalize
        self.weights = self.weights / (self.weights.sum() + 1e-8)

    def predict(self, x: torch.Tensor) -> EnsembleResult:
        """Prédiction avec poids adaptatifs."""
        weighted_score = 0.0
        explanations = []
        individual_scores = {}

        for i, (name, model) in enumerate(self.base_models.items()):
            if hasattr(model, 'predict'):
                result = model.predict(x)
                w = self.weights[i]
                weighted_score += w * result.score
                individual_scores[name] = result.score
                explanations.append(f"{name}: {result.score:.4f} (w={w:.3f})")

        final_score = weighted_score
        confidence = float(np.mean(list(individual_scores.values())))
        uncertainty = float(np.std(list(individual_scores.values())))

        result = EnsembleResult(
            score=final_score,
            is_malicious=final_score > 0.5,
            confidence=confidence,
            uncertainty=uncertainty,
            method="online",
            model_name="OnlineWeightAdapter",
            explanation=" | ".join(explanations),
            metadata={
                "weights": dict(zip(self.model_names, self.weights.tolist())),
                "individual_scores": individual_scores,
            },
        )

        self.history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "result": result,
        })

        return result

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "OnlineWeightAdapter",
            "n_models": len(self.base_models),
            "learning_rate": self.lr,
            "weights": dict(zip(self.model_names, self.weights.tolist())),
            "n_predictions": len(self.history),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 6: UNCERTAINTY QUANTIFICATION
# ═══════════════════════════════════════════════════════════════════════════

class UncertaintyQuantifier:
    """
    Uncertainty Quantification avec Monte Carlo Dropout et Deep Ensembles.
    """

    def __init__(
        self,
        model: nn.Module,
        n_mc_samples: int = 50,
        dropout_rate: float = 0.1,
        n_ensemble: int = 5,
    ):
        self.model = model
        self.n_mc_samples = n_mc_samples
        self.dropout_rate = dropout_rate
        self.n_ensemble = n_ensemble

        # Enable dropout during inference
        self._enable_dropout()

        self.history: List[Dict[str, Any]] = []

    def _enable_dropout(self):
        """Enable dropout layers for MC Dropout."""
        for module in self.model.modules():
            if isinstance(module, nn.Dropout):
                module.train()

    def mc_dropout_predict(self, x: torch.Tensor) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Monte Carlo Dropout prediction."""
        predictions = []
        with torch.no_grad():
            for _ in range(self.n_mc_samples):
                logits = self.model(x)
                probs = F.softmax(logits, dim=-1)
                predictions.append(probs.cpu().numpy())

        predictions = np.array(predictions)  # (n_samples, B, n_classes)
        mean_pred = predictions.mean(axis=0)
        std_pred = predictions.std(axis=0)
        entropy = -np.sum(mean_pred * np.log(mean_pred + 1e-8), axis=-1)

        return mean_pred, std_pred, entropy

    def predict(self, x: torch.Tensor) -> EnsembleResult:
        """Prédiction avec quantification d'incertitude."""
        mean_pred, std_pred, entropy = self.mc_dropout_predict(x)

        score = float(mean_pred[0, 1])
        confidence = float(mean_pred.max())
        epistemic_uncertainty = float(std_pred[0, 1])
        aleatoric_uncertainty = float(entropy[0])

        result = EnsembleResult(
            score=score,
            is_malicious=score > 0.5,
            confidence=confidence,
            uncertainty=epistemic_uncertainty,
            method="uq",
            model_name="UncertaintyQuantifier",
            explanation=(
                f"UQ: score={score:.4f}, "
                f"epistemic={epistemic_uncertainty:.4f}, "
                f"aleatoric={aleatoric_uncertainty:.4f}"
            ),
            metadata={
                "epistemic_uncertainty": epistemic_uncertainty,
                "aleatoric_uncertainty": aleatoric_uncertainty,
                "n_mc_samples": self.n_mc_samples,
                "std_pred": std_pred.tolist(),
            },
        )

        self.history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "result": result,
        })

        return result

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "UncertaintyQuantifier",
            "n_mc_samples": self.n_mc_samples,
            "n_ensemble": self.n_ensemble,
            "n_predictions": len(self.history),
        }


# ═══════════════════════════════════════════════════════════════════════════
# META-ENSEMBLE ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════

class MetaEnsembleOrchestrator:
    """
    Orchestrateur qui combine toutes les techniques d'ensemble.
    Utilise un meta-meta-ensemble pour la décision finale.
    """

    def __init__(
        self,
        methods: Dict[str, Any],
        weights: Optional[Dict[str, float]] = None,
    ):
        self.methods = methods
        self.weights = weights or {
            name: 1.0 / len(methods)
            for name in methods
        }
        self.history: List[Dict[str, Any]] = []

        logger.info(
            "meta_ensemble_orchestrator_initialized",
            n_methods=len(methods),
            weights=self.weights,
        )

    def predict(self, x: torch.Tensor) -> EnsembleResult:
        """Prédiction combinée de toutes les méthodes."""
        results = []
        explanations = []

        for name, method in self.methods.items():
            if hasattr(method, 'predict'):
                r = method.predict(x)
                w = self.weights.get(name, 1.0 / len(self.methods))
                results.append((r, w))
                explanations.append(f"{name}: {r.score:.4f} (w={w:.3f})")

        if not results:
            return EnsembleResult(
                score=0.0, is_malicious=False, confidence=0.0,
                uncertainty=1.0, method="meta_ensemble",
                model_name="MetaEnsembleOrchestrator",
            )

        # Weighted combination
        weighted_score = sum(r.score * w for r, w in results)
        total_weight = sum(w for _, w in results)
        final_score = weighted_score / total_weight if total_weight > 0 else 0.0

        avg_confidence = np.mean([r.confidence for r, _ in results])
        avg_uncertainty = np.mean([r.uncertainty for r, _ in results])

        result = EnsembleResult(
            score=final_score,
            is_malicious=final_score > 0.5,
            confidence=avg_confidence,
            uncertainty=avg_uncertainty,
            method="meta_ensemble",
            model_name="MetaEnsembleOrchestrator",
            explanation=" | ".join(explanations),
            metadata={
                "n_methods": len(results),
                "individual_scores": {r.model_name: r.score for r, _ in results},
            },
        )

        self.history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "result": result,
        })

        return result

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "MetaEnsembleOrchestrator",
            "n_methods": len(self.methods),
            "weights": self.weights,
            "n_predictions": len(self.history),
            "methods": {
                name: method.get_stats() if hasattr(method, 'get_stats') else {}
                for name, method in self.methods.items()
            },
        }


# ═══════════════════════════════════════════════════════════════════════════
# FACTORY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def create_meta_ensemble(
    base_models: Optional[Dict[str, Callable]] = None,
    input_dim: int = 64,
    device: str = "cpu",
    use_stacking: bool = True,
    use_bayesian: bool = True,
    use_moe: bool = True,
    use_nas: bool = True,
    use_online: bool = True,
    use_uq: bool = True,
) -> Dict[str, Any]:
    """
    Crée le système meta-ensemble complet Niveau 11.

    Args:
        base_models: Modèles de base à ensembler
        input_dim: Dimension d'entrée
        device: "cpu" ou "cuda"
        use_stacking: Activer StackingEnsemble
        use_bayesian: Activer BayesianModelAveraging
        use_moe: Activer MixtureOfExperts
        use_nas: Activer DARTSNetwork
        use_online: Activer OnlineWeightAdapter
        use_uq: Activer UncertaintyQuantifier

    Returns:
        Dict avec tous les composants
    """
    methods = {}

    if base_models is None:
        base_models = {}

    if use_stacking:
        methods["stacking"] = StackingEnsemble(base_models=base_models)
        logger.info("✅ StackingEnsemble initialized")

    if use_bayesian:
        methods["bayesian"] = BayesianModelAveraging(base_models=base_models)
        logger.info("✅ BayesianModelAveraging initialized")

    if use_moe:
        methods["moe"] = MixtureOfExperts(input_dim=input_dim)
        logger.info("✅ MixtureOfExperts initialized")

    if use_nas:
        methods["nas"] = DARTSNetwork(input_dim=input_dim)
        logger.info("✅ DARTSNetwork initialized")

    if use_online:
        methods["online"] = OnlineWeightAdapter(base_models=base_models)
        logger.info("✅ OnlineWeightAdapter initialized")

    if use_uq:
        # Use MoE as the base model for UQ
        uq_model = MixtureOfExperts(input_dim=input_dim)
        methods["uq"] = UncertaintyQuantifier(model=uq_model)
        logger.info("✅ UncertaintyQuantifier initialized")

    orchestrator = MetaEnsembleOrchestrator(methods=methods)
    logger.info("✅ MetaEnsembleOrchestrator initialized")

    return {
        "methods": methods,
        "orchestrator": orchestrator,
        "config": {
            "input_dim": input_dim,
            "device": device,
            "n_methods": len(methods),
        },
    }


def create_meta_ensemble_minimal() -> Dict[str, Any]:
    """Version minimale pour démarrage rapide."""
    return create_meta_ensemble(
        use_stacking=True,
        use_bayesian=False,
        use_moe=False,
        use_nas=False,
        use_online=False,
        use_uq=False,
    )


def create_meta_ensemble_full() -> Dict[str, Any]:
    """Version complète avec toutes les méthodes."""
    return create_meta_ensemble(
        use_stacking=True,
        use_bayesian=True,
        use_moe=True,
        use_nas=True,
        use_online=True,
        use_uq=True,
    )


# Instance globale
meta_ensemble_system = create_meta_ensemble_full()


def get_meta_ensemble() -> Dict[str, Any]:
    """Get the global meta-ensemble system instance."""
    return meta_ensemble_system
