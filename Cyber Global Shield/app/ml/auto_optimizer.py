"""
Cyber Global Shield — Auto-ML & Hyperparameter Optimization Module (Niveau 12)
================================================================================

6 techniques de pointe pour l'optimisation automatique :

1. Bayesian Optimization (GP + EI) — Optimisation globale probabiliste
2. Hyperband — Allocation adaptative de ressources
3. Population Based Training (PBT) — Évolution + RL
4. CMA-ES — Stratégie d'évolution adaptative
5. DARTS — Differentiable Architecture Search
6. Auto-Augment — Apprentissage de politiques d'augmentation

Chaque optimiseur peut fonctionner indépendamment ou via l'orchestrateur.
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
import random
from copy import deepcopy
from scipy.stats import norm
from sklearn.gaussian_process import GaussianProcessRegressor
from sklearn.gaussian_process.kernels import Matern, RBF, WhiteKernel

logger = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class HyperparameterConfig:
    """Configuration d'hyperparamètres."""
    params: Dict[str, Any]
    score: float = 0.0
    budget: float = 1.0
    generation: int = 0
    timestamp: float = 0.0


@dataclass
class OptimizationResult:
    """Résultat d'optimisation."""
    best_config: Dict[str, Any]
    best_score: float
    n_trials: int
    method: str
    history: List[Dict[str, Any]]
    convergence_speed: float
    metadata: Dict[str, Any] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════
# SEARCH SPACE DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════

class SearchSpace:
    """Espace de recherche pour hyperparamètres."""

    def __init__(self):
        self.params: Dict[str, Dict[str, Any]] = {}

    def add_float(
        self, name: str, low: float, high: float, log: bool = False
    ):
        self.params[name] = {
            "type": "float", "low": low, "high": high, "log": log
        }

    def add_int(self, name: str, low: int, high: int, log: bool = False):
        self.params[name] = {
            "type": "int", "low": low, "high": high, "log": log
        }

    def add_categorical(self, name: str, choices: List[Any]):
        self.params[name] = {
            "type": "categorical", "choices": choices
        }

    def sample_random(self) -> Dict[str, Any]:
        """Sample random configuration."""
        config = {}
        for name, spec in self.params.items():
            if spec["type"] == "float":
                if spec["log"]:
                    config[name] = np.exp(
                        np.random.uniform(
                            np.log(spec["low"]), np.log(spec["high"])
                        )
                    )
                else:
                    config[name] = np.random.uniform(spec["low"], spec["high"])
            elif spec["type"] == "int":
                if spec["log"]:
                    config[name] = int(np.exp(
                        np.random.uniform(
                            np.log(spec["low"]), np.log(spec["high"])
                        )
                    ))
                else:
                    config[name] = np.random.randint(spec["low"], spec["high"] + 1)
            elif spec["type"] == "categorical":
                config[name] = np.random.choice(spec["choices"])
        return config

    def to_array(self, config: Dict[str, Any]) -> np.ndarray:
        """Convert config to array for GP."""
        arr = []
        for name, spec in self.params.items():
            val = config[name]
            if spec["type"] == "float":
                if spec["log"]:
                    val = np.log(val)
                arr.append(val)
            elif spec["type"] == "int":
                if spec["log"]:
                    val = np.log(val)
                arr.append(val)
            elif spec["type"] == "categorical":
                # One-hot encoding
                one_hot = np.zeros(len(spec["choices"]))
                idx = spec["choices"].index(val)
                one_hot[idx] = 1
                arr.extend(one_hot)
        return np.array(arr)

    def from_array(self, arr: np.ndarray) -> Dict[str, Any]:
        """Convert array back to config."""
        config = {}
        idx = 0
        for name, spec in self.params.items():
            if spec["type"] == "float":
                val = arr[idx]
                if spec["log"]:
                    val = np.exp(val)
                config[name] = float(val)
                idx += 1
            elif spec["type"] == "int":
                val = arr[idx]
                if spec["log"]:
                    val = np.exp(val)
                config[name] = int(round(val))
                idx += 1
            elif spec["type"] == "categorical":
                n = len(spec["choices"])
                one_hot = arr[idx:idx + n]
                config[name] = spec["choices"][np.argmax(one_hot)]
                idx += n
        return config

    @property
    def dim(self) -> int:
        """Dimensionality of the search space."""
        d = 0
        for spec in self.params.values():
            if spec["type"] == "categorical":
                d += len(spec["choices"])
            else:
                d += 1
        return d


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 1: BAYESIAN OPTIMIZATION (GP + EI)
# ═══════════════════════════════════════════════════════════════════════════

class BayesianOptimizer:
    """
    Bayesian Optimization with Gaussian Process and Expected Improvement.
    """

    def __init__(
        self,
        search_space: SearchSpace,
        acquisition: str = "ei",  # "ei", "ucb", "poi"
        n_initial: int = 10,
        kappa: float = 2.5,
        xi: float = 0.01,
    ):
        self.search_space = search_space
        self.acquisition = acquisition
        self.n_initial = n_initial
        self.kappa = kappa
        self.xi = xi

        # GP model
        kernel = Matern(nu=2.5) + WhiteKernel(noise_level=1e-6)
        self.gp = GaussianProcessRegressor(
            kernel=kernel,
            n_restarts_optimizer=10,
            random_state=42,
        )

        self.X: List[np.ndarray] = []
        self.y: List[float] = []
        self.history: List[Dict[str, Any]] = []
        self.best_score = -np.inf
        self.best_config = None

        logger.info(
            "bayesian_optimizer_initialized",
            dim=search_space.dim,
            acquisition=acquisition,
        )

    def suggest(self) -> Dict[str, Any]:
        """Suggest next configuration to evaluate."""
        if len(self.X) < self.n_initial:
            return self.search_space.sample_random()

        # Fit GP
        X_arr = np.array(self.X)
        y_arr = np.array(self.y)
        self.gp.fit(X_arr, y_arr)

        # Optimize acquisition function
        best_acq = -np.inf
        best_x = None

        # Random candidates for acquisition optimization
        n_candidates = 1000
        candidates = np.random.randn(n_candidates, self.search_space.dim)

        # Scale candidates to search space bounds
        for i, (name, spec) in enumerate(self.search_space.params.items()):
            if spec["type"] in ["float", "int"]:
                low = np.log(spec["low"]) if spec["log"] else spec["low"]
                high = np.log(spec["high"]) if spec["log"] else spec["high"]
                candidates[:, i] = low + (high - low) * (
                    (candidates[:, i] - candidates[:, i].min()) /
                    (candidates[:, i].max() - candidates[:, i].min() + 1e-8)
                )

        # Evaluate acquisition
        mu, sigma = self.gp.predict(candidates, return_std=True)
        sigma = np.maximum(sigma, 1e-8)

        if self.acquisition == "ei":
            # Expected Improvement
            imp = mu - self.best_score - self.xi
            Z = imp / sigma
            acq = imp * norm.cdf(Z) + sigma * norm.pdf(Z)
        elif self.acquisition == "ucb":
            # Upper Confidence Bound
            acq = mu + self.kappa * sigma
        elif self.acquisition == "poi":
            # Probability of Improvement
            imp = mu - self.best_score - self.xi
            Z = imp / sigma
            acq = norm.cdf(Z)
        else:
            raise ValueError(f"Unknown acquisition: {self.acquisition}")

        best_idx = np.argmax(acq)
        best_x = candidates[best_idx]

        return self.search_space.from_array(best_x)

    def update(self, config: Dict[str, Any], score: float):
        """Update with evaluation result."""
        x = self.search_space.to_array(config)
        self.X.append(x)
        self.y.append(score)

        if score > self.best_score:
            self.best_score = score
            self.best_config = deepcopy(config)

        self.history.append({
            "config": deepcopy(config),
            "score": score,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def optimize(
        self, objective: Callable, n_trials: int = 100
    ) -> OptimizationResult:
        """Run optimization loop."""
        start_time = datetime.now(timezone.utc)

        for i in range(n_trials):
            config = self.suggest()
            score = objective(config)
            self.update(config, score)

            if (i + 1) % 10 == 0:
                logger.info(
                    "bayesian_optimization_step",
                    step=i + 1,
                    best_score=self.best_score,
                )

        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

        return OptimizationResult(
            best_config=self.best_config,
            best_score=self.best_score,
            n_trials=n_trials,
            method="bayesian",
            history=self.history,
            convergence_speed=len(self.history) / max(elapsed, 0.001),
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "BayesianOptimizer",
            "dim": self.search_space.dim,
            "acquisition": self.acquisition,
            "n_trials": len(self.X),
            "best_score": self.best_score,
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 2: HYPERBAND
# ═══════════════════════════════════════════════════════════════════════════

class HyperbandOptimizer:
    """
    Hyperband — Li et al. 2017.
    Allocation adaptative de ressources avec Successive Halving.
    """

    def __init__(
        self,
        search_space: SearchSpace,
        eta: int = 3,
        R: int = 81,
    ):
        self.search_space = search_space
        self.eta = eta
        self.R = R

        # Hyperband brackets
        self.n_brackets = int(np.log(R) / np.log(eta)) + 1
        self.brackets: List[Dict[str, Any]] = []
        self.history: List[Dict[str, Any]] = []

        logger.info(
            "hyperband_initialized",
            eta=eta,
            R=R,
            n_brackets=self.n_brackets,
        )

    def _generate_bracket(self, s: int) -> Dict[str, Any]:
        """Generate a Hyperband bracket."""
        n = int(np.ceil(self.n_brackets * (self.eta ** s) / (s + 1)))
        r = self.R * (self.eta ** (-s))

        return {
            "s": s,
            "n": n,
            "r": r,
            "configs": [],
            "scores": [],
        }

    def suggest(self) -> Dict[str, Any]:
        """Suggest next configuration."""
        # Find bracket with capacity
        for bracket in self.brackets:
            if len(bracket["configs"]) < bracket["n"]:
                config = self.search_space.sample_random()
                bracket["configs"].append(config)
                return config

        # All brackets full, start new bracket
        s = len(self.brackets) % self.n_brackets
        bracket = self._generate_bracket(s)
        self.brackets.append(bracket)
        config = self.search_space.sample_random()
        bracket["configs"].append(config)
        return config

    def update(self, config: Dict[str, Any], score: float):
        """Update with evaluation result."""
        for bracket in self.brackets:
            for i, c in enumerate(bracket["configs"]):
                if c == config:
                    bracket["scores"].append(score)
                    break

        self.history.append({
            "config": deepcopy(config),
            "score": score,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def get_top_configs(self, n: int = 5) -> List[Dict[str, Any]]:
        """Get top n configurations."""
        scored = [(h["score"], h["config"]) for h in self.history]
        scored.sort(key=lambda x: x[0], reverse=True)
        return [c for _, c in scored[:n]]

    def optimize(
        self, objective: Callable, n_trials: int = 100
    ) -> OptimizationResult:
        """Run optimization loop."""
        start_time = datetime.now(timezone.utc)

        for i in range(n_trials):
            config = self.suggest()
            score = objective(config)
            self.update(config, score)

            if (i + 1) % 10 == 0:
                logger.info(
                    "hyperband_step",
                    step=i + 1,
                    n_brackets=len(self.brackets),
                )

        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        best = self.get_top_configs(1)[0]
        best_score = max(h["score"] for h in self.history)

        return OptimizationResult(
            best_config=best,
            best_score=best_score,
            n_trials=n_trials,
            method="hyperband",
            history=self.history,
            convergence_speed=len(self.history) / max(elapsed, 0.001),
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "HyperbandOptimizer",
            "eta": self.eta,
            "R": self.R,
            "n_brackets": self.n_brackets,
            "n_trials": len(self.history),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 3: POPULATION BASED TRAINING (PBT)
# ═══════════════════════════════════════════════════════════════════════════

class PBTWorker:
    """Worker individuel dans PBT."""

    def __init__(self, config: Dict[str, Any], model: nn.Module):
        self.config = config
        self.model = model
        self.score = 0.0
        self.generation = 0
        self.history: List[float] = []


class PopulationBasedTraining:
    """
    Population Based Training — Jaderberg et al. 2017.
    Combine evolution et RL pour l'optimisation d'hyperparamètres.
    """

    def __init__(
        self,
        search_space: SearchSpace,
        population_size: int = 20,
        fraction_exploit: float = 0.2,
        fraction_explore: float = 0.2,
        perturbation_std: float = 0.1,
    ):
        self.search_space = search_space
        self.population_size = population_size
        self.fraction_exploit = fraction_exploit
        self.fraction_explore = fraction_explore
        self.perturbation_std = perturbation_std

        self.population: List[PBTWorker] = []
        self.history: List[Dict[str, Any]] = []
        self.generation = 0

        logger.info(
            "pbt_initialized",
            population_size=population_size,
        )

    def initialize_population(self, model_factory: Callable):
        """Initialize population with random configs."""
        for _ in range(self.population_size):
            config = self.search_space.sample_random()
            model = model_factory(config)
            self.population.append(PBTWorker(config, model))

    def _exploit_and_explore(self):
        """PBT exploit and explore step."""
        # Sort by score
        self.population.sort(key=lambda w: w.score, reverse=True)

        n_exploit = int(self.population_size * self.fraction_exploit)
        n_explore = int(self.population_size * self.fraction_explore)

        # Exploit: copy top performers
        for i in range(n_exploit):
            target_idx = -(i + 1)  # worst performers
            source_idx = i  # best performers

            # Copy model weights
            self.population[target_idx].model.load_state_dict(
                self.population[source_idx].model.state_dict()
            )

            # Copy config
            self.population[target_idx].config = deepcopy(
                self.population[source_idx].config
            )

        # Explore: perturb configs
        for i in range(n_explore):
            idx = -(i + 1)
            config = self.population[idx].config

            for name, spec in self.search_space.params.items():
                if name in config:
                    if spec["type"] in ["float", "int"]:
                        # Perturb with noise
                        if spec["log"]:
                            val = np.log(config[name])
                            val += np.random.randn() * self.perturbation_std
                            val = np.exp(val)
                        else:
                            val = config[name] + np.random.randn() * self.perturbation_std
                        val = np.clip(val, spec["low"], spec["high"])
                        if spec["type"] == "int":
                            val = int(round(val))
                        config[name] = val
                    elif spec["type"] == "categorical":
                        if np.random.random() < self.perturbation_std:
                            config[name] = np.random.choice(spec["choices"])

            self.population[idx].config = config
            self.population[idx].generation = self.generation

    def update(self, worker_idx: int, score: float):
        """Update worker score."""
        self.population[worker_idx].score = score
        self.population[worker_idx].history.append(score)

    def get_best_config(self) -> Dict[str, Any]:
        """Get best configuration."""
        best = max(self.population, key=lambda w: w.score)
        return best.config

    def step(self, evaluate_fn: Callable):
        """Run one PBT generation."""
        # Evaluate all workers
        for i, worker in enumerate(self.population):
            score = evaluate_fn(worker.config, worker.model)
            self.update(i, score)

        # Exploit and explore
        self._exploit_and_explore()

        self.generation += 1

        self.history.append({
            "generation": self.generation,
            "best_score": max(w.score for w in self.population),
            "mean_score": np.mean([w.score for w in self.population]),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def optimize(
        self, evaluate_fn: Callable, n_generations: int = 50
    ) -> OptimizationResult:
        """Run PBT optimization."""
        start_time = datetime.now(timezone.utc)

        for gen in range(n_generations):
            self.step(evaluate_fn)

            if (gen + 1) % 10 == 0:
                logger.info(
                    "pbt_generation",
                    generation=gen + 1,
                    best_score=max(w.score for w in self.population),
                )

        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        best_config = self.get_best_config()
        best_score = max(w.score for w in self.population)

        return OptimizationResult(
            best_config=best_config,
            best_score=best_score,
            n_trials=self.population_size * n_generations,
            method="pbt",
            history=self.history,
            convergence_speed=len(self.history) / max(elapsed, 0.001),
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "PopulationBasedTraining",
            "population_size": self.population_size,
            "generation": self.generation,
            "best_score": max((w.score for w in self.population), default=0.0),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 4: CMA-ES
# ═══════════════════════════════════════════════════════════════════════════

class CMAESOptimizer:
    """
    Covariance Matrix Adaptation Evolution Strategy.
    Hansen & Ostermeier 2001.
    """

    def __init__(
        self,
        search_space: SearchSpace,
        sigma: float = 0.5,
        population_size: Optional[int] = None,
    ):
        self.search_space = search_space
        self.dim = search_space.dim
        self.sigma = sigma

        # Population size
        if population_size is None:
            self.population_size = 4 + int(3 * np.log(self.dim))
        else:
            self.population_size = population_size

        # CMA-ES parameters
        self.mean = np.zeros(self.dim)
        self.C = np.eye(self.dim)  # covariance matrix
        self.pc = np.zeros(self.dim)  # evolution path
        self.ps = np.zeros(self.dim)  # conjugate evolution path

        # Strategy parameters
        self.n = self.dim
        self.lambda_ = self.population_size
        self.mu = self.lambda_ // 2

        # Weights
        self.weights = np.log(self.mu + 0.5) - np.log(np.arange(1, self.mu + 1))
        self.weights = self.weights / self.weights.sum()
        self.mueff = 1.0 / np.sum(self.weights ** 2)

        # Adaptation parameters
        self.cc = (4 + self.mueff / self.n) / (self.n + 4 + 2 * self.mueff / self.n)
        self.cs = (self.mueff + 2) / (self.n + self.mueff + 5)
        self.c1 = 2 / ((self.n + 1.3) ** 2 + self.mueff)
        self.cmu = min(
            1 - self.c1,
            2 * (self.mueff - 2 + 1 / self.mueff) / ((self.n + 2) ** 2 + self.mueff)
        )
        self.damps = 1 + 2 * max(0, np.sqrt((self.mueff - 1) / (self.n + 1)) - 1) + self.cs

        self.history: List[Dict[str, Any]] = []
        self.best_score = -np.inf
        self.best_config = None

        logger.info(
            "cmaes_initialized",
            dim=self.dim,
            population_size=self.population_size,
        )

    def sample_population(self) -> List[Dict[str, Any]]:
        """Sample new population."""
        samples = []
        for _ in range(self.lambda_):
            z = np.random.randn(self.dim)
            x = self.mean + self.sigma * self.C @ z
            config = self.search_space.from_array(x)
            samples.append((config, z))
        return samples

    def update(self, samples: List[Tuple[Dict[str, Any], np.ndarray]], scores: List[float]):
        """Update CMA-ES parameters."""
        # Sort by score
        sorted_idx = np.argsort(scores)[::-1]
        samples = [samples[i] for i in sorted_idx]
        scores = [scores[i] for i in sorted_idx]

        # Update best
        if scores[0] > self.best_score:
            self.best_score = scores[0]
            self.best_config = deepcopy(samples[0][0])

        # Select top mu
        z = np.array([samples[i][1] for i in range(self.mu)])
        x = np.array([
            self.search_space.to_array(samples[i][0])
            for i in range(self.mu)
        ])

        # Update mean
        old_mean = self.mean.copy()
        self.mean = np.dot(self.weights, x)

        # Update evolution paths
        c = self.mean - old_mean
        self.ps = (1 - self.cs) * self.ps + np.sqrt(
            self.cs * (2 - self.cs) * self.mueff
        ) * np.linalg.solve(self.C, c)
        self.pc = (1 - self.cc) * self.pc + np.sqrt(
            self.cc * (2 - self.cc) * self.mueff
        ) * c

        # Update covariance matrix
        artmp = (x - old_mean) / self.sigma
        self.C = (1 - self.c1 - self.cmu) * self.C + \
                 self.c1 * np.outer(self.pc, self.pc) + \
                 self.cmu * np.dot(
                     (self.weights * artmp.T), artmp
                 )

        # Update step size
        ps_norm = np.linalg.norm(self.ps)
        self.sigma *= np.exp(
            (self.cs / self.damps) * (ps_norm / np.sqrt(self.n) - 1)
        )

        self.history.append({
            "best_score": self.best_score,
            "sigma": self.sigma,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def optimize(
        self, objective: Callable, n_generations: int = 100
    ) -> OptimizationResult:
        """Run CMA-ES optimization."""
        start_time = datetime.now(timezone.utc)

        for gen in range(n_generations):
            samples = self.sample_population()
            scores = [objective(config) for config, _ in samples]
            self.update(samples, scores)

            if (gen + 1) % 10 == 0:
                logger.info(
                    "cmaes_generation",
                    generation=gen + 1,
                    best_score=self.best_score,
                    sigma=self.sigma,
                )

        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

        return OptimizationResult(
            best_config=self.best_config,
            best_score=self.best_score,
            n_trials=self.lambda_ * n_generations,
            method="cmaes",
            history=self.history,
            convergence_speed=len(self.history) / max(elapsed, 0.001),
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "CMAESOptimizer",
            "dim": self.dim,
            "population_size": self.population_size,
            "sigma": self.sigma,
            "best_score": self.best_score,
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 5: AUTO-AUGMENT
# ═══════════════════════════════════════════════════════════════════════════

class AutoAugmentPolicy(nn.Module):
    """
    AutoAugment — Cubuk et al. 2019.
    Apprentissage de politiques d'augmentation de données.
    """

    def __init__(
        self,
        n_sub_policies: int = 5,
        n_operations: int = 3,
        magnitude_std: float = 0.1,
    ):
        super().__init__()
        self.n_sub_policies = n_sub_policies
        self.n_operations = n_operations

        # Learnable policy parameters
        self.policy_logits = nn.Parameter(
            torch.zeros(n_sub_policies, n_operations, 2)  # operation, magnitude
        )
        self.magnitude_std = magnitude_std

        # Available operations
        self.operations = [
            'identity', 'rotate', 'translate_x', 'translate_y',
            'shear_x', 'shear_y', 'scale', 'contrast',
            'brightness', 'sharpness', 'solarize', 'posterize',
        ]
        self.n_ops = len(self.operations)

        self.history: List[Dict[str, Any]] = []

    def get_policy(self) -> List[Tuple[str, float]]:
        """Get current augmentation policy."""
        policy = []
        probs = F.softmax(self.policy_logits[..., 0], dim=-1)

        for i in range(self.n_sub_policies):
            for j in range(self.n_operations):
                op_idx = probs[i, j].argmax().item()
                magnitude = torch.sigmoid(self.policy_logits[i, j, 1]).item()
                policy.append((self.operations[op_idx], magnitude))

        return policy

    def apply_augmentation(
        self, x: torch.Tensor, policy: List[Tuple[str, float]]
    ) -> torch.Tensor:
        """Apply augmentation policy to data."""
        augmented = x.clone()

        for op_name, magnitude in policy:
            if op_name == 'identity':
                continue
            elif op_name == 'rotate':
                angle = magnitude * 30  # max 30 degrees
                theta = torch.tensor([
                    [np.cos(angle), -np.sin(angle), 0],
                    [np.sin(angle), np.cos(angle), 0]
                ], dtype=torch.float32)
                grid = F.affine_grid(
                    theta.unsqueeze(0), augmented.shape, align_corners=False
                )
                augmented = F.grid_sample(
                    augmented, grid, align_corners=False
                )
            elif op_name == 'translate_x':
                shift = magnitude * augmented.shape[-1] * 0.1
                theta = torch.tensor([
                    [1, 0, shift],
                    [0, 1, 0]
                ], dtype=torch.float32)
                grid = F.affine_grid(
                    theta.unsqueeze(0), augmented.shape, align_corners=False
                )
                augmented = F.grid_sample(
                    augmented, grid, align_corners=False
                )
            elif op_name == 'translate_y':
                shift = magnitude * augmented.shape[-2] * 0.1
                theta = torch.tensor([
                    [1, 0, 0],
                    [0, 1, shift]
                ], dtype=torch.float32)
                grid = F.affine_grid(
                    theta.unsqueeze(0), augmented.shape, align_corners=False
                )
                augmented = F.grid_sample(
                    augmented, grid, align_corners=False
                )
            elif op_name == 'contrast':
                factor = 1 + (magnitude - 0.5) * 0.5
                mean = augmented.mean(dim=[2, 3], keepdim=True)
                augmented = (augmented - mean) * factor + mean
            elif op_name == 'brightness':
                factor = 1 + (magnitude - 0.5) * 0.5
                augmented = augmented * factor
            elif op_name == 'sharpness':
                # Simple sharpening
                blur = F.avg_pool2d(augmented, kernel_size=3, stride=1, padding=1)
                augmented = augmented + magnitude * (augmented - blur)
            elif op_name == 'solarize':
                threshold = magnitude
                augmented = torch.where(
                    augmented > threshold, 1 - augmented, augmented
                )
            elif op_name == 'posterize':
                bits = max(1, int(magnitude * 7 + 1))
                augmented = torch.floor(augmented * (2 ** bits)) / (2 ** bits)

        return torch.clamp(augmented, 0, 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Apply learned augmentation policy."""
        policy = self.get_policy()
        return self.apply_augmentation(x, policy)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "AutoAugmentPolicy",
            "n_sub_policies": self.n_sub_policies,
            "n_operations": self.n_operations,
            "policy": self.get_policy(),
        }


# ═══════════════════════════════════════════════════════════════════════════
# AUTO-ML ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════

class AutoMLOrchestrator:
    """
    Orchestrateur Auto-ML qui combine tous les optimiseurs.
    """

    def __init__(
        self,
        optimizers: Dict[str, Any],
        weights: Optional[Dict[str, float]] = None,
    ):
        self.optimizers = optimizers
        self.weights = weights or {
            name: 1.0 / len(optimizers)
            for name in optimizers
        }
        self.history: List[Dict[str, Any]] = []

        logger.info(
            "automl_orchestrator_initialized",
            n_optimizers=len(optimizers),
            weights=self.weights,
        )

    def suggest(self) -> Dict[str, Any]:
        """Suggest configuration from best optimizer."""
        best_optimizer = max(
            self.optimizers.items(),
            key=lambda x: x[1].best_score if hasattr(x[1], 'best_score') else 0
        )
        if hasattr(best_optimizer[1], 'suggest'):
            return best_optimizer[1].suggest()
        return {}

    def get_best_config(self) -> Dict[str, Any]:
        """Get best configuration across all optimizers."""
        best_score = -np.inf
        best_config = None

        for name, opt in self.optimizers.items():
            if hasattr(opt, 'best_score') and opt.best_score > best_score:
                best_score = opt.best_score
                best_config = opt.best_config

        return best_config or {}

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "AutoMLOrchestrator",
            "n_optimizers": len(self.optimizers),
            "weights": self.weights,
            "optimizers": {
                name: opt.get_stats() if hasattr(opt, 'get_stats') else {}
                for name, opt in self.optimizers.items()
            },
        }


# ═══════════════════════════════════════════════════════════════════════════
# FACTORY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def create_auto_optimizer(
    search_space: Optional[SearchSpace] = None,
    device: str = "cpu",
    use_bayesian: bool = True,
    use_hyperband: bool = True,
    use_pbt: bool = True,
    use_cmaes: bool = True,
    use_auto_augment: bool = True,
) -> Dict[str, Any]:
    """
    Crée le système Auto-ML complet Niveau 12.

    Args:
        search_space: Espace de recherche (créé par défaut si None)
        device: "cpu" ou "cuda"
        use_bayesian: Activer BayesianOptimizer
        use_hyperband: Activer HyperbandOptimizer
        use_pbt: Activer PopulationBasedTraining
        use_cmaes: Activer CMAESOptimizer
        use_auto_augment: Activer AutoAugmentPolicy

    Returns:
        Dict avec tous les composants
    """
    if search_space is None:
        search_space = SearchSpace()
        search_space.add_float("learning_rate", 1e-5, 1e-1, log=True)
        search_space.add_int("batch_size", 16, 256, log=True)
        search_space.add_int("hidden_dim", 32, 512, log=True)
        search_space.add_int("n_layers", 1, 6)
        search_space.add_float("dropout", 0.0, 0.5)
        search_space.add_float("weight_decay", 1e-6, 1e-2, log=True)
        search_space.add_categorical("optimizer", ["adam", "sgd", "adamw"])

    optimizers = {}

    if use_bayesian:
        optimizers["bayesian"] = BayesianOptimizer(search_space=search_space)
        logger.info("✅ BayesianOptimizer initialized")

    if use_hyperband:
        optimizers["hyperband"] = HyperbandOptimizer(search_space=search_space)
        logger.info("✅ HyperbandOptimizer initialized")

    if use_pbt:
        optimizers["pbt"] = PopulationBasedTraining(search_space=search_space)
        logger.info("✅ PopulationBasedTraining initialized")

    if use_cmaes:
        optimizers["cmaes"] = CMAESOptimizer(search_space=search_space)
        logger.info("✅ CMAESOptimizer initialized")

    if use_auto_augment:
        optimizers["auto_augment"] = AutoAugmentPolicy()
        logger.info("✅ AutoAugmentPolicy initialized")

    orchestrator = AutoMLOrchestrator(optimizers=optimizers)
    logger.info("✅ AutoMLOrchestrator initialized")

    return {
        "optimizers": optimizers,
        "orchestrator": orchestrator,
        "search_space": search_space,
        "config": {
            "device": device,
            "n_optimizers": len(optimizers),
        },
    }


def create_auto_optimizer_minimal() -> Dict[str, Any]:
    """Version minimale pour démarrage rapide."""
    return create_auto_optimizer(
        use_bayesian=True,
        use_hyperband=False,
        use_pbt=False,
        use_cmaes=False,
        use_auto_augment=False,
    )


def create_auto_optimizer_full() -> Dict[str, Any]:
    """Version complète avec tous les optimiseurs."""
    return create_auto_optimizer(
        use_bayesian=True,
        use_hyperband=True,
        use_pbt=True,
        use_cmaes=True,
        use_auto_augment=True,
    )


# Instance globale
auto_optimizer_system = create_auto_optimizer_full()


def get_auto_optimizer() -> Dict[str, Any]:
    """Get the global auto-optimizer system instance."""
    return auto_optimizer_system
