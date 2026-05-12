"""
Cyber Global Shield — Causal Discovery
=======================================
Learning causal DAGs of security incidents from observational data.

Based on:
  - PC Algorithm (Spirtes et al., 2000)
  - NOTEARS (Zheng et al., 2018) - arXiv:1803.01422
  - DAG-GNN (Yu et al., 2019) - arXiv:1904.10098

Components:
  - PCAlgorithm: Constraint-based causal discovery
  - NOTEARS: Continuous optimization for DAG structure learning
  - CausalGraph: Causal graph representation and utilities
  - CausalEffectEstimator: Estimate causal effects from graph
  - CausalIncidentAnalyzer: Analyze root causes of security incidents
"""

import math
import warnings
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    class nn:
        class Module: pass
    class torch:
        class Tensor: pass
        class nn: pass
        class optim: pass

try:
    from scipy.stats import chi2
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False


# ─── Constants ────────────────────────────────────────────────────────────────

ALPHA = 0.05             # Significance level for conditional independence tests
LAMBDA_1 = 0.01          # L1 regularization for NOTEARS
LAMBDA_2 = 0.01          # DAG penalty for NOTEARS
MAX_ITER = 100           # Maximum iterations for NOTEARS
LR = 1e-2                # Learning rate for NOTEARS
HIDDEN_DIM = 64          # Hidden dimension


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class CausalGraph:
    """A causal graph (DAG) over variables."""
    nodes: List[str]
    adjacency: np.ndarray        # [n_nodes, n_nodes] - binary adjacency matrix
    weights: Optional[np.ndarray] = None  # [n_nodes, n_nodes] - edge weights
    scores: Optional[np.ndarray] = None   # [n_nodes, n_nodes] - confidence scores

    def __post_init__(self):
        self.adjacency = np.asarray(self.adjacency)
        if self.weights is not None:
            self.weights = np.asarray(self.weights)

    @property
    def n_nodes(self) -> int:
        return len(self.nodes)

    def get_parents(self, node: str) -> List[str]:
        """Get parents of a node."""
        idx = self.nodes.index(node)
        return [self.nodes[i] for i in range(self.n_nodes) if self.adjacency[i, idx]]

    def get_children(self, node: str) -> List[str]:
        """Get children of a node."""
        idx = self.nodes.index(node)
        return [self.nodes[i] for i in range(self.n_nodes) if self.adjacency[idx, i]]

    def get_ancestors(self, node: str) -> Set[str]:
        """Get all ancestors of a node."""
        idx = self.nodes.index(node)
        visited = set()

        def dfs(current: int):
            for i in range(self.n_nodes):
                if self.adjacency[i, current] and i not in visited:
                    visited.add(i)
                    dfs(i)

        dfs(idx)
        return {self.nodes[i] for i in visited}

    def get_descendants(self, node: str) -> Set[str]:
        """Get all descendants of a node."""
        idx = self.nodes.index(node)
        visited = set()

        def dfs(current: int):
            for i in range(self.n_nodes):
                if self.adjacency[current, i] and i not in visited:
                    visited.add(i)
                    dfs(i)

        dfs(idx)
        return {self.nodes[i] for i in visited}

    def get_markov_blanket(self, node: str) -> Set[str]:
        """Get Markov blanket of a node (parents + children + co-parents)."""
        idx = self.nodes.index(node)
        blanket = set()

        # Parents
        blanket.update(self.get_parents(node))

        # Children
        children = self.get_children(node)
        blanket.update(children)

        # Co-parents (other parents of children)
        for child in children:
            child_idx = self.nodes.index(child)
            for i in range(self.n_nodes):
                if self.adjacency[i, child_idx] and i != idx:
                    blanket.add(self.nodes[i])

        return blanket

    def is_dag(self) -> bool:
        """Check if the graph is a DAG."""
        visited = [0] * self.n_nodes
        in_stack = [0] * self.n_nodes

        def has_cycle(v: int) -> bool:
            visited[v] = 1
            in_stack[v] = 1
            for u in range(self.n_nodes):
                if self.adjacency[v, u]:
                    if not visited[u]:
                        if has_cycle(u):
                            return True
                    elif in_stack[u]:
                        return True
            in_stack[v] = 0
            return False

        for v in range(self.n_nodes):
            if not visited[v]:
                if has_cycle(v):
                    return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        edges = []
        for i in range(self.n_nodes):
            for j in range(self.n_nodes):
                if self.adjacency[i, j]:
                    edge = {
                        "source": self.nodes[i],
                        "target": self.nodes[j],
                    }
                    if self.weights is not None:
                        edge["weight"] = float(self.weights[i, j])
                    if self.scores is not None:
                        edge["score"] = float(self.scores[i, j])
                    edges.append(edge)

        return {
            "nodes": self.nodes,
            "edges": edges,
            "n_nodes": self.n_nodes,
            "n_edges": len(edges),
            "is_dag": self.is_dag(),
        }


@dataclass
class CausalEffect:
    """An estimated causal effect."""
    cause: str
    effect: str
    effect_size: float
    confidence: float
    is_direct: bool
    path: List[str]


@dataclass
class CausalAnalysisResult:
    """Result of causal analysis on an incident."""
    root_causes: List[Tuple[str, float]]
    causal_graph: CausalGraph
    effects: List[CausalEffect]
    recommendations: List[str]
    confidence: float


# ─── Conditional Independence Tests ──────────────────────────────────────────

class ConditionalIndependenceTest:
    """Base class for conditional independence tests."""

    def test(
        self,
        data: np.ndarray,
        x: int,
        y: int,
        cond_set: List[int],
    ) -> Tuple[float, float]:
        """
        Test if X ⟂ Y | Z.
        
        Returns:
            (test_statistic, p_value)
        """
        raise NotImplementedError


class PartialCorrelationTest(ConditionalIndependenceTest):
    """Partial correlation test for Gaussian data."""

    def test(
        self,
        data: np.ndarray,
        x: int,
        y: int,
        cond_set: List[int],
    ) -> Tuple[float, float]:
        n = data.shape[0]

        if not cond_set:
            # Simple correlation
            corr = np.corrcoef(data[:, x], data[:, y])[0, 1]
            test_stat = np.sqrt(n - 3) * np.arctanh(corr)
            p_value = 2 * (1 - chi2.cdf(test_stat ** 2, 1))
            return test_stat, p_value

        # Partial correlation
        # Regress out conditioning variables
        def regress_out(target: np.ndarray, covariates: np.ndarray) -> np.ndarray:
            beta = np.linalg.lstsq(covariates, target, rcond=None)[0]
            return target - covariates @ beta

        cond_data = data[:, cond_set]
        res_x = regress_out(data[:, x], cond_data)
        res_y = regress_out(data[:, y], cond_data)

        corr = np.corrcoef(res_x, res_y)[0, 1]
        dof = n - len(cond_set) - 3

        if dof <= 0:
            return 0.0, 1.0

        test_stat = np.sqrt(dof) * np.arctanh(corr)
        p_value = 2 * (1 - chi2.cdf(test_stat ** 2, 1))

        return test_stat, p_value


# ─── PC Algorithm ─────────────────────────────────────────────────────────────

class PCAlgorithm:
    """
    PC (Peter-Clark) algorithm for constraint-based causal discovery.
    
    Discovers causal structure using conditional independence tests.
    """

    def __init__(
        self,
        alpha: float = ALPHA,
        independence_test: Optional[ConditionalIndependenceTest] = None,
    ):
        self.alpha = alpha
        self.independence_test = independence_test or PartialCorrelationTest()

    def discover(
        self,
        data: np.ndarray,
        node_names: Optional[List[str]] = None,
    ) -> CausalGraph:
        """
        Discover causal graph from data.
        
        Args:
            data: Data matrix [n_samples, n_variables]
            node_names: Names of variables
        
        Returns:
            CausalGraph
        """
        n_vars = data.shape[1]
        if node_names is None:
            node_names = [f"X{i}" for i in range(n_vars)]

        # Phase 1: Skeleton discovery
        adj = np.ones((n_vars, n_vars), dtype=bool) - np.eye(n_vars, dtype=bool)
        sep_sets: Dict[Tuple[int, int], List[int]] = {}

        for depth in range(n_vars):
            for i in range(n_vars):
                for j in range(i + 1, n_vars):
                    if not adj[i, j]:
                        continue

                    # Find conditioning sets of current size
                    neighbors_i = [k for k in range(n_vars) if adj[i, k] and k != j]
                    if len(neighbors_i) < depth:
                        continue

                    # Test conditional independence
                    from itertools import combinations
                    for cond_set in combinations(neighbors_i, depth):
                        _, p_value = self.independence_test.test(data, i, j, list(cond_set))

                        if p_value > self.alpha:
                            adj[i, j] = adj[j, i] = False
                            sep_sets[(i, j)] = list(cond_set)
                            sep_sets[(j, i)] = list(cond_set)
                            break

        # Phase 2: Edge orientation (Meek rules)
        adj = self._orient_edges(adj, sep_sets)

        return CausalGraph(
            nodes=node_names,
            adjacency=adj.astype(float),
        )

    def _orient_edges(
        self,
        adj: np.ndarray,
        sep_sets: Dict[Tuple[int, int], List[int]],
    ) -> np.ndarray:
        """Orient edges using Meek's rules."""
        n = adj.shape[0]
        directed = np.zeros_like(adj, dtype=bool)

        # Rule 1: Collider orientation
        for i in range(n):
            for j in range(n):
                if not adj[i, j]:
                    continue
                for k in range(n):
                    if k == i or k == j or not adj[j, k] or adj[i, k]:
                        continue
                    # Check if j is in separating set of i and k
                    if (i, k) in sep_sets and j not in sep_sets[(i, k)]:
                        directed[i, j] = True
                        directed[k, j] = True

        # Apply Meek rules iteratively
        changed = True
        while changed:
            changed = False
            # Rule 2: i -> j -> k, i - k => i -> k
            for i in range(n):
                for j in range(n):
                    if not directed[i, j]:
                        continue
                    for k in range(n):
                        if directed[j, k] and adj[i, k] and not directed[i, k] and not directed[k, i]:
                            directed[i, k] = True
                            changed = True

            # Rule 3: i -> k -> j, i - j => i -> j
            for i in range(n):
                for k in range(n):
                    if not directed[i, k]:
                        continue
                    for j in range(n):
                        if directed[k, j] and adj[i, j] and not directed[i, j] and not directed[j, i]:
                            directed[i, j] = True
                            changed = True

        return directed


# ─── NOTEARS ──────────────────────────────────────────────────────────────────

class NOTEARS:
    """
    Continuous optimization for DAG structure learning.
    
    Solves: min_W ||X - XW||² + λ₁||W||₁  s.t.  h(W) = 0
    where h(W) = tr(e^{W∘W}) - d ensures acyclicity.
    """

    def __init__(
        self,
        lambda_1: float = LAMBDA_1,
        lambda_2: float = LAMBDA_2,
        max_iter: int = MAX_ITER,
        lr: float = LR,
    ):
        self.lambda_1 = lambda_1
        self.lambda_2 = lambda_2
        self.max_iter = max_iter
        self.lr = lr

    def _h(self, W: np.ndarray) -> float:
        """DAG penalty: h(W) = tr(e^{W∘W}) - d."""
        d = W.shape[0]
        W_sq = W * W
        # Matrix exponential using eigendecomposition
        eigenvalues = np.linalg.eigvalsh(W_sq)
        return float(np.sum(np.exp(eigenvalues)) - d)

    def _grad_h(self, W: np.ndarray) -> np.ndarray:
        """Gradient of h(W)."""
        d = W.shape[0]
        W_sq = W * W
        eigenvalues, eigenvectors = np.linalg.eigh(W_sq)
        exp_eigenvalues = np.exp(eigenvalues)
        # Gradient: (e^{W∘W})^T * 2W
        exp_W_sq = eigenvectors @ np.diag(exp_eigenvalues) @ eigenvectors.T
        return exp_W_sq.T * 2 * W

    def discover(
        self,
        data: np.ndarray,
        node_names: Optional[List[str]] = None,
    ) -> CausalGraph:
        """
        Discover causal DAG using NOTEARS.
        
        Args:
            data: Data matrix [n_samples, n_variables]
            node_names: Names of variables
        
        Returns:
            CausalGraph
        """
        n, d = data.shape
        if node_names is None:
            node_names = [f"X{i}" for i in range(d)]

        # Standardize data
        data_std = (data - data.mean(axis=0)) / (data.std(axis=0) + 1e-8)

        # Initialize W
        W = np.zeros((d, d))

        # Augmented Lagrangian method
        rho = 1.0
        alpha = 0.0
        h = self._h(W)

        for iteration in range(self.max_iter):
            # Inner optimization (gradient descent)
            for _ in range(100):
                grad = self._compute_grad(data_std, W, alpha, rho)
                W -= self.lr * grad
                W = np.maximum(W - self.lambda_1 * self.lr, 0)  # Proximal operator for L1
                np.fill_diagonal(W, 0)  # No self-loops

            # Check convergence
            h_new = self._h(W)
            if h_new < 1e-8:
                break

            # Update Lagrangian
            alpha += rho * h_new
            rho *= 10

        # Threshold small values
        W_thresholded = np.where(np.abs(W) > 0.3, W, 0.0)
        adj = (np.abs(W_thresholded) > 0).astype(float)

        return CausalGraph(
            nodes=node_names,
            adjacency=adj,
            weights=W_thresholded,
        )

    def _compute_grad(
        self,
        X: np.ndarray,
        W: np.ndarray,
        alpha: float,
        rho: float,
    ) -> np.ndarray:
        """Compute gradient of the NOTEARS objective."""
        # Least squares loss gradient
        residual = X - X @ W
        grad_ls = -2 * X.T @ residual / X.shape[0]

        # DAG penalty gradient
        h = self._h(W)
        grad_h = self._grad_h(W)

        grad = grad_ls + alpha * grad_h + rho * h * grad_h
        np.fill_diagonal(grad, 0)

        return grad


# ─── Causal Effect Estimator ──────────────────────────────────────────────────

class CausalEffectEstimator:
    """
    Estimate causal effects from a learned causal graph.
    
    Uses:
    - Direct effects: edge weights
    - Total effects: sum over paths
    - Back-door adjustment for confounders
    """

    def __init__(self, graph: CausalGraph):
        self.graph = graph

    def estimate_direct_effect(
        self,
        cause: str,
        effect: str,
    ) -> Optional[CausalEffect]:
        """Estimate direct causal effect."""
        cause_idx = self.graph.nodes.index(cause)
        effect_idx = self.graph.nodes.index(effect)

        if not self.graph.adjacency[cause_idx, effect_idx]:
            return None

        weight = 1.0
        if self.graph.weights is not None:
            weight = float(self.graph.weights[cause_idx, effect_idx])

        return CausalEffect(
            cause=cause,
            effect=effect,
            effect_size=weight,
            confidence=abs(weight) / (abs(weight) + 0.1),
            is_direct=True,
            path=[cause, effect],
        )

    def estimate_total_effect(
        self,
        cause: str,
        effect: str,
    ) -> Optional[CausalEffect]:
        """Estimate total causal effect (sum over all paths)."""
        cause_idx = self.graph.nodes.index(cause)
        effect_idx = self.graph.nodes.index(effect)

        # Find all paths using DFS
        paths = []
        visited = set()

        def dfs(current: int, path: List[int]):
            if current == effect_idx:
                paths.append(path.copy())
                return
            if current in visited:
                return
            visited.add(current)

            for next_idx in range(self.graph.n_nodes):
                if self.graph.adjacency[current, next_idx]:
                    path.append(next_idx)
                    dfs(next_idx, path)
                    path.pop()

            visited.remove(current)

        dfs(cause_idx, [cause_idx])

        if not paths:
            return None

        # Compute total effect as sum over paths
        total_effect = 0.0
        best_path = paths[0]

        for path in paths:
            path_effect = 1.0
            for i in range(len(path) - 1):
                if self.graph.weights is not None:
                    path_effect *= float(self.graph.weights[path[i], path[i + 1]])
                else:
                    path_effect *= 0.5  # Default weight
            total_effect += path_effect

            if abs(path_effect) > abs(total_effect):
                best_path = path

        path_names = [self.graph.nodes[i] for i in best_path]

        return CausalEffect(
            cause=cause,
            effect=effect,
            effect_size=total_effect,
            confidence=min(abs(total_effect), 1.0),
            is_direct=False,
            path=path_names,
        )

    def estimate_all_effects(self) -> List[CausalEffect]:
        """Estimate all causal effects in the graph."""
        effects = []
        for i, cause in enumerate(self.graph.nodes):
            for j, effect in enumerate(self.graph.nodes):
                if i != j and self.graph.adjacency[i, j]:
                    direct = self.estimate_direct_effect(cause, effect)
                    if direct:
                        effects.append(direct)
        return effects


# ─── Causal Incident Analyzer ─────────────────────────────────────────────────

class CausalIncidentAnalyzer:
    """
    Analyze root causes of security incidents using causal discovery.
    
    Given security metrics before/during an incident, identifies
    the causal structure and root causes.
    """

    def __init__(
        self,
        method: str = "pc",
        alpha: float = ALPHA,
    ):
        self.method = method
        self.alpha = alpha

        if method == "pc":
            self.discoverer = PCAlgorithm(alpha=alpha)
        elif method == "notears":
            self.discoverer = NOTEARS()
        else:
            raise ValueError(f"Unknown method: {method}")

    def analyze(
        self,
        data: np.ndarray,
        target_variable: str,
        node_names: Optional[List[str]] = None,
    ) -> CausalAnalysisResult:
        """
        Analyze causal structure of an incident.
        
        Args:
            data: Security metrics data [n_samples, n_variables]
            target_variable: Target variable (e.g., "breach", "alert")
            node_names: Names of variables
        
        Returns:
            CausalAnalysisResult
        """
        # Discover causal graph
        graph = self.discoverer.discover(data, node_names)

        # Estimate effects
        estimator = CausalEffectEstimator(graph)
        effects = estimator.estimate_all_effects()

        # Find root causes (ancestors of target with strongest effects)
        target_idx = graph.nodes.index(target_variable)
        ancestors = graph.get_ancestors(target_variable)

        root_causes = []
        for ancestor in ancestors:
            effect = estimator.estimate_total_effect(ancestor, target_variable)
            if effect:
                root_causes.append((ancestor, abs(effect.effect_size)))

        root_causes.sort(key=lambda x: x[1], reverse=True)

        # Generate recommendations
        recommendations = []
        for cause, strength in root_causes[:3]:
            recommendations.append(
                f"Address causal factor '{cause}' (effect strength: {strength:.3f})"
            )

        if not root_causes:
            recommendations.append("No clear causal factors identified")

        confidence = root_causes[0][1] if root_causes else 0.0

        return CausalAnalysisResult(
            root_causes=root_causes,
            causal_graph=graph,
            effects=effects,
            recommendations=recommendations,
            confidence=confidence,
        )


# ─── Factory Functions ────────────────────────────────────────────────────────

def create_causal_discoverer(
    method: str = "pc",
    alpha: float = ALPHA,
) -> Union[PCAlgorithm, NOTEARS]:
    """
    Create a causal discovery algorithm.
    
    Args:
        method: "pc" or "notears"
        alpha: Significance level for PC algorithm
    
    Returns:
        Causal discovery algorithm
    """
    if method == "pc":
        return PCAlgorithm(alpha=alpha)
    elif method == "notears":
        return NOTEARS()
    else:
        raise ValueError(f"Unknown method: {method}")


def create_causal_incident_analyzer(
    method: str = "pc",
) -> CausalIncidentAnalyzer:
    """Create a causal incident analyzer."""
    return CausalIncidentAnalyzer(method=method)


def create_causal_effect_estimator(graph: CausalGraph) -> CausalEffectEstimator:
    """Create a causal effect estimator."""
    return CausalEffectEstimator(graph)


__all__ = [
    "CausalGraph",
    "CausalEffect",
    "CausalAnalysisResult",
    "ConditionalIndependenceTest",
    "PartialCorrelationTest",
    "PCAlgorithm",
    "NOTEARS",
    "CausalEffectEstimator",
    "CausalIncidentAnalyzer",
    "create_causal_discoverer",
    "create_causal_incident_analyzer",
    "create_causal_effect_estimator",
]
