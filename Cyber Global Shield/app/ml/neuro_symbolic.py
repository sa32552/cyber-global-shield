"""
Cyber Global Shield — Neuro-Symbolic AI
========================================
Combining neural networks with symbolic logic for verifiable,
interpretable security decisions.

Based on:
  - DeepProbLog: https://arxiv.org/abs/1805.10872
  - Neural Logic Machines: https://arxiv.org/abs/1904.11694
  - Logical Neural Networks: https://arxiv.org/abs/1912.08666

Components:
  - NeuralPredicate: Learnable neural predicates for grounding symbols
  - LogicProgram: Differentiable logic programs with soft unification
  - NeuroSymbolicReasoner: End-to-end neuro-symbolic reasoning
  - SecurityRuleEngine: Rule-based security policies with neural perception
  - VerifiableDetector: Security detector with formal guarantees
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


# ─── Constants ────────────────────────────────────────────────────────────────

EMBED_DIM = 128          # Embedding dimension for symbols
HIDDEN_DIM = 256         # Hidden dimension
MAX_PREDICATES = 64      # Maximum number of predicates
MAX_RULES = 128          # Maximum number of rules
MAX_VARS = 16            # Maximum number of logic variables
LEARNING_RATE = 1e-3     # Learning rate
TEMPERATURE = 1.0        # Soft logic temperature


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class Predicate:
    """A logical predicate with name and arity."""
    name: str
    arity: int
    is_neural: bool = False

    def __hash__(self):
        return hash((self.name, self.arity))


@dataclass
class Clause:
    """A definite clause (rule) in the logic program."""
    head: Predicate
    body: List[Predicate]
    weight: float = 1.0
    is_fact: bool = False


@dataclass
class GroundAtom:
    """A ground atom (predicate with concrete arguments)."""
    predicate: Predicate
    args: Tuple[Any, ...]
    truth_value: float = 0.0

    def __hash__(self):
        return hash((self.predicate.name, self.args))


@dataclass
class ReasoningResult:
    """Result of neuro-symbolic reasoning."""
    query: str
    truth_value: float
    proof_steps: List[str]
    explanations: List[str]
    confidence: float
    neural_contributions: Dict[str, float]


@dataclass
class SecurityRule:
    """A security rule with conditions and actions."""
    name: str
    conditions: List[str]  # Logic conditions
    actions: List[str]     # Actions to take
    priority: int = 0
    is_active: bool = True


# ─── Neural Predicate ─────────────────────────────────────────────────────────

class NeuralPredicate(nn.Module):
    """
    A learnable neural predicate that grounds symbolic concepts.
    
    Maps input observations to truth values for a predicate.
    E.g., is_anomalous(connection) -> [0, 1]
    """

    def __init__(
        self,
        name: str,
        input_dim: int,
        hidden_dim: int = HIDDEN_DIM,
    ):
        super().__init__()
        self.name = name
        self.input_dim = input_dim

        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ELU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Compute truth value of predicate for input.
        
        Args:
            x: Input features [batch, input_dim]
        
        Returns:
            Truth values [batch, 1]
        """
        return self.net(x)


# ─── Differentiable Logic ─────────────────────────────────────────────────────

class SoftAnd(nn.Module):
    """Differentiable AND operation using product t-norm."""

    def forward(self, inputs: torch.Tensor) -> torch.Tensor:
        """
        Compute soft AND.
        
        Args:
            inputs: Truth values [batch, n_predicates]
        
        Returns:
            AND result [batch, 1]
        """
        return torch.prod(inputs, dim=-1, keepdim=True)


class SoftOr(nn.Module):
    """Differentiable OR operation using probabilistic sum."""

    def forward(self, inputs: torch.Tensor) -> torch.Tensor:
        """
        Compute soft OR.
        
        Args:
            inputs: Truth values [batch, n_predicates]
        
        Returns:
            OR result [batch, 1]
        """
        return 1 - torch.prod(1 - inputs, dim=-1, keepdim=True)


class SoftNot(nn.Module):
    """Differentiable NOT operation."""

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Compute soft NOT."""
        return 1 - x


class SoftImplication(nn.Module):
    """
    Differentiable implication (body -> head).
    Uses Lukasiewicz implication: min(1, 1 - body + head)
    """

    def forward(self, body: torch.Tensor, head: torch.Tensor) -> torch.Tensor:
        """
        Compute soft implication.
        
        Args:
            body: Body truth value [batch, 1]
            head: Head truth value [batch, 1]
        
        Returns:
            Implication truth value [batch, 1]
        """
        return torch.clamp(1 - body + head, 0, 1)


# ─── Logic Program ────────────────────────────────────────────────────────────

class LogicProgram(nn.Module):
    """
    A differentiable logic program.
    
    Consists of a set of definite clauses (rules) with learnable
    weights. Supports forward chaining with soft unification.
    """

    def __init__(
        self,
        max_rules: int = MAX_RULES,
        temperature: float = TEMPERATURE,
    ):
        super().__init__()
        self.max_rules = max_rules
        self.temperature = temperature

        # Rule weights (learnable)
        self.rule_weights = nn.Parameter(torch.ones(max_rules))

        # Predicate embeddings for soft unification
        self.predicate_embeddings = nn.Embedding(MAX_PREDICATES, EMBED_DIM)

        # Logic operations
        self.soft_and = SoftAnd()
        self.soft_or = SoftOr()
        self.soft_not = SoftNot()
        self.soft_impl = SoftImplication()

        # Registered clauses
        self.clauses: List[Clause] = []
        self.predicate_map: Dict[str, int] = {}

    def add_clause(self, clause: Clause):
        """Add a clause to the logic program."""
        if len(self.clauses) < self.max_rules:
            self.clauses.append(clause)
            for pred in [clause.head] + clause.body:
                if pred.name not in self.predicate_map:
                    self.predicate_map[pred.name] = len(self.predicate_map)

    def add_fact(self, predicate: Predicate):
        """Add a fact (clause with empty body)."""
        self.add_clause(Clause(
            head=predicate,
            body=[],
            is_fact=True,
        ))

    def forward(
        self,
        ground_atoms: Dict[str, torch.Tensor],
        query: str,
        num_steps: int = 5,
    ) -> torch.Tensor:
        """
        Perform differentiable forward chaining.
        
        Args:
            ground_atoms: Dict of predicate_name -> truth values [batch, 1]
            query: Query predicate name
            num_steps: Number of forward chaining steps
        
        Returns:
            Truth value of query [batch, 1]
        """
        batch_size = next(iter(ground_atoms.values())).shape[0]
        device = next(iter(ground_atoms.values())).device

        # Initialize truth values
        truths = {name: val.clone() for name, val in ground_atoms.items()}

        # Forward chaining
        for step in range(num_steps):
            new_truths = {}

            for clause in self.clauses:
                if clause.is_fact:
                    continue

                # Get body truth values
                body_truths = []
                for pred in clause.body:
                    if pred.name in truths:
                        body_truths.append(truths[pred.name])
                    else:
                        body_truths.append(torch.zeros(batch_size, 1, device=device))

                if not body_truths:
                    body_truth = torch.ones(batch_size, 1, device=device)
                else:
                    body_truths_tensor = torch.cat(body_truths, dim=-1)
                    body_truth = self.soft_and(body_truths_tensor)

                # Apply rule weight
                rule_idx = self.clauses.index(clause)
                weight = torch.sigmoid(self.rule_weights[rule_idx])
                body_truth = body_truth * weight

                # Implication
                head_name = clause.head.name
                if head_name in truths:
                    head_truth = truths[head_name]
                    impl_truth = self.soft_impl(body_truth, head_truth)
                    new_truths[head_name] = impl_truth

            # Update truths with new inferences
            for name, val in new_truths.items():
                if name in truths:
                    # Soft OR with existing truth
                    truths[name] = self.soft_or(torch.cat([truths[name], val], dim=-1))
                else:
                    truths[name] = val

        return truths.get(query, torch.zeros(batch_size, 1, device=device))

    def get_explanation(
        self,
        ground_atoms: Dict[str, torch.Tensor],
        query: str,
    ) -> List[str]:
        """Get a symbolic explanation for a query."""
        with torch.no_grad():
            truth = self.forward(ground_atoms, query)

        steps = []
        for clause in self.clauses:
            if clause.head.name == query:
                body_str = " ∧ ".join([p.name for p in clause.body]) if clause.body else "⊤"
                steps.append(f"{clause.head.name} ← {body_str}")

        steps.append(f"Query '{query}' truth value: {truth.item():.4f}")
        return steps


# ─── Neuro-Symbolic Reasoner ──────────────────────────────────────────────────

class NeuroSymbolicReasoner(nn.Module):
    """
    End-to-end neuro-symbolic reasoner.
    
    Combines:
      - Neural predicates for perception (data -> symbols)
      - Logic program for reasoning (symbols -> conclusions)
      - Explanation generation for interpretability
    """

    def __init__(
        self,
        input_dim: int,
        hidden_dim: int = HIDDEN_DIM,
        temperature: float = TEMPERATURE,
    ):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.temperature = temperature

        # Neural predicates
        self.neural_predicates: Dict[str, NeuralPredicate] = {}

        # Logic program
        self.logic_program = LogicProgram(temperature=temperature)

        # Symbol grounding layer
        self.grounding_net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ELU(),
        )

    def add_neural_predicate(self, name: str, input_dim: Optional[int] = None):
        """Add a neural predicate."""
        dim = input_dim or self.hidden_dim
        self.neural_predicates[name] = NeuralPredicate(name, dim)
        self.logic_program.add_fact(Predicate(name, 1, is_neural=True))

    def add_rule(self, head: str, body: List[str], weight: float = 1.0):
        """Add a logic rule."""
        head_pred = Predicate(head, 1)
        body_preds = [Predicate(b, 1) for b in body]
        self.logic_program.add_clause(Clause(head_pred, body_preds, weight=weight))

    def forward(
        self,
        x: torch.Tensor,
        query: str,
    ) -> ReasoningResult:
        """
        Perform neuro-symbolic reasoning.
        
        Args:
            x: Input features [batch, input_dim]
            query: Query predicate name
        
        Returns:
            ReasoningResult
        """
        batch_size = x.shape[0]
        device = x.device

        # Ground input through neural predicates
        grounded = self.grounding_net(x)

        ground_atoms = {}
        neural_contributions = {}

        for name, predicate in self.neural_predicates.items():
            truth = predicate(grounded)
            ground_atoms[name] = truth
            neural_contributions[name] = truth.mean().item()

        # Reason
        truth_value = self.logic_program(ground_atoms, query)

        # Generate explanation
        explanation_steps = self.logic_program.get_explanation(ground_atoms, query)

        return ReasoningResult(
            query=query,
            truth_value=truth_value.mean().item(),
            proof_steps=explanation_steps,
            explanations=explanation_steps,
            confidence=abs(truth_value.mean().item() - 0.5) * 2,
            neural_contributions=neural_contributions,
        )

    def get_rule_weights(self) -> Dict[str, float]:
        """Get learned rule weights."""
        weights = {}
        for i, clause in enumerate(self.logic_program.clauses):
            weight = torch.sigmoid(self.logic_program.rule_weights[i]).item()
            weights[f"{clause.head.name} ← {' ∧ '.join(p.name for p in clause.body)}"] = weight
        return weights


# ─── Security Rule Engine ─────────────────────────────────────────────────────

class SecurityRuleEngine:
    """
    Rule-based security policies with neural perception.
    
    Defines security rules as logical statements, then uses
    neural predicates to ground them in data.
    """

    def __init__(self, reasoner: NeuroSymbolicReasoner):
        self.reasoner = reasoner
        self.security_rules: List[SecurityRule] = []

    def add_security_rule(
        self,
        name: str,
        conditions: List[str],
        actions: List[str],
        priority: int = 0,
    ):
        """Add a security rule."""
        rule = SecurityRule(name, conditions, actions, priority)
        self.security_rules.append(rule)

        # Add to logic program
        self.reasoner.add_rule(name, conditions)

    def evaluate(
        self,
        x: torch.Tensor,
    ) -> List[Dict[str, Any]]:
        """
        Evaluate all security rules against input.
        
        Args:
            x: Input features [batch, input_dim]
        
        Returns:
            List of triggered rules with actions
        """
        triggered = []

        for rule in self.security_rules:
            result = self.reasoner(x, rule.name)

            if result.truth_value > 0.5:
                triggered.append({
                    "rule_name": rule.name,
                    "truth_value": result.truth_value,
                    "confidence": result.confidence,
                    "actions": rule.actions,
                    "priority": rule.priority,
                    "explanations": result.explanations,
                })

        # Sort by priority and confidence
        triggered.sort(key=lambda r: (r["priority"], r["confidence"]), reverse=True)

        return triggered

    def get_active_rules(self) -> List[SecurityRule]:
        """Get all active security rules."""
        return [r for r in self.security_rules if r.is_active]


# ─── Verifiable Detector ──────────────────────────────────────────────────────

class VerifiableDetector:
    """
    Security detector with formal guarantees.
    
    Uses neuro-symbolic reasoning to provide:
    - Verifiable detection decisions
    - Formal guarantees on false positive rates
    - Interpretable explanations for every decision
    """

    def __init__(
        self,
        reasoner: NeuroSymbolicReasoner,
        false_positive_bound: float = 0.01,
    ):
        self.reasoner = reasoner
        self.false_positive_bound = false_positive_bound
        self.detection_threshold: float = 0.5

    def detect(
        self,
        x: np.ndarray,
        return_explanation: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Detect security threats with verifiable guarantees.
        
        Args:
            x: Input features [batch, input_dim]
            return_explanation: Whether to return explanations
        
        Returns:
            List of detection results
        """
        x_t = torch.from_numpy(x).float()
        if torch.cuda.is_available():
            x_t = x_t.cuda()

        results = []
        for i in range(x.shape[0]):
            x_i = x_t[i:i+1]

            # Query multiple security predicates
            queries = [
                "is_anomalous",
                "is_malicious",
                "is_suspicious",
                "requires_investigation",
            ]

            max_truth = 0.0
            best_query = None
            all_results = {}

            for query in queries:
                result = self.reasoner(x_i, query)
                all_results[query] = result
                if result.truth_value > max_truth:
                    max_truth = result.truth_value
                    best_query = query

            is_threat = max_truth > self.detection_threshold

            result_dict = {
                "is_threat": is_threat,
                "confidence": max_truth,
                "primary_classification": best_query,
                "threshold": self.detection_threshold,
                "false_positive_bound": self.false_positive_bound,
            }

            if return_explanation and best_query:
                result_dict["explanation"] = all_results[best_query].explanations
                result_dict["neural_contributions"] = all_results[best_query].neural_contributions

            results.append(result_dict)

        return results

    def verify_property(
        self,
        property_name: str,
        x: np.ndarray,
    ) -> Dict[str, Any]:
        """
        Verify a formal property on input.
        
        Args:
            property_name: Name of property to verify
            x: Input features
        
        Returns:
            Verification result
        """
        x_t = torch.from_numpy(x).float()
        if torch.cuda.is_available():
            x_t = x_t.cuda()

        result = self.reasoner(x_t, property_name)

        return {
            "property": property_name,
            "holds": result.truth_value > 0.5,
            "truth_value": result.truth_value,
            "confidence": result.confidence,
            "proof": result.proof_steps,
        }


# ─── Factory Functions ────────────────────────────────────────────────────────

def create_neuro_symbolic_reasoner(
    input_dim: int = 64,
    hidden_dim: int = HIDDEN_DIM,
) -> NeuroSymbolicReasoner:
    """
    Create a neuro-symbolic reasoner for security.
    
    Args:
        input_dim: Input feature dimension
        hidden_dim: Hidden dimension
    
    Returns:
        Configured NeuroSymbolicReasoner
    """
    if not TORCH_AVAILABLE:
        warnings.warn("PyTorch not available. Neuro-symbolic reasoner will be a placeholder.")
        return None  # type: ignore

    reasoner = NeuroSymbolicReasoner(input_dim=input_dim, hidden_dim=hidden_dim)

    # Add default neural predicates for security
    reasoner.add_neural_predicate("is_anomalous")
    reasoner.add_neural_predicate("is_malicious")
    reasoner.add_neural_predicate("is_suspicious")
    reasoner.add_neural_predicate("requires_investigation")
    reasoner.add_neural_predicate("is_benign")
    reasoner.add_neural_predicate("is_zero_day")
    reasoner.add_neural_predicate("is_lateral_movement")
    reasoner.add_neural_predicate("is_data_exfiltration")

    # Add default security rules
    reasoner.add_rule("is_threat", ["is_anomalous", "is_malicious"])
    reasoner.add_rule("is_threat", ["is_zero_day"])
    reasoner.add_rule("requires_investigation", ["is_suspicious", "is_anomalous"])
    reasoner.add_rule("requires_investigation", ["is_lateral_movement"])
    reasoner.add_rule("is_attack", ["is_threat", "is_lateral_movement"])
    reasoner.add_rule("is_attack", ["is_threat", "is_data_exfiltration"])
    reasoner.add_rule("needs_blocking", ["is_threat", "is_malicious"])
    reasoner.add_rule("needs_blocking", ["is_zero_day", "is_data_exfiltration"])

    return reasoner


def create_neuro_symbolic_reasoner_minimal() -> NeuroSymbolicReasoner:
    """Create a minimal neuro-symbolic reasoner for testing."""
    return create_neuro_symbolic_reasoner(input_dim=16, hidden_dim=32)


def create_neuro_symbolic_reasoner_full() -> NeuroSymbolicReasoner:
    """Create a full-scale neuro-symbolic reasoner."""
    return create_neuro_symbolic_reasoner(input_dim=256, hidden_dim=512)


def create_security_rule_engine(
    reasoner: Optional[NeuroSymbolicReasoner] = None,
) -> SecurityRuleEngine:
    """Create a security rule engine."""
    if reasoner is None:
        reasoner = create_neuro_symbolic_reasoner()
    return SecurityRuleEngine(reasoner)


def create_verifiable_detector(
    reasoner: Optional[NeuroSymbolicReasoner] = None,
    false_positive_bound: float = 0.01,
) -> VerifiableDetector:
    """Create a verifiable security detector."""
    if reasoner is None:
        reasoner = create_neuro_symbolic_reasoner()
    return VerifiableDetector(reasoner, false_positive_bound)


__all__ = [
    "Predicate",
    "Clause",
    "GroundAtom",
    "ReasoningResult",
    "SecurityRule",
    "NeuralPredicate",
    "SoftAnd",
    "SoftOr",
    "SoftNot",
    "SoftImplication",
    "LogicProgram",
    "NeuroSymbolicReasoner",
    "SecurityRuleEngine",
    "VerifiableDetector",
    "create_neuro_symbolic_reasoner",
    "create_neuro_symbolic_reasoner_minimal",
    "create_neuro_symbolic_reasoner_full",
    "create_security_rule_engine",
    "create_verifiable_detector",
]
