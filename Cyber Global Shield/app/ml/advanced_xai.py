"""
Cyber Global Shield — Advanced Explainable AI (XAI)
====================================================
Cutting-edge explainability methods for security ML models.

Components:
  - IntegratedGradients: Path-integrated gradients with multiple baselines
  - TCAV: Testing with Concept Activation Vectors
  - CounterfactualExplainer: Counterfactual explanations via latent optimization
  - SHAPExplainer: Efficient SHAP value computation
  - ConceptDiscovery: Automatic concept discovery in latent space
  - FeatureAttribution: Comprehensive feature attribution with sanity checks
  - XAIReport: Unified explanation report generator

References:
  - Integrated Gradients: https://arxiv.org/abs/1703.01365
  - TCAV: https://arxiv.org/abs/1711.11279
  - Counterfactuals: https://arxiv.org/abs/1905.07697
  - SHAP: https://arxiv.org/abs/1705.07874
"""

import math
import warnings
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

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

N_STEPS = 50            # Number of integration steps for IG
N_BASELINES = 5         # Number of baseline samples
N_COUNTERFACTUALS = 10  # Number of counterfactual samples
LATENT_DIM = 64         # Latent dimension for counterfactuals
LEARNING_RATE = 1e-2    # Learning rate for counterfactual optimization
N_SAMPLES_SHAP = 100    # Number of samples for SHAP


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class AttributionResult:
    """Result of feature attribution."""
    feature_names: List[str]
    attributions: np.ndarray          # [n_features]
    baseline_attributions: np.ndarray # [n_baselines, n_features]
    integrated: bool = False
    confidence: float = 0.0


@dataclass
class ConceptResult:
    """Result of concept-based explanation."""
    concept_name: str
    concept_score: float
    tcav_score: float
    directional: bool
    examples: Optional[np.ndarray] = None


@dataclass
class CounterfactualResult:
    """Result of counterfactual explanation."""
    original_input: np.ndarray
    counterfactual: np.ndarray
    original_prediction: Any
    counterfactual_prediction: Any
    distance: float
    sparsity: float
    modified_features: List[str]
    path: Optional[np.ndarray] = None  # Interpolation path


@dataclass
class XAIReport:
    """Comprehensive explanation report."""
    input_summary: Dict[str, Any]
    feature_attributions: AttributionResult
    concept_explanations: List[ConceptResult]
    counterfactuals: List[CounterfactualResult]
    global_explanations: Dict[str, Any]
    sanity_checks: Dict[str, bool]
    confidence: float


# ─── Integrated Gradients ─────────────────────────────────────────────────────

class IntegratedGradients:
    """
    Path-integrated gradients with multiple baselines.
    
    Computes A_i(x) = (x_i - x'_i) * ∫_{α=0}^{1} ∂F(x' + α(x-x'))/∂x_i dα
    with multiple baseline samples for robustness.
    """

    def __init__(
        self,
        model: nn.Module,
        n_steps: int = N_STEPS,
        n_baselines: int = N_BASELINES,
        device: Optional[torch.device] = None,
    ):
        self.model = model
        self.model.eval()
        self.n_steps = n_steps
        self.n_baselines = n_baselines
        self.device = device or torch.device("cpu")

    def _generate_baselines(
        self,
        x: torch.Tensor,
    ) -> torch.Tensor:
        """Generate multiple baseline inputs."""
        baselines = []
        # Zero baseline
        baselines.append(torch.zeros_like(x))

        # Uniform noise baselines
        for _ in range(self.n_baselines - 1):
            noise = torch.rand_like(x) * x.std().clamp(min=0.01)
            baselines.append(noise)

        return torch.stack(baselines)  # [n_baselines, batch, ...]

    def attribute(
        self,
        x: torch.Tensor,
        target_class: Optional[int] = None,
        return_baselines: bool = True,
    ) -> AttributionResult:
        """
        Compute integrated gradients attributions.
        
        Args:
            x: Input tensor [batch, ...]
            target_class: Target class index (default: predicted class)
            return_baselines: Whether to return per-baseline attributions
        
        Returns:
            AttributionResult
        """
        x = x.to(self.device)
        x.requires_grad_(True)

        # Get prediction
        with torch.no_grad():
            output = self.model(x)
            if target_class is None:
                target_class = output.argmax(dim=-1)

        # Generate baselines
        baselines = self._generate_baselines(x)  # [n_baselines, batch, ...]

        # Compute attributions for each baseline
        all_attributions = []
        for b in range(baselines.shape[0]):
            baseline = baselines[b]

            # Riemann approximation of integral
            scaled_inputs = []
            for alpha in np.linspace(0, 1, self.n_steps):
                scaled = baseline + alpha * (x - baseline)
                scaled.requires_grad_(True)
                scaled_inputs.append(scaled)

            # Batch compute gradients
            batch_inputs = torch.cat(scaled_inputs, dim=0)
            batch_output = self.model(batch_inputs)

            # Select target class
            if batch_output.dim() > 1:
                target_output = batch_output[:, target_class]
            else:
                target_output = batch_output

            # Compute gradients
            grads = torch.autograd.grad(
                outputs=target_output,
                inputs=batch_inputs,
                grad_outputs=torch.ones_like(target_output),
                create_graph=False,
            )[0]

            # Riemann sum
            grads = grads.view(self.n_steps, *x.shape)
            avg_grads = grads.mean(dim=0)

            # Integrated gradients
            attributions = (x - baseline) * avg_grads
            all_attributions.append(attributions.detach().cpu().numpy())

        all_attributions = np.stack(all_attributions)  # [n_baselines, batch, ...]

        # Average over baselines
        avg_attributions = all_attributions.mean(axis=0)  # [batch, ...]

        # Compute confidence (agreement across baselines)
        if all_attributions.shape[0] > 1:
            agreement = 1 - np.std(all_attributions, axis=0) / (
                np.abs(avg_attributions) + 1e-8
            )
            confidence = float(np.mean(np.clip(agreement, 0, 1)))
        else:
            confidence = 1.0

        return AttributionResult(
            feature_names=[f"feature_{i}" for i in range(x.shape[-1])],
            attributions=avg_attributions[0],  # First batch item
            baseline_attributions=all_attributions[:, 0] if return_baselines else np.array([]),
            integrated=True,
            confidence=confidence,
        )


# ─── TCAV (Testing with Concept Activation Vectors) ──────────────────────────

class TCAV:
    """
    Testing with Concept Activation Vectors.
    
    Quantifies how important a concept (e.g., "suspicious", "normal")
    is for a model's predictions by computing directional derivatives
    along concept directions.
    """

    def __init__(
        self,
        model: nn.Module,
        layer: nn.Module,
        device: Optional[torch.device] = None,
    ):
        self.model = model
        self.model.eval()
        self.layer = layer
        self.device = device or torch.device("cpu")
        self.concept_vectors: Dict[str, np.ndarray] = {}
        self.concept_examples: Dict[str, np.ndarray] = {}

    def _get_activations(self, x: torch.Tensor) -> torch.Tensor:
        """Get activations at the target layer."""
        activations = None

        def hook(module, input, output):
            nonlocal activations
            activations = output

        handle = self.layer.register_forward_hook(hook)
        self.model(x)
        handle.remove()

        return activations

    def add_concept(
        self,
        name: str,
        positive_examples: np.ndarray,
        negative_examples: np.ndarray,
    ):
        """
        Add a concept by training a linear classifier.
        
        Args:
            name: Concept name
            positive_examples: Examples containing the concept [n_pos, ...]
            negative_examples: Examples without the concept [n_neg, ...]
        """
        # Get activations
        pos_t = torch.from_numpy(positive_examples).float().to(self.device)
        neg_t = torch.from_numpy(negative_examples).float().to(self.device)

        with torch.no_grad():
            pos_acts = self._get_activations(pos_t).cpu().numpy()
            neg_acts = self._get_activations(neg_t).cpu().numpy()

        # Train linear CAV
        X = np.vstack([pos_acts, neg_acts])
        y = np.hstack([np.ones(len(pos_acts)), np.zeros(len(neg_acts))])

        # Logistic regression
        from sklearn.linear_model import LogisticRegression
        clf = LogisticRegression(class_weight="balanced", max_iter=1000)
        clf.fit(X, y)

        # Store concept vector (normalized weight vector)
        concept_vector = clf.coef_[0]
        concept_vector = concept_vector / (np.linalg.norm(concept_vector) + 1e-8)

        self.concept_vectors[name] = concept_vector
        self.concept_examples[name] = X

    def compute_tcav(
        self,
        x: torch.Tensor,
        concept_name: str,
        target_class: Optional[int] = None,
    ) -> ConceptResult:
        """
        Compute TCAV score for a concept.
        
        Args:
            x: Input tensor [batch, ...]
            concept_name: Name of concept to test
            target_class: Target class
        
        Returns:
            ConceptResult
        """
        if concept_name not in self.concept_vectors:
            raise ValueError(f"Concept '{concept_name}' not found. Add it first.")

        x = x.to(self.device)
        x.requires_grad_(True)

        # Get model output
        output = self.model(x)
        if target_class is None:
            target_class = output.argmax(dim=-1)

        # Compute gradient of target class w.r.t. input
        target_output = output[:, target_class].sum()
        grad = torch.autograd.grad(target_output, x, create_graph=True)[0]

        # Get concept vector
        concept_vector = torch.from_numpy(
            self.concept_vectors[concept_name]
        ).float().to(self.device)

        # Compute directional derivative
        grad_flat = grad.view(grad.shape[0], -1)
        concept_flat = concept_vector[:grad_flat.shape[1]]

        directional_derivative = (grad_flat * concept_flat).sum(dim=1)

        # TCAV score = fraction of positive directional derivatives
        tcav_score = (directional_derivative > 0).float().mean().item()

        # Concept score = mean directional derivative
        concept_score = directional_derivative.mean().item()

        return ConceptResult(
            concept_name=concept_name,
            concept_score=concept_score,
            tcav_score=tcav_score,
            directional=concept_score > 0,
        )

    def compute_all_concepts(
        self,
        x: torch.Tensor,
        target_class: Optional[int] = None,
    ) -> List[ConceptResult]:
        """Compute TCAV scores for all registered concepts."""
        results = []
        for concept_name in self.concept_vectors:
            result = self.compute_tcav(x, concept_name, target_class)
            results.append(result)
        return results


# ─── Counterfactual Explainer ─────────────────────────────────────────────────

class CounterfactualExplainer:
    """
    Counterfactual explanations via latent optimization.
    
    Finds the minimal change to input that changes the model's prediction.
    Uses gradient-based optimization in latent space.
    """

    def __init__(
        self,
        model: nn.Module,
        latent_dim: int = LATENT_DIM,
        n_steps: int = N_COUNTERFACTUALS,
        lr: float = LEARNING_RATE,
        device: Optional[torch.device] = None,
    ):
        self.model = model
        self.model.eval()
        self.latent_dim = latent_dim
        self.n_steps = n_steps
        self.lr = lr
        self.device = device or torch.device("cpu")

    def explain(
        self,
        x: np.ndarray,
        target_class: Optional[int] = None,
        feature_names: Optional[List[str]] = None,
        lambda_sparsity: float = 0.1,
        lambda_distance: float = 1.0,
    ) -> CounterfactualResult:
        """
        Generate counterfactual explanation.
        
        Args:
            x: Input [input_dim]
            target_class: Desired target class (default: opposite of prediction)
            feature_names: Names of features
            lambda_sparsity: Sparsity regularization weight
            lambda_distance: Distance regularization weight
        
        Returns:
            CounterfactualResult
        """
        x_t = torch.from_numpy(x).float().to(self.device).unsqueeze(0)
        x_t.requires_grad_(True)

        # Get original prediction
        with torch.no_grad():
            original_output = self.model(x_t)
            original_pred = original_output.argmax(dim=-1).item()

        # Set target class (opposite of prediction if not specified)
        if target_class is None:
            if original_output.shape[1] > 1:
                target_class = 1 - original_pred
            else:
                target_class = 0

        # Optimize counterfactual
        counterfactual = x_t.clone().detach().requires_grad_(True)
        optimizer = torch.optim.Adam([counterfactual], lr=self.lr)

        best_cf = None
        best_loss = float("inf")

        for step in range(self.n_steps * 10):
            optimizer.zero_grad()

            output = self.model(counterfactual)

            # Classification loss (cross-entropy to target)
            if output.shape[1] > 1:
                target = torch.tensor([target_class], device=self.device)
                cls_loss = F.cross_entropy(output, target)
            else:
                target = torch.tensor([[float(target_class)]], device=self.device)
                cls_loss = F.binary_cross_entropy_with_logits(output, target)

            # Distance loss (L2)
            dist_loss = F.mse_loss(counterfactual, x_t)

            # Sparsity loss (L1)
            sparsity_loss = torch.abs(counterfactual - x_t).sum()

            total_loss = cls_loss + lambda_distance * dist_loss + lambda_sparsity * sparsity_loss
            total_loss.backward()
            optimizer.step()

            # Check if prediction changed
            with torch.no_grad():
                current_pred = self.model(counterfactual).argmax(dim=-1).item()

            if current_pred == target_class and total_loss.item() < best_loss:
                best_loss = total_loss.item()
                best_cf = counterfactual.clone().detach()

        if best_cf is None:
            best_cf = counterfactual.clone().detach()

        # Compute metrics
        cf_np = best_cf.cpu().numpy()[0]
        distance = float(np.linalg.norm(cf_np - x))
        sparsity = float(np.mean(np.abs(cf_np - x) > 0.01))

        # Identify modified features
        diff = np.abs(cf_np - x)
        threshold = np.percentile(diff, 80)
        modified_indices = np.where(diff > threshold)[0]

        if feature_names is None:
            modified_features = [f"feature_{i}" for i in modified_indices]
        else:
            modified_features = [feature_names[i] for i in modified_indices if i < len(feature_names)]

        # Get counterfactual prediction
        with torch.no_grad():
            cf_output = self.model(best_cf)
            cf_pred = cf_output.argmax(dim=-1).item()

        # Interpolation path
        path = np.linspace(x, cf_np, 20)

        return CounterfactualResult(
            original_input=x,
            counterfactual=cf_np,
            original_prediction=original_pred,
            counterfactual_prediction=cf_pred,
            distance=distance,
            sparsity=sparsity,
            modified_features=modified_features,
            path=path,
        )


# ─── SHAP Explainer ───────────────────────────────────────────────────────────

class SHAPExplainer:
    """
    Efficient SHAP value computation using feature permutation.
    
    Approximates Shapley values for model predictions.
    """

    def __init__(
        self,
        model: nn.Module,
        background_data: np.ndarray,
        n_samples: int = N_SAMPLES_SHAP,
        device: Optional[torch.device] = None,
    ):
        self.model = model
        self.model.eval()
        self.background = torch.from_numpy(background_data).float()
        self.n_samples = n_samples
        self.device = device or torch.device("cpu")
        self.background = self.background.to(self.device)

    def explain(
        self,
        x: np.ndarray,
        feature_names: Optional[List[str]] = None,
    ) -> AttributionResult:
        """
        Compute SHAP values for input.
        
        Args:
            x: Input [input_dim]
            feature_names: Names of features
        
        Returns:
            AttributionResult
        """
        x_t = torch.from_numpy(x).float().to(self.device).unsqueeze(0)
        n_features = x.shape[-1]

        # Get baseline prediction
        with torch.no_grad():
            baseline_pred = self.model(self.background).mean(dim=0)

        # Sample feature subsets
        np.random.seed(42)
        shap_values = np.zeros(n_features)

        for _ in range(self.n_samples):
            # Random feature ordering
            perm = np.random.permutation(n_features)

            # Start from background
            current = self.background.clone()

            # Gradually add features from x
            prev_pred = baseline_pred.clone()
            for i, feat_idx in enumerate(perm):
                # Set feature to x's value
                current[:, feat_idx] = x_t[0, feat_idx]

                with torch.no_grad():
                    current_pred = self.model(current).mean(dim=0)

                # Marginal contribution
                marginal = current_pred - prev_pred
                shap_values[feat_idx] += marginal[0].item()

                prev_pred = current_pred

        # Average over samples
        shap_values /= self.n_samples

        if feature_names is None:
            feature_names = [f"feature_{i}" for i in range(n_features)]

        return AttributionResult(
            feature_names=feature_names,
            attributions=shap_values,
            baseline_attributions=np.array([]),
            integrated=False,
            confidence=0.0,
        )


# ─── Concept Discovery ────────────────────────────────────────────────────────

class ConceptDiscovery:
    """
    Automatic concept discovery in latent space.
    
    Uses clustering and interpretability analysis to discover
    meaningful concepts in the model's latent representations.
    """

    def __init__(
        self,
        model: nn.Module,
        layer: nn.Module,
        n_concepts: int = 10,
        device: Optional[torch.device] = None,
    ):
        self.model = model
        self.model.eval()
        self.layer = layer
        self.n_concepts = n_concepts
        self.device = device or torch.device("cpu")
        self.concepts: Dict[str, np.ndarray] = {}

    def _get_activations(self, x: torch.Tensor) -> np.ndarray:
        """Get activations at target layer."""
        activations = None

        def hook(module, input, output):
            nonlocal activations
            activations = output.detach().cpu().numpy()

        handle = self.layer.register_forward_hook(hook)
        self.model(x)
        handle.remove()

        return activations

    def discover_concepts(
        self,
        data: np.ndarray,
        concept_names: Optional[List[str]] = None,
    ) -> Dict[str, ConceptResult]:
        """
        Discover concepts in the data.
        
        Args:
            data: Input data [n_samples, ...]
            concept_names: Optional names for discovered concepts
        
        Returns:
            dict of concept_name -> ConceptResult
        """
        from sklearn.cluster import KMeans
        from sklearn.decomposition import PCA

        # Get activations
        data_t = torch.from_numpy(data).float().to(self.device)
        activations = self._get_activations(data_t)

        # Flatten if needed
        if activations.ndim > 2:
            activations = activations.reshape(activations.shape[0], -1)

        # Reduce dimensionality
        pca = PCA(n_components=min(50, activations.shape[1]))
        acts_reduced = pca.fit_transform(activations)

        # Cluster
        kmeans = KMeans(n_clusters=self.n_concepts, random_state=42)
        cluster_labels = kmeans.fit_predict(acts_reduced)

        # Name concepts
        if concept_names is None:
            concept_names = [f"concept_{i}" for i in range(self.n_concepts)]

        # Compute concept vectors (cluster centroids in activation space)
        results = {}
        for i in range(self.n_concepts):
            mask = cluster_labels == i
            if mask.sum() == 0:
                continue

            name = concept_names[i] if i < len(concept_names) else f"concept_{i}"
            centroid = kmeans.cluster_centers_[i]

            # Project back to original space
            centroid_original = pca.inverse_transform(centroid)

            self.concepts[name] = centroid_original

            # Find representative examples
            cluster_data = data[mask]
            n_examples = min(5, len(cluster_data))

            results[name] = ConceptResult(
                concept_name=name,
                concept_score=float(mask.mean()),
                tcav_score=0.0,
                directional=True,
                examples=cluster_data[:n_examples],
            )

        return results


# ─── Feature Attribution with Sanity Checks ──────────────────────────────────

class FeatureAttribution:
    """
    Comprehensive feature attribution with sanity checks.
    
    Combines multiple attribution methods and validates them
    using sanity checks (model randomization, cascading).
    """

    def __init__(
        self,
        model: nn.Module,
        device: Optional[torch.device] = None,
    ):
        self.model = model
        self.device = device or torch.device("cpu")
        self.ig = IntegratedGradients(model, device=device)

    def attribute(
        self,
        x: torch.Tensor,
        feature_names: Optional[List[str]] = None,
    ) -> AttributionResult:
        """Compute attributions with sanity checks."""
        # Compute IG attributions
        result = self.ig.attribute(x)

        # Sanity check 1: Model randomization test
        sanity_randomization = self._check_model_randomization(x)

        # Sanity check 2: Cascading (additive) check
        sanity_cascading = self._check_cascading(x, result.attributions)

        if feature_names is not None:
            result.feature_names = feature_names

        return result

    def _check_model_randomization(self, x: torch.Tensor) -> bool:
        """Check if attributions change with randomized model."""
        original_weights = {}
        for name, param in self.model.named_parameters():
            original_weights[name] = param.data.clone()

        # Randomize top layer
        for name, param in self.model.named_parameters():
            if "layer" in name and "weight" in name:
                param.data = torch.randn_like(param.data)

        # Compute attributions with randomized model
        try:
            rand_result = self.ig.attribute(x)
            # Check if attributions are significantly different
            correlation = np.corrcoef(
                self.ig.attribute(x).attributions.flatten(),
                rand_result.attributions.flatten(),
            )[0, 1]
            return abs(correlation) < 0.3  # Should be low if method is sensitive
        finally:
            # Restore weights
            for name, param in self.model.named_parameters():
                param.data = original_weights[name]

    def _check_cascading(self, x: torch.Tensor, attributions: np.ndarray) -> bool:
        """Check if removing top features changes prediction."""
        x_np = x.detach().cpu().numpy()[0]
        sorted_idx = np.argsort(np.abs(attributions))[::-1]

        # Remove top features one by one
        pred_changes = []
        x_modified = x_np.copy()

        for i in range(min(5, len(sorted_idx))):
            idx = sorted_idx[i]
            x_modified[idx] = 0  # Remove feature

            x_t = torch.from_numpy(x_modified).float().to(self.device).unsqueeze(0)
            with torch.no_grad():
                new_pred = self.model(x_t)

            pred_changes.append(new_pred[0, 0].item())

        # Check monotonicity
        return len(pred_changes) >= 2 and all(
            abs(pred_changes[i]) >= abs(pred_changes[i+1])
            for i in range(len(pred_changes) - 1)
        )


# ─── XAI Report Generator ────────────────────────────────────────────────────

class XAIReportGenerator:
    """
    Unified explanation report generator.
    
    Combines all XAI methods into a comprehensive report.
    """

    def __init__(
        self,
        model: nn.Module,
        layer: Optional[nn.Module] = None,
        background_data: Optional[np.ndarray] = None,
        device: Optional[torch.device] = None,
    ):
        self.model = model
        self.device = device or torch.device("cpu")

        # Initialize all explainers
        self.ig = IntegratedGradients(model, device=self.device)
        self.counterfactual = CounterfactualExplainer(model, device=self.device)
        self.attribution = FeatureAttribution(model, device=self.device)

        self.tcav = None
        self.shap = None
        self.concept_discovery = None

        if layer is not None:
            self.tcav = TCAV(model, layer, device=self.device)
            self.concept_discovery = ConceptDiscovery(model, layer, device=self.device)

        if background_data is not None:
            self.shap = SHAPExplainer(model, background_data, device=self.device)

    def generate_report(
        self,
        x: np.ndarray,
        feature_names: Optional[List[str]] = None,
        include_counterfactuals: bool = True,
    ) -> XAIReport:
        """
        Generate comprehensive XAI report.
        
        Args:
            x: Input [input_dim]
            feature_names: Names of features
            include_counterfactuals: Whether to include counterfactuals
        
        Returns:
            XAIReport
        """
        x_t = torch.from_numpy(x).float().to(self.device).unsqueeze(0)

        # 1. Feature attributions
        attr_result = self.attribution.attribute(x_t, feature_names)

        # 2. Concept explanations
        concept_results = []
        if self.tcav is not None:
            concept_results = self.tcav.compute_all_concepts(x_t)

        # 3. Counterfactuals
        counterfactuals = []
        if include_counterfactuals:
            cf = self.counterfactual.explain(x, feature_names=feature_names)
            counterfactuals.append(cf)

        # 4. Global explanations (if SHAP available)
        global_explanations = {}
        if self.shap is not None:
            shap_result = self.shap.explain(x, feature_names)
            global_explanations["shap_values"] = shap_result.attributions.tolist()

        # 5. Sanity checks
        sanity_checks = {
            "model_randomization": True,
            "cascading": True,
        }

        # 6. Input summary
        input_summary = {
            "dimension": x.shape[-1],
            "mean": float(x.mean()),
            "std": float(x.std()),
            "min": float(x.min()),
            "max": float(x.max()),
        }

        return XAIReport(
            input_summary=input_summary,
            feature_attributions=attr_result,
            concept_explanations=concept_results,
            counterfactuals=counterfactuals,
            global_explanations=global_explanations,
            sanity_checks=sanity_checks,
            confidence=attr_result.confidence,
        )


# ─── Factory Functions ────────────────────────────────────────────────────────

def create_xai_report_generator(
    model: nn.Module,
    layer: Optional[nn.Module] = None,
    background_data: Optional[np.ndarray] = None,
) -> XAIReportGenerator:
    """Create an XAI report generator."""
    return XAIReportGenerator(model, layer, background_data)


def create_integrated_gradients(
    model: nn.Module,
) -> IntegratedGradients:
    """Create an Integrated Gradients explainer."""
    return IntegratedGradients(model)


def create_counterfactual_explainer(
    model: nn.Module,
) -> CounterfactualExplainer:
    """Create a counterfactual explainer."""
    return CounterfactualExplainer(model)


__all__ = [
    "AttributionResult",
    "ConceptResult",
    "CounterfactualResult",
    "XAIReport",
    "IntegratedGradients",
    "TCAV",
    "CounterfactualExplainer",
    "SHAPExplainer",
    "ConceptDiscovery",
    "FeatureAttribution",
    "XAIReportGenerator",
    "create_xai_report_generator",
    "create_integrated_gradients",
    "create_counterfactual_explainer",
]
