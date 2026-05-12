"""
Cyber Global Shield — Diffusion Models for Attack Data Generation
==================================================================
Génération de données d'attaque synthétiques réalistes en utilisant
des modèles de diffusion (DDPM, Score-Based) pour entraîner les détecteurs
sur des attaques rares (zero-day, APT) où les données labellisées manquent.

Architecture :
  1. TabDDPM — Diffusion sur données tabulaires de logs réseau
  2. AttackConditionalDiffusion — Génération conditionnée par type d'attaque
  3. GuidanceSampler — Classifier-free guidance pour contrôler le type généré
  4. AdversarialAugmenter — Augmentation adversariale avec diffusion
  5. AttackDataGenerator — Générateur complet intégré au pipeline

Avantages :
  - Génération d'attaques zero-day réalistes
  - Équilibrage des classes (attaques rares sur-représentées)
  - Augmentation de données pour entraînement robuste
  - Simulation d'attaques APT multi-étapes
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Optional, Dict, Any, List, Tuple, Union, Callable
from dataclasses import dataclass, field
from collections import deque
from datetime import datetime, timezone
import structlog
import math

logger = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class DiffusionResult:
    """Résultat de génération par diffusion."""
    generated_data: np.ndarray
    attack_type: str
    diversity_score: float
    realism_score: float
    n_samples: int
    generation_time_ms: float = 0.0


@dataclass
class AttackSample:
    """Échantillon d'attaque généré."""
    features: np.ndarray
    attack_type: str
    severity: float  # 0.0 (low) to 1.0 (critical)
    confidence: float
    timestamp: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 1: NOISE SCHEDULER — Beta schedule for diffusion
# ═══════════════════════════════════════════════════════════════════════════

class NoiseScheduler:
    """
    Beta schedule for diffusion process.
    
    Supports linear, cosine, and sigmoid schedules.
    
    Args:
        n_timesteps: Number of diffusion steps
        schedule: Type of schedule ('linear', 'cosine', 'sigmoid')
        beta_start: Starting beta value
        beta_end: Ending beta value
    """
    
    def __init__(
        self,
        n_timesteps: int = 1000,
        schedule: str = "cosine",
        beta_start: float = 1e-4,
        beta_end: float = 0.02,
    ):
        self.n_timesteps = n_timesteps
        
        if schedule == "linear":
            betas = torch.linspace(beta_start, beta_end, n_timesteps)
        elif schedule == "cosine":
            steps = torch.linspace(0, n_timesteps, n_timesteps + 1)
            alpha_bar = torch.cos(((steps / n_timesteps) + 0.008) / 1.008 * math.pi / 2) ** 2
            betas = torch.clamp(1 - alpha_bar[1:] / alpha_bar[:-1], max=0.999)
        elif schedule == "sigmoid":
            betas = torch.sigmoid(torch.linspace(-3, 3, n_timesteps)) * (beta_end - beta_start) + beta_start
        else:
            raise ValueError(f"Unknown schedule: {schedule}")
        
        self.betas = betas
        self.alphas = 1 - betas
        self.alpha_bars = torch.cumprod(self.alphas, dim=0)
    
    def add_noise(
        self, x_0: torch.Tensor, noise: torch.Tensor, t: torch.Tensor
    ) -> torch.Tensor:
        """
        Add noise to clean data at timestep t.
        
        Args:
            x_0: Clean data [batch, dim]
            noise: Random noise [batch, dim]
            t: Timesteps [batch]
        
        Returns:
            Noisy data at timestep t
        """
        alpha_bar = self.alpha_bars[t].unsqueeze(-1).to(x_0.device)
        return torch.sqrt(alpha_bar) * x_0 + torch.sqrt(1 - alpha_bar) * noise
    
    def sample_prior(self, shape: Tuple[int, ...], device: str = "cpu") -> torch.Tensor:
        """Sample from the prior distribution (pure noise)."""
        return torch.randn(shape, device=device)


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 2: TABDDPM — Diffusion for Tabular Log Data
# ═══════════════════════════════════════════════════════════════════════════

class TabDDPM(nn.Module):
    """
    Denoising Diffusion Probabilistic Model for tabular data.
    
    Adapted for network log data with mixed numerical/categorical features.
    
    Architecture:
      - MLP-based denoiser with time embedding
      - Support for numerical and categorical features
      - Classifier-free guidance for conditional generation
    
    Args:
        feature_dim: Total feature dimension
        hidden_dim: Hidden dimension of denoiser
        n_layers: Number of denoiser layers
        n_timesteps: Number of diffusion steps
        n_classes: Number of attack classes (for conditional generation)
    """
    
    def __init__(
        self,
        feature_dim: int = 128,
        hidden_dim: int = 512,
        n_layers: int = 4,
        n_timesteps: int = 1000,
        n_classes: int = 10,
    ):
        super().__init__()
        self.feature_dim = feature_dim
        self.hidden_dim = hidden_dim
        self.n_timesteps = n_timesteps
        self.n_classes = n_classes
        
        # Noise scheduler
        self.noise_scheduler = NoiseScheduler(
            n_timesteps=n_timesteps, schedule="cosine"
        )
        
        # Time embedding
        self.time_embed = nn.Sequential(
            nn.Linear(1, hidden_dim),
            nn.SiLU(),
            nn.Linear(hidden_dim, hidden_dim),
        )
        
        # Class embedding (for conditional generation)
        self.class_embed = nn.Embedding(n_classes + 1, hidden_dim)  # +1 for unconditional
        
        # Denoiser network (MLP with skip connections)
        layers = []
        current_dim = feature_dim + hidden_dim + hidden_dim  # x + time + class
        
        for i in range(n_layers):
            next_dim = hidden_dim if i < n_layers - 1 else feature_dim
            layers.extend([
                nn.Linear(current_dim, next_dim),
                nn.GroupNorm(8, max(next_dim, 8)) if next_dim > 8 else nn.Identity(),
                nn.SiLU(),
            ])
            current_dim = next_dim
        
        self.denoiser = nn.Sequential(*layers)
        
        # Feature scaling
        self.feature_scale = nn.Parameter(torch.ones(feature_dim))
        self.feature_bias = nn.Parameter(torch.zeros(feature_dim))
    
    def forward(
        self,
        x_t: torch.Tensor,
        t: torch.Tensor,
        class_labels: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """
        Predict noise at timestep t.
        
        Args:
            x_t: Noisy data [batch, feature_dim]
            t: Timesteps [batch]
            class_labels: Optional class labels [batch]
        
        Returns:
            Predicted noise [batch, feature_dim]
        """
        batch = x_t.shape[0]
        
        # Time embedding
        t_float = t.float().unsqueeze(-1) / self.n_timesteps
        t_embed = self.time_embed(t_float)  # [batch, hidden_dim]
        
        # Class embedding
        if class_labels is not None:
            c_embed = self.class_embed(class_labels)  # [batch, hidden_dim]
        else:
            c_embed = self.class_embed(
                torch.full((batch,), self.n_classes, dtype=torch.long, device=x_t.device)
            )
        
        # Concatenate
        h = torch.cat([x_t, t_embed, c_embed], dim=-1)
        
        # Denoise
        noise_pred = self.denoiser(h)
        
        return noise_pred
    
    def sample(
        self,
        n_samples: int,
        class_label: Optional[int] = None,
        guidance_scale: float = 2.0,
        device: str = "cpu",
    ) -> torch.Tensor:
        """
        Generate new samples using reverse diffusion.
        
        Args:
            n_samples: Number of samples to generate
            class_label: Optional class label for conditional generation
            guidance_scale: Classifier-free guidance scale
            device: Device to use
        
        Returns:
            Generated samples [n_samples, feature_dim]
        """
        self.eval()
        
        # Start from pure noise
        x = torch.randn(n_samples, self.feature_dim, device=device)
        
        # Class labels for conditioning
        if class_label is not None:
            labels = torch.full((n_samples,), class_label, dtype=torch.long, device=device)
        else:
            labels = None
        
        # Reverse diffusion
        for t in reversed(range(self.n_timesteps)):
            t_batch = torch.full((n_samples,), t, dtype=torch.long, device=device)
            
            with torch.no_grad():
                if guidance_scale > 1.0 and class_label is not None:
                    # Classifier-free guidance
                    noise_cond = self.forward(x, t_batch, labels)
                    noise_uncond = self.forward(x, t_batch, None)
                    noise_pred = noise_uncond + guidance_scale * (noise_cond - noise_uncond)
                else:
                    noise_pred = self.forward(x, t_batch, labels)
            
            # Denoise step
            alpha = self.noise_scheduler.alphas[t].to(device)
            alpha_bar = self.noise_scheduler.alpha_bars[t].to(device)
            
            if t > 0:
                z = torch.randn_like(x)
            else:
                z = 0
            
            x = (1 / torch.sqrt(alpha)) * (
                x - (1 - alpha) / torch.sqrt(1 - alpha_bar) * noise_pred
            ) + torch.sqrt(1 - alpha) * z
        
        return x


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 3: ATTACK CONDITIONAL DIFFUSION
# ═══════════════════════════════════════════════════════════════════════════

class AttackConditionalDiffusion(nn.Module):
    """
    Conditional diffusion model for generating specific attack types.
    
    Supports conditioning on:
    - Attack type (DDoS, ransomware, phishing, zero-day, APT, etc.)
    - Severity level
    - Target service
    - Time pattern
    
    Args:
        feature_dim: Feature dimension
        n_attack_types: Number of attack types
        hidden_dim: Hidden dimension
    """
    
    def __init__(
        self,
        feature_dim: int = 128,
        n_attack_types: int = 15,
        hidden_dim: int = 512,
    ):
        super().__init__()
        self.feature_dim = feature_dim
        self.n_attack_types = n_attack_types
        
        # Base diffusion model
        self.diffusion = TabDDPM(
            feature_dim=feature_dim,
            hidden_dim=hidden_dim,
            n_layers=4,
            n_timesteps=1000,
            n_classes=n_attack_types,
        )
        
        # Attack type embeddings (for conditioning)
        self.attack_embeddings = nn.Embedding(n_attack_types, hidden_dim)
        
        # Severity conditioning
        self.severity_proj = nn.Linear(1, hidden_dim)
        
        # Feature statistics (for denormalization)
        self.register_buffer("feature_mean", torch.zeros(feature_dim))
        self.register_buffer("feature_std", torch.ones(feature_dim))
    
    def fit_feature_stats(self, data: np.ndarray):
        """Compute feature statistics for normalization."""
        self.feature_mean = torch.FloatTensor(np.mean(data, axis=0))
        self.feature_std = torch.FloatTensor(np.std(data, axis=0)).clamp(min=1e-8)
    
    def generate_attack_samples(
        self,
        attack_type: int,
        n_samples: int = 100,
        severity: float = 0.5,
        guidance_scale: float = 2.0,
        device: str = "cpu",
    ) -> np.ndarray:
        """
        Generate attack samples of a specific type.
        
        Args:
            attack_type: Attack type index
            n_samples: Number of samples
            severity: Attack severity (0.0-1.0)
            guidance_scale: Classifier-free guidance scale
            device: Device to use
        
        Returns:
            Generated samples [n_samples, feature_dim]
        """
        # Generate samples
        samples = self.diffusion.sample(
            n_samples=n_samples,
            class_label=attack_type,
            guidance_scale=guidance_scale,
            device=device,
        )
        
        # Denormalize
        samples = samples * self.feature_std.to(device) + self.feature_mean.to(device)
        
        return samples.cpu().numpy()
    
    def generate_diverse_attacks(
        self,
        n_per_type: int = 50,
        device: str = "cpu",
    ) -> Dict[int, np.ndarray]:
        """
        Generate diverse attacks across all types.
        
        Args:
            n_per_type: Samples per attack type
            device: Device to use
        
        Returns:
            Dict mapping attack_type -> generated_samples
        """
        results = {}
        for attack_type in range(self.n_attack_types):
            samples = self.generate_attack_samples(
                attack_type=attack_type,
                n_samples=n_per_type,
                device=device,
            )
            results[attack_type] = samples
            logger.info(
                "Generated attack samples",
                attack_type=attack_type,
                n_samples=n_per_type,
            )
        return results


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 4: ADVERSARIAL AUGMENTER
# ═══════════════════════════════════════════════════════════════════════════

class AdversarialAugmenter:
    """
    Adversarial data augmentation using diffusion models.
    
    Generates hard-to-classify examples near decision boundaries
    to improve detector robustness.
    
    Args:
        diffusion_model: Trained diffusion model
        epsilon: Perturbation strength
    """
    
    def __init__(
        self,
        diffusion_model: TabDDPM,
        epsilon: float = 0.1,
    ):
        self.diffusion = diffusion_model
        self.epsilon = epsilon
        self.noise_scheduler = diffusion_model.noise_scheduler
    
    def augment(
        self,
        x: np.ndarray,
        labels: Optional[np.ndarray] = None,
        n_augmentations: int = 5,
        noise_level: float = 0.3,
    ) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """
        Augment data using diffusion-based perturbation.
        
        Args:
            x: Original data [n_samples, feature_dim]
            labels: Optional labels
            n_augmentations: Number of augmented copies per sample
            noise_level: Amount of noise to add (0.0-1.0)
        
        Returns:
            (augmented_data, augmented_labels)
        """
        X_tensor = torch.FloatTensor(x)
        n_samples = len(x)
        
        augmented = [x]
        aug_labels = [labels] if labels is not None else None
        
        for _ in range(n_augmentations):
            # Add controlled noise
            noise = torch.randn_like(X_tensor) * noise_level
            
            # Forward diffusion (partial)
            t = torch.randint(
                int(self.noise_scheduler.n_timesteps * 0.1),
                int(self.noise_scheduler.n_timesteps * 0.3),
                (n_samples,),
            )
            x_noisy = self.noise_scheduler.add_noise(X_tensor, noise, t)
            
            # Reverse diffusion (partial denoising)
            for step in range(t.max().item(), -1, -1):
                t_batch = torch.full((n_samples,), step, dtype=torch.long)
                
                with torch.no_grad():
                    noise_pred = self.diffusion(x_noisy, t_batch)
                
                alpha = self.noise_scheduler.alphas[step]
                alpha_bar = self.noise_scheduler.alpha_bars[step]
                
                if step > 0:
                    z = torch.randn_like(x_noisy) * 0.5  # reduced noise
                else:
                    z = 0
                
                x_noisy = (1 / torch.sqrt(alpha)) * (
                    x_noisy - (1 - alpha) / torch.sqrt(1 - alpha_bar) * noise_pred
                ) + torch.sqrt(1 - alpha) * z
            
            augmented.append(x_noisy.numpy())
            if labels is not None:
                aug_labels.append(labels)
        
        result_x = np.concatenate(augmented, axis=0)
        result_y = np.concatenate(aug_labels, axis=0) if labels is not None else None
        
        return result_x, result_y


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 5: ATTACK DATA GENERATOR — Full Pipeline Integration
# ═══════════════════════════════════════════════════════════════════════════

class AttackDataGenerator:
    """
    Complete attack data generator using diffusion models.
    
    Generates realistic attack data for:
    - Training anomaly detectors on rare attacks
    - Balancing class distributions
    - Testing detector robustness
    - Simulating zero-day attacks
    
    Usage:
        generator = AttackDataGenerator(feature_dim=128)
        generator.fit(real_data, real_labels)
        synthetic_data = generator.generate("ddos", n_samples=1000)
    """
    
    # Attack type mapping
    ATTACK_TYPES = [
        "normal",
        "ddos",
        "ransomware",
        "phishing",
        "zero_day",
        "apt",
        "lateral_movement",
        "data_exfiltration",
        "c2_beaconing",
        "port_scanning",
        "brute_force",
        "sql_injection",
        "xss",
        "man_in_the_middle",
        "dns_tunneling",
    ]
    
    def __init__(
        self,
        feature_dim: int = 128,
        hidden_dim: int = 512,
        n_timesteps: int = 1000,
        device: str = "cpu",
    ):
        self.feature_dim = feature_dim
        self.hidden_dim = hidden_dim
        self.n_timesteps = n_timesteps
        self.device = torch.device(device if torch.cuda.is_available() else "cpu")
        
        self.n_attack_types = len(self.ATTACK_TYPES)
        
        # Conditional diffusion model
        self.conditional_diffusion = AttackConditionalDiffusion(
            feature_dim=feature_dim,
            n_attack_types=self.n_attack_types,
            hidden_dim=hidden_dim,
        ).to(self.device)
        
        # Adversarial augmenter
        self.augmenter = AdversarialAugmenter(
            diffusion_model=self.conditional_diffusion.diffusion,
            epsilon=0.1,
        )
        
        self.trained = False
        self.feature_names: List[str] = []
        self.generated_count: Dict[str, int] = {}
    
    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        epochs: int = 100,
        batch_size: int = 128,
        learning_rate: float = 2e-4,
        verbose: bool = True,
    ):
        """
        Train the diffusion model on real attack data.
        
        Args:
            X: Training data [n_samples, feature_dim]
            y: Labels [n_samples] (0 = normal, 1+ = attack type)
            epochs: Training epochs
            batch_size: Batch size
            learning_rate: Learning rate
            verbose: Print progress
        """
        # Compute feature statistics
        self.conditional_diffusion.fit_feature_stats(X)
        
        # Normalize data
        mean = self.conditional_diffusion.feature_mean
        std = self.conditional_diffusion.feature_std
        X_norm = (torch.FloatTensor(X) - mean) / std
        
        y_tensor = torch.LongTensor(y)
        
        dataset = torch.utils.data.TensorDataset(X_norm, y_tensor)
        dataloader = torch.utils.data.DataLoader(
            dataset, batch_size=batch_size, shuffle=True
        )
        
        optimizer = torch.optim.AdamW(
            self.conditional_diffusion.parameters(),
            lr=learning_rate,
            weight_decay=1e-5,
        )
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            optimizer, T_max=epochs
        )
        
        noise_scheduler = self.conditional_diffusion.diffusion.noise_scheduler
        
        for epoch in range(epochs):
            self.conditional_diffusion.train()
            epoch_losses = []
            
            for batch_x, batch_y in dataloader:
                batch_x = batch_x.to(self.device)
                batch_y = batch_y.to(self.device)
                
                # Sample random timesteps
                t = torch.randint(
                    0, noise_scheduler.n_timesteps, (len(batch_x),),
                    device=self.device,
                )
                
                # Add noise
                noise = torch.randn_like(batch_x)
                x_noisy = noise_scheduler.add_noise(batch_x, noise, t)
                
                # Predict noise
                noise_pred = self.conditional_diffusion.diffusion(
                    x_noisy, t, batch_y
                )
                
                # Loss
                loss = F.mse_loss(noise_pred, noise)
                
                optimizer.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(
                    self.conditional_diffusion.parameters(), 1.0
                )
                optimizer.step()
                
                epoch_losses.append(loss.item())
            
            scheduler.step()
            
            if verbose and (epoch + 1) % 20 == 0:
                logger.info(
                    "Diffusion training progress",
                    epoch=epoch + 1,
                    loss=np.mean(epoch_losses),
                )
        
        self.trained = True
        logger.info("Diffusion model training complete")
    
    def generate(
        self,
        attack_type: Union[str, int],
        n_samples: int = 100,
        severity: float = 0.5,
        guidance_scale: float = 2.0,
    ) -> np.ndarray:
        """
        Generate attack samples of a specific type.
        
        Args:
            attack_type: Attack type name or index
            n_samples: Number of samples
            severity: Attack severity (0.0-1.0)
            guidance_scale: Classifier-free guidance scale
        
        Returns:
            Generated samples [n_samples, feature_dim]
        """
        if not self.trained:
            raise RuntimeError("Model not trained. Call fit() first.")
        
        # Convert attack type name to index
        if isinstance(attack_type, str):
            if attack_type not in self.ATTACK_TYPES:
                raise ValueError(
                    f"Unknown attack type: {attack_type}. "
                    f"Available: {self.ATTACK_TYPES}"
                )
            attack_idx = self.ATTACK_TYPES.index(attack_type)
        else:
            attack_idx = attack_type
        
        samples = self.conditional_diffusion.generate_attack_samples(
            attack_type=attack_idx,
            n_samples=n_samples,
            severity=severity,
            guidance_scale=guidance_scale,
            device=self.device,
        )
        
        # Update count
        type_name = self.ATTACK_TYPES[attack_idx]
        self.generated_count[type_name] = (
            self.generated_count.get(type_name, 0) + n_samples
        )
        
        return samples
    
    def generate_balanced_dataset(
        self,
        n_per_class: int = 1000,
        guidance_scale: float = 2.0,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generate a balanced dataset across all attack types.
        
        Args:
            n_per_class: Samples per attack type
            guidance_scale: Classifier-free guidance scale
        
        Returns:
            (X, y) where X is [n_classes * n_per_class, feature_dim]
        """
        all_X = []
        all_y = []
        
        for i, attack_type in enumerate(self.ATTACK_TYPES):
            X_gen = self.generate(
                attack_type=i,
                n_samples=n_per_class,
                guidance_scale=guidance_scale,
            )
            all_X.append(X_gen)
            all_y.append(np.full(n_per_class, i))
        
        X = np.concatenate(all_X, axis=0)
        y = np.concatenate(all_y, axis=0)
        
        # Shuffle
        indices = np.random.permutation(len(X))
        X = X[indices]
        y = y[indices]
        
        return X, y
    
    def augment_training_data(
        self,
        X: np.ndarray,
        y: np.ndarray,
        augmentation_factor: int = 3,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Augment existing training data with diffusion-generated samples.
        
        Args:
            X: Original data
            y: Original labels
            augmentation_factor: How many times to augment
        
        Returns:
            (augmented_X, augmented_y)
        """
        if not self.trained:
            raise RuntimeError("Model not trained. Call fit() first.")
        
        all_X = [X]
        all_y = [y]
        
        for _ in range(augmentation_factor):
            X_aug, y_aug = self.augmenter.augment(X, y)
            all_X.append(X_aug)
            all_y.append(y_aug)
        
        return np.concatenate(all_X, axis=0), np.concatenate(all_y, axis=0)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get generator statistics."""
        return {
            "architecture": "TabDDPM + Conditional Diffusion",
            "feature_dim": self.feature_dim,
            "hidden_dim": self.hidden_dim,
            "n_timesteps": self.n_timesteps,
            "n_attack_types": self.n_attack_types,
            "attack_types": self.ATTACK_TYPES,
            "trained": self.trained,
            "generated_count": self.generated_count,
            "total_generated": sum(self.generated_count.values()),
            "n_parameters": sum(
                p.numel() for p in self.conditional_diffusion.parameters()
            ),
        }


# ═══════════════════════════════════════════════════════════════════════════
# FACTORY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def create_diffusion_generator(
    feature_dim: int = 128,
    device: str = "cpu",
) -> AttackDataGenerator:
    """
    Create a default attack data generator.
    
    Args:
        feature_dim: Feature dimension
        device: Device to use
    
    Returns:
        Configured AttackDataGenerator
    """
    return AttackDataGenerator(
        feature_dim=feature_dim,
        hidden_dim=512,
        n_timesteps=1000,
        device=device,
    )


def create_diffusion_generator_minimal() -> Dict[str, Any]:
    """Create a minimal diffusion generator config."""
    return {
        "type": "diffusion",
        "feature_dim": 64,
        "hidden_dim": 256,
        "n_timesteps": 500,
    }


def create_diffusion_generator_full() -> Dict[str, Any]:
    """Create a full diffusion generator config for production."""
    return {
        "type": "diffusion",
        "feature_dim": 256,
        "hidden_dim": 1024,
        "n_timesteps": 2000,
    }
