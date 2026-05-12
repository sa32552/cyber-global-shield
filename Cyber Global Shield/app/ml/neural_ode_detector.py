"""
Cyber Global Shield — Neural ODE Detector
==========================================
Continuous-time modeling of security attack evolution using
Neural Ordinary Differential Equations (Neural ODEs).

Based on: "Neural Ordinary Differential Equations" (Chen et al., 2018)
arXiv:1806.07366

Components:
  - ODEFunc: Learnable vector field for attack dynamics
  - ODEAnomalyDetector: Detect anomalies via reconstruction error in ODE latent space
  - ODEAttackPredictor: Predict future attack states using learned dynamics
  - ODEInterpolator: Handle irregularly-sampled security metrics
  - LatentODEClassifier: Classify attack types from continuous latent trajectories

References:
  - Neural ODE: https://arxiv.org/abs/1806.07366
  - ODE-RNN: https://arxiv.org/abs/1907.03907
  - Latent ODE: https://arxiv.org/abs/1907.03907
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

# Try to import torchdiffeq (Neural ODE solver)
try:
    from torchdiffeq import odeint_adjoint as odeint
    TORCHDIFFEQ_AVAILABLE = True
except ImportError:
    try:
        from torchdiffeq import odeint
        TORCHDIFFEQ_AVAILABLE = True
    except ImportError:
        TORCHDIFFEQ_AVAILABLE = False
        # Dummy solver for when torchdiffeq is not available
        def odeint(func, y0, t, *args, **kwargs):
            """Dummy ODE solver that falls back to Euler method."""
            warnings.warn("torchdiffeq not available. Using Euler method fallback.")
            ys = [y0]
            y = y0
            for i in range(1, len(t)):
                dt = t[i] - t[i-1]
                y = y + dt * func(y, t[i-1:i])
                ys.append(y)
            return torch.stack(ys)


# ─── Constants ────────────────────────────────────────────────────────────────

LATENT_DIM = 64          # Latent state dimension
HIDDEN_DIM = 256         # Hidden dimension for ODE function
OBS_DIM = 32             # Observation dimension (security metrics)
N_LAYERS = 4             # Number of layers in ODE function
SOLVER = "dopri5"        # ODE solver (dopri5, rk4, euler)
RTOL = 1e-6              # Relative tolerance for ODE solver
ATOL = 1e-8              # Absolute tolerance for ODE solver
LEARNING_RATE = 1e-3     # Adam learning rate


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class ODEDetectionResult:
    """Result from Neural ODE anomaly detection."""
    is_anomaly: bool
    anomaly_score: float
    reconstruction_error: float
    latent_trajectory: Optional[np.ndarray] = None
    predicted_next_state: Optional[np.ndarray] = None
    explanation: Optional[str] = None


@dataclass
class ODEPredictionResult:
    """Result from ODE-based attack prediction."""
    predicted_states: np.ndarray          # [T_pred, obs_dim]
    prediction_times: np.ndarray          # [T_pred]
    latent_trajectory: np.ndarray         # [T_pred, latent_dim]
    confidence_intervals: Optional[np.ndarray] = None  # [T_pred, 2, obs_dim]


@dataclass
class IrregularTimeSeries:
    """Container for irregularly-sampled time series data."""
    times: np.ndarray           # [N] observation times
    values: np.ndarray          # [N, obs_dim] observations
    masks: np.ndarray           # [N, obs_dim] mask for missing values
    lengths: np.ndarray         # [batch] sequence lengths


# ─── ODE Function ─────────────────────────────────────────────────────────────

class ODEFunc(nn.Module):
    """
    Learnable vector field for attack dynamics.
    
    dz/dt = f_θ(z, t)
    
    Maps latent state z and time t to the derivative dz/dt.
    Uses a residual network with Lipschitz regularization.
    """

    def __init__(
        self,
        latent_dim: int = LATENT_DIM,
        hidden_dim: int = HIDDEN_DIM,
        n_layers: int = N_LAYERS,
        time_dependent: bool = True,
    ):
        super().__init__()
        self.latent_dim = latent_dim
        self.time_dependent = time_dependent

        input_dim = latent_dim + (1 if time_dependent else 0)

        layers = []
        prev_dim = input_dim
        for i in range(n_layers):
            layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.GroupNorm(8, hidden_dim) if hidden_dim >= 8 else nn.Identity(),
                nn.SiLU(),
            ])
            prev_dim = hidden_dim
        layers.append(nn.Linear(hidden_dim, latent_dim))

        self.net = nn.Sequential(*layers)

        # Lipschitz regularization parameter
        self.lipschitz_weight = 0.01

        # Initialize weights with small values for stability
        self._init_weights()

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.orthogonal_(m.weight, gain=0.1)
                if m.bias is not None:
                    nn.init.zeros_(m.bias)

    def forward(self, t: torch.Tensor, z: torch.Tensor) -> torch.Tensor:
        """
        Compute dz/dt at time t.
        
        Args:
            t: Current time [1] or scalar
            z: Latent state [batch, latent_dim]
        
        Returns:
            dz/dt [batch, latent_dim]
        """
        if self.time_dependent:
            # Expand time to match batch dimension
            if t.dim() == 0:
                t_expanded = t.expand(z.shape[0], 1)
            elif t.dim() == 1:
                t_expanded = t.view(-1, 1).expand(z.shape[0], -1)
            else:
                t_expanded = t
            x = torch.cat([z, t_expanded], dim=-1)
        else:
            x = z

        return self.net(x)


class ODEFuncWrapper(nn.Module):
    """Wrapper to match torchdiffeq's expected signature f(t, z)."""

    def __init__(self, func: ODEFunc):
        super().__init__()
        self.func = func

    def forward(self, t: torch.Tensor, z: torch.Tensor) -> torch.Tensor:
        return self.func(t, z)


# ─── ODE Encoder / Decoder ────────────────────────────────────────────────────

class ODEEncoder(nn.Module):
    """
    Encode observations into initial latent state z0.
    
    Uses an ODE-RNN to handle irregularly-sampled observations.
    """

    def __init__(
        self,
        obs_dim: int = OBS_DIM,
        latent_dim: int = LATENT_DIM,
        hidden_dim: int = HIDDEN_DIM,
    ):
        super().__init__()
        self.obs_dim = obs_dim
        self.latent_dim = latent_dim

        # Observation encoder
        self.obs_encoder = nn.Sequential(
            nn.Linear(obs_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ELU(),
        )

        # GRU for temporal aggregation
        self.gru = nn.GRUCell(hidden_dim, hidden_dim)

        # Map to latent mean and logvar
        self.mean_head = nn.Linear(hidden_dim, latent_dim)
        self.logvar_head = nn.Sequential(
            nn.Linear(hidden_dim, latent_dim),
            nn.Tanh(),
        )

    def forward(
        self,
        times: torch.Tensor,
        values: torch.Tensor,
        masks: Optional[torch.Tensor] = None,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Encode irregular time series to latent distribution parameters.
        
        Args:
            times: Observation times [batch, T]
            values: Observation values [batch, T, obs_dim]
            masks: Observation masks [batch, T, obs_dim]
        
        Returns:
            (mean, logvar) of latent initial state z0
        """
        batch_size, T, _ = values.shape
        device = values.device

        if masks is None:
            masks = torch.ones_like(values)

        # Initialize hidden state
        hidden = torch.zeros(batch_size, self.gru.hidden_size, device=device)

        for t in range(T):
            # Encode observation
            obs_encoded = self.obs_encoder(values[:, t])  # [batch, hidden_dim]

            # Apply mask
            mask_t = masks[:, t].mean(dim=-1, keepdim=True)  # [batch, 1]
            obs_encoded = obs_encoded * mask_t

            # Update hidden state
            hidden = self.gru(obs_encoded, hidden)

        # Map to latent distribution
        mean = self.mean_head(hidden)
        logvar = self.logvar_head(hidden)

        return mean, logvar


class ODEDecoder(nn.Module):
    """Decode latent states back to observation space."""

    def __init__(
        self,
        latent_dim: int = LATENT_DIM,
        obs_dim: int = OBS_DIM,
        hidden_dim: int = HIDDEN_DIM,
    ):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, obs_dim),
        )

    def forward(self, z: torch.Tensor) -> torch.Tensor:
        """Decode latent state to observation."""
        return self.net(z)


# ─── Latent ODE Model ─────────────────────────────────────────────────────────

class LatentODEModel(nn.Module):
    """
    Full Latent ODE model for continuous-time security dynamics.
    
    Architecture:
      1. Encode irregular observations -> z0 (latent initial state)
      2. Solve ODE from z0 over time grid -> z(t)
      3. Decode z(t) -> reconstructed observations
    """

    def __init__(
        self,
        obs_dim: int = OBS_DIM,
        latent_dim: int = LATENT_DIM,
        hidden_dim: int = HIDDEN_DIM,
        solver: str = SOLVER,
    ):
        super().__init__()
        self.obs_dim = obs_dim
        self.latent_dim = latent_dim
        self.solver = solver

        self.encoder = ODEEncoder(obs_dim, latent_dim, hidden_dim)
        self.decoder = ODEDecoder(latent_dim, obs_dim, hidden_dim)
        self.ode_func = ODEFunc(latent_dim, hidden_dim)
        self.ode_func_wrapper = ODEFuncWrapper(self.ode_func)

    def forward(
        self,
        times: torch.Tensor,
        values: torch.Tensor,
        masks: Optional[torch.Tensor] = None,
        pred_times: Optional[torch.Tensor] = None,
    ) -> Dict[str, torch.Tensor]:
        """
        Forward pass through the Latent ODE model.
        
        Args:
            times: Observation times [batch, T_obs]
            values: Observation values [batch, T_obs, obs_dim]
            masks: Observation masks [batch, T_obs, obs_dim]
            pred_times: Prediction times [batch, T_pred] (optional)
        
        Returns:
            dict with reconstructions, predictions, latent trajectory
        """
        batch_size = values.shape[0]
        device = values.device

        # Encode to z0
        mean, logvar = self.encoder(times, values, masks)
        std = torch.exp(0.5 * logvar)
        epsilon = torch.randn_like(std)
        z0 = mean + epsilon * std  # [batch, latent_dim]

        # Solve ODE over observation times
        obs_times = times[0]  # Use first batch's times (assumed same grid)
        z_t_obs = odeint(
            self.ode_func_wrapper,
            z0,
            obs_times,
            method=self.solver,
            rtol=RTOL,
            atol=ATOL,
        )  # [T_obs, batch, latent_dim]

        # Decode observations
        z_t_obs_flat = z_t_obs.view(-1, self.latent_dim)
        obs_recon = self.decoder(z_t_obs_flat)
        obs_recon = obs_recon.view(-1, batch_size, self.obs_dim)  # [T_obs, batch, obs_dim]

        # Predictions at additional time points
        if pred_times is not None:
            z_t_pred = odeint(
                self.ode_func_wrapper,
                z0,
                pred_times[0],
                method=self.solver,
                rtol=RTOL,
                atol=ATOL,
            )  # [T_pred, batch, latent_dim]

            z_t_pred_flat = z_t_pred.view(-1, self.latent_dim)
            obs_pred = self.decoder(z_t_pred_flat)
            obs_pred = obs_pred.view(-1, batch_size, self.obs_dim)
        else:
            z_t_pred = None
            obs_pred = None

        return {
            "z0": z0,
            "mean": mean,
            "logvar": logvar,
            "z_t_obs": z_t_obs,
            "obs_recon": obs_recon,
            "z_t_pred": z_t_pred,
            "obs_pred": obs_pred,
        }

    def compute_loss(
        self,
        times: torch.Tensor,
        values: torch.Tensor,
        masks: Optional[torch.Tensor] = None,
    ) -> Dict[str, torch.Tensor]:
        """Compute the training loss."""
        outputs = self.forward(times, values, masks)

        # Reconstruction loss (masked MSE)
        obs_recon = outputs["obs_recon"]  # [T, batch, obs_dim]
        obs_target = values.permute(1, 0, 2)  # [T, batch, obs_dim]

        if masks is not None:
            mask = masks.permute(1, 0, 2)  # [T, batch, obs_dim]
            recon_loss = (mask * (obs_recon - obs_target) ** 2).sum() / (mask.sum() + 1e-8)
        else:
            recon_loss = F.mse_loss(obs_recon, obs_target)

        # KL divergence
        mean = outputs["mean"]
        logvar = outputs["logvar"]
        kl_loss = -0.5 * torch.sum(1 + logvar - mean.pow(2) - logvar.exp())
        kl_loss = kl_loss / values.shape[0]

        # ODE function regularization (Lipschitz)
        lip_reg = 0.0
        for param in self.ode_func.parameters():
            lip_reg += torch.norm(param)

        total_loss = recon_loss + 0.1 * kl_loss + 1e-5 * lip_reg

        return {
            "loss": total_loss,
            "recon_loss": recon_loss,
            "kl_loss": kl_loss,
            "lip_reg": lip_reg,
        }


# ─── ODE Anomaly Detector ─────────────────────────────────────────────────────

class ODEAnomalyDetector:
    """
    Detect anomalies using Neural ODE reconstruction error.
    
    Normal security metrics follow learned continuous dynamics.
    Anomalies are events that deviate from the learned dynamics,
    resulting in high reconstruction error.
    """

    def __init__(
        self,
        obs_dim: int = OBS_DIM,
        latent_dim: int = LATENT_DIM,
        hidden_dim: int = HIDDEN_DIM,
        lr: float = LEARNING_RATE,
        device: Optional[torch.device] = None,
    ):
        if not TORCH_AVAILABLE:
            raise ImportError("PyTorch is required for ODEAnomalyDetector")

        self.obs_dim = obs_dim
        self.latent_dim = latent_dim
        self.device = device or torch.device("cpu")

        self.model = LatentODEModel(obs_dim, latent_dim, hidden_dim).to(self.device)
        self.optimizer = torch.optim.AdamW(self.model.parameters(), lr=lr, weight_decay=1e-5)
        self.scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(self.optimizer, T_max=100)

        self.threshold: Optional[float] = None
        self.training_losses: List[float] = []

    def fit(
        self,
        times: np.ndarray,
        values: np.ndarray,
        masks: Optional[np.ndarray] = None,
        epochs: int = 100,
        batch_size: int = 64,
        verbose: bool = True,
    ) -> Dict[str, List[float]]:
        """
        Train the ODE model on normal security data.
        
        Args:
            times: Observation times [batch, T]
            values: Observation values [batch, T, obs_dim]
            masks: Observation masks [batch, T, obs_dim]
            epochs: Number of training epochs
            batch_size: Batch size
            verbose: Whether to print progress
        
        Returns:
            dict of training history
        """
        self.model.train()
        n_samples = values.shape[0]
        history = {"loss": [], "recon_loss": [], "kl_loss": []}

        times_t = torch.from_numpy(times).float().to(self.device)
        values_t = torch.from_numpy(values).float().to(self.device)
        masks_t = torch.from_numpy(masks).float().to(self.device) if masks is not None else None

        for epoch in range(epochs):
            epoch_losses = {"loss": 0.0, "recon_loss": 0.0, "kl_loss": 0.0}
            n_batches = 0

            # Mini-batch training
            indices = torch.randperm(n_samples)
            for start in range(0, n_samples, batch_size):
                batch_idx = indices[start:start + batch_size]
                batch_times = times_t[batch_idx]
                batch_values = values_t[batch_idx]
                batch_masks = masks_t[batch_idx] if masks_t is not None else None

                self.optimizer.zero_grad()
                losses = self.model.compute_loss(batch_times, batch_values, batch_masks)
                losses["loss"].backward()

                # Gradient clipping for ODE stability
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 10.0)
                self.optimizer.step()

                for k in epoch_losses:
                    epoch_losses[k] += losses[k].item()
                n_batches += 1

            self.scheduler.step()

            # Record
            for k in epoch_losses:
                history[k].append(epoch_losses[k] / n_batches)
            self.training_losses.append(epoch_losses["loss"] / n_batches)

            if verbose and (epoch + 1) % 10 == 0:
                print(f"Epoch {epoch+1}/{epochs} - Loss: {history['loss'][-1]:.4f}")

        return history

    def detect(
        self,
        times: np.ndarray,
        values: np.ndarray,
        masks: Optional[np.ndarray] = None,
    ) -> List[ODEDetectionResult]:
        """
        Detect anomalies in security time series.
        
        Args:
            times: Observation times [batch, T]
            values: Observation values [batch, T, obs_dim]
            masks: Observation masks [batch, T, obs_dim]
        
        Returns:
            List of ODEDetectionResult per sample
        """
        self.model.eval()
        batch_size = values.shape[0]

        times_t = torch.from_numpy(times).float().to(self.device)
        values_t = torch.from_numpy(values).float().to(self.device)
        masks_t = torch.from_numpy(masks).float().to(self.device) if masks is not None else None

        results = []
        with torch.no_grad():
            outputs = self.model(times_t, values_t, masks_t)
            obs_recon = outputs["obs_recon"]  # [T, batch, obs_dim]
            obs_target = values_t.permute(1, 0, 2)  # [T, batch, obs_dim]

            # Per-sample reconstruction error
            recon_errors = (obs_recon - obs_target).norm(dim=-1).mean(dim=0)  # [batch]

            for i in range(batch_size):
                error = recon_errors[i].item()
                is_anomaly = self.threshold is not None and error > self.threshold

                # Get latent trajectory
                latent_traj = outputs["z_t_obs"][:, i].cpu().numpy()  # [T, latent_dim]

                # Predict next state (extrapolate one step)
                last_time = times_t[i, -1:].unsqueeze(0)
                z0 = outputs["z0"][i:i+1]
                z_next = odeint(
                    self.model.ode_func_wrapper,
                    z0,
                    last_time + 0.1,
                    method=self.model.solver,
                )
                next_state = self.model.decoder(z_next[-1]).cpu().numpy()[0]

                results.append(ODEDetectionResult(
                    is_anomaly=is_anomaly,
                    anomaly_score=error,
                    reconstruction_error=error,
                    latent_trajectory=latent_traj,
                    predicted_next_state=next_state,
                    explanation=f"Reconstruction error: {error:.4f}" if is_anomaly else None,
                ))

        return results

    def calibrate_threshold(
        self,
        times: np.ndarray,
        values: np.ndarray,
        percentile: float = 95.0,
    ) -> float:
        """
        Calibrate anomaly threshold using validation data.
        
        Args:
            times: Validation observation times
            values: Validation observation values
            percentile: Percentile for threshold
        
        Returns:
            Threshold value
        """
        results = self.detect(times, values)
        errors = [r.reconstruction_error for r in results]
        self.threshold = float(np.percentile(errors, percentile))
        return self.threshold

    def save(self, path: str):
        """Save model weights."""
        torch.save({
            "model_state_dict": self.model.state_dict(),
            "optimizer_state_dict": self.optimizer.state_dict(),
            "threshold": self.threshold,
            "training_losses": self.training_losses,
        }, path)

    def load(self, path: str):
        """Load model weights."""
        checkpoint = torch.load(path, map_location=self.device)
        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.optimizer.load_state_dict(checkpoint["optimizer_state_dict"])
        self.threshold = checkpoint["threshold"]
        self.training_losses = checkpoint["training_losses"]


# ─── ODE Attack Predictor ─────────────────────────────────────────────────────

class ODEAttackPredictor:
    """
    Predict future attack states using learned ODE dynamics.
    
    Given observed security metrics, extrapolate the latent trajectory
    forward in time to predict future attack states.
    """

    def __init__(self, detector: ODEAnomalyDetector):
        self.detector = detector
        self.model = detector.model
        self.device = detector.device

    def predict(
        self,
        times: np.ndarray,
        values: np.ndarray,
        prediction_horizon: float = 10.0,
        n_steps: int = 50,
        return_confidence: bool = True,
    ) -> ODEPredictionResult:
        """
        Predict future states.
        
        Args:
            times: Observation times [batch, T_obs]
            values: Observation values [batch, T_obs, obs_dim]
            prediction_horizon: How far to predict into the future
            n_steps: Number of prediction steps
            return_confidence: Whether to estimate confidence intervals
        
        Returns:
            ODEPredictionResult
        """
        self.model.eval()
        batch_size = values.shape[0]

        times_t = torch.from_numpy(times).float().to(self.device)
        values_t = torch.from_numpy(values).float().to(self.device)

        with torch.no_grad():
            outputs = self.model(times_t, values_t)
            z0 = outputs["z0"]  # [batch, latent_dim]

            # Create prediction time grid
            last_time = times_t[0, -1].item()
            pred_times = torch.linspace(
                last_time,
                last_time + prediction_horizon,
                n_steps,
                device=self.device,
            )

            # Solve ODE forward
            z_t_pred = odeint(
                self.model.ode_func_wrapper,
                z0,
                pred_times,
                method=self.model.solver,
                rtol=RTOL,
                atol=ATOL,
            )  # [T_pred, batch, latent_dim]

            # Decode to observation space
            z_flat = z_t_pred.view(-1, self.model.latent_dim)
            obs_pred = self.model.decoder(z_flat)
            obs_pred = obs_pred.view(n_steps, batch_size, self.model.obs_dim)

            # Confidence intervals via latent noise
            confidence_intervals = None
            if return_confidence:
                # Sample multiple trajectories with noise
                n_samples = 20
                all_preds = []
                for _ in range(n_samples):
                    noise = torch.randn_like(z0) * 0.1
                    z_noisy = z0 + noise
                    z_t_noisy = odeint(
                        self.model.ode_func_wrapper,
                        z_noisy,
                        pred_times,
                        method=self.model.solver,
                    )
                    z_flat_noisy = z_t_noisy.view(-1, self.model.latent_dim)
                    obs_noisy = self.model.decoder(z_flat_noisy)
                    obs_noisy = obs_noisy.view(n_steps, batch_size, self.model.obs_dim)
                    all_preds.append(obs_noisy)

                all_preds = torch.stack(all_preds)  # [n_samples, T_pred, batch, obs_dim]
                lower = torch.quantile(all_preds, 0.05, dim=0)
                upper = torch.quantile(all_preds, 0.95, dim=0)
                confidence_intervals = torch.stack([lower, upper], dim=-2).cpu().numpy()

        return ODEPredictionResult(
            predicted_states=obs_pred.cpu().numpy(),
            prediction_times=pred_times.cpu().numpy(),
            latent_trajectory=z_t_pred.cpu().numpy(),
            confidence_intervals=confidence_intervals,
        )


# ─── ODE Interpolator ─────────────────────────────────────────────────────────

class ODEInterpolator:
    """
    Handle irregularly-sampled security metrics using ODE interpolation.
    
    Security logs often arrive at irregular intervals. This interpolator
    uses the learned ODE to fill in missing values and create
    uniformly-sampled time series.
    """

    def __init__(self, detector: ODEAnomalyDetector):
        self.detector = detector
        self.model = detector.model
        self.device = detector.device

    def interpolate(
        self,
        times: np.ndarray,
        values: np.ndarray,
        masks: np.ndarray,
        target_times: np.ndarray,
    ) -> np.ndarray:
        """
        Interpolate values at target time points.
        
        Args:
            times: Observation times [batch, T_obs]
            values: Observation values [batch, T_obs, obs_dim]
            masks: Observation masks [batch, T_obs, obs_dim]
            target_times: Target time points [T_target]
        
        Returns:
            Interpolated values [batch, T_target, obs_dim]
        """
        self.model.eval()

        times_t = torch.from_numpy(times).float().to(self.device)
        values_t = torch.from_numpy(values).float().to(self.device)
        masks_t = torch.from_numpy(masks).float().to(self.device)
        target_t = torch.from_numpy(target_times).float().to(self.device)

        with torch.no_grad():
            outputs = self.model(times_t, values_t, masks_t)
            z0 = outputs["z0"]

            # Solve ODE at target times
            z_t = odeint(
                self.model.ode_func_wrapper,
                z0,
                target_t,
                method=self.model.solver,
            )  # [T_target, batch, latent_dim]

            # Decode
            z_flat = z_t.view(-1, self.model.latent_dim)
            obs_interp = self.model.decoder(z_flat)
            obs_interp = obs_interp.view(len(target_times), -1, self.model.obs_dim)

        return obs_interp.cpu().numpy()


# ─── Latent ODE Classifier ────────────────────────────────────────────────────

class LatentODEClassifier(nn.Module):
    """
    Classify attack types from continuous latent trajectories.
    
    Uses the ODE latent trajectory as input to a classifier head,
    enabling classification of attack types based on their
    continuous-time dynamics.
    """

    def __init__(
        self,
        latent_dim: int = LATENT_DIM,
        num_classes: int = 10,
        hidden_dim: int = HIDDEN_DIM,
    ):
        super().__init__()
        self.latent_dim = latent_dim

        # Process trajectory: aggregate over time
        self.traj_encoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ELU(),
        )

        # Self-attention over time
        self.attention = nn.MultiheadAttention(hidden_dim, num_heads=4, batch_first=True)

        # Classifier
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ELU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim, num_classes),
        )

    def forward(
        self,
        z_trajectory: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Classify from latent trajectory.
        
        Args:
            z_trajectory: Latent trajectory [batch, T, latent_dim]
        
        Returns:
            (logits, attention_weights)
        """
        # Encode each time step
        traj_encoded = self.traj_encoder(z_trajectory)  # [batch, T, hidden_dim]

        # Self-attention
        attended, attn_weights = self.attention(traj_encoded, traj_encoded, traj_encoded)

        # Global pooling (mean over time)
        pooled = attended.mean(dim=1)  # [batch, hidden_dim]

        # Classify
        logits = self.classifier(pooled)

        return logits, attn_weights


# ─── Factory Functions ────────────────────────────────────────────────────────

def create_ode_detector(
    obs_dim: int = OBS_DIM,
    latent_dim: int = LATENT_DIM,
    hidden_dim: int = HIDDEN_DIM,
    device: Optional[torch.device] = None,
) -> ODEAnomalyDetector:
    """
    Create a Neural ODE anomaly detector.
    
    Args:
        obs_dim: Observation dimension
        latent_dim: Latent state dimension
        hidden_dim: Hidden dimension
        device: Torch device
    
    Returns:
        Configured ODEAnomalyDetector
    """
    if not TORCH_AVAILABLE:
        warnings.warn("PyTorch not available. ODE detector will be a placeholder.")
        return None  # type: ignore

    return ODEAnomalyDetector(
        obs_dim=obs_dim,
        latent_dim=latent_dim,
        hidden_dim=hidden_dim,
        device=device,
    )


def create_ode_detector_minimal() -> ODEAnomalyDetector:
    """Create a minimal ODE detector for testing."""
    return create_ode_detector(obs_dim=8, latent_dim=16, hidden_dim=32)


def create_ode_detector_full() -> ODEAnomalyDetector:
    """Create a full-scale ODE detector."""
    return create_ode_detector(obs_dim=128, latent_dim=128, hidden_dim=512)


def create_ode_predictor(
    detector: Optional[ODEAnomalyDetector] = None,
) -> ODEAttackPredictor:
    """Create an ODE attack predictor."""
    if detector is None:
        detector = create_ode_detector_minimal()
    return ODEAttackPredictor(detector)


def create_ode_interpolator(
    detector: Optional[ODEAnomalyDetector] = None,
) -> ODEInterpolator:
    """Create an ODE interpolator."""
    if detector is None:
        detector = create_ode_detector_minimal()
    return ODEInterpolator(detector)


__all__ = [
    "ODEDetectionResult",
    "ODEPredictionResult",
    "IrregularTimeSeries",
    "ODEFunc",
    "ODEFuncWrapper",
    "ODEEncoder",
    "ODEDecoder",
    "LatentODEModel",
    "ODEAnomalyDetector",
    "ODEAttackPredictor",
    "ODEInterpolator",
    "LatentODEClassifier",
    "create_ode_detector",
    "create_ode_detector_minimal",
    "create_ode_detector_full",
    "create_ode_predictor",
    "create_ode_interpolator",
]
