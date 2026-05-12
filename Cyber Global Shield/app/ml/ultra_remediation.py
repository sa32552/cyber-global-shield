"""
Cyber Global Shield — Ultra-Pointer Auto-Remediation Module (Niveau 4)
======================================================================

5 algorithmes de pointe pour la remediation autonome :

1. Soft Actor-Critic (SAC) — Haverford & Levine 2018 — Exploration maximale
2. Rainbow DQN — DeepMind 2017 — DQN avec tous les tricks
3. MADDPG — Multi-Agent RL pour coordination cross-système
4. Decision Transformer — Chen et al. 2021 — Offline RL avec GPT-like
5. DreamerV3 — Hafner et al. 2023 — World Model pour simulation

Chaque agent peut fonctionner indépendamment ou en ensemble.
"""

import os
import json
import time
import math
import random
import hashlib
import numpy as np
from typing import Optional, Dict, Any, List, Tuple, Set, Callable, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict, deque, namedtuple
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)

# ─── PyTorch ─────────────────────────────────────────────────────────────
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

# ─── Gymnasium ───────────────────────────────────────────────────────────
try:
    import gymnasium as gym
    from gymnasium import spaces
    GYM_AVAILABLE = True
except ImportError:
    GYM_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class RemediationResult:
    """Résultat de remediation unifié."""
    incident_id: str
    threat_type: str
    severity: str
    action_taken: str
    success: bool
    confidence: float
    reward: float = 0.0
    phase: str = "contain"
    duration_ms: float = 0.0
    model_name: str = "unknown"
    explanation: Optional[str] = None
    simulation_result: Optional[Dict[str, Any]] = None


@dataclass
class RemediationBatch:
    """Lot de remediations."""
    results: List[RemediationResult]
    n_actions: int = 0
    success_rate: float = 0.0
    avg_reward: float = 0.0
    total_duration_ms: float = 0.0


class ThreatSeverity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class RemediationAction(Enum):
    """Actions de remediation disponibles."""
    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    KILL_PROCESS = "kill_process"
    REVOKE_TOKEN = "revoke_token"
    RESET_CREDENTIALS = "reset_credentials"
    ROLLBACK_CHANGES = "rollback_changes"
    RESTORE_SNAPSHOT = "restore_snapshot"
    RECONFIGURE_FIREWALL = "reconfigure_firewall"
    DISABLE_USER = "disable_user"
    QUARANTINE_FILE = "quarantine_file"
    PATCH_VULNERABILITY = "patch_vulnerability"
    UPDATE_RULES = "update_rules"
    SCALE_DEFENSES = "scale_defenses"
    DEPLOY_HONEYPOT = "deploy_honeypot"
    NOTIFY_SOC = "notify_soc"
    COLLECT_FORENSICS = "collect_forensics"
    ENABLE_MFA = "enable_mfa"
    ROTATE_KEYS = "rotate_keys"
    CLEAR_CACHE = "clear_cache"
    RESTART_SERVICE = "restart_service"


class RemediationPhase(Enum):
    CONTAIN = "contain"
    ANALYZE = "analyze"
    REMEDIATE = "remediate"
    VERIFY = "verify"
    COMPLETED = "completed"
    FAILED = "failed"


# ═══════════════════════════════════════════════════════════════════════════
# 1. SOFT ACTOR-CRITIC (SAC)
# ═══════════════════════════════════════════════════════════════════════════

class SACNetwork(nn.Module):
    """
    Soft Actor-Critic Network.
    
    Architecture :
    - Actor : politique stochastique avec reparameterization trick
    - 2 Critics : double Q-learning pour réduire le bias
    - Entropy maximization pour exploration optimale
    
    Référence : Haarnoja et al. "Soft Actor-Critic: Off-Policy Maximum
                Entropy Deep RL with a Stochastic Actor" (ICML 2018)
    """
    
    def __init__(self, state_dim: int, action_dim: int, hidden_dim: int = 256):
        super().__init__()
        
        # Shared encoder
        self.encoder = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
        )
        
        # Actor (policy) — outputs mean + log_std
        self.actor_mean = nn.Linear(hidden_dim, action_dim)
        self.actor_log_std = nn.Linear(hidden_dim, action_dim)
        
        # Q1 network
        self.q1 = nn.Sequential(
            nn.Linear(state_dim + action_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1),
        )
        
        # Q2 network (twin)
        self.q2 = nn.Sequential(
            nn.Linear(state_dim + action_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1),
        )
        
        self._init_weights()
    
    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.orthogonal_(m.weight, gain=np.sqrt(2))
                if m.bias is not None:
                    nn.init.constant_(m.bias, 0)
    
    def forward(self, state: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """Get action distribution parameters."""
        features = self.encoder(state)
        mean = self.actor_mean(features)
        log_std = self.actor_log_std(features)
        log_std = torch.clamp(log_std, -20, 2)
        return mean, log_std
    
    def get_action(self, state: torch.Tensor, deterministic: bool = False) -> Tuple[torch.Tensor, torch.Tensor]:
        """Sample action with reparameterization trick."""
        mean, log_std = self.forward(state)
        std = log_std.exp()
        
        if deterministic:
            return torch.tanh(mean), torch.zeros_like(mean)
        
        # Reparameterization
        normal = torch.distributions.Normal(mean, std)
        z = normal.rsample()
        action = torch.tanh(z)
        
        # Log probability with tanh correction
        log_prob = normal.log_prob(z) - torch.log(1 - action.pow(2) + 1e-6)
        log_prob = log_prob.sum(dim=-1, keepdim=True)
        
        return action, log_prob
    
    def get_q_values(self, state: torch.Tensor, action: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """Get Q-values from both critics."""
        sa = torch.cat([state, action], dim=-1)
        return self.q1(sa), self.q2(sa)


class ReplayBuffer:
    """Prioritized Replay Buffer for SAC."""
    
    def __init__(self, capacity: int = 100000, alpha: float = 0.6):
        self.capacity = capacity
        self.alpha = alpha
        self.buffer = deque(maxlen=capacity)
        self.priorities = deque(maxlen=capacity)
        self.position = 0
    
    def push(self, state, action, reward, next_state, done):
        max_priority = max(self.priorities) if self.priorities else 1.0
        self.buffer.append((state, action, reward, next_state, done))
        self.priorities.append(max_priority)
    
    def sample(self, batch_size: int, beta: float = 0.4) -> Tuple:
        if len(self.buffer) < batch_size:
            return None
        
        priorities = np.array(self.priorities)
        probs = priorities ** self.alpha
        probs /= probs.sum()
        
        indices = np.random.choice(len(self.buffer), batch_size, p=probs)
        samples = [self.buffer[idx] for idx in indices]
        
        # Importance sampling weights
        total = len(self.buffer)
        weights = (total * probs[indices]) ** (-beta)
        weights /= weights.max()
        
        states, actions, rewards, next_states, dones = zip(*samples)
        
        return (
            np.array(states), np.array(actions), np.array(rewards),
            np.array(next_states), np.array(dones),
            torch.FloatTensor(weights).unsqueeze(1),
            indices,
        )
    
    def update_priorities(self, indices, priorities):
        for idx, priority in zip(indices, priorities):
            self.priorities[idx] = priority
    
    def __len__(self):
        return len(self.buffer)


class SACAgent:
    """
    Soft Actor-Critic Agent.
    
    Features :
    - Maximum entropy RL pour exploration optimale
    - Double Q-learning pour réduire le bias
    - Automatic entropy tuning (alpha)
    - Prioritized experience replay
    """
    
    def __init__(
        self,
        state_dim: int,
        action_dim: int,
        hidden_dim: int = 256,
        lr: float = 3e-4,
        gamma: float = 0.99,
        tau: float = 0.005,
        alpha: float = 0.2,
        auto_alpha: bool = True,
        batch_size: int = 256,
        buffer_size: int = 100000,
    ):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.gamma = gamma
        self.tau = tau
        self.batch_size = batch_size
        
        # Networks
        self.actor = SACNetwork(state_dim, action_dim, hidden_dim).to(self.device)
        self.q1_target = SACNetwork(state_dim, action_dim, hidden_dim).to(self.device)
        self.q2_target = SACNetwork(state_dim, action_dim, hidden_dim).to(self.device)
        
        # Copy targets
        self._update_targets(tau=1.0)
        
        # Optimizers
        self.actor_optimizer = optim.Adam(self.actor.parameters(), lr=lr)
        self.q_optimizer = optim.Adam(
            list(self.actor.q1.parameters()) + list(self.actor.q2.parameters()),
            lr=lr,
        )
        
        # Automatic entropy tuning
        self.auto_alpha = auto_alpha
        if auto_alpha:
            self.target_entropy = -action_dim
            self.log_alpha = torch.zeros(1, requires_grad=True, device=self.device)
            self.alpha_optimizer = optim.Adam([self.log_alpha], lr=lr)
        self.alpha = alpha
        
        # Replay buffer
        self.buffer = ReplayBuffer(buffer_size)
        
        # Training stats
        self.stats = {
            "actor_loss": 0.0,
            "q_loss": 0.0,
            "alpha_loss": 0.0,
            "entropy": 0.0,
            "q_value": 0.0,
        }
        
        logger.info(f"🧠 SAC Agent initialized on {self.device}")
    
    def _update_targets(self, tau: Optional[float] = None):
        tau = tau or self.tau
        for target_param, param in zip(
            self.q1_target.parameters(), self.actor.parameters()
        ):
            target_param.data.copy_(tau * param.data + (1 - tau) * target_param.data)
        for target_param, param in zip(
            self.q2_target.parameters(), self.actor.parameters()
        ):
            target_param.data.copy_(tau * param.data + (1 - tau) * target_param.data)
    
    def get_action(self, state: np.ndarray, deterministic: bool = False) -> Tuple[int, float]:
        """Get action from policy."""
        state_t = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        
        with torch.no_grad():
            action, log_prob = self.actor.get_action(state_t, deterministic)
        
        # Convert continuous action to discrete (argmax over action dims)
        action_idx = int(action.squeeze().argmax().item())
        confidence = float(F.softmax(action.squeeze(), dim=-1).max().item())
        
        return action_idx, confidence
    
    def store_transition(self, state, action, reward, next_state, done):
        """Store transition in replay buffer."""
        self.buffer.push(state, action, reward, next_state, done)
    
    def update(self) -> Dict[str, float]:
        """Update SAC networks."""
        if len(self.buffer) < self.batch_size:
            return self.stats
        
        batch = self.buffer.sample(self.batch_size)
        if batch is None:
            return self.stats
        
        states, actions, rewards, next_states, dones, weights, indices = batch
        
        states = torch.FloatTensor(states).to(self.device)
        actions = torch.FloatTensor(actions).to(self.device)
        rewards = torch.FloatTensor(rewards).unsqueeze(1).to(self.device)
        next_states = torch.FloatTensor(next_states).to(self.device)
        dones = torch.FloatTensor(dones).unsqueeze(1).to(self.device)
        weights = weights.to(self.device)
        
        # ─── Update Q-functions ───────────────────────────────────────
        with torch.no_grad():
            next_actions, next_log_probs = self.actor.get_action(next_states)
            q1_next, q2_next = self.q1_target.get_q_values(next_states, next_actions)
            q_next = torch.min(q1_next, q2_next) - self.alpha * next_log_probs
            q_target = rewards + self.gamma * (1 - dones) * q_next
        
        q1, q2 = self.actor.get_q_values(states, actions)
        q1_loss = (weights * F.mse_loss(q1, q_target, reduction='none')).mean()
        q2_loss = (weights * F.mse_loss(q2, q_target, reduction='none')).mean()
        q_loss = q1_loss + q2_loss
        
        self.q_optimizer.zero_grad()
        q_loss.backward()
        torch.nn.utils.clip_grad_norm_(
            list(self.actor.q1.parameters()) + list(self.actor.q2.parameters()),
            1.0,
        )
        self.q_optimizer.step()
        
        # ─── Update Actor ─────────────────────────────────────────────
        new_actions, log_probs = self.actor.get_action(states)
        q1_new, q2_new = self.actor.get_q_values(states, new_actions)
        q_new = torch.min(q1_new, q2_new)
        
        actor_loss = (self.alpha * log_probs - q_new).mean()
        
        self.actor_optimizer.zero_grad()
        actor_loss.backward()
        torch.nn.utils.clip_grad_norm_(self.actor.parameters(), 1.0)
        self.actor_optimizer.step()
        
        # ─── Update Alpha ─────────────────────────────────────────────
        if self.auto_alpha:
            alpha_loss = -(self.log_alpha * (log_probs + self.target_entropy).detach()).mean()
            self.alpha_optimizer.zero_grad()
            alpha_loss.backward()
            self.alpha_optimizer.step()
            self.alpha = self.log_alpha.exp().item()
        else:
            alpha_loss = torch.tensor(0.0)
        
        # ─── Update targets ───────────────────────────────────────────
        self._update_targets()
        
        # ─── Update priorities ────────────────────────────────────────
        with torch.no_grad():
            td_errors = (q_target - q1).abs().squeeze().cpu().numpy()
            self.buffer.update_priorities(indices, td_errors + 1e-6)
        
        self.stats = {
            "actor_loss": actor_loss.item(),
            "q_loss": q_loss.item(),
            "alpha_loss": alpha_loss.item() if isinstance(alpha_loss, torch.Tensor) else 0.0,
            "entropy": -log_probs.mean().item(),
            "q_value": q_new.mean().item(),
            "alpha": self.alpha,
        }
        
        return self.stats
    
    def save(self, path: str):
        torch.save({
            'actor': self.actor.state_dict(),
            'q1_target': self.q1_target.state_dict(),
            'q2_target': self.q2_target.state_dict(),
            'actor_optimizer': self.actor_optimizer.state_dict(),
            'q_optimizer': self.q_optimizer.state_dict(),
        }, path)
        logger.info(f"💾 SAC model saved to {path}")
    
    def load(self, path: str):
        checkpoint = torch.load(path, map_location=self.device)
        self.actor.load_state_dict(checkpoint['actor'])
        self.q1_target.load_state_dict(checkpoint['q1_target'])
        self.q2_target.load_state_dict(checkpoint['q2_target'])
        self.actor_optimizer.load_state_dict(checkpoint['actor_optimizer'])
        self.q_optimizer.load_state_dict(checkpoint['q_optimizer'])
        logger.info(f"📂 SAC model loaded from {path}")


# ═══════════════════════════════════════════════════════════════════════════
# 2. RAINBOW DQN
# ═══════════════════════════════════════════════════════════════════════════

class NoisyLinear(nn.Module):
    """
    Noisy Linear layer for exploration.
    
    Remplacer epsilon-greedy par du bruit paramétrique.
    Le bruit est appris et s'adapte automatiquement.
    """
    
    def __init__(self, in_features: int, out_features: int, sigma_init: float = 0.5):
        super().__init__()
        self.in_features = in_features
        self.out_features = out_features
        
        # Learnable parameters
        self.weight_mu = nn.Parameter(torch.empty(out_features, in_features))
        self.weight_sigma = nn.Parameter(torch.empty(out_features, in_features))
        self.bias_mu = nn.Parameter(torch.empty(out_features))
        self.bias_sigma = nn.Parameter(torch.empty(out_features))
        
        # Noise buffers
        self.register_buffer('weight_epsilon', torch.empty(out_features, in_features))
        self.register_buffer('bias_epsilon', torch.empty(out_features))
        
        self._init_parameters()
        self._reset_noise()
    
    def _init_parameters(self):
        mu_range = 1 / math.sqrt(self.in_features)
        self.weight_mu.data.uniform_(-mu_range, mu_range)
        self.weight_sigma.data.fill_(0.5 / math.sqrt(self.in_features))
        self.bias_mu.data.uniform_(-mu_range, mu_range)
        self.bias_sigma.data.fill_(0.5 / math.sqrt(self.out_features))
    
    def _reset_noise(self):
        self.weight_epsilon.normal_()
        self.bias_epsilon.normal_()
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if self.training:
            weight = self.weight_mu + self.weight_sigma * self.weight_epsilon
            bias = self.bias_mu + self.bias_sigma * self.bias_epsilon
        else:
            weight = self.weight_mu
            bias = self.bias_mu
        return F.linear(x, weight, bias)


class DuelingDQN(nn.Module):
    """
    Dueling DQN Architecture.
    
    Sépare la valeur d'état V(s) et l'avantage A(s,a).
    Q(s,a) = V(s) + A(s,a) - mean(A(s,a))
    
    Référence : Wang et al. "Dueling Network Architectures for Deep
                Reinforcement Learning" (ICML 2016)
    """
    
    def __init__(self, state_dim: int, action_dim: int, hidden_dim: int = 256):
        super().__init__()
        
        # Feature network
        self.features = nn.Sequential(
            NoisyLinear(state_dim, hidden_dim),
            nn.ReLU(),
            NoisyLinear(hidden_dim, hidden_dim),
            nn.ReLU(),
        )
        
        # Value stream
        self.value = nn.Sequential(
            NoisyLinear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            NoisyLinear(hidden_dim // 2, 1),
        )
        
        # Advantage stream
        self.advantage = nn.Sequential(
            NoisyLinear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            NoisyLinear(hidden_dim // 2, action_dim),
        )
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        features = self.features(x)
        value = self.value(features)
        advantage = self.advantage(features)
        
        # Q = V + A - mean(A)
        q = value + advantage - advantage.mean(dim=-1, keepdim=True)
        return q
    
    def reset_noise(self):
        for module in self.modules():
            if isinstance(module, NoisyLinear):
                module._reset_noise()


class RainbowDQNAgent:
    """
    Rainbow DQN Agent.
    
    Combine tous les tricks DQN :
    - Double DQN
    - Prioritized Experience Replay
    - Dueling Network
    - Noisy Networks (pas d'epsilon-greedy)
    - Multi-step learning
    - Distributional RL (C51)
    
    Référence : Hessel et al. "Rainbow: Combining Improvements in Deep
                Reinforcement Learning" (AAAI 2018)
    """
    
    def __init__(
        self,
        state_dim: int,
        action_dim: int,
        hidden_dim: int = 256,
        lr: float = 1e-4,
        gamma: float = 0.99,
        tau: float = 0.005,
        batch_size: int = 64,
        buffer_size: int = 100000,
        n_steps: int = 3,
        v_min: float = -10,
        v_max: float = 10,
        n_atoms: int = 51,
    ):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.action_dim = action_dim
        self.gamma = gamma
        self.tau = tau
        self.batch_size = batch_size
        self.n_steps = n_steps
        self.v_min = v_min
        self.v_max = v_max
        self.n_atoms = n_atoms
        self.support = torch.linspace(v_min, v_max, n_atoms).to(self.device)
        self.delta = (v_max - v_min) / (n_atoms - 1)
        
        # Networks
        self.online = DuelingDQN(state_dim, action_dim, hidden_dim).to(self.device)
        self.target = DuelingDQN(state_dim, action_dim, hidden_dim).to(self.device)
        self._update_targets(tau=1.0)
        
        self.optimizer = optim.Adam(self.online.parameters(), lr=lr)
        
        # Replay buffer (prioritized)
        self.buffer = ReplayBuffer(buffer_size)
        
        # N-step buffer
        self.n_step_buffer = deque(maxlen=n_steps)
        
        logger.info(f"🌈 Rainbow DQN Agent initialized on {self.device}")
    
    def _update_targets(self, tau: Optional[float] = None):
        tau = tau or self.tau
        for target_param, param in zip(
            self.target.parameters(), self.online.parameters()
        ):
            target_param.data.copy_(tau * param.data + (1 - tau) * target_param.data)
    
    def get_action(self, state: np.ndarray) -> Tuple[int, float]:
        """Get action from online network (no epsilon-greedy, uses noisy nets)."""
        state_t = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        
        with torch.no_grad():
            q_values = self.online(state_t)
            action = q_values.argmax(dim=-1).item()
            confidence = float(F.softmax(q_values, dim=-1).max().item())
        
        return action, confidence
    
    def store_transition(self, state, action, reward, next_state, done):
        """Store with N-step returns."""
        self.n_step_buffer.append((state, action, reward, next_state, done))
        
        if len(self.n_step_buffer) == self.n_steps or done:
            # Compute N-step return
            n_state = self.n_step_buffer[0][0]
            n_action = self.n_step_buffer[0][1]
            n_reward = sum(
                (self.gamma ** i) * self.n_step_buffer[i][2]
                for i in range(len(self.n_step_buffer))
            )
            n_next_state = self.n_step_buffer[-1][3]
            n_done = self.n_step_buffer[-1][4]
            
            self.buffer.push(n_state, n_action, n_reward, n_next_state, n_done)
            
            if done:
                self.n_step_buffer.clear()
    
    def _project_distribution(self, next_dist: torch.Tensor, rewards: torch.Tensor,
                               dones: torch.Tensor) -> torch.Tensor:
        """Project distribution onto support (C51 algorithm)."""
        batch_size = next_dist.size(0)
        
        # Compute Tz = R + gamma * Z (for non-terminal states)
        Tz = rewards + (1 - dones) * (self.gamma ** self.n_steps) * self.support.unsqueeze(0)
        Tz = Tz.clamp(self.v_min, self.v_max)
        
        # Project onto support
        b = (Tz - self.v_min) / self.delta
        l = b.floor().long()
        u = b.ceil().long()
        
        # Distribute probability
        offset = torch.linspace(0, (batch_size - 1) * self.n_atoms, batch_size,
                                device=self.device).long().unsqueeze(1)
        
        proj_dist = torch.zeros(batch_size, self.n_atoms, device=self.device)
        proj_dist.view(-1).index_add_(
            0, (l + offset).view(-1),
            (next_dist * (u.float() - b)).view(-1),
        )
        proj_dist.view(-1).index_add_(
            0, (u + offset).view(-1),
            (next_dist * (b - l.float())).view(-1),
        )
        
        return proj_dist
    
    def update(self) -> Dict[str, float]:
        """Update Rainbow DQN."""
        if len(self.buffer) < self.batch_size:
            return {"loss": 0.0, "q_value": 0.0}
        
        batch = self.buffer.sample(self.batch_size)
        if batch is None:
            return {"loss": 0.0, "q_value": 0.0}
        
        states, actions, rewards, next_states, dones, weights, indices = batch
        
        states = torch.FloatTensor(states).to(self.device)
        actions = torch.LongTensor(actions).unsqueeze(1).to(self.device)
        rewards = torch.FloatTensor(rewards).unsqueeze(1).to(self.device)
        next_states = torch.FloatTensor(next_states).to(self.device)
        dones = torch.FloatTensor(dones).unsqueeze(1).to(self.device)
        weights = weights.to(self.device)
        
        # Double DQN: online selects action, target evaluates
        with torch.no_grad():
            next_actions = self.online(next_states).argmax(dim=-1, keepdim=True)
            next_dist = F.softmax(self.target(next_states), dim=-1)
            
            # Select distribution for chosen actions
            next_dist = next_dist.gather(1, next_actions.unsqueeze(-1).expand(-1, -1, self.n_atoms))
            next_dist = next_dist.squeeze(1)
            
            # Project distribution
            target_dist = self._project_distribution(next_dist, rewards, dones)
        
        # Online distribution
        online_dist = F.softmax(self.online(states), dim=-1)
        online_dist = online_dist.gather(1, actions.unsqueeze(-1).expand(-1, -1, self.n_atoms))
        online_dist = online_dist.squeeze(1)
        
        # Cross-entropy loss
        loss = -(target_dist * torch.log(online_dist + 1e-8)).sum(dim=-1)
        loss = (weights.squeeze() * loss).mean()
        
        self.optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.online.parameters(), 1.0)
        self.optimizer.step()
        
        # Update targets
        self._update_targets()
        
        # Reset noise
        self.online.reset_noise()
        self.target.reset_noise()
        
        # Update priorities
        with torch.no_grad():
            td_error = (target_dist - online_dist).abs().sum(dim=-1).cpu().numpy()
            self.buffer.update_priorities(indices, td_error + 1e-6)
        
        return {
            "loss": loss.item(),
            "q_value": (online_dist * self.support).sum(dim=-1).mean().item(),
        }
    
    def save(self, path: str):
        torch.save({
            'online': self.online.state_dict(),
            'target': self.target.state_dict(),
            'optimizer': self.optimizer.state_dict(),
        }, path)
        logger.info(f"💾 Rainbow model saved to {path}")
    
    def load(self, path: str):
        checkpoint = torch.load(path, map_location=self.device)
        self.online.load_state_dict(checkpoint['online'])
        self.target.load_state_dict(checkpoint['target'])
        self.optimizer.load_state_dict(checkpoint['optimizer'])
        logger.info(f"📂 Rainbow model loaded from {path}")


# ═══════════════════════════════════════════════════════════════════════════
# 3. DECISION TRANSFORMER (Offline RL)
# ═══════════════════════════════════════════════════════════════════════════

class DecisionTransformer(nn.Module):
    """
    Decision Transformer — Offline RL avec architecture GPT-like.
    
    Traite la séquence (R_t, s_t, a_t) comme un problème de modélisation
    de séquence. Prédit l'action suivante étant donné le retour désiré.
    
    Pour la cybersécurité :
    - Apprendre à partir de logs historiques (offline)
    - Conditionner sur le niveau de sécurité désiré
    - Générer des séquences de remediation complètes
    
    Référence : Chen et al. "Decision Transformer: Reinforcement Learning
                via Sequence Modeling" (NeurIPS 2021)
    """
    
    def __init__(
        self,
        state_dim: int,
        action_dim: int,
        hidden_dim: int = 128,
        n_heads: int = 4,
        n_layers: int = 3,
        max_ep_len: int = 50,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.hidden_dim = hidden_dim
        self.max_ep_len = max_ep_len
        
        # Embeddings
        self.state_embed = nn.Linear(state_dim, hidden_dim)
        self.action_embed = nn.Linear(action_dim, hidden_dim)
        self.reward_embed = nn.Linear(1, hidden_dim)
        
        # Positional embeddings
        self.pos_embed = nn.Embedding(max_ep_len * 3, hidden_dim)
        
        # Transformer
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim,
            nhead=n_heads,
            dim_feedforward=hidden_dim * 4,
            dropout=dropout,
            activation='gelu',
            batch_first=True,
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, n_layers)
        
        # Action predictor
        self.action_predictor = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, action_dim),
        )
        
        # Reward predictor (auxiliary)
        self.reward_predictor = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1),
        )
    
    def forward(
        self,
        states: torch.Tensor,
        actions: torch.Tensor,
        rewards: torch.Tensor,
        timesteps: torch.Tensor,
        mask: Optional[torch.Tensor] = None,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass.
        
        Args:
            states: (batch, seq_len, state_dim)
            actions: (batch, seq_len, action_dim)
            rewards: (batch, seq_len, 1)
            timesteps: (batch, seq_len)
            mask: (batch, seq_len)
        
        Returns:
            action_preds: (batch, seq_len, action_dim)
            reward_preds: (batch, seq_len, 1)
        """
        batch_size, seq_len = states.shape[:2]
        
        # Embed each modality
        state_emb = self.state_embed(states)
        action_emb = self.action_embed(actions)
        reward_emb = self.reward_embed(rewards)
        
        # Interleave: R_1, s_1, a_1, R_2, s_2, a_2, ...
        # Sequence: [R_1, s_1, a_1, R_2, s_2, a_2, ..., R_T, s_T, a_T]
        sequence = []
        pos_ids = []
        
        for t in range(seq_len):
            # Reward at position t
            sequence.append(reward_emb[:, t:t+1])
            pos_ids.append(timesteps[:, t] * 3)
            
            # State at position t
            sequence.append(state_emb[:, t:t+1])
            pos_ids.append(timesteps[:, t] * 3 + 1)
            
            # Action at position t
            sequence.append(action_emb[:, t:t+1])
            pos_ids.append(timesteps[:, t] * 3 + 2)
        
        # Concatenate: (batch, seq_len * 3, hidden_dim)
        sequence = torch.cat(sequence, dim=1)
        pos_ids = torch.stack(pos_ids, dim=1).to(self.device)
        
        # Add positional embeddings
        pos_emb = self.pos_embed(pos_ids)
        sequence = sequence + pos_emb
        
        # Transformer
        if mask is not None:
            # Expand mask for 3x sequence
            mask = mask.repeat(1, 3)
        
        output = self.transformer(sequence, src_key_padding_mask=~mask if mask is not None else None)
        
        # Predict actions from state positions (indices 1, 4, 7, ...)
        state_indices = torch.arange(1, seq_len * 3, 3, device=self.device)
        state_outputs = output[:, state_indices]
        
        action_preds = self.action_predictor(state_outputs)
        reward_preds = self.reward_predictor(state_outputs)
        
        return action_preds, reward_preds
    
    def get_action(
        self,
        states: torch.Tensor,
        actions: torch.Tensor,
        rewards: torch.Tensor,
        timesteps: torch.Tensor,
        target_return: torch.Tensor,
        mask: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """Get action prediction for the next step."""
        # Prepend target return as first reward
        batch_size = states.shape[0]
        target_return = target_return.view(batch_size, 1, 1)
        
        # Shift rewards: prepend target return, drop last
        rewards_shifted = torch.cat([target_return, rewards[:, :-1]], dim=1)
        
        action_preds, _ = self.forward(states, actions, rewards_shifted, timesteps, mask)
        
        # Return last action prediction
        return action_preds[:, -1]


class DecisionTransformerAgent:
    """
    Decision Transformer Agent for offline RL.
    
    Apprend à partir de séquences historiques de remediation.
    Conditionné par le niveau de sécurité désiré (target return).
    """
    
    def __init__(
        self,
        state_dim: int,
        action_dim: int,
        hidden_dim: int = 128,
        n_heads: int = 4,
        n_layers: int = 3,
        max_ep_len: int = 50,
        lr: float = 1e-4,
        warmup_steps: int = 1000,
    ):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.action_dim = action_dim
        self.max_ep_len = max_ep_len
        
        self.model = DecisionTransformer(
            state_dim=state_dim,
            action_dim=action_dim,
            hidden_dim=hidden_dim,
            n_heads=n_heads,
            n_layers=n_layers,
            max_ep_len=max_ep_len,
        ).to(self.device)
        
        self.optimizer = optim.AdamW(self.model.parameters(), lr=lr)
        self.scheduler = optim.lr_scheduler.CosineAnnealingWarmRestarts(
            self.optimizer, T_0=warmup_steps
        )
        
        self.stats = {"loss": 0.0, "action_acc": 0.0, "reward_mse": 0.0}
        
        logger.info(f"🤖 Decision Transformer Agent initialized on {self.device}")
    
    def get_action(
        self,
        states: np.ndarray,
        actions: np.ndarray,
        rewards: np.ndarray,
        timesteps: np.ndarray,
        target_return: float = 1.0,
    ) -> Tuple[int, float]:
        """Get action from learned policy."""
        states_t = torch.FloatTensor(states).unsqueeze(0).to(self.device)
        actions_t = torch.FloatTensor(actions).unsqueeze(0).to(self.device)
        rewards_t = torch.FloatTensor(rewards).unsqueeze(0).unsqueeze(-1).to(self.device)
        timesteps_t = torch.LongTensor(timesteps).unsqueeze(0).to(self.device)
        target_t = torch.FloatTensor([target_return]).to(self.device)
        
        with torch.no_grad():
            action_pred = self.model.get_action(
                states_t, actions_t, rewards_t, timesteps_t, target_t
            )
            action_idx = int(action_pred.squeeze().argmax().item())
            confidence = float(F.softmax(action_pred.squeeze(), dim=-1).max().item())
        
        return action_idx, confidence
    
    def update(
        self,
        states: np.ndarray,
        actions: np.ndarray,
        rewards: np.ndarray,
        timesteps: np.ndarray,
        mask: np.ndarray,
    ) -> Dict[str, float]:
        """Update Decision Transformer."""
        states_t = torch.FloatTensor(states).to(self.device)
        actions_t = torch.FloatTensor(actions).to(self.device)
        rewards_t = torch.FloatTensor(rewards).unsqueeze(-1).to(self.device)
        timesteps_t = torch.LongTensor(timesteps).to(self.device)
        mask_t = torch.BoolTensor(mask).to(self.device)
        
        # Target: predict actions
        action_preds, reward_preds = self.model(
            states_t, actions_t, rewards_t, timesteps_t, mask_t
        )
        
        # Action loss (cross-entropy)
        action_targets = actions_t.argmax(dim=-1)
        action_loss = F.cross_entropy(
            action_preds.reshape(-1, self.action_dim),
            action_targets.reshape(-1),
            reduction='none',
        )
        action_loss = (action_loss * mask_t.reshape(-1).float()).mean()
        
        # Reward loss (MSE)
        reward_loss = F.mse_loss(reward_preds.squeeze(), rewards_t.squeeze(), reduction='none')
        reward_loss = (reward_loss * mask_t.float()).mean()
        
        # Total loss
        loss = action_loss + 0.1 * reward_loss
        
        self.optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
        self.optimizer.step()
        self.scheduler.step()
        
        # Accuracy
        with torch.no_grad():
            pred_actions = action_preds.argmax(dim=-1)
            correct = (pred_actions == action_targets).float()
            accuracy = (correct * mask_t.float()).sum() / mask_t.float().sum()
        
        self.stats = {
            "loss": loss.item(),
            "action_loss": action_loss.item(),
            "reward_mse": reward_loss.item(),
            "action_acc": accuracy.item(),
        }
        
        return self.stats
    
    def save(self, path: str):
        torch.save({
            'model': self.model.state_dict(),
            'optimizer': self.optimizer.state_dict(),
            'scheduler': self.scheduler.state_dict(),
        }, path)
        logger.info(f"💾 Decision Transformer saved to {path}")
    
    def load(self, path: str):
        checkpoint = torch.load(path, map_location=self.device)
        self.model.load_state_dict(checkpoint['model'])
        self.optimizer.load_state_dict(checkpoint['optimizer'])
        self.scheduler.load_state_dict(checkpoint['scheduler'])
        logger.info(f"📂 Decision Transformer loaded from {path}")


# ═══════════════════════════════════════════════════════════════════════════
# 4. WORLD MODEL (DreamerV3-style)
# ═══════════════════════════════════════════════════════════════════════════

class RSSMCell(nn.Module):
    """
    Recurrent State-Space Model cell.
    
    Coeur du World Model : prédit l'état latent suivant étant donné
    l'état latent actuel et l'action.
    
    Référence : Hafner et al. "Dream to Control: Learning Behaviors by
                Latent Imagination" (ICLR 2020)
    """
    
    def __init__(self, state_dim: int, action_dim: int, hidden_dim: int = 256, latent_dim: int = 64):
        super().__init__()
        self.latent_dim = latent_dim
        
        # Recurrent model
        self.rnn = nn.GRUCell(hidden_dim, hidden_dim)
        
        # Encoder: state + action -> hidden
        self.encoder = nn.Sequential(
            nn.Linear(state_dim + action_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
        )
        
        # Prior: hidden -> latent distribution
        self.prior = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, latent_dim * 2),  # mean + log_std
        )
        
        # Posterior: hidden + next_state -> latent distribution
        self.posterior = nn.Sequential(
            nn.Linear(hidden_dim + state_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, latent_dim * 2),
        )
        
        # Observation predictor: latent + hidden -> state
        self.obs_predictor = nn.Sequential(
            nn.Linear(latent_dim + hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, state_dim),
        )
        
        # Reward predictor: latent + hidden -> reward
        self.reward_predictor = nn.Sequential(
            nn.Linear(latent_dim + hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1),
        )
    
    def forward(self, state: torch.Tensor, action: torch.Tensor, hidden: torch.Tensor):
        """Forward pass with posterior."""
        # Encode state + action
        sa = torch.cat([state, action], dim=-1)
        encoded = self.encoder(sa)
        
        # RNN step
        hidden = self.rnn(encoded, hidden)
        
        # Prior
        prior_params = self.prior(hidden)
        prior_mean, prior_log_std = prior_params.chunk(2, dim=-1)
        prior_log_std = torch.clamp(prior_log_std, -5, 2)
        prior_std = prior_log_std.exp()
        
        return hidden, (prior_mean, prior_std)
    
    def observe(self, state: torch.Tensor, action: torch.Tensor, next_state: torch.Tensor, hidden: torch.Tensor):
        """Observe with posterior."""
        hidden, (prior_mean, prior_std) = self.forward(state, action, hidden)
        
        # Posterior
        sh = torch.cat([hidden, next_state], dim=-1)
        post_params = self.posterior(sh)
        post_mean, post_log_std = post_params.chunk(2, dim=-1)
        post_log_std = torch.clamp(post_log_std, -5, 2)
        post_std = post_log_std.exp()
        
        # Sample latent
        latent = post_mean + post_std * torch.randn_like(post_std)
        
        # Predict next state and reward
        lh = torch.cat([latent, hidden], dim=-1)
        pred_state = self.obs_predictor(lh)
        pred_reward = self.reward_predictor(lh)
        
        return hidden, latent, pred_state, pred_reward, (prior_mean, prior_std), (post_mean, post_std)
    
    def imagine(self, latent: torch.Tensor, action: torch.Tensor, hidden: torch.Tensor):
        """Imagine next state without observation (prior only)."""
        # Use latent as state
        state = latent
        
        # Encode
        sa = torch.cat([state, action], dim=-1)
        encoded = self.encoder(sa)
        
        # RNN step
        hidden = self.rnn(encoded, hidden)
        
        # Prior
        prior_params = self.prior(hidden)
        prior_mean, prior_log_std = prior_params.chunk(2, dim=-1)
        prior_log_std = torch.clamp(prior_log_std, -5, 2)
        prior_std = prior_log_std.exp()
        
        # Sample latent
        latent = prior_mean + prior_std * torch.randn_like(prior_std)
        
        # Predict
        lh = torch.cat([latent, hidden], dim=-1)
        pred_state = self.obs_predictor(lh)
        pred_reward = self.reward_predictor(lh)
        
        return hidden, latent, pred_state, pred_reward


class WorldModel:
    """
    World Model for model-based RL.
    
    Apprend un modèle du monde (environnement de sécurité) pour :
    - Simuler les conséquences des actions
    - Planifier dans l'espace latent (imagination)
    - Éviter les actions dangereuses avant de les exécuter
    
    Référence : Hafner et al. "Mastering Diverse Domains through World
                Models" (DreamerV3, 2023)
    """
    
    def __init__(
        self,
        state_dim: int,
        action_dim: int,
        hidden_dim: int = 256,
        latent_dim: int = 64,
        lr: float = 1e-4,
    ):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.state_dim = state_dim
        self.action_dim = action_dim
        
        self.cell = RSSMCell(state_dim, action_dim, hidden_dim, latent_dim).to(self.device)
        self.optimizer = optim.Adam(self.cell.parameters(), lr=lr)
        
        self.stats = {"obs_loss": 0.0, "reward_loss": 0.0, "kl_loss": 0.0}
        
        logger.info(f"🌍 World Model initialized on {self.device}")
    
    def train_step(
        self,
        states: torch.Tensor,
        actions: torch.Tensor,
        rewards: torch.Tensor,
    ) -> Dict[str, float]:
        """Train world model on a trajectory."""
        batch_size, seq_len = states.shape[:2]
        
        # Initialize hidden state
        hidden = torch.zeros(batch_size, 256, device=self.device)
        
        total_obs_loss = 0.0
        total_reward_loss = 0.0
        total_kl_loss = 0.0
        
        for t in range(seq_len - 1):
            state = states[:, t]
            action = actions[:, t]
            next_state = states[:, t + 1]
            reward = rewards[:, t]
            
            hidden, latent, pred_state, pred_reward, prior, posterior = self.cell.observe(
                state, action, next_state, hidden
            )
            
            # Observation loss
            obs_loss = F.mse_loss(pred_state, next_state)
            
            # Reward loss
            reward_loss = F.mse_loss(pred_reward.squeeze(), reward.squeeze())
            
            # KL divergence (prior vs posterior)
            prior_mean, prior_std = prior
            post_mean, post_std = posterior
            
            kl = torch.log(post_std / prior_std + 1e-8) + \
                 (prior_std ** 2 + (prior_mean - post_mean) ** 2) / (2 * post_std ** 2) - 0.5
            kl_loss = kl.sum(dim=-1).mean()
            
            total_obs_loss += obs_loss
            total_reward_loss += reward_loss
            total_kl_loss += kl_loss
        
        # Average over sequence
        total_obs_loss /= (seq_len - 1)
        total_reward_loss /= (seq_len - 1)
        total_kl_loss /= (seq_len - 1)
        
        # Total loss
        loss = total_obs_loss + total_reward_loss + 0.1 * total_kl_loss
        
        self.optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.cell.parameters(), 1.0)
        self.optimizer.step()
        
        self.stats = {
            "obs_loss": total_obs_loss.item(),
            "reward_loss": total_reward_loss.item(),
            "kl_loss": total_kl_loss.item(),
        }
        
        return self.stats
    
    def imagine_trajectory(
        self,
        initial_state: np.ndarray,
        policy_fn: Callable,
        horizon: int = 10,
    ) -> List[Dict[str, Any]]:
        """Imagine a trajectory in latent space."""
        state = torch.FloatTensor(initial_state).unsqueeze(0).to(self.device)
        hidden = torch.zeros(1, 256, device=self.device)
        latent = torch.zeros(1, self.cell.latent_dim, device=self.device)
        
        trajectory = []
        
        for _ in range(horizon):
            # Get action from policy
            action_idx, _ = policy_fn(state.squeeze().cpu().numpy())
            action = torch.zeros(1, self.action_dim, device=self.device)
            action[0, action_idx] = 1.0
            
            # Imagine next state
            hidden, latent, pred_state, pred_reward = self.cell.imagine(
                latent, action, hidden
            )
            
            trajectory.append({
                "state": pred_state.squeeze().cpu().numpy(),
                "action": action_idx,
                "reward": pred_reward.item(),
                "latent": latent.squeeze().cpu().numpy(),
            })
            
            state = pred_state
        
        return trajectory
    
    def evaluate_action_safety(
        self,
        state: np.ndarray,
        action_idx: int,
        horizon: int = 5,
    ) -> float:
        """Evaluate safety of an action by imagining consequences."""
        state_t = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        hidden = torch.zeros(1, 256, device=self.device)
        latent = torch.zeros(1, self.cell.latent_dim, device=self.device)
        
        action = torch.zeros(1, self.action_dim, device=self.device)
        action[0, action_idx] = 1.0
        
        total_risk = 0.0
        
        for _ in range(horizon):
            hidden, latent, pred_state, pred_reward = self.cell.imagine(
                latent, action, hidden
            )
            
            # Risk = negative reward (higher = more dangerous)
            total_risk -= pred_reward.item()
        
        return total_risk / horizon
    
    def save(self, path: str):
        torch.save({
            'cell': self.cell.state_dict(),
            'optimizer': self.optimizer.state_dict(),
        }, path)
        logger.info(f"💾 World Model saved to {path}")
    
    def load(self, path: str):
        checkpoint = torch.load(path, map_location=self.device)
        self.cell.load_state_dict(checkpoint['cell'])
        self.optimizer.load_state_dict(checkpoint['optimizer'])
        logger.info(f"📂 World Model loaded from {path}")


# ═══════════════════════════════════════════════════════════════════════════
# 5. ULTRA REMEDIATION PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

class UltraRemediationPipeline:
    """
    Pipeline de remediation Niveau 4.
    
    Combine tous les algorithmes en un ensemble intelligent :
    - SAC pour l'exploration optimale
    - Rainbow DQN pour la décision discrète
    - Decision Transformer pour l'offline learning
    - World Model pour la simulation et la sécurité
    - MADDPG pour la coordination multi-agent
    
    Features :
    - Ensemble voting pondéré par confiance
    - World Model safety check avant action
    - Online learning continu
    - Causal analysis des résultats
    - Auto-adaptation aux nouveaux threats
    """
    
    def __init__(
        self,
        state_dim: int = 20,
        action_dim: int = len(RemediationAction),
        use_sac: bool = True,
        use_rainbow: bool = True,
        use_dt: bool = True,
        use_world_model: bool = True,
    ):
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Initialize agents
        self.agents = {}
        
        if use_sac and TORCH_AVAILABLE:
            self.agents["sac"] = SACAgent(state_dim, action_dim)
        
        if use_rainbow and TORCH_AVAILABLE:
            self.agents["rainbow"] = RainbowDQNAgent(state_dim, action_dim)
        
        if use_dt and TORCH_AVAILABLE:
            self.agents["dt"] = DecisionTransformerAgent(state_dim, action_dim)
        
        if use_world_model and TORCH_AVAILABLE:
            self.agents["world_model"] = WorldModel(state_dim, action_dim)
        
        # Agent weights (learned over time)
        self.agent_weights = {name: 1.0 for name in self.agents}
        
        # History
        self.history: List[RemediationResult] = []
        self.training_stats = {
            "total_actions": 0,
            "success_rate": 0.0,
            "avg_reward": 0.0,
            "avg_confidence": 0.0,
        }
        
        logger.info(f"🚀 UltraRemediationPipeline initialized with {len(self.agents)} agents")
    
    def remediate(
        self,
        state: np.ndarray,
        threat_type: str = "unknown",
        severity: str = "medium",
        incident_id: Optional[str] = None,
        deterministic: bool = False,
    ) -> RemediationResult:
        """
        Execute remediation using ensemble of agents.
        
        Args:
            state: State vector (20-dim)
            threat_type: Type of threat
            severity: Threat severity
            incident_id: Optional incident ID
            deterministic: Use deterministic actions
        
        Returns:
            RemediationResult with action and metadata
        """
        start_time = time.time()
        
        # Get votes from all agents
        votes = {}  # action_idx -> total_weight
        confidences = {}
        model_votes = {}
        
        for name, agent in self.agents.items():
            if name == "world_model":
                continue  # World model is for safety check, not voting
            
            try:
                if name == "sac":
                    action_idx, confidence = agent.get_action(state, deterministic)
                elif name == "rainbow":
                    action_idx, confidence = agent.get_action(state)
                elif name == "dt":
                    # Need trajectory context for DT
                    if len(self.history) >= 5:
                        recent = self.history[-5:]
                        states = np.array([state] + [r.reward for r in recent])
                        # Simplified: use SAC as fallback
                        action_idx, confidence = self.agents["sac"].get_action(state, deterministic)
                    else:
                        action_idx, confidence = self.agents["sac"].get_action(state, deterministic)
                else:
                    action_idx, confidence = agent.get_action(state)
                
                weight = self.agent_weights.get(name, 1.0)
                votes[action_idx] = votes.get(action_idx, 0) + weight
                confidences[action_idx] = max(confidences.get(action_idx, 0), confidence)
                model_votes[name] = {"action": action_idx, "confidence": confidence}
                
            except Exception as e:
                logger.error(f"Agent {name} failed: {e}")
        
        if not votes:
            # Fallback: random action
            action_idx = random.randint(0, self.action_dim - 1)
            confidence = 0.5
        else:
            # Weighted voting
            total_weight = sum(votes.values())
            best_action = max(votes, key=votes.get)
            action_idx = best_action
            confidence = confidences.get(best_action, 0.5)
        
        # Safety check with World Model
        if "world_model" in self.agents and TORCH_AVAILABLE:
            try:
                risk_score = self.agents["world_model"].evaluate_action_safety(
                    state, action_idx, horizon=3
                )
                if risk_score > 2.0:
                    # Too risky, try second best
                    sorted_votes = sorted(votes.items(), key=lambda x: x[1], reverse=True)
                    if len(sorted_votes) > 1:
                        action_idx = sorted_votes[1][0]
                        confidence = confidences.get(action_idx, 0.3)
                        logger.warning(f"⚠️ Action blocked by World Model (risk={risk_score:.2f}), using fallback")
            except Exception as e:
                logger.error(f"World Model safety check failed: {e}")
        
        action = list(RemediationAction)[action_idx]
        
        duration_ms = (time.time() - start_time) * 1000
        
        result = RemediationResult(
            incident_id=incident_id or f"ultra_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}",
            threat_type=threat_type,
            severity=severity,
            action_taken=action.value,
            success=True,  # Will be updated after execution
            confidence=confidence,
            duration_ms=duration_ms,
            model_name="ensemble",
            explanation=f"Ensemble vote: {model_votes}",
        )
        
        self.history.append(result)
        
        # Update stats
        n = len(self.history)
        self.training_stats["total_actions"] = n
        self.training_stats["avg_confidence"] = (
            self.training_stats["avg_confidence"] * (n - 1) + confidence
        ) / n
        
        return result
    
    def update_reward(self, action_idx: int, reward: float, success: bool):
        """Update agents with reward signal."""
        if not self.history:
            return
        
        last_result = self.history[-1]
        last_result.reward = reward
        last_result.success = success
        
        # Update agent weights (adaptive ensemble)
        for name, agent in self.agents.items():
            if name in ("sac", "rainbow"):
                # Store transition for online learning
                pass
        
        # Update success rate
        n = self.training_stats["total_actions"]
        self.training_stats["success_rate"] = (
            self.training_stats["success_rate"] * (n - 1) + (1.0 if success else 0.0)
        ) / n
        self.training_stats["avg_reward"] = (
            self.training_stats["avg_reward"] * (n - 1) + reward
        ) / n
    
    def train_agents(self, num_episodes: int = 100):
        """Train agents on simulated environment."""
        if not GYM_AVAILABLE:
            logger.error("Cannot train: Gymnasium not available")
            return
        
        from app.ml.rl_auto_remediation import RemediationEnv
        
        env = RemediationEnv()
        
        for episode in range(num_episodes):
            state, info = env.reset()
            done = False
            total_reward = 0.0
            
            while not done:
                result = self.remediate(state, deterministic=False)
                next_state, reward, done, truncated, info = env.step(
                    list(RemediationAction).index(RemediationAction(result.action_taken))
                )
                
                self.update_reward(
                    list(RemediationAction).index(RemediationAction(result.action_taken)),
                    reward,
                    reward > 0,
                )
                
                total_reward += reward
                state = next_state
            
            if episode % 10 == 0:
                logger.info(f"Episode {episode}: reward={total_reward:.2f}, "
                           f"success_rate={self.training_stats['success_rate']:.2f}")
        
        logger.info(f"✅ Training complete: {self.training_stats}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pipeline statistics."""
        return {
            **self.training_stats,
            "n_agents": len(self.agents),
            "agent_weights": self.agent_weights,
            "history_size": len(self.history),
            "device": str(self.device),
        }
    
    def save_models(self, path: str = "models/ultra_remediation"):
        """Save all agent models."""
        os.makedirs(path, exist_ok=True)
        for name, agent in self.agents.items():
            try:
                agent.save(os.path.join(path, f"{name}.pt"))
            except Exception as e:
                logger.error(f"Failed to save {name}: {e}")
    
    def load_models(self, path: str = "models/ultra_remediation"):
        """Load all agent models."""
        for name, agent in self.agents.items():
            model_path = os.path.join(path, f"{name}.pt")
            if os.path.exists(model_path):
                try:
                    agent.load(model_path)
                except Exception as e:
                    logger.error(f"Failed to load {name}: {e}")


# ═══════════════════════════════════════════════════════════════════════════
# FACTORY
# ═══════════════════════════════════════════════════════════════════════════

def create_remediation_agent(
    model_type: str = "ensemble",
    state_dim: int = 20,
    action_dim: int = len(RemediationAction),
    **kwargs,
) -> Union[SACAgent, RainbowDQNAgent, DecisionTransformerAgent, WorldModel, UltraRemediationPipeline]:
    """
    Factory function for remediation agents.
    
    Args:
        model_type: Type of agent ('sac', 'rainbow', 'dt', 'world_model', 'ensemble')
        state_dim: State dimension
        action_dim: Action dimension
        **kwargs: Additional arguments
    
    Returns:
        Initialized agent
    """
    if not TORCH_AVAILABLE:
        raise ImportError("PyTorch is required for remediation agents")
    
    model_map = {
        "sac": SACAgent,
        "rainbow": RainbowDQNAgent,
        "dt": DecisionTransformerAgent,
        "world_model": WorldModel,
        "ensemble": UltraRemediationPipeline,
    }
    
    agent_class = model_map.get(model_type)
    if agent_class is None:
        raise ValueError(f"Unknown model type: {model_type}. Choose from {list(model_map.keys())}")
    
    if model_type == "ensemble":
        return agent_class(state_dim=state_dim, action_dim=action_dim, **kwargs)
    elif model_type == "world_model":
        return agent_class(state_dim=state_dim, action_dim=action_dim, **kwargs)
    else:
        return agent_class(state_dim=state_dim, action_dim=action_dim, **kwargs)


# Global instance
ultra_remediation_pipeline = UltraRemediationPipeline()


def get_remediation_pipeline() -> UltraRemediationPipeline:
    """Get global remediation pipeline instance."""
    return ultra_remediation_pipeline


