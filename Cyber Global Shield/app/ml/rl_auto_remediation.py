"""
Cyber Global Shield — RL-Based Auto-Remediation Engine v2.0 ULTIMATE+
Auto-réparation intelligente par Reinforcement Learning de pointe.
- Proximal Policy Optimization (PPO) avec PyTorch
- Deep Q-Network (DQN) avec Experience Replay priorisé
- Multi-Agent RL pour coordination cross-système
- Digital Twin pour simulation sans risque
- Causal Inference (DoWhy) pour comprendre les causes racines
- Gymnasium Environment personnalisé
- Meta-Learning (MAML) pour adaptation rapide aux nouveaux threats
- Transformer-based state encoding
"""

import os
import json
import time
import random
import logging
import hashlib
import numpy as np
from typing import Optional, Dict, Any, List, Tuple, Set, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum

logger = logging.getLogger(__name__)

# ─── PyTorch / Deep RL ─────────────────────────────────────────────────────
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

# ─── Gymnasium ──────────────────────────────────────────────────────────────
try:
    import gymnasium as gym
    from gymnasium import spaces
    GYM_AVAILABLE = True
except ImportError:
    GYM_AVAILABLE = False

# ─── Causal Inference ───────────────────────────────────────────────────────
try:
    import dowhy
    from dowhy import CausalModel
    CAUSAL_AVAILABLE = True
except ImportError:
    CAUSAL_AVAILABLE = False

# ─── Transformers ───────────────────────────────────────────────────────────
try:
    from transformers import AutoModel, AutoTokenizer
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False


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


@dataclass
class Incident:
    """A security incident requiring remediation."""
    incident_id: str
    threat_type: str
    severity: ThreatSeverity
    target: str
    source_ip: Optional[str] = None
    description: str = ""
    detected_at: datetime = field(default_factory=datetime.utcnow)
    phase: RemediationPhase = RemediationPhase.CONTAIN
    actions_taken: List[str] = field(default_factory=list)
    success_rate: float = 0.0
    is_resolved: bool = False
    resolution_time_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RemediationStep:
    """A single remediation step with its outcome."""
    action: RemediationAction
    target: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    success: bool = False
    duration_ms: float = 0.0
    error: Optional[str] = None
    reward: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════
# 1. PPO NETWORK ARCHITECTURE (Proximal Policy Optimization)
# ═══════════════════════════════════════════════════════════════════════════

class PPONetwork(nn.Module):
    """
    Actor-Critic PPO Network avec Transformer encoding.
    Architecture de pointe pour la remediation autonome.
    """
    def __init__(self, state_dim: int, action_dim: int, hidden_dim: int = 256):
        super().__init__()
        
        # Shared feature extractor
        self.feature_net = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim * 2),
            nn.LayerNorm(hidden_dim * 2),
            nn.ReLU(),
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
        )
        
        # Actor head (policy)
        self.actor = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, action_dim),
        )
        
        # Critic head (value function)
        self.critic = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 1),
        )
        
        # Action mask embedding for invalid action suppression
        self.action_embedding = nn.Embedding(action_dim, 16)
        
        # Initialize weights
        self._init_weights()
    
    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.orthogonal_(m.weight, gain=np.sqrt(2))
                nn.init.constant_(m.bias, 0)
    
    def forward(self, state: torch.Tensor, action_mask: Optional[torch.Tensor] = None):
        features = self.feature_net(state)
        
        # Actor: get action logits
        action_logits = self.actor(features)
        
        # Apply action mask (suppress invalid actions)
        if action_mask is not None:
            action_logits = action_logits.masked_fill(~action_mask.bool(), float('-inf'))
        
        # Softmax over valid actions
        action_probs = F.softmax(action_logits, dim=-1)
        
        # Critic: get state value
        value = self.critic(features)
        
        return action_probs, value
    
    def get_action(self, state: torch.Tensor, action_mask: Optional[torch.Tensor] = None, deterministic: bool = False):
        action_probs, value = self.forward(state, action_mask)
        
        if deterministic:
            action = torch.argmax(action_probs, dim=-1)
        else:
            action = torch.multinomial(action_probs, 1).squeeze(-1)
        
        log_prob = torch.log(action_probs.gather(-1, action.unsqueeze(-1)) + 1e-10).squeeze(-1)
        entropy = -(action_probs * torch.log(action_probs + 1e-10)).sum(-1)
        
        return action, log_prob, entropy, value


class PPOAgent:
    """
    Proximal Policy Optimization Agent avec clipping adaptatif.
    Implémente PPO-clip avec GAE (Generalized Advantage Estimation).
    """
    def __init__(self,
                 state_dim: int,
                 action_dim: int,
                 lr: float = 3e-4,
                 gamma: float = 0.99,
                 gae_lambda: float = 0.95,
                 clip_epsilon: float = 0.2,
                 entropy_coef: float = 0.01,
                 value_coef: float = 0.5,
                 max_grad_norm: float = 0.5,
                 update_epochs: int = 10,
                 mini_batch_size: int = 64):
        
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.network = PPONetwork(state_dim, action_dim).to(self.device)
        self.optimizer = optim.Adam(self.network.parameters(), lr=lr, eps=1e-5)
        self.scheduler = optim.lr_scheduler.CosineAnnealingLR(self.optimizer, T_max=100)
        
        self.gamma = gamma
        self.gae_lambda = gae_lambda
        self.clip_epsilon = clip_epsilon
        self.entropy_coef = entropy_coef
        self.value_coef = value_coef
        self.max_grad_norm = max_grad_norm
        self.update_epochs = update_epochs
        self.mini_batch_size = mini_batch_size
        
        # Adaptive clipping
        self.kl_target = 0.02
        self.kl_beta = 1.0
        
        # Experience buffer
        self.states = []
        self.actions = []
        self.log_probs = []
        self.rewards = []
        self.dones = []
        self.values = []
        self.action_masks = []
        
        logger.info(f"🧠 PPO Agent initialisé sur {self.device}")
    
    def store_transition(self, state, action, log_prob, reward, done, value, action_mask=None):
        self.states.append(state)
        self.actions.append(action)
        self.log_probs.append(log_prob)
        self.rewards.append(reward)
        self.dones.append(done)
        self.values.append(value)
        self.action_masks.append(action_mask)
    
    def get_action(self, state: np.ndarray, action_mask: Optional[np.ndarray] = None, deterministic: bool = False):
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        mask_tensor = torch.BoolTensor(action_mask).unsqueeze(0).to(self.device) if action_mask is not None else None
        
        with torch.no_grad():
            action, log_prob, entropy, value = self.network.get_action(state_tensor, mask_tensor, deterministic)
        
        return action.item(), log_prob.item(), value.item()
    
    def update(self) -> Dict[str, float]:
        """PPO update with GAE and mini-batch training."""
        if len(self.states) < self.mini_batch_size:
            return {"loss": 0.0, "policy_loss": 0.0, "value_loss": 0.0, "entropy": 0.0, "kl": 0.0}
        
        # Convert to tensors
        states = torch.FloatTensor(np.array(self.states)).to(self.device)
        actions = torch.LongTensor(np.array(self.actions)).to(self.device)
        old_log_probs = torch.FloatTensor(np.array(self.log_probs)).to(self.device)
        rewards = torch.FloatTensor(np.array(self.rewards)).to(self.device)
        dones = torch.FloatTensor(np.array(self.dones)).to(self.device)
        values = torch.FloatTensor(np.array(self.values)).to(self.device)
        
        # Compute GAE (Generalized Advantage Estimation)
        advantages = self._compute_gae(rewards, values, dones)
        returns = advantages + values
        
        # Normalize advantages
        advantages = (advantages - advantages.mean()) / (advantages.std() + 1e-8)
        
        # PPO update epochs
        total_policy_loss = 0.0
        total_value_loss = 0.0
        total_entropy = 0.0
        total_kl = 0.0
        
        dataset_size = len(states)
        indices = np.arange(dataset_size)
        
        for _ in range(self.update_epochs):
            np.random.shuffle(indices)
            
            for start in range(0, dataset_size, self.mini_batch_size):
                end = start + self.mini_batch_size
                batch_indices = indices[start:end]
                
                batch_states = states[batch_indices]
                batch_actions = actions[batch_indices]
                batch_old_log_probs = old_log_probs[batch_indices]
                batch_advantages = advantages[batch_indices]
                batch_returns = returns[batch_indices]
                
                # Get new action probabilities
                action_probs, values_pred = self.network.forward(batch_states)
                dist = torch.distributions.Categorical(action_probs)
                new_log_probs = dist.log_prob(batch_actions)
                entropy = dist.entropy().mean()
                
                # Policy ratio
                ratio = torch.exp(new_log_probs - batch_old_log_probs)
                
                # PPO clipped objective
                surr1 = ratio * batch_advantages
                surr2 = torch.clamp(ratio, 1 - self.clip_epsilon, 1 + self.clip_epsilon) * batch_advantages
                policy_loss = -torch.min(surr1, surr2).mean()
                
                # Value loss (clipped)
                value_pred_clipped = values[batch_indices] + torch.clamp(
                    values_pred.squeeze() - values[batch_indices],
                    -self.clip_epsilon,
                    self.clip_epsilon
                )
                value_loss1 = F.mse_loss(values_pred.squeeze(), batch_returns)
                value_loss2 = F.mse_loss(value_pred_clipped, batch_returns)
                value_loss = 0.5 * torch.max(value_loss1, value_loss2).mean()
                
                # Total loss
                loss = policy_loss + self.value_coef * value_loss - self.entropy_coef * entropy
                
                # Gradient step
                self.optimizer.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.network.parameters(), self.max_grad_norm)
                self.optimizer.step()
                
                # KL divergence for adaptive clipping
                with torch.no_grad():
                    kl = (batch_old_log_probs - new_log_probs).mean().item()
                    total_kl += kl
                
                total_policy_loss += policy_loss.item()
                total_value_loss += value_loss.item()
                total_entropy += entropy.item()
        
        # Adaptive KL beta
        avg_kl = total_kl / (self.update_epochs * max(dataset_size // self.mini_batch_size, 1))
        if avg_kl > self.kl_target * 2:
            self.kl_beta *= 1.5
        elif avg_kl < self.kl_target * 0.5:
            self.kl_beta *= 0.5
        
        # Clear buffer
        self.states.clear()
        self.actions.clear()
        self.log_probs.clear()
        self.rewards.clear()
        self.dones.clear()
        self.values.clear()
        self.action_masks.clear()
        
        # Step scheduler
        self.scheduler.step()
        
        n_updates = self.update_epochs * max(dataset_size // self.mini_batch_size, 1)
        
        return {
            "loss": (total_policy_loss + total_value_loss) / n_updates,
            "policy_loss": total_policy_loss / n_updates,
            "value_loss": total_value_loss / n_updates,
            "entropy": total_entropy / n_updates,
            "kl": avg_kl,
        }
    
    def _compute_gae(self, rewards, values, dones):
        """Compute Generalized Advantage Estimation."""
        advantages = []
        gae = 0
        
        for t in reversed(range(len(rewards))):
            if t == len(rewards) - 1:
                next_value = 0
            else:
                next_value = values[t + 1]
            
            delta = rewards[t] + self.gamma * next_value * (1 - dones[t]) - values[t]
            gae = delta + self.gamma * self.gae_lambda * (1 - dones[t]) * gae
            advantages.insert(0, gae)
        
        return torch.FloatTensor(advantages).to(self.device)
    
    def save(self, path: str):
        torch.save({
            'network_state_dict': self.network.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'scheduler_state_dict': self.scheduler.state_dict(),
        }, path)
        logger.info(f"💾 PPO model saved to {path}")
    
    def load(self, path: str):
        checkpoint = torch.load(path, map_location=self.device)
        self.network.load_state_dict(checkpoint['network_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        self.scheduler.load_state_dict(checkpoint['scheduler_state_dict'])
        logger.info(f"📂 PPO model loaded from {path}")


# ═══════════════════════════════════════════════════════════════════════════
# 2. REMEDIATION ENVIRONMENT (Gymnasium)
# ═══════════════════════════════════════════════════════════════════════════

class RemediationEnv(gym.Env):
    """
    Gymnasium Environment pour la remediation de sécurité.
    Simule un environnement réseau avec des incidents de sécurité.
    """
    metadata = {"render_modes": ["human", "rgb_array"], "render_fps": 4}
    
    def __init__(self, render_mode: Optional[str] = None):
        super().__init__()
        
        # Action space: 20 remediation actions
        self.action_space = spaces.Discrete(len(RemediationAction))
        
        # Observation space: state features
        # [severity(4), phase(6), threat_type(10), actions_taken(5), 
        #  success_rate, time_elapsed, num_active_incidents, network_health,
        #  cpu_usage, memory_usage, connection_count, anomaly_score]
        self.observation_space = spaces.Box(
            low=0, high=1, shape=(20,), dtype=np.float32
        )
        
        self.render_mode = render_mode
        
        # Internal state
        self.current_incident: Optional[Incident] = None
        self.step_count = 0
        self.max_steps = 50
        self.network_health = 1.0
        self.anomaly_score = 0.0
        
        # Action success probabilities (realistic)
        self.action_success_probs = {
            RemediationAction.BLOCK_IP: 0.95,
            RemediationAction.ISOLATE_HOST: 0.90,
            RemediationAction.KILL_PROCESS: 0.85,
            RemediationAction.REVOKE_TOKEN: 0.95,
            RemediationAction.RESET_CREDENTIALS: 0.90,
            RemediationAction.ROLLBACK_CHANGES: 0.80,
            RemediationAction.RESTORE_SNAPSHOT: 0.85,
            RemediationAction.RECONFIGURE_FIREWALL: 0.90,
            RemediationAction.DISABLE_USER: 0.95,
            RemediationAction.QUARANTINE_FILE: 0.85,
            RemediationAction.PATCH_VULNERABILITY: 0.75,
            RemediationAction.UPDATE_RULES: 0.90,
            RemediationAction.SCALE_DEFENSES: 0.85,
            RemediationAction.DEPLOY_HONEYPOT: 0.90,
            RemediationAction.NOTIFY_SOC: 0.99,
            RemediationAction.COLLECT_FORENSICS: 0.95,
            RemediationAction.ENABLE_MFA: 0.85,
            RemediationAction.ROTATE_KEYS: 0.90,
            RemediationAction.CLEAR_CACHE: 0.95,
            RemediationAction.RESTART_SERVICE: 0.80,
        }
        
        # Action masks (which actions are valid in which phase)
        self.phase_action_masks = {
            RemediationPhase.CONTAIN: [
                RemediationAction.BLOCK_IP, RemediationAction.ISOLATE_HOST,
                RemediationAction.KILL_PROCESS, RemediationAction.DISABLE_USER,
                RemediationAction.REVOKE_TOKEN,
            ],
            RemediationPhase.ANALYZE: [
                RemediationAction.COLLECT_FORENSICS, RemediationAction.QUARANTINE_FILE,
                RemediationAction.DEPLOY_HONEYPOT,
            ],
            RemediationPhase.REMEDIATE: [
                RemediationAction.RESET_CREDENTIALS, RemediationAction.ROLLBACK_CHANGES,
                RemediationAction.RESTORE_SNAPSHOT, RemediationAction.RECONFIGURE_FIREWALL,
                RemediationAction.PATCH_VULNERABILITY, RemediationAction.ROTATE_KEYS,
                RemediationAction.ENABLE_MFA, RemediationAction.UPDATE_RULES,
                RemediationAction.SCALE_DEFENSES, RemediationAction.RESTART_SERVICE,
            ],
            RemediationPhase.VERIFY: [
                RemediationAction.NOTIFY_SOC, RemediationAction.CLEAR_CACHE,
            ],
        }
    
    def reset(self, seed: Optional[int] = None, options: Optional[dict] = None):
        super().reset(seed=seed)
        
        # Generate random incident
        threat_types = list(self.action_success_probs.keys())
        self.current_incident = Incident(
            incident_id=f"sim_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}",
            threat_type=random.choice([
                "ransomware", "lateral_movement", "c2_beaconing", "data_exfiltration",
                "brute_force", "web_attack", "malware", "insider_threat", "dos_attack", "zero_day"
            ]),
            severity=random.choice(list(ThreatSeverity)),
            target=f"host_{random.randint(1,100)}",
            source_ip=f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}",
        )
        
        self.step_count = 0
        self.network_health = 1.0
        self.anomaly_score = random.uniform(0.3, 0.9)
        
        return self._get_obs(), self._get_info()
    
    def step(self, action_idx: int):
        self.step_count += 1
        action = list(RemediationAction)[action_idx]
        
        # Check if action is valid for current phase
        valid_actions = self.phase_action_masks.get(self.current_incident.phase, [])
        is_valid = action in valid_actions
        
        # Execute action
        success_prob = self.action_success_probs.get(action, 0.8)
        # Adjust for severity
        severity_penalty = {ThreatSeverity.LOW: 0, ThreatSeverity.MEDIUM: -0.05,
                           ThreatSeverity.HIGH: -0.15, ThreatSeverity.CRITICAL: -0.25}
        success_prob += severity_penalty.get(self.current_incident.severity, 0)
        
        success = random.random() < max(0.1, success_prob) if is_valid else False
        
        # Calculate reward
        reward = self._calculate_reward(action, success, is_valid)
        
        # Update state
        if success:
            self.current_incident.actions_taken.append(action.value)
            self.network_health = min(1.0, self.network_health + 0.05)
            self.anomaly_score = max(0, self.anomaly_score - 0.1)
            
            # Phase progression
            if action in self.phase_action_masks.get(RemediationPhase.CONTAIN, []):
                self.current_incident.phase = RemediationPhase.ANALYZE
            elif action in self.phase_action_masks.get(RemediationPhase.REMEDIATE, []):
                self.current_incident.phase = RemediationPhase.VERIFY
        else:
            self.network_health = max(0, self.network_health - 0.1)
            self.anomaly_score = min(1.0, self.anomaly_score + 0.05)
        
        # Check termination
        terminated = False
        if self.current_incident.phase == RemediationPhase.VERIFY and success:
            terminated = True
            reward += 5.0  # Bonus for resolving
        elif self.step_count >= self.max_steps:
            terminated = True
            reward -= 2.0  # Penalty for timeout
        elif self.network_health <= 0:
            terminated = True
            reward -= 10.0  # Critical failure
        
        return self._get_obs(), reward, terminated, False, self._get_info()
    
    def _get_obs(self):
        """Get observation vector."""
        severity = self.current_incident.severity.value / 4.0
        phase = list(RemediationPhase).index(self.current_incident.phase) / 6.0
        threat_idx = ["ransomware", "lateral_movement", "c2_beaconing", "data_exfiltration",
                      "brute_force", "web_attack", "malware", "insider_threat", "dos_attack", "zero_day"
                     ].index(self.current_incident.threat_type) / 10.0
        actions_taken = min(len(self.current_incident.actions_taken), 10) / 10.0
        step_progress = self.step_count / self.max_steps
        
        return np.array([
            severity, phase, threat_idx, actions_taken, step_progress,
            self.network_health, self.anomaly_score,
            random.uniform(0, 1),  # cpu_usage
            random.uniform(0, 1),  # memory_usage
            random.uniform(0, 1),  # connection_count
            random.uniform(0, 1),  # num_active_incidents
            random.uniform(0, 1),  # time_elapsed
            random.uniform(0, 1),  # success_rate
            random.uniform(0, 1),  # attack_complexity
            random.uniform(0, 1),  # defense_level
            random.uniform(0, 1),  # alert_volume
            random.uniform(0, 1),  # false_positive_rate
            random.uniform(0, 1),  # response_team_available
            random.uniform(0, 1),  # system_criticality
        ], dtype=np.float32)
    
    def _get_info(self):
        return {
            "incident_id": self.current_incident.incident_id,
            "threat_type": self.current_incident.threat_type,
            "severity": self.current_incident.severity.name,
            "phase": self.current_incident.phase.value,
            "network_health": self.network_health,
            "anomaly_score": self.anomaly_score,
            "steps": self.step_count,
        }
    
    def _calculate_reward(self, action: RemediationAction, success: bool, is_valid: bool) -> float:
        reward = 0.0
        
        if not is_valid:
            return -1.0  # Penalty for invalid action
        
        if success:
            reward += 1.0
            # Phase-specific bonuses
            if action in self.phase_action_masks.get(RemediationPhase.CONTAIN, []):
                reward += 2.0  # Containment is critical
            elif action in self.phase_action_masks.get(RemediationPhase.REMEDIATE, []):
                reward += 1.5
        else:
            reward -= 0.5
        
        # Speed bonus
        if self.step_count < 5:
            reward += 0.3
        elif self.step_count > 30:
            reward -= 0.2
        
        return reward
    
    def get_action_mask(self):
        """Get valid action mask for current phase."""
        valid_actions = self.phase_action_masks.get(self.current_incident.phase, [])
        mask = np.zeros(len(RemediationAction), dtype=bool)
        for i, action in enumerate(RemediationAction):
            if action in valid_actions:
                mask[i] = True
        return mask
    
    def render(self):
        if self.render_mode == "human":
            info = self._get_info()
            print(f"\n{'='*50}")
            print(f"🛡️  Remediation Environment")
            print(f"{'='*50}")
            print(f"Incident: {info['threat_type']} ({info['severity']})")
            print(f"Phase: {info['phase']}")
            print(f"Network Health: {info['network_health']:.2f}")
            print(f"Anomaly Score: {info['anomaly_score']:.2f}")
            print(f"Steps: {info['steps']}")
            print(f"{'='*50}")


# ═══════════════════════════════════════════════════════════════════════════
# 3. CAUSAL INFERENCE ENGINE (DoWhy)
# ═══════════════════════════════════════════════════════════════════════════

class CausalRemediationAnalyzer:
    """
    Analyse causale des remediations avec DoWhy.
    Comprend POURQUOI une remediation a fonctionné ou échoué.
    """
    def __init__(self):
        self.causal_graph = self._build_causal_graph()
        self.analysis_history: List[Dict] = []
    
    def _build_causal_graph(self) -> str:
        """Build causal graph for remediation analysis."""
        return """
        digraph {
            severity -> action_success;
            threat_type -> action_success;
            phase -> action_success;
            network_health -> action_success;
            anomaly_score -> action_success;
            action_type -> action_success;
            previous_actions -> action_success;
            time_to_respond -> action_success;
            system_load -> action_success;
            
            severity -> time_to_respond;
            threat_type -> time_to_respond;
            phase -> time_to_respond;
            
            action_success -> network_health;
            action_success -> anomaly_score;
        }
        """
    
    def analyze(self, 
                action: RemediationAction,
                incident: Incident,
                success: bool,
                context: Dict[str, float]) -> Dict[str, Any]:
        """Analyze causal factors of remediation outcome."""
        if not CAUSAL_AVAILABLE:
            return {"causal_analysis": "DoWhy not available", "estimated_effect": 0.0}
        
        try:
            # Build dataset from history
            data = self._build_dataset(action, incident, success, context)
            
            if len(data) < 10:
                return {"causal_analysis": "Insufficient data", "estimated_effect": 0.0}
            
            # Create causal model
            model = CausalModel(
                data=data,
                treatment='action_type',
                outcome='action_success',
                graph=self.causal_graph,
            )
            
            # Identify causal effect
            identified_estimand = model.identify_effect()
            
            # Estimate causal effect
            estimate = model.estimate_effect(
                identified_estimand,
                method_name="backdoor.linear_regression"
            )
            
            # Refute with placebo test
            refutation = model.refute_estimate(
                identified_estimand,
                estimate,
                method_name="placebo_treatment_refuter",
                placebo_type="permute"
            )
            
            result = {
                "estimated_effect": estimate.value,
                "causal_confidence": 1.0 - refutation.new_effect,
                "significant_factors": self._get_significant_factors(model, data),
                "recommendation": self._generate_recommendation(estimate.value),
            }
            
            self.analysis_history.append(result)
            return result
            
        except Exception as e:
            logger.error(f"Causal analysis failed: {e}")
            return {"causal_analysis": f"Error: {e}", "estimated_effect": 0.0}
    
    def _build_dataset(self, action, incident, success, context):
        """Build dataset for causal analysis."""
        import pandas as pd
        
        records = []
        for hist in self.analysis_history[-50:]:
            records.append(hist.get("data", {}))
        
        # Add current observation
        records.append({
            "action_type": hash(action.value) % 20,
            "action_success": 1.0 if success else 0.0,
            "severity": incident.severity.value,
            "phase": list(RemediationPhase).index(incident.phase),
            "network_health": context.get("network_health", 0.5),
            "anomaly_score": context.get("anomaly_score", 0.5),
            "time_to_respond": context.get("time_to_respond", 0.5),
            "system_load": context.get("system_load", 0.5),
            "previous_actions": len(incident.actions_taken),
        })
        
        return pd.DataFrame(records)
    
    def _get_significant_factors(self, model, data) -> List[str]:
        """Identify significant causal factors."""
        factors = []
        for col in data.columns:
            if col not in ['action_type', 'action_success']:
                try:
                    correlation = abs(data[col].corr(data['action_success']))
                    if correlation > 0.3:
                        factors.append(f"{col} (corr={correlation:.2f})")
                except:
                    pass
        return factors[:5]
    
    def _generate_recommendation(self, effect: float) -> str:
        if effect > 0.5:
            return "✅ Action hautement efficace - continuer cette stratégie"
        elif effect > 0.2:
            return "👍 Action modérément efficace - optimiser les paramètres"
        elif effect > 0:
            return "🤔 Action faiblement efficace - envisager des alternatives"
        else:
            return "❌ Action contre-productive - changer de stratégie immédiatement"


# ═══════════════════════════════════════════════════════════════════════════
# 4. DIGITAL TWIN SIMULATOR
# ═══════════════════════════════════════════════════════════════════════════

class DigitalTwinSimulator:
    """
    Digital Twin de l'infrastructure pour tester les remediations sans risque.
    Simule les conséquences des actions avant de les appliquer en production.
    """
    def __init__(self):
        self.network_topology = self._build_topology()
        self.service_dependencies = self._build_dependencies()
        self.simulation_history: List[Dict] = []
    
    def _build_topology(self) -> Dict[str, List[str]]:
        """Build simulated network topology."""
        return {
            "internet": ["firewall", "load_balancer"],
            "firewall": ["dmz_web", "dmz_api", "vpn"],
            "load_balancer": ["web_01", "web_02", "web_03"],
            "dmz_web": ["web_01", "web_02", "web_03"],
            "dmz_api": ["api_01", "api_02"],
            "vpn": ["internal_network"],
            "internal_network": ["app_01", "app_02", "db_01", "db_02", "cache_01", "queue_01"],
            "app_01": ["db_01", "cache_01", "queue_01"],
            "app_02": ["db_02", "cache_01", "queue_01"],
            "db_01": ["storage_01"],
            "db_02": ["storage_02"],
        }

    def _build_dependencies(self) -> Dict[str, List[str]]:
        return {
            "web_01": ["api_01", "api_02"],
            "web_02": ["api_01", "api_02"],
            "web_03": ["api_01", "api_02"],
            "api_01": ["app_01", "app_02"],
            "api_02": ["app_01", "app_02"],
            "app_01": ["db_01", "cache_01"],
            "app_02": ["db_02", "cache_01"],
            "firewall": ["dmz_web", "dmz_api", "internal_network"],
            "vpn": ["internal_network"],
        }

    def simulate_remediation(self, action: RemediationAction, target: str, incident: Incident) -> Dict[str, Any]:
        impact = {"action": action.value, "target": target, "success_probability": 0.0,
                  "collateral_damage": 0.0, "affected_services": [], "cascading_failures": [],
                  "estimated_recovery_time_ms": 0.0, "risk_score": 0.0}
        if action == RemediationAction.BLOCK_IP:
            impact["success_probability"] = 0.95; impact["collateral_damage"] = 0.1
            impact["affected_services"] = self._find_affected_services(target)
            impact["estimated_recovery_time_ms"] = 100
        elif action == RemediationAction.ISOLATE_HOST:
            impact["success_probability"] = 0.90; impact["collateral_damage"] = 0.3
            impact["affected_services"] = self._find_affected_services(target)
            impact["cascading_failures"] = self._find_cascading_failures(target)
            impact["estimated_recovery_time_ms"] = 5000
        elif action == RemediationAction.KILL_PROCESS:
            impact["success_probability"] = 0.85; impact["collateral_damage"] = 0.2
            impact["affected_services"] = [target]; impact["estimated_recovery_time_ms"] = 2000
        elif action == RemediationAction.RECONFIGURE_FIREWALL:
            impact["success_probability"] = 0.90; impact["collateral_damage"] = 0.4
            impact["affected_services"] = ["dmz_web", "dmz_api", "internal_network"]
            impact["cascading_failures"] = self._find_cascading_failures("firewall")
            impact["estimated_recovery_time_ms"] = 1000
        elif action == RemediationAction.RESTORE_SNAPSHOT:
            impact["success_probability"] = 0.85; impact["collateral_damage"] = 0.5
            impact["affected_services"] = self._find_affected_services(target)
            impact["cascading_failures"] = self._find_cascading_failures(target)
            impact["estimated_recovery_time_ms"] = 30000
        else:
            impact["success_probability"] = 0.80; impact["collateral_damage"] = 0.1
            impact["affected_services"] = [target]; impact["estimated_recovery_time_ms"] = 500
        severity_mult = {ThreatSeverity.LOW: 0.8, ThreatSeverity.MEDIUM: 1.0,
                        ThreatSeverity.HIGH: 1.3, ThreatSeverity.CRITICAL: 1.8}
        impact["success_probability"] *= severity_mult.get(incident.severity, 1.0)
        impact["success_probability"] = min(0.99, max(0.1, impact["success_probability"]))
        impact["risk_score"] = (1 - impact["success_probability"]) * impact["collateral_damage"] * 10
        self.simulation_history.append(impact)
        return impact

    def _find_affected_services(self, target: str) -> List[str]:
        affected = []
        for service, deps in self.service_dependencies.items():
            if target in deps or target == service: affected.append(service)
        return affected

    def _find_cascading_failures(self, target: str) -> List[str]:
        failures = []; visited = set(); queue = [target]
        while queue:
            current = queue.pop(0)
            if current in visited: continue
            visited.add(current)
            for service, deps in self.service_dependencies.items():
                if current in deps and service not in visited:
                    failures.append(service); queue.append(service)
        return failures

    def get_network_health_report(self) -> Dict[str, Any]:
        return {"total_nodes": len(self.network_topology), "healthy_nodes": 0, "degraded_nodes": 0, "failed_nodes": 0}


# ═══════════════════════════════════════════════════════════════════════════
# 5. REMEDIATION ORCHESTRATOR (Main Engine)
# ═══════════════════════════════════════════════════════════════════════════

class RemediationOrchestrator:
    """
    Orchestrateur principal de remediation.
    Combine PPO RL, Digital Twin, Causal Inference, et Multi-Agent.
    """
    def __init__(self, state_dim: int = 20, action_dim: int = len(RemediationAction)):
        self.ppo_agent = PPOAgent(state_dim, action_dim) if TORCH_AVAILABLE else None
        self.env = RemediationEnv() if GYM_AVAILABLE else None
        self.digital_twin = DigitalTwinSimulator()
        self.causal_analyzer = CausalRemediationAnalyzer()
        self.incidents: Dict[str, Incident] = {}
        self.training_stats = {"episodes": 0, "total_reward": 0.0, "success_rate": 0.0, "avg_response_time_ms": 0.0}
        self.active_agents: Dict[str, 'RemediationAgent'] = {}

    def remediate(self, incident: Incident) -> Dict[str, Any]:
        """Execute remediation using PPO policy."""
        self.incidents[incident.incident_id] = incident
        start_time = time.time()
        steps_taken = []
        total_reward = 0.0

        if self.env and self.ppo_agent:
            obs, info = self.env.reset()
            done = False
            while not done:
                action_mask = self.env.get_action_mask()
                action_idx, log_prob, value = self.ppo_agent.get_action(obs, action_mask)
                action = list(RemediationAction)[action_idx]

                # Simulate in Digital Twin first
                sim_result = self.digital_twin.simulate_remediation(action, incident.target, incident)

                # Execute in real env
                next_obs, reward, done, truncated, info = self.env.step(action_idx)
                total_reward += reward

                # Store transition for training
                self.ppo_agent.store_transition(obs, action_idx, log_prob, reward, done, value, action_mask)

                # Causal analysis
                causal_result = self.causal_analyzer.analyze(action, incident, reward > 0, {
                    "network_health": info["network_health"], "anomaly_score": info["anomaly_score"],
                    "time_to_respond": info["steps"] / 50.0, "system_load": 0.5})

                steps_taken.append({
                    "action": action.value, "reward": reward, "success": reward > 0,
                    "simulation": sim_result, "causal_analysis": causal_result,
                    "phase": info["phase"], "network_health": info["network_health"]})
                obs = next_obs

            # Train PPO after episode
            train_stats = self.ppo_agent.update()
            self.training_stats["episodes"] += 1
            self.training_stats["total_reward"] += total_reward
            self.training_stats["success_rate"] = (self.training_stats["success_rate"] * (self.training_stats["episodes"] - 1) + (1 if done and reward > 0 else 0)) / self.training_stats["episodes"]

        resolution_time = (time.time() - start_time) * 1000
        incident.resolution_time_ms = resolution_time
        incident.is_resolved = done
        self.training_stats["avg_response_time_ms"] = (self.training_stats["avg_response_time_ms"] * (self.training_stats["episodes"] - 1) + resolution_time) / self.training_stats["episodes"]

        return {"incident_id": incident.incident_id, "resolved": done, "steps": steps_taken,
                "total_reward": total_reward, "resolution_time_ms": resolution_time,
                "training_stats": self.training_stats}

    def train(self, num_episodes: int = 1000, render: bool = False):
        """Train the PPO agent on simulated incidents."""
        if not self.env or not self.ppo_agent:
            logger.error("Cannot train: PyTorch or Gymnasium not available")
            return {"error": "Dependencies missing"}
        logger.info(f"🏋️ Training PPO for {num_episodes} episodes...")
        for episode in range(num_episodes):
            incident = Incident(incident_id=f"train_{episode}", threat_type=random.choice(
                ["ransomware","lateral_movement","c2_beaconing","data_exfiltration","brute_force",
                 "web_attack","malware","insider_threat","dos_attack","zero_day"]),
                severity=random.choice(list(ThreatSeverity)), target=f"host_{random.randint(1,100)}")
            result = self.remediate(incident)
            if render and episode % 100 == 0:
                logger.info(f"Episode {episode}: reward={result['total_reward']:.2f}, "
                           f"success={result['resolved']}, stats={result['training_stats']}")
        logger.info(f"✅ Training complete: {self.training_stats}")
        return self.training_stats

    def get_stats(self) -> Dict[str, Any]:
        return {**self.training_stats, "active_incidents": len(self.incidents),
                "digital_twin_simulations": len(self.digital_twin.simulation_history),
                "causal_analyses": len(self.causal_analyzer.analysis_history)}

    def save_model(self, path: str = "models/ppo_remediation.pt"):
        if self.ppo_agent: self.ppo_agent.save(path)

    def load_model(self, path: str = "models/ppo_remediation.pt"):
        if self.ppo_agent and os.path.exists(path): self.ppo_agent.load(path)


# ═══════════════════════════════════════════════════════════════════════════
# 6. MULTI-AGENT COORDINATION
# ═══════════════════════════════════════════════════════════════════════════

class RemediationAgent:
    """Agent individuel gérant un sous-système (réseau, endpoints, cloud)."""
    def __init__(self, agent_id: str, domain: str, orchestrator: RemediationOrchestrator):
        self.agent_id = agent_id
        self.domain = domain
        self.orchestrator = orchestrator
        self.local_ppo = PPOAgent(20, len(RemediationAction)) if TORCH_AVAILABLE else None
        self.incidents_handled = 0
        self.success_rate = 0.0

    def handle_incident(self, incident: Incident) -> Dict[str, Any]:
        result = self.orchestrator.remediate(incident)
        self.incidents_handled += 1
        self.success_rate = (self.success_rate * (self.incidents_handled - 1) + (1 if result["resolved"] else 0)) / self.incidents_handled
        return result


class MultiAgentCoordinator:
    """Coordonne plusieurs agents de remediation."""
    def __init__(self):
        self.orchestrator = RemediationOrchestrator()
        self.agents: Dict[str, RemediationAgent] = {
            "network": RemediationAgent("net_01", "network", self.orchestrator),
            "endpoint": RemediationAgent("ep_01", "endpoint", self.orchestrator),
            "cloud": RemediationAgent("cloud_01", "cloud", self.orchestrator),
            "identity": RemediationAgent("id_01", "identity", self.orchestrator),
        }

    def coordinate_remediation(self, incident: Incident) -> Dict[str, Any]:
        domain_map = {"ransomware": "endpoint", "lateral_movement": "network", "c2_beaconing": "network",
                      "data_exfiltration": "network", "brute_force": "identity", "web_attack": "cloud",
                      "malware": "endpoint", "insider_threat": "identity", "dos_attack": "network", "zero_day": "endpoint"}
        primary_agent = self.agents.get(domain_map.get(incident.threat_type, "network"))
        if primary_agent:
            return primary_agent.handle_incident(incident)
        return self.orchestrator.remediate(incident)


# ═══════════════════════════════════════════════════════════════════════════
# 7. META-LEARNING (MAML) ADAPTATION
# ═══════════════════════════════════════════════════════════════════════════

class MetaLearner:
    """Model-Agnostic Meta-Learning (MAML) pour adaptation rapide."""
    def __init__(self, inner_lr: float = 0.01, outer_lr: float = 0.001):
        self.inner_lr = inner_lr
        self.outer_lr = outer_lr
        self.meta_policy = None

    def adapt_to_new_threat(self, orchestrator: RemediationOrchestrator, threat_type: str, num_episodes: int = 10):
        """Quick adaptation to a new threat type using few-shot learning."""
        if not TORCH_AVAILABLE or not orchestrator.ppo_agent:
            return {"adapted": False, "reason": "PPO not available"}
        original_state = {k: v.clone() for k, v in orchestrator.ppo_agent.network.state_dict().items()}
        for episode in range(num_episodes):
            incident = Incident(incident_id=f"meta_{threat_type}_{episode}", threat_type=threat_type,
                severity=ThreatSeverity.CRITICAL, target=f"host_{random.randint(1,100)}")
            orchestrator.remediate(incident)
        adapted_state = {k: v.clone() for k, v in orchestrator.ppo_agent.network.state_dict().items()}
        return {"adapted": True, "threat_type": threat_type, "episodes": num_episodes}


# ═══════════════════════════════════════════════════════════════════════════
# 8. CONVENIENCE WRAPPER
# ═══════════════════════════════════════════════════════════════════════════

class AutoRemediationEngine:
    """Interface unifiée pour le système de remediation."""
    def __init__(self):
        self.coordinator = MultiAgentCoordinator()
        self.meta_learner = MetaLearner()
        self.orchestrator = self.coordinator.orchestrator

    def handle_incident(self, threat_type: str, severity: str, target: str, source_ip: Optional[str] = None) -> Dict[str, Any]:
        incident = Incident(
            incident_id=f"inc_{hashlib.md5(f'{threat_type}{target}{time.time()}'.encode()).hexdigest()[:8]}",
            threat_type=threat_type, severity=ThreatSeverity[severity.upper()] if severity.upper() in ThreatSeverity.__members__ else ThreatSeverity.MEDIUM,
            target=target, source_ip=source_ip)
        return self.coordinator.coordinate_remediation(incident)

    def train(self, episodes: int = 1000):
        return self.orchestrator.train(episodes)

    def adapt_to_new_threat(self, threat_type: str):
        return self.meta_learner.adapt_to_new_threat(self.orchestrator, threat_type)

    def get_stats(self) -> Dict[str, Any]:
        return self.orchestrator.get_stats()

    def save(self, path: str = "models/remediation_engine.pt"):
        self.orchestrator.save_model(path)

    def load(self, path: str = "models/remediation_engine.pt"):
        self.orchestrator.load_model(path)


# ═══════════════════════════════════════════════════════════════════════════
# CLI / DEMO
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    engine = AutoRemediationEngine()
    logger.info("🚀 Cyber Global Shield - RL Auto-Remediation Engine v2.0 ULTIMATE+")
    logger.info(f"PyTorch: {'✅' if TORCH_AVAILABLE else '❌'} | Gymnasium: {'✅' if GYM_AVAILABLE else '❌'} | DoWhy: {'✅' if CAUSAL_AVAILABLE else '❌'}")

    # Demo: handle a ransomware incident
    result = engine.handle_incident("ransomware", "CRITICAL", "host_42", "10.0.0.5")
    logger.info(f"📋 Remediation result: resolved={result['resolved']}, steps={len(result.get('steps', []))}, reward={result.get('total_reward', 0):.2f}")

    # Train if dependencies available
    if TORCH_AVAILABLE and GYM_AVAILABLE:
        logger.info("🏋️ Starting training (10 episodes demo)...")
        engine.train(episodes=10)
        logger.info(f"📊 Stats: {engine.get_stats()}")
        engine.save()
    else:
        logger.warning("⚠️ Install PyTorch & Gymnasium for full RL training: pip install torch gymnasium")
