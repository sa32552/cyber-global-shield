"""
Cyber Global Shield — World Models (DreamerV3)
==============================================
DreamerV3-style world model for simulating attack scenarios,
optimizing defense strategies through latent imagination,
and performing what-if analysis on security incidents.

Based on: "Mastering Diverse Domains through World Models" (Hafner et al., 2023)
arXiv:2301.04104v2

Components:
  - RSSM (Recurrent State Space Model): Deterministic + stochastic state transitions
  - DreamerV3Agent: Latent imagination for defense policy optimization
  - AttackSimulator: Full environment simulator using learned world model
  - DefenseOptimizer: Policy optimization via imagined trajectories
  - WhatIfAnalyzer: Counterfactual reasoning about security scenarios

References:
  - DreamerV3: https://arxiv.org/abs/2301.04104
  - PlaNet: https://arxiv.org/abs/1811.04551
  - Dreamer: https://arxiv.org/abs/1912.01603
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
    from torch.distributions import Normal, Independent, kl_divergence, OneHotCategoricalStraightThrough
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    # Placeholder
    class nn:
        class Module: pass
    class torch:
        class Tensor: pass
        class nn: pass
        class optim: pass


# ─── Constants ────────────────────────────────────────────────────────────────

DETERMINISTIC_DIM = 512  # Deterministic state dimension (h_t)
STOCHASTIC_DIM = 64     # Stochastic state dimension (z_t)
HIDDEN_DIM = 256        # Hidden dimension for MLPs
EMBED_DIM = 128         # Observation embedding dimension
ACTION_DIM = 16         # Action dimension
HORIZON = 15            # Imagination horizon for policy optimization
DISCOUNT = 0.997        # Discount factor (λ)
LAMBDA = 0.95           # GAE λ parameter
FREE_NATS = 3.0         # Free nats for KL balancing
LEARNING_RATE = 3e-4    # Adam learning rate
GRAD_CLIP = 100.0       # Gradient clipping norm


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class WorldModelState:
    """State of the world model (deterministic + stochastic)."""
    deterministic: Optional[np.ndarray] = None   # h_t
    stochastic: Optional[np.ndarray] = None      # z_t
    logits: Optional[np.ndarray] = None          # Prior logits for z_t
    reward: Optional[float] = None
    terminal: bool = False


@dataclass
class ImaginationTrajectory:
    """A trajectory imagined in latent space."""
    states: List[WorldModelState] = field(default_factory=list)
    actions: List[np.ndarray] = field(default_factory=list)
    rewards: List[float] = field(default_factory=list)
    values: List[float] = field(default_factory=list)
    discounts: List[float] = field(default_factory=list)
    log_probs: List[float] = field(default_factory=list)

    @property
    def return_(self) -> float:
        """Compute discounted return."""
        ret = 0.0
        discount = 1.0
        for r, d in zip(self.rewards, self.discounts):
            ret += discount * r
            discount *= d
        return ret

    @property
    def length(self) -> int:
        return len(self.states)


@dataclass
class SimulationResult:
    """Result of a full attack simulation."""
    attack_type: str
    severity: str
    initial_state: WorldModelState
    trajectory: ImaginationTrajectory
    predicted_outcome: Dict[str, Any]
    defense_recommendations: List[Dict[str, Any]]
    confidence: float
    counterfactuals: Optional[Dict[str, ImaginationTrajectory]] = None


# ─── RSSM: Recurrent State Space Model ────────────────────────────────────────

class RSSMCell(nn.Module):
    """
    Recurrent State Space Model cell.
    
    Transition: h_t = f(h_{t-1}, z_{t-1}, a_{t-1})
                z_t ~ p(z_t | h_t)
    Observation: o_t ~ p(o_t | h_t, z_t)
    Reward: r_t ~ p(r_t | h_t, z_t)
    Discount: γ_t ~ p(γ_t | h_t, z_t)
    """

    def __init__(
        self,
        deter_dim: int = DETERMINISTIC_DIM,
        stoch_dim: int = STOCHASTIC_DIM,
        action_dim: int = ACTION_DIM,
        hidden_dim: int = HIDDEN_DIM,
        embed_dim: int = EMBED_DIM,
        num_discrete: int = 32,
        use_discrete: bool = True,
    ):
        super().__init__()
        self.deter_dim = deter_dim
        self.stoch_dim = stoch_dim
        self.action_dim = action_dim
        self.hidden_dim = hidden_dim
        self.embed_dim = embed_dim
        self.num_discrete = num_discrete
        self.use_discrete = use_discrete
        self.stoch_output_dim = stoch_dim * num_discrete if use_discrete else stoch_dim

        # GRU-style recurrent cell for deterministic state
        self.rnn_input = nn.Linear(self.stoch_output_dim + action_dim, hidden_dim)
        self.rnn_cell = nn.GRUCell(hidden_dim, deter_dim)

        # Prior network: p(z_t | h_t)
        if use_discrete:
            self.prior = nn.Sequential(
                nn.Linear(deter_dim, hidden_dim),
                nn.ELU(),
                nn.Linear(hidden_dim, num_discrete * stoch_dim),
            )
        else:
            self.prior = nn.Sequential(
                nn.Linear(deter_dim, hidden_dim),
                nn.ELU(),
                nn.Linear(hidden_dim, stoch_dim * 2),
            )

        # Posterior network: q(z_t | h_t, o_t)
        if use_discrete:
            self.posterior = nn.Sequential(
                nn.Linear(deter_dim + embed_dim, hidden_dim),
                nn.ELU(),
                nn.Linear(hidden_dim, num_discrete * stoch_dim),
            )
        else:
            self.posterior = nn.Sequential(
                nn.Linear(deter_dim + embed_dim, hidden_dim),
                nn.ELU(),
                nn.Linear(hidden_dim, stoch_dim * 2),
            )

        # Reward predictor: p(r_t | h_t, z_t)
        self.reward_head = nn.Sequential(
            nn.Linear(deter_dim + self.stoch_output_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, 1),
        )

        # Discount predictor: p(γ_t | h_t, z_t)
        self.discount_head = nn.Sequential(
            nn.Linear(deter_dim + self.stoch_output_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid(),
        )

    def _dist_from_logits(self, logits: torch.Tensor) -> torch.distributions.Distribution:
        """Convert logits to distribution (discrete or continuous)."""
        if self.use_discrete:
            batch_size = logits.shape[0]
            logits_reshaped = logits.view(batch_size, self.stoch_dim, self.num_discrete)
            return OneHotCategoricalStraightThrough(logits=logits_reshaped)
        else:
            mean = logits[..., :self.stoch_dim]
            std = F.softplus(logits[..., self.stoch_dim:]) + 0.1
            return Normal(mean, std)

    def _sample_from_dist(self, dist: torch.distributions.Distribution) -> torch.Tensor:
        """Sample from distribution with straight-through gradients if discrete."""
        if self.use_discrete:
            sample = dist.rsample()
            return sample.flatten(1)
        else:
            return dist.rsample()

    def prior_step(
        self,
        prev_deter: torch.Tensor,
        prev_stoch: torch.Tensor,
        prev_action: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Prior step: predict next state without observation.
        
        Returns:
            (next_deter, next_stoch, prior_logits)
        """
        rnn_in = torch.cat([prev_stoch, prev_action], dim=-1)
        rnn_in = self.rnn_input(rnn_in)
        next_deter = self.rnn_cell(rnn_in, prev_deter)

        prior_logits = self.prior(next_deter)
        prior_dist = self._dist_from_logits(prior_logits)
        next_stoch = self._sample_from_dist(prior_dist)

        return next_deter, next_stoch, prior_logits

    def posterior_step(
        self,
        prev_deter: torch.Tensor,
        prev_stoch: torch.Tensor,
        prev_action: torch.Tensor,
        obs_embed: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Posterior step: predict next state given observation.
        
        Returns:
            (next_deter, next_stoch, prior_logits, posterior_logits)
        """
        rnn_in = torch.cat([prev_stoch, prev_action], dim=-1)
        rnn_in = self.rnn_input(rnn_in)
        next_deter = self.rnn_cell(rnn_in, prev_deter)

        prior_logits = self.prior(next_deter)

        post_in = torch.cat([next_deter, obs_embed], dim=-1)
        posterior_logits = self.posterior(post_in)
        posterior_dist = self._dist_from_logits(posterior_logits)
        next_stoch = self._sample_from_dist(posterior_dist)

        return next_deter, next_stoch, prior_logits, posterior_logits

    def predict_reward(self, deter: torch.Tensor, stoch: torch.Tensor) -> torch.Tensor:
        """Predict reward from state."""
        x = torch.cat([deter, stoch], dim=-1)
        return self.reward_head(x).squeeze(-1)

    def predict_discount(self, deter: torch.Tensor, stoch: torch.Tensor) -> torch.Tensor:
        """Predict discount factor from state."""
        x = torch.cat([deter, stoch], dim=-1)
        return self.discount_head(x).squeeze(-1)

    def kl_loss(
        self,
        prior_logits: torch.Tensor,
        posterior_logits: torch.Tensor,
        free_nats: float = FREE_NATS,
    ) -> torch.Tensor:
        """Compute KL divergence between prior and posterior with free nats."""
        prior_dist = self._dist_from_logits(prior_logits)
        posterior_dist = self._dist_from_logits(posterior_logits)

        if self.use_discrete:
            kl = kl_divergence(posterior_dist, prior_dist).sum(-1).mean()
        else:
            kl = kl_divergence(posterior_dist, prior_dist).mean()

        kl = torch.max(kl, kl.new_tensor(free_nats))
        return kl


class ObservationEncoder(nn.Module):
    """Encode observations (security metrics/logs) into embeddings."""

    def __init__(self, input_dim: int, embed_dim: int = EMBED_DIM, hidden_dim: int = HIDDEN_DIM):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, embed_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class ObservationDecoder(nn.Module):
    """Decode latent states back to observation space."""

    def __init__(self, deter_dim: int, stoch_output_dim: int, output_dim: int, hidden_dim: int = HIDDEN_DIM):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(deter_dim + stoch_output_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, output_dim),
        )

    def forward(self, deter: torch.Tensor, stoch: torch.Tensor) -> torch.Tensor:
        x = torch.cat([deter, stoch], dim=-1)
        return self.net(x)


# ─── World Model ──────────────────────────────────────────────────────────────

class WorldModel(nn.Module):
    """
    Full DreamerV3-style world model.
    
    Components:
      - RSSM cell for state transitions
      - Observation encoder/decoder
      - Reward predictor
      - Discount predictor
    """

    def __init__(
        self,
        obs_dim: int,
        action_dim: int = ACTION_DIM,
        deter_dim: int = DETERMINISTIC_DIM,
        stoch_dim: int = STOCHASTIC_DIM,
        embed_dim: int = EMBED_DIM,
        hidden_dim: int = HIDDEN_DIM,
        num_discrete: int = 32,
        use_discrete: bool = True,
    ):
        super().__init__()
        self.obs_dim = obs_dim
        self.action_dim = action_dim
        self.deter_dim = deter_dim
        self.stoch_dim = stoch_dim
        self.stoch_output_dim = stoch_dim * num_discrete if use_discrete else stoch_dim

        self.encoder = ObservationEncoder(obs_dim, embed_dim, hidden_dim)
        self.decoder = ObservationDecoder(deter_dim, self.stoch_output_dim, obs_dim, hidden_dim)
        self.rssm = RSSMCell(
            deter_dim=deter_dim,
            stoch_dim=stoch_dim,
            action_dim=action_dim,
            hidden_dim=hidden_dim,
            embed_dim=embed_dim,
            num_discrete=num_discrete,
            use_discrete=use_discrete,
        )

    def forward(
        self,
        observations: torch.Tensor,
        actions: torch.Tensor,
        nonterminals: torch.Tensor,
    ) -> Dict[str, torch.Tensor]:
        """
        Forward pass through the world model.
        
        Args:
            observations: [T+1, batch, obs_dim]
            actions: [T, batch, action_dim]
            nonterminals: [T, batch]
        
        Returns:
            dict with losses
        """
        T = actions.shape[0]
        batch_size = observations.shape[1]
        device = observations.device

        embeds = self.encoder(observations)

        deter = torch.zeros(batch_size, self.deter_dim, device=device)
        stoch = torch.zeros(batch_size, self.stoch_output_dim, device=device)

        prior_logits_list = []
        posterior_logits_list = []
        reward_preds = []
        discount_preds = []
        obs_preds = []

        for t in range(T):
            deter, stoch, prior_logits, posterior_logits = self.rssm.posterior_step(
                deter, stoch, actions[t], embeds[t + 1]
            )

            mask = nonterminals[t].unsqueeze(-1)
            deter = deter * mask
            stoch = stoch * mask

            prior_logits_list.append(prior_logits)
            posterior_logits_list.append(posterior_logits)
            reward_preds.append(self.rssm.predict_reward(deter, stoch))
            discount_preds.append(self.rssm.predict_discount(deter, stoch))
            obs_preds.append(self.decoder(deter, stoch))

        prior_logits = torch.stack(prior_logits_list, dim=0)
        posterior_logits = torch.stack(posterior_logits_list, dim=0)
        reward_preds = torch.stack(reward_preds, dim=0)
        discount_preds = torch.stack(discount_preds, dim=0)
        obs_preds = torch.stack(obs_preds, dim=0)

        reward_targets = observations[1:, :, 0]
        discount_targets = nonterminals
        obs_targets = observations[1:]

        obs_loss = F.mse_loss(obs_preds, obs_targets)
        reward_loss = F.mse_loss(reward_preds, reward_targets)
        discount_loss = F.binary_cross_entropy(discount_preds, discount_targets)

        kl_loss = 0.0
        for t in range(T):
            kl_loss += self.rssm.kl_loss(prior_logits[t], posterior_logits[t])
        kl_loss = kl_loss / T

        total_loss = obs_loss + reward_loss + discount_loss + kl_loss

        return {
            "loss": total_loss,
            "obs_loss": obs_loss,
            "reward_loss": reward_loss,
            "discount_loss": discount_loss,
            "kl_loss": kl_loss,
        }

    def imagine(
        self,
        init_deter: torch.Tensor,
        init_stoch: torch.Tensor,
        policy: Callable[[torch.Tensor, torch.Tensor], torch.Tensor],
        horizon: int = HORIZON,
    ) -> ImaginationTrajectory:
        """
        Imagine a trajectory in latent space using a policy.
        
        Args:
            init_deter: Initial deterministic state [1, deter_dim]
            init_stoch: Initial stochastic state [1, stoch_output_dim]
            policy: Function mapping (deter, stoch) -> action
            horizon: Number of steps to imagine
        
        Returns:
            ImaginationTrajectory
        """
        trajectory = ImaginationTrajectory()
        deter = init_deter
        stoch = init_stoch

        for _ in range(horizon):
            action = policy(deter, stoch)
            deter, stoch, prior_logits = self.rssm.prior_step(deter, stoch, action)
            reward = self.rssm.predict_reward(deter, stoch).item()
            discount = self.rssm.predict_discount(deter, stoch).item()

            state = WorldModelState(
                deterministic=deter.detach().cpu().numpy()[0],
                stochastic=stoch.detach().cpu().numpy()[0],
                logits=prior_logits.detach().cpu().numpy()[0],
                reward=reward,
            )
            trajectory.states.append(state)
            trajectory.actions.append(action.detach().cpu().numpy()[0])
            trajectory.rewards.append(reward)
            trajectory.discounts.append(discount)

        return trajectory


# ─── Actor-Critic for Latent Policy ──────────────────────────────────────────

class ActorNetwork(nn.Module):
    """Policy network that maps latent state to action distribution."""

    def __init__(
        self,
        deter_dim: int,
        stoch_dim: int,
        action_dim: int,
        hidden_dim: int = HIDDEN_DIM,
        use_discrete: bool = False,
    ):
        super().__init__()
        self.use_discrete = use_discrete
        self.net = nn.Sequential(
            nn.Linear(deter_dim + stoch_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ELU(),
        )
        if use_discrete:
            self.action_head = nn.Linear(hidden_dim, action_dim)
        else:
            self.action_mean = nn.Linear(hidden_dim, action_dim)
            self.action_std = nn.Parameter(torch.ones(action_dim) * 0.1)

    def forward(self, deter: torch.Tensor, stoch: torch.Tensor) -> torch.distributions.Distribution:
        x = torch.cat([deter, stoch], dim=-1)
        x = self.net(x)
        if self.use_discrete:
            logits = self.action_head(x)
            return torch.distributions.Categorical(logits=logits)
        else:
            mean = self.action_mean(x)
            std = F.softplus(self.action_std) + 0.01
            return Normal(mean, std)

    def get_action(self, deter: torch.Tensor, stoch: torch.Tensor, deterministic: bool = False) -> torch.Tensor:
        """Sample or select action."""
        dist = self.forward(deter, stoch)
        if deterministic:
            if self.use_discrete:
                return F.one_hot(dist.logits.argmax(-1), num_classes=dist.logits.shape[-1]).float()
            else:
                return dist.mean
        else:
            if self.use_discrete:
                return F.one_hot(dist.sample(), num_classes=dist.logits.shape[-1]).float()
            else:
                return dist.rsample()


class CriticNetwork(nn.Module):
    """Value network that estimates return from latent state."""

    def __init__(self, deter_dim: int, stoch_dim: int, hidden_dim: int = HIDDEN_DIM):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(deter_dim + stoch_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, 1),
        )

    def forward(self, deter: torch.Tensor, stoch: torch.Tensor) -> torch.Tensor:
        x = torch.cat([deter, stoch], dim=-1)
        return self.net(x).squeeze(-1)


# ─── DreamerV3 Agent ─────────────────────────────────────────────────────────

class DreamerV3Agent(nn.Module):
    """
    DreamerV3 agent for security defense optimization.
    
    Learns a world model from experience, then uses it to
    imagine trajectories and optimize a policy via actor-critic.
    """

    def __init__(
        self,
        obs_dim: int,
        action_dim: int = ACTION_DIM,
        deter_dim: int = DETERMINISTIC_DIM,
        stoch_dim: int = STOCHASTIC_DIM,
        hidden_dim: int = HIDDEN_DIM,
        horizon: int = HORIZON,
        lr: float = LEARNING_RATE,
        use_discrete_actions: bool = False,
    ):
        super().__init__()
        self.obs_dim = obs_dim
        self.action_dim = action_dim
        self.horizon = horizon
        self.use_discrete_actions = use_discrete_actions

        self.world_model = WorldModel(
            obs_dim=obs_dim,
            action_dim=action_dim,
            deter_dim=deter_dim,
            stoch_dim=stoch_dim,
            hidden_dim=hidden_dim,
        )

        stoch_output_dim = stoch_dim * self.world_model.rssm.num_discrete if self.world_model.rssm.use_discrete else stoch_dim
        self.actor = ActorNetwork(deter_dim, stoch_output_dim, action_dim, hidden_dim, use_discrete_actions)
        self.critic = CriticNetwork(deter_dim, stoch_output_dim, hidden_dim)

        self.wm_optimizer = torch.optim.Adam(self.world_model.parameters(), lr=lr)
        self.ac_optimizer = torch.optim.Adam(
            list(self.actor.parameters()) + list(self.critic.parameters()), lr=lr
        )

        self.training_step = 0
        self.device = torch.device("cpu")

    def to(self, device: torch.device) -> "DreamerV3Agent":
        self.device = device
        return super().to(device)

    def train_world_model(
        self,
        observations: torch.Tensor,
        actions: torch.Tensor,
        nonterminals: torch.Tensor,
    ) -> Dict[str, float]:
        """Train the world model on a batch of experience."""
        self.world_model.train()
        self.wm_optimizer.zero_grad()

        losses = self.world_model(observations, actions, nonterminals)
        losses["loss"].backward()
        torch.nn.utils.clip_grad_norm_(self.world_model.parameters(), GRAD_CLIP)
        self.wm_optimizer.step()

        self.training_step += 1
        return {k: v.item() for k, v in losses.items()}

    def train_actor_critic(
        self,
        init_deter: torch.Tensor,
        init_stoch: torch.Tensor,
    ) -> Dict[str, float]:
        """Train actor and critic using imagined trajectories."""
        self.actor.train()
        self.critic.train()
        self.world_model.eval()

        batch_size = init_deter.shape[0]
        deter = init_deter
        stoch = init_stoch

        actions_list = []
        log_probs_list = []
        rewards_list = []
        values_list = []
        discounts_list = []

        with torch.no_grad():
            for _ in range(self.horizon):
                action_dist = self.actor(deter, stoch)
                if self.use_discrete_actions:
                    action = F.one_hot(action_dist.sample(), num_classes=self.action_dim).float()
                    log_prob = action_dist.log_prob(action.argmax(-1))
                else:
                    action = action_dist.rsample()
                    log_prob = action_dist.log_prob(action).sum(-1)

                deter, stoch, _ = self.world_model.rssm.prior_step(deter, stoch, action)
                reward = self.world_model.rssm.predict_reward(deter, stoch)
                discount = self.world_model.rssm.predict_discount(deter, stoch)
                value = self.critic(deter, stoch)

                actions_list.append(action)
                log_probs_list.append(log_prob)
                rewards_list.append(reward)
                values_list.append(value)
                discounts_list.append(discount)

        rewards = torch.stack(rewards_list, dim=0)
        values = torch.stack(values_list, dim=0)
        discounts = torch.stack(discounts_list, dim=0)
        log_probs = torch.stack(log_probs_list, dim=0)

        returns = []
        gae = 0.0
        for t in reversed(range(self.horizon)):
            delta = rewards[t] + DISCOUNT * discounts[t] * (values[t + 1] if t < self.horizon - 1 else 0) - values[t]
            gae = delta + DISCOUNT * LAMBDA * discounts[t] * gae
            returns.append(gae + values[t])
        returns = torch.stack(list(reversed(returns)), dim=0)

        advantages = returns.detach() - values.detach()
        actor_loss = -(log_probs * advantages.detach()).mean()
        critic_loss = F.mse_loss(values, returns.detach())
        entropy = -torch.mean(log_probs)

        total_loss = actor_loss + 0.8 * critic_loss - 1e-3 * entropy

        self.ac_optimizer.zero_grad()
        total_loss.backward()
        torch.nn.utils.clip_grad_norm_(
            list(self.actor.parameters()) + list(self.critic.parameters()), GRAD_CLIP
        )
        self.ac_optimizer.step()

        return {
            "actor_loss": actor_loss.item(),
            "critic_loss": critic_loss.item(),
            "entropy": entropy.item(),
            "mean_return": returns.mean().item(),
        }

    def get_action(
        self,
        observation: np.ndarray,
        state: Optional[WorldModelState] = None,
        deterministic: bool = False,
    ) -> Tuple[np.ndarray, WorldModelState]:
        """Get action for a given observation."""
        self.eval()
        obs_t = torch.from_numpy(observation).float().to(self.device).unsqueeze(0)

        if state is None:
            deter = torch.zeros(1, self.world_model.deter_dim, device=self.device)
            stoch = torch.zeros(1, self.world_model.rssm.stoch_output_dim, device=self.device)
        else:
            deter = torch.from_numpy(state.deterministic).float().to(self.device).unsqueeze(0)
            stoch = torch.from_numpy(state.stochastic).float().to(self.device).unsqueeze(0)

        with torch.no_grad():
            embed = self.world_model.encoder(obs_t)
            deter, stoch, _, _ = self.world_model.rssm.posterior_step(
                deter, stoch, torch.zeros(1, self.action_dim, device=self.device), embed
            )
            action = self.actor.get_action(deter, stoch, deterministic=deterministic)

        new_state = WorldModelState(
            deterministic=deter.cpu().numpy()[0],
            stochastic=stoch.cpu().numpy()[0],
        )

        return action.cpu().numpy()[0], new_state

    def save(self, path: str):
        """Save model weights."""
        torch.save({
            "world_model": self.world_model.state_dict(),
            "actor": self.actor.state_dict(),
            "critic": self.critic.state_dict(),
            "training_step": self.training_step,
        }, path)

    def load(self, path: str):
        """Load model weights."""
        checkpoint = torch.load(path, map_location=self.device)
        self.world_model.load_state_dict(checkpoint["world_model"])
        self.actor.load_state_dict(checkpoint["actor"])
        self.critic.load_state_dict(checkpoint["critic"])
        self.training_step = checkpoint["training_step"]


# ─── Attack Simulator ─────────────────────────────────────────────────────────

class AttackSimulator:
    """
    Simulate attack scenarios using the learned world model.
    
    Given an initial security state, uses the world model to predict
    how different attack patterns evolve over time.
    """

    def __init__(self, agent: DreamerV3Agent):
        self.agent = agent
        self.device = agent.device

    def simulate_attack(
        self,
        initial_observation: np.ndarray,
        attack_actions: np.ndarray,
        state: Optional[WorldModelState] = None,
    ) -> SimulationResult:
        """Simulate a specific attack trajectory."""
        self.agent.eval()
        T = attack_actions.shape[0]

        obs_t = torch.from_numpy(initial_observation).float().to(self.device).unsqueeze(0)

        if state is None:
            deter = torch.zeros(1, self.agent.world_model.deter_dim, device=self.device)
            stoch = torch.zeros(1, self.agent.world_model.rssm.stoch_output_dim, device=self.device)
        else:
            deter = torch.from_numpy(state.deterministic).float().to(self.device).unsqueeze(0)
            stoch = torch.from_numpy(state.stochastic).float().to(self.device).unsqueeze(0)

        trajectory = ImaginationTrajectory()

        with torch.no_grad():
            embed = self.agent.world_model.encoder(obs_t)
            deter, stoch, _, _ = self.agent.world_model.rssm.posterior_step(
                deter, stoch, torch.zeros(1, self.agent.action_dim, device=self.device), embed
            )

            for t in range(T):
                action_t = torch.from_numpy(attack_actions[t]).float().to(self.device).unsqueeze(0)
                deter, stoch, prior_logits = self.agent.world_model.rssm.prior_step(deter, stoch, action_t)
                reward = self.agent.world_model.rssm.predict_reward(deter, stoch).item()
                discount = self.agent.world_model.rssm.predict_discount(deter, stoch).item()

                state_obj = WorldModelState(
                    deterministic=deter.cpu().numpy()[0],
                    stochastic=stoch.cpu().numpy()[0],
                    logits=prior_logits.cpu().numpy()[0],
                    reward=reward,
                )
                trajectory.states.append(state_obj)
                trajectory.actions.append(attack_actions[t])
                trajectory.rewards.append(reward)
                trajectory.discounts.append(discount)

        # Compute predicted outcome
        final_state = trajectory.states[-1] if trajectory.states else None
        predicted_outcome = {
            "total_reward": sum(trajectory.rewards),
            "avg_reward": np.mean(trajectory.rewards) if trajectory.rewards else 0.0,
            "final_reward": trajectory.rewards[-1] if trajectory.rewards else 0.0,
            "trajectory_length": len(trajectory.states),
            "discounted_return": trajectory.return_,
        }

        return SimulationResult(
            attack_type="simulated",
            severity="unknown",
            initial_state=state or WorldModelState(),
            trajectory=trajectory,
            predicted_outcome=predicted_outcome,
            defense_recommendations=[],
            confidence=0.0,
        )

    def compare_attack_strategies(
        self,
        initial_observation: np.ndarray,
        attack_strategies: Dict[str, np.ndarray],
    ) -> Dict[str, SimulationResult]:
        """Compare multiple attack strategies."""
        results = {}
        for name, actions in attack_strategies.items():
            results[name] = self.simulate_attack(initial_observation, actions)
        return results


# ─── Defense Optimizer ────────────────────────────────────────────────────────

class DefenseOptimizer:
    """
    Optimize defense policies using the learned world model.
    
    Uses the DreamerV3 agent's actor-critic to find optimal
    defense actions through latent imagination.
    """

    def __init__(self, agent: DreamerV3Agent):
        self.agent = agent

    def optimize_defense(
        self,
        initial_observation: np.ndarray,
        num_iterations: int = 100,
    ) -> Dict[str, Any]:
        """
        Optimize defense policy for a given initial state.
        
        Args:
            initial_observation: Initial security metrics
            num_iterations: Number of actor-critic training iterations
        
        Returns:
            dict with optimized policy stats
        """
        obs_t = torch.from_numpy(initial_observation).float().to(self.agent.device).unsqueeze(0)

        with torch.no_grad():
            embed = self.agent.world_model.encoder(obs_t)
            deter = torch.zeros(1, self.agent.world_model.deter_dim, device=self.agent.device)
            stoch = torch.zeros(1, self.agent.world_model.rssm.stoch_output_dim, device=self.agent.device)
            deter, stoch, _, _ = self.agent.world_model.rssm.posterior_step(
                deter, stoch, torch.zeros(1, self.agent.action_dim, device=self.agent.device), embed
            )

        stats = []
        for i in range(num_iterations):
            step_stats = self.agent.train_actor_critic(deter, stoch)
            stats.append(step_stats)

        # Get optimal action
        action, _ = self.agent.get_action(initial_observation, deterministic=True)

        return {
            "optimal_action": action,
            "mean_return": np.mean([s["mean_return"] for s in stats[-10:]]),
            "final_actor_loss": stats[-1]["actor_loss"],
            "final_critic_loss": stats[-1]["critic_loss"],
            "iterations": num_iterations,
        }

    def get_defense_recommendation(
        self,
        current_observation: np.ndarray,
        threat_level: str = "high",
    ) -> Dict[str, Any]:
        """
        Get a defense recommendation for the current state.
        
        Args:
            current_observation: Current security metrics
            threat_level: Current threat level
        
        Returns:
            dict with recommendation
        """
        action, state = self.agent.get_action(current_observation, deterministic=True)

        # Map action dimensions to defense actions
        action_meaning = self._interpret_action(action)

        return {
            "recommended_action": action_meaning,
            "action_vector": action.tolist(),
            "confidence": float(np.mean(np.abs(action))),
            "threat_level": threat_level,
            "state": state,
        }

    def _interpret_action(self, action: np.ndarray) -> Dict[str, float]:
        """Interpret action vector as defense actions."""
        action_names = [
            "block_ip", "rate_limit", "honeypot_redirect", "increase_monitoring",
            "isolate_endpoint", "update_firewall", "enable_mfa", "scan_vulnerability",
            "patch_system", "quarantine_file", "revoke_cert", "alert_admin",
            "enable_dlp", "throttle_bandwidth", "capture_packet", "deploy_decoy",
        ]
        result = {}
        for i, name in enumerate(action_names):
            if i < len(action):
                result[name] = float(action[i])
        return result


# ─── What-If Analyzer ─────────────────────────────────────────────────────────

class WhatIfAnalyzer:
    """
    Counterfactual reasoning about security scenarios.
    
    Given an observed trajectory, the analyzer can answer questions like:
    - "What if we had blocked the IP earlier?"
    - "What if the attack had started 1 hour later?"
    - "What if we had deployed a honeypot instead?"
    """

    def __init__(self, agent: DreamerV3Agent):
        self.agent = agent
        self.simulator = AttackSimulator(agent)

    def what_if_action(
        self,
        initial_observation: np.ndarray,
        original_actions: np.ndarray,
        modified_action_idx: int,
        new_action: np.ndarray,
    ) -> Tuple[SimulationResult, SimulationResult]:
        """
        Compare original trajectory with a modified action at a specific step.
        
        Args:
            initial_observation: Initial security metrics
            original_actions: Original sequence of actions [T, action_dim]
            modified_action_idx: Index of action to modify
            new_action: Replacement action [action_dim]
        
        Returns:
            (original_result, modified_result)
        """
        # Original simulation
        original = self.simulator.simulate_attack(initial_observation, original_actions)

        # Modified simulation
        modified_actions = original_actions.copy()
        modified_actions[modified_action_idx] = new_action
        modified = self.simulator.simulate_attack(initial_observation, modified_actions)

        return original, modified

    def what_if_early_intervention(
        self,
        initial_observation: np.ndarray,
        attack_actions: np.ndarray,
        intervention_action: np.ndarray,
        intervention_time: int,
    ) -> SimulationResult:
        """
        What if we intervened at a specific time?
        
        Args:
            initial_observation: Initial security metrics
            attack_actions: Original attack actions [T, action_dim]
            intervention_action: Defense action to insert
            intervention_time: When to intervene
        
        Returns:
            SimulationResult with intervention
        """
        modified_actions = attack_actions.copy()
        modified_actions[intervention_time] = intervention_action
        return self.simulator.simulate_attack(initial_observation, modified_actions)

    def what_if_delayed_attack(
        self,
        initial_observation: np.ndarray,
        attack_actions: np.ndarray,
        delay_steps: int,
    ) -> SimulationResult:
        """
        What if the attack started later?
        
        Args:
            initial_observation: Initial security metrics
            attack_actions: Attack actions [T, action_dim]
            delay_steps: Number of steps to delay
        
        Returns:
            SimulationResult with delayed attack
        """
        # Pad with neutral actions at the beginning
        neutral_action = np.zeros_like(attack_actions[0])
        delayed_actions = np.vstack([
            np.tile(neutral_action, (delay_steps, 1)),
            attack_actions,
        ])
        return self.simulator.simulate_attack(initial_observation, delayed_actions)

    def compare_strategies(
        self,
        initial_observation: np.ndarray,
        strategies: Dict[str, np.ndarray],
    ) -> Dict[str, Dict[str, float]]:
        """
        Compare multiple defense strategies.
        
        Args:
            initial_observation: Initial security metrics
            strategies: Dict of strategy_name -> action_sequence
        
        Returns:
            dict of strategy_name -> metrics
        """
        results = {}
        for name, actions in strategies.items():
            result = self.simulator.simulate_attack(initial_observation, actions)
            results[name] = {
                "total_reward": result.predicted_outcome["total_reward"],
                "discounted_return": result.predicted_outcome["discounted_return"],
                "trajectory_length": result.predicted_outcome["trajectory_length"],
            }
        return results


# ─── Factory Functions ────────────────────────────────────────────────────────

def create_world_model_agent(
    obs_dim: int = 64,
    action_dim: int = ACTION_DIM,
    deter_dim: int = DETERMINISTIC_DIM,
    stoch_dim: int = STOCHASTIC_DIM,
    horizon: int = HORIZON,
    lr: float = LEARNING_RATE,
    use_discrete_actions: bool = False,
) -> DreamerV3Agent:
    """
    Create a DreamerV3 agent for security defense optimization.
    
    Args:
        obs_dim: Observation dimension (security metrics)
        action_dim: Action dimension
        deter_dim: Deterministic state dimension
        stoch_dim: Stochastic state dimension
        horizon: Imagination horizon
        lr: Learning rate
        use_discrete_actions: Whether to use discrete actions
    
    Returns:
        Configured DreamerV3Agent
    """
    if not TORCH_AVAILABLE:
        warnings.warn("PyTorch not available. World model agent will be a placeholder.")
        return None  # type: ignore

    agent = DreamerV3Agent(
        obs_dim=obs_dim,
        action_dim=action_dim,
        deter_dim=deter_dim,
        stoch_dim=stoch_dim,
        horizon=horizon,
        lr=lr,
        use_discrete_actions=use_discrete_actions,
    )
    return agent


def create_world_model_agent_minimal() -> DreamerV3Agent:
    """Create a minimal world model agent for testing."""
    return create_world_model_agent(
        obs_dim=16,
        action_dim=4,
        deter_dim=64,
        stoch_dim=8,
        horizon=5,
    )


def create_world_model_agent_full() -> DreamerV3Agent:
    """Create a full-scale world model agent."""
    return create_world_model_agent(
        obs_dim=128,
        action_dim=32,
        deter_dim=1024,
        stoch_dim=128,
        horizon=30,
        lr=1e-4,
    )


def create_attack_simulator(agent: Optional[DreamerV3Agent] = None) -> AttackSimulator:
    """Create an attack simulator with optional agent."""
    if agent is None:
        agent = create_world_model_agent_minimal()
    return AttackSimulator(agent)


def create_defense_optimizer(agent: Optional[DreamerV3Agent] = None) -> DefenseOptimizer:
    """Create a defense optimizer with optional agent."""
    if agent is None:
        agent = create_world_model_agent_minimal()
    return DefenseOptimizer(agent)


def create_what_if_analyzer(agent: Optional[DreamerV3Agent] = None) -> WhatIfAnalyzer:
    """Create a what-if analyzer with optional agent."""
    if agent is None:
        agent = create_world_model_agent_minimal()
    return WhatIfAnalyzer(agent)


__all__ = [
    "WorldModelState",
    "ImaginationTrajectory",
    "SimulationResult",
    "RSSMCell",
    "ObservationEncoder",
    "ObservationDecoder",
    "WorldModel",
    "ActorNetwork",
    "CriticNetwork",
    "DreamerV3Agent",
    "AttackSimulator",
    "DefenseOptimizer",
    "WhatIfAnalyzer",
    "create_world_model_agent",
    "create_world_model_agent_minimal",
    "create_world_model_agent_full",
    "create_attack_simulator",
    "create_defense_optimizer",
    "create_what_if_analyzer",
]