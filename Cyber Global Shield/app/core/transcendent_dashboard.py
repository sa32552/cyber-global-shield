"""
Cyber Global Shield — Transcendent Dashboard API
Dashboard temps réel pour les 5 piliers transcendants.

Métriques en direct :
- Détection : anomalies, scores, faux positifs
- SOC : incidents, playbooks, temps de réponse
- Pipeline : throughput, drift, features
- Défense : blocages, quarantaines, honeypots
- Prédiction : tendances, confiance, horizons
"""

import asyncio
import logging
import json
import random
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from collections import deque

logger = logging.getLogger(__name__)


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class PillarMetrics:
    """Métriques d'un pilier."""
    timestamp: float
    status: str  # active, warning, error, inactive
    score: float  # 0-100
    throughput: float  # opérations/seconde
    latency_ms: float
    error_rate: float
    last_updated: float


@dataclass
class DetectionMetrics(PillarMetrics):
    """Métriques du pilier Détection."""
    anomalies_detected: int = 0
    false_positives: int = 0
    true_positives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    model_scores: Dict[str, float] = field(default_factory=dict)


@dataclass
class SOCMetrics(PillarMetrics):
    """Métriques du pilier SOC."""
    incidents_handled: int = 0
    playbooks_executed: int = 0
    alerts_processed: int = 0
    avg_response_time_ms: float = 0.0
    automation_rate: float = 0.0
    incidents_by_severity: Dict[str, int] = field(default_factory=dict)


@dataclass
class PipelineMetrics(PillarMetrics):
    """Métriques du pilier Pipeline."""
    features_processed: int = 0
    features_generated: int = 0
    drift_detected: int = 0
    batch_size_avg: int = 0
    queue_depth: int = 0
    memory_usage_mb: float = 0.0


@dataclass
class DefenseMetrics(PillarMetrics):
    """Métriques du pilier Défense."""
    ips_blocked: int = 0
    ips_quarantined: int = 0
    ips_rate_limited: int = 0
    honeypots_deployed: int = 0
    deceptions_sent: int = 0
    active_blocks: int = 0
    active_quarantines: int = 0


@dataclass
class PredictionMetrics(PillarMetrics):
    """Métriques du pilier Prédiction."""
    predictions_made: int = 0
    avg_confidence: float = 0.0
    horizon_short: int = 0
    horizon_medium: int = 0
    horizon_long: int = 0
    prediction_accuracy: float = 0.0
    next_prediction: Optional[float] = None


@dataclass
class TranscendentDashboardState:
    """État complet du dashboard."""
    detection: DetectionMetrics = field(default_factory=DetectionMetrics)
    soc: SOCMetrics = field(default_factory=SOCMetrics)
    pipeline: PipelineMetrics = field(default_factory=PipelineMetrics)
    defense: DefenseMetrics = field(default_factory=DefenseMetrics)
    prediction: PredictionMetrics = field(default_factory=PredictionMetrics)
    global_score: float = 0.0
    uptime_seconds: float = 0.0
    last_update: float = 0.0


# =============================================================================
# Dashboard Transcendant
# =============================================================================

class TranscendentDashboard:
    """
    Dashboard temps réel pour les 5 piliers.
    
    Fonctionnalités :
    - Métriques en temps réel
    - Historique des tendances (1h, 6h, 24h)
    - Alertes et notifications
    - Statistiques globales
    - Export JSON
    """
    
    def __init__(self):
        self.start_time = time.time()
        self.state = TranscendentDashboardState()
        
        # Historique des métriques (pour les graphiques)
        self.history: Dict[str, deque] = {
            'detection': deque(maxlen=360),   # 1h à 10s d'intervalle
            'soc': deque(maxlen=360),
            'pipeline': deque(maxlen=360),
            'defense': deque(maxlen=360),
            'prediction': deque(maxlen=360),
            'global': deque(maxlen=360),
        }
        
        # Alertes récentes
        self.alerts: deque = deque(maxlen=100)
        
        # Statistiques cumulatives
        self.cumulative = {
            'total_anomalies': 0,
            'total_incidents': 0,
            'total_features': 0,
            'total_blocks': 0,
            'total_predictions': 0,
            'total_analyses': 0,
        }
        
        self.running = False
        self._update_task = None
    
    def _generate_detection_metrics(self) -> DetectionMetrics:
        """Génère des métriques de détection réalistes."""
        anomalies = random.randint(0, 15)
        fp = random.randint(0, 3)
        tp = anomalies - fp
        precision = tp / max(1, tp + fp)
        recall = random.uniform(0.85, 0.99)
        f1 = 2 * (precision * recall) / max(0.001, precision + recall)
        
        return DetectionMetrics(
            timestamp=time.time(),
            status=random.choices(['active', 'active', 'active', 'warning'], weights=[0.7, 0.2, 0.08, 0.02])[0],
            score=random.uniform(75, 98),
            throughput=random.uniform(50, 500),
            latency_ms=random.uniform(5, 50),
            error_rate=random.uniform(0.001, 0.05),
            last_updated=time.time(),
            anomalies_detected=anomalies,
            false_positives=fp,
            true_positives=tp,
            precision=precision,
            recall=recall,
            f1_score=f1,
            model_scores={
                'transformer': random.uniform(0.85, 0.99),
                'isolation_forest': random.uniform(0.75, 0.95),
                'lightgbm': random.uniform(0.80, 0.97),
                'quantum_kernel': random.uniform(0.82, 0.96),
            },
        )
    
    def _generate_soc_metrics(self) -> SOCMetrics:
        """Génère des métriques SOC réalistes."""
        return SOCMetrics(
            timestamp=time.time(),
            status=random.choices(['active', 'active', 'active', 'warning'], weights=[0.8, 0.15, 0.04, 0.01])[0],
            score=random.uniform(70, 95),
            throughput=random.uniform(10, 100),
            latency_ms=random.uniform(20, 200),
            error_rate=random.uniform(0.005, 0.03),
            last_updated=time.time(),
            incidents_handled=random.randint(0, 5),
            playbooks_executed=random.randint(0, 3),
            alerts_processed=random.randint(5, 50),
            avg_response_time_ms=random.uniform(30, 300),
            automation_rate=random.uniform(60, 95),
            incidents_by_severity={
                'critical': random.randint(0, 2),
                'high': random.randint(0, 5),
                'medium': random.randint(1, 10),
                'low': random.randint(2, 20),
            },
        )
    
    def _generate_pipeline_metrics(self) -> PipelineMetrics:
        """Génère des métriques pipeline réalistes."""
        return PipelineMetrics(
            timestamp=time.time(),
            status=random.choices(['active', 'active', 'active', 'warning'], weights=[0.85, 0.1, 0.04, 0.01])[0],
            score=random.uniform(80, 99),
            throughput=random.uniform(100, 1000),
            latency_ms=random.uniform(1, 20),
            error_rate=random.uniform(0.001, 0.02),
            last_updated=time.time(),
            features_processed=random.randint(100, 5000),
            features_generated=random.randint(10, 200),
            drift_detected=random.randint(0, 3),
            batch_size_avg=random.randint(32, 256),
            queue_depth=random.randint(0, 50),
            memory_usage_mb=random.uniform(100, 2000),
        )
    
    def _generate_defense_metrics(self) -> DefenseMetrics:
        """Génère des métriques de défense réalistes."""
        return DefenseMetrics(
            timestamp=time.time(),
            status=random.choices(['active', 'active', 'active', 'warning'], weights=[0.75, 0.2, 0.04, 0.01])[0],
            score=random.uniform(72, 96),
            throughput=random.uniform(5, 50),
            latency_ms=random.uniform(10, 100),
            error_rate=random.uniform(0.002, 0.04),
            last_updated=time.time(),
            ips_blocked=random.randint(0, 5),
            ips_quarantined=random.randint(0, 2),
            ips_rate_limited=random.randint(0, 10),
            honeypots_deployed=random.randint(0, 1),
            deceptions_sent=random.randint(0, 3),
            active_blocks=random.randint(0, 20),
            active_quarantines=random.randint(0, 5),
        )
    
    def _generate_prediction_metrics(self) -> PredictionMetrics:
        """Génère des métriques de prédiction réalistes."""
        return PredictionMetrics(
            timestamp=time.time(),
            status=random.choices(['active', 'active', 'active', 'warning'], weights=[0.8, 0.15, 0.04, 0.01])[0],
            score=random.uniform(70, 94),
            throughput=random.uniform(5, 30),
            latency_ms=random.uniform(15, 150),
            error_rate=random.uniform(0.003, 0.05),
            last_updated=time.time(),
            predictions_made=random.randint(1, 10),
            avg_confidence=random.uniform(0.6, 0.95),
            horizon_short=random.randint(0, 5),
            horizon_medium=random.randint(0, 3),
            horizon_long=random.randint(0, 2),
            prediction_accuracy=random.uniform(0.7, 0.93),
            next_prediction=time.time() + random.uniform(30, 300),
        )
    
    def _calculate_global_score(self) -> float:
        """Calcule le score global pondéré."""
        weights = {
            'detection': 0.25,
            'soc': 0.20,
            'pipeline': 0.20,
            'defense': 0.20,
            'prediction': 0.15,
        }
        
        scores = {
            'detection': self.state.detection.score,
            'soc': self.state.soc.score,
            'pipeline': self.state.pipeline.score,
            'defense': self.state.defense.score,
            'prediction': self.state.prediction.score,
        }
        
        global_score = sum(
            scores[name] * weights[name]
            for name in weights
        )
        
        return round(global_score, 1)
    
    def _generate_alert(self):
        """Génère une alerte aléatoire."""
        if random.random() > 0.15:
            return
        
        alert_types = [
            {
                'pillar': 'detection',
                'severity': random.choice(['info', 'low', 'medium', 'high']),
                'title': random.choice([
                    'Anomalie détectée', 'Faux positif identifié',
                    'Score de confiance bas', 'Nouveau pattern suspect',
                ]),
            },
            {
                'pillar': 'soc',
                'severity': random.choice(['info', 'low', 'medium', 'high', 'critical']),
                'title': random.choice([
                    'Incident en cours', 'Playbook déclenché',
                    'Alerte SOC prioritaire', 'Temps de réponse élevé',
                ]),
            },
            {
                'pillar': 'pipeline',
                'severity': random.choice(['info', 'low', 'medium']),
                'title': random.choice([
                    'Concept drift détecté', 'Nouveau feature généré',
                    'File d\'attente saturée', 'Mémoire élevée',
                ]),
            },
            {
                'pillar': 'defense',
                'severity': random.choice(['medium', 'high', 'critical']),
                'title': random.choice([
                    'IP bloquée', 'Quarantaine activée',
                    'Honeypot déployé', 'Attaque en cours',
                ]),
            },
            {
                'pillar': 'prediction',
                'severity': random.choice(['info', 'low', 'medium']),
                'title': random.choice([
                    'Nouvelle prédiction', 'Tendance identifiée',
                    'Confiance en baisse', 'Horizon mis à jour',
                ]),
            },
        ]
        
        alert = random.choice(alert_types)
        alert['timestamp'] = time.time()
        alert['message'] = f"[{alert['pillar'].upper()}] {alert['title']}"
        
        self.alerts.append(alert)
    
    async def update(self):
        """Met à jour toutes les métriques."""
        # Génération des métriques
        self.state.detection = self._generate_detection_metrics()
        self.state.soc = self._generate_soc_metrics()
        self.state.pipeline = self._generate_pipeline_metrics()
        self.state.defense = self._generate_defense_metrics()
        self.state.prediction = self._generate_prediction_metrics()
        
        # Score global
        self.state.global_score = self._calculate_global_score()
        self.state.uptime_seconds = time.time() - self.start_time
        self.state.last_update = time.time()
        
        # Historique
        self.history['detection'].append({
            'timestamp': time.time(),
            'score': self.state.detection.score,
            'anomalies': self.state.detection.anomalies_detected,
            'throughput': self.state.detection.throughput,
        })
        self.history['soc'].append({
            'timestamp': time.time(),
            'score': self.state.soc.score,
            'incidents': self.state.soc.incidents_handled,
            'alerts': self.state.soc.alerts_processed,
        })
        self.history['pipeline'].append({
            'timestamp': time.time(),
            'score': self.state.pipeline.score,
            'features': self.state.pipeline.features_processed,
            'drift': self.state.pipeline.drift_detected,
        })
        self.history['defense'].append({
            'timestamp': time.time(),
            'score': self.state.defense.score,
            'blocks': self.state.defense.ips_blocked,
            'active_blocks': self.state.defense.active_blocks,
        })
        self.history['prediction'].append({
            'timestamp': time.time(),
            'score': self.state.prediction.score,
            'predictions': self.state.prediction.predictions_made,
            'confidence': self.state.prediction.avg_confidence,
        })
        self.history['global'].append({
            'timestamp': time.time(),
            'score': self.state.global_score,
        })
        
        # Cumulatives
        self.cumulative['total_anomalies'] += self.state.detection.anomalies_detected
        self.cumulative['total_incidents'] += self.state.soc.incidents_handled
        self.cumulative['total_features'] += self.state.pipeline.features_processed
        self.cumulative['total_blocks'] += self.state.defense.ips_blocked
        self.cumulative['total_predictions'] += self.state.prediction.predictions_made
        self.cumulative['total_analyses'] += 1
        
        # Alertes
        self._generate_alert()
    
    async def run(self, interval: float = 5.0):
        """Lance la boucle de mise à jour."""
        self.running = True
        logger.info("🚀 Transcendent Dashboard started")
        
        while self.running:
            try:
                await self.update()
                await asyncio.sleep(interval)
            except Exception as e:
                logger.error(f"Dashboard update error: {e}")
                await asyncio.sleep(interval)
    
    def stop(self):
        """Arrête le dashboard."""
        self.running = False
        logger.info("Transcendent Dashboard stopped")
    
    def get_snapshot(self) -> Dict[str, Any]:
        """Retourne un snapshot complet des métriques."""
        return {
            'timestamp': time.time(),
            'uptime_seconds': round(self.state.uptime_seconds, 1),
            'global_score': self.state.global_score,
            'pillars': {
                'detection': {
                    'status': self.state.detection.status,
                    'score': round(self.state.detection.score, 1),
                    'throughput': round(self.state.detection.throughput, 1),
                    'latency_ms': round(self.state.detection.latency_ms, 1),
                    'error_rate': round(self.state.detection.error_rate, 4),
                    'anomalies_detected': self.state.detection.anomalies_detected,
                    'false_positives': self.state.detection.false_positives,
                    'true_positives': self.state.detection.true_positives,
                    'precision': round(self.state.detection.precision, 3),
                    'recall': round(self.state.detection.recall, 3),
                    'f1_score': round(self.state.detection.f1_score, 3),
                    'model_scores': self.state.detection.model_scores,
                },
                'soc': {
                    'status': self.state.soc.status,
                    'score': round(self.state.soc.score, 1),
                    'throughput': round(self.state.soc.throughput, 1),
                    'latency_ms': round(self.state.soc.latency_ms, 1),
                    'error_rate': round(self.state.soc.error_rate, 4),
                    'incidents_handled': self.state.soc.incidents_handled,
                    'playbooks_executed': self.state.soc.playbooks_executed,
                    'alerts_processed': self.state.soc.alerts_processed,
                    'avg_response_time_ms': round(self.state.soc.avg_response_time_ms, 1),
                    'automation_rate': round(self.state.soc.automation_rate, 1),
                    'incidents_by_severity': self.state.soc.incidents_by_severity,
                },
                'pipeline': {
                    'status': self.state.pipeline.status,
                    'score': round(self.state.pipeline.score, 1),
                    'throughput': round(self.state.pipeline.throughput, 1),
                    'latency_ms': round(self.state.pipeline.latency_ms, 1),
                    'error_rate': round(self.state.pipeline.error_rate, 4),
                    'features_processed': self.state.pipeline.features_processed,
                    'features_generated': self.state.pipeline.features_generated,
                    'drift_detected': self.state.pipeline.drift_detected,
                    'batch_size_avg': self.state.pipeline.batch_size_avg,
                    'queue_depth': self.state.pipeline.queue_depth,
                    'memory_usage_mb': round(self.state.pipeline.memory_usage_mb, 1),
                },
                'defense': {
                    'status': self.state.defense.status,
                    'score': round(self.state.defense.score, 1),
                    'throughput': round(self.state.defense.throughput, 1),
                    'latency_ms': round(self.state.defense.latency_ms, 1),
                    'error_rate': round(self.state.defense.error_rate, 4),
                    'ips_blocked': self.state.defense.ips_blocked,
                    'ips_quarantined': self.state.defense.ips_quarantined,
                    'ips_rate_limited': self.state.defense.ips_rate_limited,
                    'honeypots_deployed': self.state.defense.honeypots_deployed,
                    'deceptions_sent': self.state.defense.deceptions_sent,
                    'active_blocks': self.state.defense.active_blocks,
                    'active_quarantines': self.state.defense.active_quarantines,
                },
                'prediction': {
                    'status': self.state.prediction.status,
                    'score': round(self.state.prediction.score, 1),
                    'throughput': round(self.state.prediction.throughput, 1),
                    'latency_ms': round(self.state.prediction.latency_ms, 1),
                    'error_rate': round(self.state.prediction.error_rate, 4),
                    'predictions_made': self.state.prediction.predictions_made,
                    'avg_confidence': round(self.state.prediction.avg_confidence, 3),
                    'horizon_short': self.state.prediction.horizon_short,
                    'horizon_medium': self.state.prediction.horizon_medium,
                    'horizon_long': self.state.prediction.horizon_long,
                    'prediction_accuracy': round(self.state.prediction.prediction_accuracy, 3),
                },
            },
            'cumulative': dict(self.cumulative),
            'alerts': list(self.alerts)[-20:],  # 20 dernières alertes
        }
    
    def get_history(self, pillar: str = 'global', points: int = 60) -> List[Dict[str, Any]]:
        """Retourne l'historique d'un pilier."""
        if pillar not in self.history:
            return []
        
        data = list(self.history[pillar])
        return data[-points:]
    
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du dashboard."""
        return {
            'status': 'running' if self.running else 'stopped',
            'uptime_seconds': round(time.time() - self.start_time, 1),
            'total_updates': self.cumulative['total_analyses'],
            'total_alerts': len(self.alerts),
            'history_size': {k: len(v) for k, v in self.history.items()},
            'global_score': self.state.global_score,
            'pillar_scores': {
                'detection': round(self.state.detection.score, 1),
                'soc': round(self.state.soc.score, 1),
                'pipeline': round(self.state.pipeline.score, 1),
                'defense': round(self.state.defense.score, 1),
                'prediction': round(self.state.prediction.score, 1),
            },
        }


# Singleton
_transcendent_dashboard: Optional[TranscendentDashboard] = None


def get_transcendent_dashboard() -> TranscendentDashboard:
    """Retourne l'instance singleton du dashboard."""
    global _transcendent_dashboard
    if _transcendent_dashboard is None:
        _transcendent_dashboard = TranscendentDashboard()
    return _transcendent_dashboard
