"""
Cyber Global Shield — Conformal Prediction
===========================================
Distribution-free uncertainty quantification for security predictions.
Provides statistical guarantees (95-99%) on detection decisions.

Based on:
  - "Conformal Prediction: A Gentle Introduction" (Angelopoulos & Bates, 2022)
  - "Split Conformal Prediction" (Papadopoulos et al., 2002)
  - "Adaptive Prediction Sets" (Romano et al., 2020)

Components:
  - SplitConformal: Split conformal prediction for i.i.d. data
  - AdaptiveConformal: Adaptive conformal prediction for non-stationary data
  - ConformalDetector: Security detector with guaranteed coverage
  - ConformalEnsemble: Ensemble of conformal predictors
  - ConformalCalibrator: Online calibration for changing distributions
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

DEFAULT_ALPHA = 0.05     # Default significance level (95% coverage)
DEFAULT_ALPHA_HIGH = 0.01  # High confidence (99% coverage)
WINDOW_SIZE = 1000       # Default window size for adaptive methods
LEARNING_RATE = 0.01     # Learning rate for adaptive methods


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class ConformalResult:
    """Result from conformal prediction."""
    prediction: Any
    prediction_set: List[Any]
    confidence_scores: np.ndarray
    coverage: float
    significance: float
    is_reliable: bool
    nonconformity_score: float


@dataclass
class CalibrationPoint:
    """A single calibration point."""
    nonconformity_score: float
    label: Any
    timestamp: float


# ─── Nonconformity Measures ───────────────────────────────────────────────────

class NonconformityMeasure:
    """Base class for nonconformity measures."""

    def compute(self, scores: np.ndarray, label_idx: int) -> np.ndarray:
        """
        Compute nonconformity scores.
        
        Args:
            scores: Prediction scores [n_samples, n_classes]
            label_idx: True label index
        
        Returns:
            Nonconformity scores [n_samples]
        """
        raise NotImplementedError


class InverseProbabilityMeasure(NonconformityMeasure):
    """Nonconformity = 1 - p(y|x)."""

    def compute(self, scores: np.ndarray, label_idx: int) -> np.ndarray:
        return 1 - scores[:, label_idx]


class MarginMeasure(NonconformityMeasure):
    """Nonconformity = max score - score of true label."""

    def compute(self, scores: np.ndarray, label_idx: int) -> np.ndarray:
        max_scores = scores.max(axis=1)
        true_scores = scores[:, label_idx]
        return max_scores - true_scores


class TopKMeasure(NonconformityMeasure):
    """Nonconformity = sum of scores above true label score."""

    def __init__(self, k: int = 5):
        self.k = k

    def compute(self, scores: np.ndarray, label_idx: int) -> np.ndarray:
        true_score = scores[:, label_idx:label_idx+1]
        higher = (scores > true_score).sum(axis=1)
        return higher.astype(float)


class ResidualMeasure(NonconformityMeasure):
    """Nonconformity = |y - y_hat| for regression."""

    def compute(self, scores: np.ndarray, label_idx: int) -> np.ndarray:
        return np.abs(scores[:, 0] - label_idx)


# ─── Split Conformal Prediction ──────────────────────────────────────────────

class SplitConformal:
    """
    Split conformal prediction for i.i.d. data.
    
    Uses a separate calibration set to compute quantiles of
    nonconformity scores, providing marginal coverage guarantees.
    """

    def __init__(
        self,
        alpha: float = DEFAULT_ALPHA,
        nonconformity_measure: Optional[NonconformityMeasure] = None,
    ):
        self.alpha = alpha
        self.nonconformity_measure = nonconformity_measure or InverseProbabilityMeasure()
        self.calibration_scores: Optional[np.ndarray] = None
        self.quantile: Optional[float] = None
        self.n_calibration: int = 0

    def calibrate(
        self,
        calibration_scores: np.ndarray,
        calibration_labels: np.ndarray,
    ) -> float:
        """
        Calibrate using a held-out calibration set.
        
        Args:
            calibration_scores: Prediction scores [n_cal, n_classes]
            calibration_labels: True labels [n_cal]
        
        Returns:
            Calibrated quantile threshold
        """
        # Compute nonconformity scores
        scores = []
        for i in range(len(calibration_labels)):
            nc_score = self.nonconformity_measure.compute(
                calibration_scores[i:i+1],
                int(calibration_labels[i]),
            )
            scores.append(nc_score[0])

        self.calibration_scores = np.array(scores)
        self.n_calibration = len(scores)

        # Compute quantile with finite sample correction
        n = self.n_calibration
        q_level = min((1 - self.alpha) * (1 + 1 / n), 1.0)
        self.quantile = float(np.quantile(self.calibration_scores, q_level))

        return self.quantile

    def predict(
        self,
        scores: np.ndarray,
        return_set: bool = True,
    ) -> ConformalResult:
        """
        Predict with conformal prediction set.
        
        Args:
            scores: Prediction scores [n_classes]
            return_set: Whether to return prediction set
        
        Returns:
            ConformalResult
        """
        if self.quantile is None:
            raise ValueError("Must calibrate before predicting")

        # Compute nonconformity for each possible label
        prediction_set = []
        for i in range(len(scores)):
            nc_score = self.nonconformity_measure.compute(
                scores.reshape(1, -1), i
            )[0]
            if nc_score <= self.quantile:
                prediction_set.append(i)

        # Primary prediction
        prediction = int(np.argmax(scores))

        # Coverage estimate
        coverage = 1 - self.alpha

        # Nonconformity of prediction
        nc_prediction = self.nonconformity_measure.compute(
            scores.reshape(1, -1), prediction
        )[0]

        return ConformalResult(
            prediction=prediction,
            prediction_set=prediction_set,
            confidence_scores=scores,
            coverage=coverage,
            significance=self.alpha,
            is_reliable=len(prediction_set) <= len(scores) // 2,
            nonconformity_score=nc_prediction,
        )

    def predict_set_size(self, scores: np.ndarray) -> int:
        """Get the size of the prediction set."""
        result = self.predict(scores)
        return len(result.prediction_set)

    def update_alpha(self, new_alpha: float):
        """Update significance level and recompute quantile."""
        self.alpha = new_alpha
        if self.calibration_scores is not None:
            n = self.n_calibration
            q_level = min((1 - self.alpha) * (1 + 1 / n), 1.0)
            self.quantile = float(np.quantile(self.calibration_scores, q_level))


# ─── Adaptive Conformal Prediction ───────────────────────────────────────────

class AdaptiveConformal:
    """
    Adaptive conformal prediction for non-stationary data.
    
    Uses a rolling window and adaptive update rule to maintain
    valid coverage under distribution shift.
    """

    def __init__(
        self,
        alpha: float = DEFAULT_ALPHA,
        window_size: int = WINDOW_SIZE,
        learning_rate: float = LEARNING_RATE,
        nonconformity_measure: Optional[NonconformityMeasure] = None,
    ):
        self.alpha = alpha
        self.window_size = window_size
        self.learning_rate = learning_rate
        self.nonconformity_measure = nonconformity_measure or InverseProbabilityMeasure()

        # Rolling buffer of nonconformity scores
        self.score_buffer: List[float] = []
        self.quantile: float = 1.0
        self.step = 0

    def update(
        self,
        scores: np.ndarray,
        true_label: int,
    ) -> float:
        """
        Update conformal predictor with new labeled example.
        
        Args:
            scores: Prediction scores [n_classes]
            true_label: True label
        
        Returns:
            Updated quantile
        """
        # Compute nonconformity score
        nc_score = self.nonconformity_measure.compute(
            scores.reshape(1, -1), true_label
        )[0]

        # Add to buffer
        self.score_buffer.append(nc_score)
        if len(self.score_buffer) > self.window_size:
            self.score_buffer.pop(0)

        # Update quantile using adaptive method
        n = len(self.score_buffer)
        if n > 10:
            # Compute empirical coverage
            empirical_coverage = (np.array(self.score_buffer) <= self.quantile).mean()

            # Adaptive update (gradient descent on quantile)
            error = (1 - self.alpha) - empirical_coverage
            self.quantile += self.learning_rate * error * self.quantile
            self.quantile = max(self.quantile, 0.01)

            # Also compute direct quantile
            q_level = min((1 - self.alpha) * (1 + 1 / n), 1.0)
            direct_quantile = float(np.quantile(self.score_buffer, q_level))

            # Blend adaptive and direct
            blend = min(1.0, self.step / 100)
            self.quantile = blend * self.quantile + (1 - blend) * direct_quantile

        self.step += 1
        return self.quantile

    def predict(
        self,
        scores: np.ndarray,
    ) -> ConformalResult:
        """Predict with adaptive conformal prediction set."""
        prediction_set = []
        for i in range(len(scores)):
            nc_score = self.nonconformity_measure.compute(
                scores.reshape(1, -1), i
            )[0]
            if nc_score <= self.quantile:
                prediction_set.append(i)

        prediction = int(np.argmax(scores))

        # Estimate current coverage
        if len(self.score_buffer) > 10:
            current_coverage = (np.array(self.score_buffer) <= self.quantile).mean()
        else:
            current_coverage = 1 - self.alpha

        nc_prediction = self.nonconformity_measure.compute(
            scores.reshape(1, -1), prediction
        )[0]

        return ConformalResult(
            prediction=prediction,
            prediction_set=prediction_set,
            confidence_scores=scores,
            coverage=current_coverage,
            significance=self.alpha,
            is_reliable=current_coverage >= (1 - self.alpha) * 0.9,
            nonconformity_score=nc_prediction,
        )

    def get_coverage_trace(self) -> np.ndarray:
        """Get empirical coverage over time."""
        if len(self.score_buffer) < 10:
            return np.array([])
        window = np.array(self.score_buffer)
        return (window <= self.quantile).astype(float)


# ─── Conformal Detector ───────────────────────────────────────────────────────

class ConformalDetector:
    """
    Security detector with guaranteed coverage using conformal prediction.
    
    Provides statistical guarantees on detection decisions:
    - 95% coverage: The true label is in the prediction set 95% of the time
    - Adaptive to distribution shift
    - Calibrated false positive rate
    """

    def __init__(
        self,
        alpha: float = DEFAULT_ALPHA,
        adaptive: bool = True,
        window_size: int = WINDOW_SIZE,
    ):
        self.alpha = alpha
        self.adaptive = adaptive

        if adaptive:
            self.conformal = AdaptiveConformal(alpha, window_size)
        else:
            self.conformal = SplitConformal(alpha)

        self.is_calibrated = False
        self.calibration_history: List[Dict[str, Any]] = []

    def calibrate(
        self,
        scores: np.ndarray,
        labels: np.ndarray,
    ) -> float:
        """
        Calibrate the detector.
        
        Args:
            scores: Prediction scores [n_samples, n_classes]
            labels: True labels [n_samples]
        
        Returns:
            Calibration threshold
        """
        if self.adaptive:
            # For adaptive, we update sequentially
            thresholds = []
            for i in range(len(scores)):
                thresh = self.conformal.update(scores[i], int(labels[i]))
                thresholds.append(thresh)
                self.calibration_history.append({
                    "step": i,
                    "threshold": thresh,
                    "score": scores[i].tolist(),
                    "label": int(labels[i]),
                })
            self.is_calibrated = True
            return thresholds[-1]
        else:
            # For split conformal, calibrate on all data
            threshold = self.conformal.calibrate(scores, labels)
            self.is_calibrated = True
            return threshold

    def detect(
        self,
        scores: np.ndarray,
        true_label: Optional[int] = None,
    ) -> ConformalResult:
        """
        Detect with conformal guarantees.
        
        Args:
            scores: Prediction scores [n_classes]
            true_label: Optional true label for online update
        
        Returns:
            ConformalResult
        """
        if not self.is_calibrated and not self.adaptive:
            raise ValueError("Must calibrate before detecting")

        # Update if label is provided (adaptive mode)
        if true_label is not None and self.adaptive:
            self.conformal.update(scores, true_label)

        return self.conformal.predict(scores)

    def detect_batch(
        self,
        scores_batch: np.ndarray,
        labels: Optional[np.ndarray] = None,
    ) -> List[ConformalResult]:
        """Detect on a batch of samples."""
        results = []
        for i in range(len(scores_batch)):
            label = int(labels[i]) if labels is not None else None
            result = self.detect(scores_batch[i], label)
            results.append(result)
        return results

    def get_coverage_estimate(self) -> float:
        """Get current coverage estimate."""
        if self.adaptive:
            trace = self.conformal.get_coverage_trace()
            return float(trace.mean()) if len(trace) > 0 else (1 - self.alpha)
        else:
            return 1 - self.alpha

    def get_prediction_set_size(self) -> float:
        """Get average prediction set size."""
        if not self.calibration_history:
            return 0.0
        return np.mean([len(h["score"]) for h in self.calibration_history])


# ─── Conformal Ensemble ───────────────────────────────────────────────────────

class ConformalEnsemble:
    """
    Ensemble of conformal predictors for robust uncertainty quantification.
    
    Combines multiple conformal predictors with different:
    - Nonconformity measures
    - Significance levels
    - Calibration windows
    """

    def __init__(
        self,
        alphas: List[float] = None,
        measures: List[NonconformityMeasure] = None,
    ):
        self.alphas = alphas or [0.01, 0.05, 0.1]
        self.measures = measures or [
            InverseProbabilityMeasure(),
            MarginMeasure(),
            TopKMeasure(k=3),
        ]

        # Create all combinations
        self.predictors: List[AdaptiveConformal] = []
        for alpha in self.alphas:
            for measure in self.measures:
                self.predictors.append(
                    AdaptiveConformal(alpha=alpha, nonconformity_measure=measure)
                )

    def update_all(self, scores: np.ndarray, true_label: int):
        """Update all predictors with new labeled example."""
        for predictor in self.predictors:
            predictor.update(scores, true_label)

    def predict_ensemble(
        self,
        scores: np.ndarray,
    ) -> Dict[str, Any]:
        """
        Predict with ensemble voting.
        
        Args:
            scores: Prediction scores [n_classes]
        
        Returns:
            dict with aggregated results
        """
        all_results = []
        prediction_votes = {}
        set_sizes = []

        for predictor in self.predictors:
            result = predictor.predict(scores)
            all_results.append(result)

            # Vote for prediction
            pred = result.prediction
            prediction_votes[pred] = prediction_votes.get(pred, 0) + 1
            set_sizes.append(len(result.prediction_set))

        # Majority vote
        ensemble_prediction = max(prediction_votes, key=prediction_votes.get)
        consensus = prediction_votes[ensemble_prediction] / len(self.predictors)

        # Aggregate prediction set (union with frequency threshold)
        freq_threshold = 0.3
        all_labels = set()
        for result in all_results:
            all_labels.update(result.prediction_set)

        ensemble_set = []
        for label in all_labels:
            frequency = sum(
                1 for r in all_results if label in r.prediction_set
            ) / len(all_results)
            if frequency >= freq_threshold:
                ensemble_set.append(label)

        # Average coverage
        avg_coverage = np.mean([r.coverage for r in all_results])

        return {
            "prediction": ensemble_prediction,
            "prediction_set": ensemble_set,
            "consensus": consensus,
            "avg_coverage": avg_coverage,
            "avg_set_size": np.mean(set_sizes),
            "n_predictors": len(self.predictors),
            "individual_results": all_results,
        }


# ─── Conformal Calibrator ─────────────────────────────────────────────────────

class ConformalCalibrator:
    """
    Online calibration for changing distributions.
    
    Monitors coverage and adjusts significance level to maintain
    target coverage under concept drift.
    """

    def __init__(
        self,
        target_coverage: float = 0.95,
        window_size: int = 500,
        adaptation_rate: float = 0.01,
    ):
        self.target_coverage = target_coverage
        self.target_alpha = 1 - target_coverage
        self.window_size = window_size
        self.adaptation_rate = adaptation_rate

        # Coverage monitoring
        self.coverage_buffer: List[bool] = []
        self.alpha_history: List[float] = [self.target_alpha]

    def update(self, in_prediction_set: bool):
        """
        Update calibrator with feedback.
        
        Args:
            in_prediction_set: Whether true label was in prediction set
        """
        self.coverage_buffer.append(in_prediction_set)
        if len(self.coverage_buffer) > self.window_size:
            self.coverage_buffer.pop(0)

        # Adjust alpha based on empirical coverage
        if len(self.coverage_buffer) >= 100:
            empirical_coverage = np.mean(self.coverage_buffer)
            gap = self.target_coverage - empirical_coverage

            # Adjust alpha
            new_alpha = self.alpha_history[-1] - self.adaptation_rate * gap
            new_alpha = np.clip(new_alpha, 0.001, 0.5)
            self.alpha_history.append(new_alpha)

    def get_current_alpha(self) -> float:
        """Get current recommended significance level."""
        return self.alpha_history[-1]

    def get_coverage_trend(self) -> Dict[str, float]:
        """Get coverage statistics."""
        if len(self.coverage_buffer) < 10:
            return {"current_coverage": 0.0, "trend": 0.0}

        recent = np.mean(self.coverage_buffer[-100:])
        overall = np.mean(self.coverage_buffer)

        return {
            "current_coverage": recent,
            "overall_coverage": overall,
            "target_coverage": self.target_coverage,
            "current_alpha": self.alpha_history[-1],
            "trend": recent - overall,
        }


# ─── Factory Functions ────────────────────────────────────────────────────────

def create_conformal_detector(
    alpha: float = DEFAULT_ALPHA,
    adaptive: bool = True,
) -> ConformalDetector:
    """
    Create a conformal prediction detector.
    
    Args:
        alpha: Significance level (0.05 = 95% coverage)
        adaptive: Whether to use adaptive conformal prediction
    
    Returns:
        Configured ConformalDetector
    """
    return ConformalDetector(alpha=alpha, adaptive=adaptive)


def create_conformal_detector_high_confidence() -> ConformalDetector:
    """Create a high-confidence conformal detector (99% coverage)."""
    return create_conformal_detector(alpha=0.01, adaptive=True)


def create_conformal_detector_low_confidence() -> ConformalDetector:
    """Create a lower-confidence conformal detector (90% coverage)."""
    return create_conformal_detector(alpha=0.1, adaptive=True)


def create_conformal_ensemble() -> ConformalEnsemble:
    """Create a conformal ensemble with multiple measures and levels."""
    return ConformalEnsemble()


def create_conformal_calibrator(
    target_coverage: float = 0.95,
) -> ConformalCalibrator:
    """Create a conformal calibrator."""
    return ConformalCalibrator(target_coverage=target_coverage)


__all__ = [
    "ConformalResult",
    "CalibrationPoint",
    "NonconformityMeasure",
    "InverseProbabilityMeasure",
    "MarginMeasure",
    "TopKMeasure",
    "ResidualMeasure",
    "SplitConformal",
    "AdaptiveConformal",
    "ConformalDetector",
    "ConformalEnsemble",
    "ConformalCalibrator",
    "create_conformal_detector",
    "create_conformal_detector_high_confidence",
    "create_conformal_detector_low_confidence",
    "create_conformal_ensemble",
    "create_conformal_calibrator",
]
