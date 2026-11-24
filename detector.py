"""AI-Based MITM Anomaly Detection Pipeline for Diffie-Hellman Handshakes.

Primary Model (Slide 7):
  - Isolation Forest trained ONLY on normal baseline traffic.
  - Maps anomaly scores to a normalized 0-100 Risk Score (Slide 8).
  - Produces interpretable per-feature indicators for analyst triage.

Comparison Baselines (Slide 7):
  - Random Forest, Gradient Boosting, and MLP (ANN) evaluated side-by-side
    on a held-out test split.
"""

from __future__ import annotations

import math
import pickle
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import (
    GradientBoostingClassifier,
    IsolationForest,
    RandomForestClassifier,
)
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

from dh_engine import generate_dataset
from features import FEATURE_NAMES, FEATURE_SPEC_MAP, extract_feature_vector, records_to_dataframe

DEFAULT_MODEL_PATH = Path(__file__).resolve().parent / "models" / "dh_mitm_detector.pkl"


@dataclass
class DetectionVerdict:
    risk_score: int
    risk_level: str
    verdict: str
    is_anomalous: bool
    raw_anomaly_score: float
    indicators: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DHMitmDetector:
    """Unsupervised Isolation Forest detector with interpretable indicators."""

    def __init__(self, contamination: float = 0.03, random_state: int = 42) -> None:
        self.contamination = contamination
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.iso_forest = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
        )
        self.baseline_mean: np.ndarray | None = None
        self.baseline_std: np.ndarray | None = None
        self.score_center: float = 0.0
        self.score_scale: float = 0.1
        self.comparison_metrics: list[dict[str, Any]] = []
        self.is_trained: bool = False

    def fit_and_evaluate(
        self,
        n_normal: int = 500,
        n_attack: int = 200,
        seed: int = 42,
    ) -> list[dict[str, Any]]:
        """Train Isolation Forest on normal baseline and benchmark against baselines."""
        records = generate_dataset(n_normal=n_normal, n_attack=n_attack, seed=seed)
        df = records_to_dataframe(records)
        X = df.values
        y = np.array([int(r["label"]) for r in records], dtype=np.int64)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.30, random_state=seed, stratify=y
        )

        # Primary model: Isolation Forest trained ONLY on normal baseline samples
        X_train_normal = X_train[y_train == 0]
        X_train_normal_scaled = self.scaler.fit_transform(X_train_normal)
        self.iso_forest.fit(X_train_normal_scaled)

        self.baseline_mean = np.mean(X_train_normal, axis=0)
        self.baseline_std = np.maximum(np.std(X_train_normal, axis=0), 1e-3)

        # Calibrate logistic mapping from decision_function to 0-100 risk score
        normal_decision_scores = self.iso_forest.decision_function(X_train_normal_scaled)
        self.score_center = float(np.percentile(normal_decision_scores, 5))
        self.score_scale = float(max(np.std(normal_decision_scores), 0.04))

        # Evaluate Isolation Forest on held-out test set
        X_test_scaled = self.scaler.transform(X_test)
        iso_raw = self.iso_forest.decision_function(X_test_scaled)
        iso_pred = (self.iso_forest.predict(X_test_scaled) == -1).astype(int)
        iso_prob = np.array([self._decision_to_prob(float(s)) for s in iso_raw])

        metrics: list[dict[str, Any]] = [
            self._compute_metrics(
                "Isolation Forest (Primary)",
                "Unsupervised",
                y_test,
                iso_pred,
                iso_prob,
            )
        ]

        # Supervised comparison baselines (Slide 7)
        X_train_all_scaled = self.scaler.transform(X_train)
        baselines = [
            (
                "Random Forest",
                "Supervised",
                RandomForestClassifier(n_estimators=150, random_state=seed),
            ),
            (
                "Gradient Boosting",
                "Supervised",
                GradientBoostingClassifier(random_state=seed),
            ),
            (
                "ANN (MLP)",
                "Supervised",
                MLPClassifier(hidden_layer_sizes=(32, 16), max_iter=500, random_state=seed),
            ),
        ]

        for name, paradigm, clf in baselines:
            clf.fit(X_train_all_scaled, y_train)
            y_pred = clf.predict(X_test_scaled)
            y_prob = clf.predict_proba(X_test_scaled)[:, 1]
            metrics.append(self._compute_metrics(name, paradigm, y_test, y_pred, y_prob))

        self.comparison_metrics = metrics
        self.is_trained = True
        return metrics

    def _decision_to_prob(self, decision_score: float) -> float:
        """Map IsolationForest decision_function (negative=anomaly) to [0, 1]."""
        z = (self.score_center - decision_score) / (self.score_scale * 1.4)
        z = max(-20.0, min(20.0, z))
        return 1.0 / (1.0 + math.exp(-z))

    @staticmethod
    def _compute_metrics(
        model_name: str,
        paradigm: str,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_prob: np.ndarray,
    ) -> dict[str, Any]:
        return {
            "model": model_name,
            "paradigm": paradigm,
            "accuracy": round(float(accuracy_score(y_true, y_pred)) * 100, 2),
            "precision": round(float(precision_score(y_true, y_pred, zero_division=0)) * 100, 2),
            "recall": round(float(recall_score(y_true, y_pred, zero_division=0)) * 100, 2),
            "f1": round(float(f1_score(y_true, y_pred, zero_division=0)) * 100, 2),
            "roc_auc": round(float(roc_auc_score(y_true, y_prob)), 4),
        }

    def score_session(self, telemetry: dict[str, Any]) -> DetectionVerdict:
        """Score a single DH session and return Risk Score + interpretable indicators."""
        if not self.is_trained or self.baseline_mean is None or self.baseline_std is None:
            raise RuntimeError("Detector must be trained before scoring sessions.")

        vec = extract_feature_vector(telemetry)
        vec_scaled = self.scaler.transform(vec.reshape(1, -1))
        decision_val = float(self.iso_forest.decision_function(vec_scaled)[0])
        prob = self._decision_to_prob(decision_val)
        risk_score = int(round(max(0.0, min(100.0, prob * 100.0))))

        if risk_score >= 70:
            risk_level = "HIGH"
            verdict = "POTENTIAL MITM DETECTED"
            is_anomalous = True
        elif risk_score >= 45:
            risk_level = "MEDIUM"
            verdict = "SUSPICIOUS HANDSHAKE"
            is_anomalous = True
        else:
            risk_level = "LOW"
            verdict = "NORMAL"
            is_anomalous = False

        indicators = self._explain_indicators(vec)
        return DetectionVerdict(
            risk_score=risk_score,
            risk_level=risk_level,
            verdict=verdict,
            is_anomalous=is_anomalous,
            raw_anomaly_score=round(decision_val, 4),
            indicators=indicators,
        )

    def _explain_indicators(self, vec: np.ndarray, top_k: int = 4) -> list[dict[str, Any]]:
        """Identify top features deviating from the learned normal baseline."""
        assert self.baseline_mean is not None and self.baseline_std is not None
        z_scores = (vec - self.baseline_mean) / self.baseline_std

        ranked_indices = np.argsort(-np.maximum(z_scores, 0.0))
        indicators: list[dict[str, Any]] = []
        for idx in ranked_indices:
            z = float(z_scores[idx])
            if z < 1.5:
                continue
            fname = FEATURE_NAMES[idx]
            spec = FEATURE_SPEC_MAP[fname]
            indicators.append(
                {
                    "feature": fname,
                    "category": spec.category,
                    "label": spec.indicator_label,
                    "z_score": round(z, 2),
                    "observed": round(float(vec[idx]), 2),
                    "baseline_mean": round(float(self.baseline_mean[idx]), 2),
                    "severity": "high" if z >= 3.0 else "medium",
                }
            )
            if len(indicators) >= top_k:
                break

        return indicators

    def save(self, path: Path = DEFAULT_MODEL_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as f:
            pickle.dump(self, f)

    @classmethod
    def load_or_train(cls, path: Path = DEFAULT_MODEL_PATH) -> "DHMitmDetector":
        if path.exists():
            with path.open("rb") as f:
                detector = pickle.load(f)
                if isinstance(detector, cls) and detector.is_trained:
                    return detector
        detector = cls()
        detector.fit_and_evaluate()
        detector.save(path)
        return detector
