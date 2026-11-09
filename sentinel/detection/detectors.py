"""Detectors. ScoringDetector is the template; each subclass only supplies fit() and _score() (Open/Closed)."""
from __future__ import annotations
from abc import abstractmethod
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.neural_network import MLPRegressor
from sentinel.config import Settings
from sentinel.domain.interfaces import Detector, FeatureExtractor
from sentinel.domain.models import Alert, Event, EventKind


class AnomalyCalibrator:
    """Maps raw anomaly scores to [0,1]: benign median -> 0, worst benign score -> 1/(1+margin), beyond -> toward 1.
    margin=1.0 puts the worst benign score at 0.5, so only clearly rarer events cross the alert threshold."""

    def fit(self, benign_scores: np.ndarray, margin: float = 1.5) -> "AnomalyCalibrator":
        self.lo = float(np.median(benign_scores))
        mx = float(np.max(benign_scores))
        self.hi = mx + margin * max(mx - self.lo, 1e-9)
        return self

    def __call__(self, s: float) -> float:
        return float(np.clip((s - self.lo) / (self.hi - self.lo), 0.0, 1.0))


class SafeScaler:
    """z-score with a floor on the spread, so a feature that is constant in normal data (e.g. 'remote_exec')
    still produces a large value the first time it appears."""

    def __init__(self, floor: float = 0.05) -> None:
        self.floor = floor

    def fit(self, X):
        self.mean, self.std = X.mean(axis=0), np.maximum(X.std(axis=0), self.floor)
        return self

    def transform(self, X):
        return (np.asarray(X) - self.mean) / self.std


class ScoringDetector(Detector):
    kind: EventKind

    def __init__(self, extractor: FeatureExtractor, settings: Settings) -> None:
        self.extractor, self.s = extractor, settings

    def supports(self, event: Event) -> bool:
        return event.kind == self.kind

    def reset(self) -> None:
        self.extractor.reset()

    @abstractmethod
    def fit(self, events: list[Event]) -> None: ...
    @abstractmethod
    def _score(self, x: list[float]) -> float: ...

    def _matrix(self, events: list[Event]):
        self.extractor.reset()
        evs = sorted((e for e in events if e.kind == self.kind), key=lambda e: e.ts)
        X = np.array([self.extractor.extract(e) for e in evs], dtype=float)
        y = np.array([e.is_malicious for e in evs], dtype=int)
        self.extractor.reset()
        return X, y

    def detect(self, e: Event) -> Alert | None:
        x = self.extractor.extract(e)            # always extract so window state stays current
        score = self._score(x)
        if score <= self.s.alert_threshold:
            return None
        feats = dict(zip(self.extractor.names, (round(v, 3) for v in x)))
        top = ", ".join(f"{k}={v}" for k, v in feats.items() if v)
        return Alert(event_id=e.id, ts=e.ts, detector=self.name, score=round(score, 4), confidence=round(score, 4),
                     uncertain=score < self.s.uncertain_upper, user=e.user, host=e.host, src_ip=e.src_ip,
                     dst_ip=e.dst_ip, features=feats, reason=f"{self.name} score={score:.2f} ({top})")


def build_classifier(seed: int):
    try:
        from xgboost import XGBClassifier
        return XGBClassifier(n_estimators=120, max_depth=4, learning_rate=0.1, eval_metric="logloss", random_state=seed)
    except ImportError:
        return HistGradientBoostingClassifier(random_state=seed)


class FlowDetector(ScoringDetector):
    name, kind = "flow-xgb", EventKind.FLOW

    def fit(self, events):
        X, y = self._matrix(events)
        self.model = CalibratedClassifierCV(build_classifier(self.s.seed), method="isotonic", cv=3).fit(X, y)

    def _score(self, x):
        return self.model.predict_proba([x])[0][1]


class AuthDetector(ScoringDetector):
    name, kind = "auth-iforest", EventKind.AUTH

    def fit(self, events):
        X, y = self._matrix(events)
        X = X[y == 0]
        self.model = IsolationForest(n_estimators=200, random_state=self.s.seed).fit(X)
        self.cal = AnomalyCalibrator().fit(-self.model.score_samples(X), margin=1.0)

    def _score(self, x):
        return self.cal(-self.model.score_samples([x])[0])


class EndpointDetector(ScoringDetector):
    name, kind = "endpoint-autoencoder", EventKind.ENDPOINT

    def fit(self, events):
        X, y = self._matrix(events)
        X = X[y == 0]
        self.scaler = SafeScaler().fit(X)
        Z = self.scaler.transform(X)
        self.model = MLPRegressor(hidden_layer_sizes=(4,), max_iter=800, random_state=self.s.seed).fit(Z, Z)
        self.cal = AnomalyCalibrator().fit(self._error(Z))

    def _error(self, Z):
        return ((self.model.predict(Z) - Z) ** 2).mean(axis=1)

    def _score(self, x):
        return self.cal(self._error(self.scaler.transform([x]))[0])
