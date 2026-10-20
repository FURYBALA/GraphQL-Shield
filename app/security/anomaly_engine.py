"""Adaptive behavioral anomaly detection over the gateway's live audit stream.

The deterministic per-event ``risk_engine`` scores every authorization decision in
isolation: an ownership mismatch is "80 / HIGH", a clean access is "0 / LOW". That
is sufficient for single-request BOLA, but it has no *principal-level memory*. It
cannot distinguish a one-off mistake from sustained abuse, and it assigns risk 0 to
a compromised account that stays fully authorized while enumerating every record it
can reach (mass data access), or to a low-and-slow scan that hides between benign
reads.

This module adds a complementary, unsupervised behavioral layer. It aggregates the
real audit events the gateway has already persisted and derives, per authenticated
principal, an anomaly score from four behavioural signals:

* ``deny_ratio``      - share of the principal's requests that were denied
* ``target_breadth``  - number of distinct object identifiers requested
* ``velocity``        - requests per minute within the principal's own activity span
* ``deny_trend``      - escalation of the deny ratio in the recent half of the history

Two adaptive mechanisms are used rather than a fixed score table:

1. **Robust peer-relative baseline** - each feature is turned into a median/MAD
   robust z-score against the observed population of principals, so the "normal"
   reference moves with the traffic instead of being hard-coded.
2. **Temporal drift** - the deny trend compares a principal against its *own* earlier
   behaviour, so a stable principal that suddenly turns abusive is detected even
   when its absolute numbers are unremarkable.

Each feature's deviation is the maximum of its peer-relative z-score and its value
expressed in *absolute behavioural units* (value / a documented threshold). The
absolute term is a floor: it keeps the engine usable during cold start or on a tiny
population (for example the three seeded demo users) where a robust z-score against a
two-point population saturates and cannot separate an outlier from its single peer.
On realistic population sizes the peer-relative term dominates and the reference
adapts to observed traffic. The per-feature contributions are combined as a blend of
the weighted mean and the peak signal, so a single unmistakable indicator (for
example extreme target breadth) is not diluted by otherwise ordinary features.

The layer is strictly advisory: it never grants, denies, or mutates an enforcement
decision. It reads persisted audit rows only.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

FEATURE_WEIGHTS: Dict[str, float] = {
    "deny_ratio": 0.35,
    "target_breadth": 0.25,
    "velocity": 0.20,
    "deny_trend": 0.20,
}

FEATURE_EPSILON: Dict[str, float] = {
    "deny_ratio": 0.05,
    "target_breadth": 1.0,
    "velocity": 2.0,
    "deny_trend": 0.10,
}

# Absolute fallback thresholds, used only when the population is too small
# (fewer than two principals) for a peer-relative baseline to be meaningful.
ABSOLUTE_TARGET_BREADTH_THRESHOLD = 4
ABSOLUTE_VELOCITY_THRESHOLD = 6.0
ABSOLUTE_DENY_RATIO_THRESHOLD = 0.5
ABSOLUTE_DENY_TREND_THRESHOLD = 0.4

MAD_SCALE = 1.4826  # makes MAD a consistent estimator of sigma for normal data

AGGREGATION_MAX_WEIGHT = 0.4  # blend of weighted mean and peak feature signal

HIGH_THRESHOLD = 60
MEDIUM_THRESHOLD = 30

_PATTERN_VELOCITY_MIN = 6.0
_PATTERN_BREADTH_MIN = 4


@dataclass
class PrincipalAnomaly:
    """Behavioural assessment of a single authenticated principal."""

    user_id: Optional[int]
    role: str
    event_count: int
    features: Dict[str, float]
    component_scores: Dict[str, float]
    anomaly_score: int
    anomaly_level: str
    pattern: str
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "role": self.role,
            "event_count": self.event_count,
            "features": {k: round(v, 4) for k, v in self.features.items()},
            "component_scores": {k: round(v, 2) for k, v in self.component_scores.items()},
            "anomaly_score": self.anomaly_score,
            "anomaly_level": self.anomaly_level,
            "pattern": self.pattern,
            "explanation": self.explanation,
        }


@dataclass
class AnomalyReport:
    """Aggregate anomaly assessment over an audit window."""

    window_minutes: int
    analyzed_events: int
    population_size: int
    baseline_mode: str
    generated_at: str
    principals: List[PrincipalAnomaly] = field(default_factory=list)

    @property
    def flagged(self) -> List[PrincipalAnomaly]:
        return [p for p in self.principals if p.anomaly_level == "HIGH"]

    def to_dict(self) -> Dict[str, Any]:
        ordered = sorted(self.principals, key=lambda p: p.anomaly_score, reverse=True)
        return {
            "window_minutes": self.window_minutes,
            "analyzed_events": self.analyzed_events,
            "population_size": self.population_size,
            "baseline_mode": self.baseline_mode,
            "generated_at": self.generated_at,
            "flagged_count": len(self.flagged),
            "principals": [p.to_dict() for p in ordered],
        }


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    text = str(value).strip().replace("T", " ")
    if "." in text:
        text = text.split(".")[0]
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _path_depth(path: Optional[str]) -> int:
    if not path:
        return 1
    return path.count(".") + 1


def _principal_rows(rows: Sequence[Dict[str, Any]]) -> Dict[Optional[int], List[Dict[str, Any]]]:
    grouped: Dict[Optional[int], List[Dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row.get("user_id"), []).append(row)
    return grouped


def _extract_features(events: List[Dict[str, Any]], window_minutes: int) -> Dict[str, float]:
    total = len(events)
    denies = sum(1 for e in events if (e.get("decision") or "").upper() == "DENY")
    targets = {e.get("object_id") for e in events if e.get("object_id") is not None}

    timestamps = [ts for ts in (_parse_timestamp(e.get("timestamp")) for e in events) if ts]
    if len(timestamps) >= 2:
        span_minutes = (max(timestamps) - min(timestamps)).total_seconds() / 60.0
    else:
        span_minutes = 0.0
    span_minutes = max(span_minutes, 1.0)

    ordered = sorted(events, key=lambda e: _parse_timestamp(e.get("timestamp")) or datetime.min)
    half = max(1, len(ordered) // 2)
    older, recent = ordered[:half], ordered[half:] or ordered
    older_deny = sum(1 for e in older if (e.get("decision") or "").upper() == "DENY") / len(older)
    recent_deny = sum(1 for e in recent if (e.get("decision") or "").upper() == "DENY") / len(recent)

    return {
        "deny_ratio": denies / total if total else 0.0,
        "target_breadth": float(len(targets)),
        "velocity": total / span_minutes,
        "deny_trend": recent_deny - older_deny,
    }


def _robust_baseline(values: Sequence[float]) -> Tuple[float, float]:
    if not values:
        return 0.0, 1.0
    median = statistics.median(values)
    deviations = [abs(v - median) for v in values]
    mad = statistics.median(deviations)
    scale = MAD_SCALE * mad
    return median, scale


def _saturating_component(z: float) -> float:
    if z <= 0:
        return 0.0
    return 100.0 * (1.0 - math.exp(-z))


def _classify(score: int) -> str:
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    if score >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def _label_pattern(features: Dict[str, float]) -> str:
    if features["deny_ratio"] >= ABSOLUTE_DENY_RATIO_THRESHOLD:
        return "SUSTAINED_AUTHORIZATION_ABUSE"
    if (
        features["target_breadth"] >= _PATTERN_BREADTH_MIN
        and features["velocity"] >= _PATTERN_VELOCITY_MIN
    ):
        return "HIGH_VELOCITY_ENUMERATION"
    if features["target_breadth"] >= ABSOLUTE_TARGET_BREADTH_THRESHOLD:
        return "BROAD_TARGET_SCAN"
    if features["deny_trend"] >= ABSOLUTE_DENY_TREND_THRESHOLD:
        return "ESCALATING_DENY_PATTERN"
    return "NO_PATTERN"


def _explain(features: Dict[str, float], components: Dict[str, float], mode: str) -> str:
    drivers = sorted(components.items(), key=lambda kv: kv[1], reverse=True)
    top = ", ".join(f"{name}={components[name]:.0f}" for name, _ in drivers[:2])
    return (
        f"{mode} scoring. Dominant signals: {top}. "
        f"(deny_ratio={features['deny_ratio']:.2f}, "
        f"breadth={features['target_breadth']:.0f} targets, "
        f"velocity={features['velocity']:.1f}/min, "
        f"deny_trend={features['deny_trend']:+.2f})."
    )


def analyze_events(
    rows: Iterable[Dict[str, Any]],
    *,
    window_minutes: int = 30,
    now: Optional[datetime] = None,
    weights: Optional[Dict[str, float]] = None,
) -> AnomalyReport:
    """Compute a principal-level behavioural anomaly report from audit rows.

    ``rows`` are audit-log dictionaries (as returned by ``sqlite3.Row`` converted with
    ``dict()``). The function is pure: identical input rows always produce identical
    output, which makes it directly testable.
    """

    active_weights = dict(weights or FEATURE_WEIGHTS)
    effective_now = now or datetime.now()
    cutoff = effective_now - timedelta(minutes=window_minutes) if now else None

    usable: List[Dict[str, Any]] = []
    for row in rows:
        ts = _parse_timestamp(row.get("timestamp"))
        if cutoff is not None and ts is not None and ts < cutoff:
            continue
        usable.append(dict(row))

    grouped = _principal_rows(usable)
    feature_table: Dict[Optional[int], Dict[str, float]] = {
        uid: _extract_features(events, window_minutes) for uid, events in grouped.items()
    }

    population_mode = "hybrid" if len(feature_table) >= 2 else "absolute_fallback"

    baselines: Dict[str, Tuple[float, float]] = {}
    for feature, eps in FEATURE_EPSILON.items():
        values = [ft[feature] for ft in feature_table.values()]
        median, scale = _robust_baseline(values)
        baselines[feature] = (median, max(scale, eps))

    principals: List[PrincipalAnomaly] = []
    total_weight = sum(active_weights.values()) or 1.0

    for uid, events in grouped.items():
        features = feature_table[uid]
        components: Dict[str, float] = {}

        for feature, weight in active_weights.items():
            deviation = _absolute_units(feature, features[feature])
            if population_mode == "hybrid":
                median, scale = baselines[feature]
                z_peer = (features[feature] - median) / scale
                deviation = max(deviation, z_peer)
            components[feature] = _saturating_component(deviation)

        weighted = sum(components[f] * w for f, w in active_weights.items()) / total_weight
        peak = max(components.values()) if components else 0.0
        blended = (1 - AGGREGATION_MAX_WEIGHT) * weighted + AGGREGATION_MAX_WEIGHT * peak
        score = int(min(100, max(0, round(blended))))

        role = ""
        for e in events:
            if e.get("role"):
                role = e["role"]
                break

        principals.append(
            PrincipalAnomaly(
                user_id=uid,
                role=role,
                event_count=len(events),
                features=features,
                component_scores=components,
                anomaly_score=score,
                anomaly_level=_classify(score),
                pattern=_label_pattern(features),
                explanation=_explain(features, components, population_mode),
            )
        )

    return AnomalyReport(
        window_minutes=window_minutes,
        analyzed_events=len(usable),
        population_size=len(grouped),
        baseline_mode=population_mode,
        generated_at=effective_now.strftime("%Y-%m-%d %H:%M:%S"),
        principals=principals,
    )


def _absolute_units(feature: str, value: float) -> float:
    """Map an absolute feature value to z-units for the small-population fallback."""
    if feature == "deny_ratio":
        return value / ABSOLUTE_DENY_RATIO_THRESHOLD
    if feature == "target_breadth":
        return value / ABSOLUTE_TARGET_BREADTH_THRESHOLD
    if feature == "velocity":
        return value / ABSOLUTE_VELOCITY_THRESHOLD
    if feature == "deny_trend":
        return value / ABSOLUTE_DENY_TREND_THRESHOLD
    return 0.0


def analyze_from_db(connection, *, window_minutes: int = 30, limit: int = 5000) -> AnomalyReport:
    """Convenience wrapper reading directly from the ``audit_logs`` table.

    SQLite's ``CURRENT_TIMESTAMP`` stores naive UTC, so the reference "now" is taken
    as naive UTC as well to keep the window comparison in a single time basis.
    """
    cursor = connection.cursor()
    cursor.execute(
        "SELECT user_id, role, object_id, path, decision, reason, risk_score, risk_level, timestamp "
        "FROM audit_logs ORDER BY timestamp DESC LIMIT ?",
        (limit,),
    )
    columns = [col[0] for col in cursor.description]
    rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    return analyze_events(rows, window_minutes=window_minutes, now=now_utc)
