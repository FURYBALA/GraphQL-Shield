import os
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.seed import seed_database
from app.config import settings
from app.core.security import create_access_token
from app.security.anomaly_engine import analyze_events, analyze_from_db

client = TestClient(app)


def _row(user_id, role, object_id, decision, ts, risk_score=0, path="resource"):
    return {
        "user_id": user_id,
        "role": role,
        "object_id": object_id,
        "path": path,
        "decision": decision,
        "reason": "OWNERSHIP_MISMATCH" if decision == "DENY" else "OWNER_MATCH",
        "risk_score": risk_score,
        "risk_level": "HIGH" if risk_score >= 60 else "LOW",
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
    }


def _attacker_rows():
    base = datetime(2026, 10, 14, 10, 0, 0)
    rows = []
    for i in range(12):
        decision = "ALLOW" if i < 6 else "DENY"
        rows.append(_row(102, "user", 100 + i, decision, base + timedelta(seconds=i * 10),
                         risk_score=0 if decision == "ALLOW" else 80))
    return rows


def _benign_rows():
    base = datetime(2026, 10, 14, 10, 0, 0)
    return [
        _row(101, "user", 101, "ALLOW", base + timedelta(seconds=i * 30))
        for i in range(5)
    ]


def test_attacker_flagged_benign_not():
    report = analyze_events(_attacker_rows() + _benign_rows())
    by_user = {p.user_id: p for p in report.principals}

    assert by_user[102].anomaly_level == "HIGH"
    assert by_user[102].anomaly_score >= 60
    assert by_user[101].anomaly_level == "LOW"
    assert by_user[101].anomaly_score < 30
    assert by_user[102].anomaly_score > by_user[101].anomaly_score


def test_high_velocity_enumeration_pattern_label():
    report = analyze_events(_attacker_rows() + _benign_rows())
    attacker = next(p for p in report.principals if p.user_id == 102)
    assert attacker.pattern in {"HIGH_VELOCITY_ENUMERATION", "SUSTAINED_AUTHORIZATION_ABUSE"}


def test_empty_population_is_safe():
    report = analyze_events([])
    assert report.analyzed_events == 0
    assert report.population_size == 0
    assert report.principals == []


def test_single_principal_uses_absolute_fallback_and_flags_recon():
    rows = []
    base = datetime(2026, 10, 14, 10, 0, 0)
    for i in range(10):
        rows.append(_row(999, "user", 200 + i, "ALLOW", base + timedelta(seconds=i * 5)))
    report = analyze_events(rows)
    assert report.baseline_mode == "absolute_fallback"
    assert len(report.principals) == 1
    assert report.principals[0].anomaly_level == "HIGH"


def test_temporal_drift_contributes_for_escalation():
    base = datetime(2026, 10, 14, 10, 0, 0)
    rows = []
    for i in range(10):
        decision = "ALLOW" if i < 5 else "DENY"
        rows.append(_row(555, "user", 101, decision, base + timedelta(seconds=i * 20),
                         risk_score=0 if decision == "ALLOW" else 80))
    report = analyze_events(rows)
    p = report.principals[0]
    assert p.features["deny_trend"] > 0
    assert p.component_scores["deny_trend"] > 0


def test_identical_input_is_deterministic():
    a = analyze_events(_attacker_rows() + _benign_rows()).to_dict()
    b = analyze_events(_attacker_rows() + _benign_rows()).to_dict()
    a.pop("generated_at")
    b.pop("generated_at")
    assert a == b


@pytest.fixture
def seeded_db():
    original_url = settings.DATABASE_URL
    settings.DATABASE_URL = "sqlite:///./test_anomaly.db"
    seed_database()
    yield
    db_file = settings.DATABASE_URL.replace("sqlite:///", "")
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except PermissionError:
            pass
    settings.DATABASE_URL = original_url


def test_analyze_from_db_reads_real_table(seeded_db):
    from app.database import get_db_connection
    from app.security.audit import log_decision

    log_decision(101, "user", "query", "Resource", 101, "resource", "ALLOW", "OWNER_MATCH", 0, "LOW")
    log_decision(101, "user", "query", "Resource", 102, "resource", "DENY", "OWNERSHIP_MISMATCH", 80, "HIGH")

    conn = get_db_connection()
    try:
        report = analyze_from_db(conn)
    finally:
        conn.close()
    assert report.analyzed_events >= 2
    assert any(p.user_id == 101 for p in report.principals)


def test_anomaly_endpoint_requires_admin(seeded_db):
    user_token = create_access_token(user_id=101, role="user")
    admin_token = create_access_token(user_id=103, role="admin")

    assert client.get("/api/v1/security/anomaly", headers={"Authorization": f"Bearer {user_token}"}).status_code == 403
    resp = client.get("/api/v1/security/anomaly", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert "principals" in body
    assert "baseline_mode" in body


def test_dashboard_stats_expose_anomaly(seeded_db):
    resp = client.get("/api/v1/dashboard-stats")
    assert resp.status_code == 200
    assert "anomaly" in resp.json()
