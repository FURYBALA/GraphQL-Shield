"""Empirical evaluation of adaptive behavioural anomaly detection vs the static baseline.

Method
------
Real traffic is generated through the *actual* FastAPI gateway using a TestClient, so
every audit row used in the comparison is produced by the real enforcement middleware
and the real deterministic risk engine. Two detection approaches are then compared on
the identical audit stream:

* **Baseline (static, per-event):** a principal is flagged if the *maximum* single-event
  risk score it generated is HIGH (>= 60). This is exactly what the shipped
  ``risk_engine`` produces per request; it has no memory across requests.

* **Adaptive (principal-level behavioural):** a principal is flagged if the anomaly
  engine (``app/security/anomaly_engine.py``) assigns a HIGH (>= 60) anomaly score from
  aggregate behaviour (deny ratio, target breadth, velocity, temporal drift).

The script reports detection on two attack behaviours and false positives on benign
traffic, and writes ``anomaly_evaluation.json``. Every number is measured, not assumed.
"""

import io
import json
import os
import sys
from contextlib import redirect_stdout
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient

from app.config import settings
from app.core.security import create_access_token
from app.database import get_db_connection
from app.main import app
from app.security.anomaly_engine import analyze_from_db
from app.seed import seed_database

EVAL_DB = "sqlite:///./anomaly_eval.db"
STATIC_FLAG_THRESHOLD = 60
ADAPTIVE_FLAG_THRESHOLD = 60

ATTACK_PRINCIPALS = {102, 104}
BENIGN_PRINCIPALS = {101, 103}


def _prepare_db():
    settings.DATABASE_URL = EVAL_DB
    db_file = EVAL_DB.replace("sqlite:///", "")
    if os.path.exists(db_file):
        os.remove(db_file)
    seed_database()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
        (104, "mallory", "hash_mallory123", "user"),
    )
    for i in range(15):
        cursor.execute(
            "INSERT INTO objects (id, object_type, owner_id, name, parent_id) VALUES (?, ?, ?, ?, ?)",
            (300 + i, "document", 102, f"Bob Owned Record {i}", None),
        )
    conn.commit()
    conn.close()


def _run_query(client, token, query):
    with redirect_stdout(io.StringIO()):
        return client.post(
            "/graphql",
            json={"query": query},
            headers={"Authorization": f"Bearer {token}"},
        )


def _generate_traffic(client):
    tokens = {
        101: create_access_token(user_id=101, role="user"),
        102: create_access_token(user_id=102, role="user"),
        103: create_access_token(user_id=103, role="admin"),
        104: create_access_token(user_id=104, role="user"),
    }
    traffic_log = {}

    # Benign: Alice reads only her own objects at a normal pace.
    for oid in (101, 201, 202):
        _run_query(client, tokens[101], "{ resource(id: %d) { id name } }" % oid)
    traffic_log["benign_alice_own_reads"] = 3

    # Benign: admin performs two authorized admin reads.
    for oid in (102, 103):
        _run_query(client, tokens[103], "{ resource(id: %d) { id name } }" % oid)
    traffic_log["benign_admin_reads"] = 2

    # Attack A: direct BOLA burst - Mallory enumerates foreign objects.
    for oid in (101, 102, 103, 201, 202, 203):
        _run_query(client, tokens[104], "{ resource(id: %d) { id name } }" % oid)
    traffic_log["attack_direct_bola_foreign_reads"] = 6

    # Attack B: mass authorized enumeration - Bob rapidly reads every record he owns.
    # Every request is legitimately authorized (ALLOW, risk 0): the static per-event
    # engine sees nothing wrong, while the aggregate behaviour is anomalous.
    for i in range(15):
        _run_query(client, tokens[102], "{ resource(id: %d) { id name } }" % (300 + i))
    traffic_log["attack_mass_authorized_enumeration"] = 15

    return traffic_log


def _static_baseline(rows):
    by_user = {}
    for r in rows:
        uid = r["user_id"]
        current = by_user.get(uid, {"max_risk": 0, "events": 0, "denies": 0})
        current["max_risk"] = max(current["max_risk"], int(r["risk_score"] or 0))
        current["events"] += 1
        current["denies"] += 1 if (r["decision"] or "").upper() == "DENY" else 0
        by_user[uid] = current
    return by_user


def _metrics(detections):
    tp = sum(1 for uid in ATTACK_PRINCIPALS if detections.get(uid, False))
    fn = len(ATTACK_PRINCIPALS) - tp
    fp = sum(1 for uid in BENIGN_PRINCIPALS if detections.get(uid, False))
    tn = len(BENIGN_PRINCIPALS) - fp
    tpr = tp / len(ATTACK_PRINCIPALS) if ATTACK_PRINCIPALS else 0.0
    fpr = fp / len(BENIGN_PRINCIPALS) if BENIGN_PRINCIPALS else 0.0
    return {
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "true_negatives": tn,
        "detection_rate_pct": round(tpr * 100, 1),
        "false_positive_rate_pct": round(fpr * 100, 1),
    }


def main():
    _prepare_db()
    client = TestClient(app)

    traffic_log = _generate_traffic(client)

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT user_id, role, object_id, path, decision, reason, risk_score, risk_level, timestamp "
            "FROM audit_logs ORDER BY timestamp ASC"
        )
        rows = [dict(row) for row in cursor.fetchall()]

        baseline = _static_baseline(rows)
        adaptive_report = analyze_from_db(conn, window_minutes=30).to_dict()
    finally:
        conn.close()

    adaptive_by_user = {p["user_id"]: p for p in adaptive_report["principals"]}

    static_detections = {
        uid: baseline.get(uid, {}).get("max_risk", 0) >= STATIC_FLAG_THRESHOLD
        for uid in list(ATTACK_PRINCIPALS) + list(BENIGN_PRINCIPALS)
    }
    adaptive_detections = {
        uid: adaptive_by_user.get(uid, {}).get("anomaly_score", 0) >= ADAPTIVE_FLAG_THRESHOLD
        for uid in list(ATTACK_PRINCIPALS) + list(BENIGN_PRINCIPALS)
    }

    principal_table = []
    for uid in sorted(set(list(ATTACK_PRINCIPALS) + list(BENIGN_PRINCIPALS))):
        b = baseline.get(uid, {})
        a = adaptive_by_user.get(uid, {})
        principal_table.append({
            "user_id": uid,
            "ground_truth": "attack" if uid in ATTACK_PRINCIPALS else "benign",
            "events": b.get("events", 0),
            "max_static_risk": b.get("max_risk", 0),
            "static_flagged": static_detections.get(uid, False),
            "adaptive_score": a.get("anomaly_score", 0),
            "adaptive_level": a.get("anomaly_level", "LOW"),
            "adaptive_pattern": a.get("pattern", "NO_PATTERN"),
            "adaptive_flagged": adaptive_detections.get(uid, False),
        })

    result = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "method": (
            "Real traffic generated through the live gateway (TestClient). Baseline = maximum "
            "single-event static risk score; adaptive = principal-level behavioural anomaly score. "
            "Flag threshold = 60 (HIGH) for both."
        ),
        "traffic_generated": traffic_log,
        "total_audit_events": len(rows),
        "flag_threshold": {"static": STATIC_FLAG_THRESHOLD, "adaptive": ADAPTIVE_FLAG_THRESHOLD},
        "principals": principal_table,
        "static_baseline_metrics": _metrics(static_detections),
        "adaptive_metrics": _metrics(adaptive_detections),
    }

    with open("anomaly_evaluation.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print("=" * 72)
    print("Adaptive Behavioural Anomaly Detection - Empirical Evaluation")
    print("=" * 72)
    print(f"Audit events analysed: {len(rows)}")
    print()
    print(f"{'User':>5} {'Truth':>7} {'Events':>7} {'MaxStatic':>10} {'Static':>7} "
          f"{'Adaptive':>9} {'Level':>7}  Pattern")
    print("-" * 72)
    for row in principal_table:
        print(f"{row['user_id']:>5} {row['ground_truth']:>7} {row['events']:>7} "
              f"{row['max_static_risk']:>10} {str(row['static_flagged']):>7} "
              f"{row['adaptive_score']:>9} {row['adaptive_level']:>7}  {row['adaptive_pattern']}")
    print("-" * 72)
    sm, am = result["static_baseline_metrics"], result["adaptive_metrics"]
    print(f"Static baseline : detection {sm['detection_rate_pct']}%  "
          f"false-positive {sm['false_positive_rate_pct']}%")
    print(f"Adaptive engine : detection {am['detection_rate_pct']}%  "
          f"false-positive {am['false_positive_rate_pct']}%")
    print()
    print("Written to anomaly_evaluation.json")

    settings.DATABASE_URL = "sqlite:///./shield.db"


if __name__ == "__main__":
    main()
