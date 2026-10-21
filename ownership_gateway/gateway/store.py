"""Module 5: Security event store (SQLite). Feeds the dashboard and the evaluation."""
import json
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          REAL NOT NULL,
  uid         TEXT,
  role        TEXT,
  mode        TEXT NOT NULL,
  operation   TEXT,          -- query | mutation | batch
  query       TEXT,
  decision    TEXT NOT NULL, -- allowed | redacted | blocked
  reason      TEXT,
  violations  TEXT,          -- JSON list
  latency_ms  REAL,
  test_case   TEXT           -- attack/benign case id when sent by the attack lab or evaluator
);
CREATE TABLE IF NOT EXISTS alerts (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      REAL NOT NULL,
  uid     TEXT,
  kind    TEXT,
  detail  TEXT
);
"""


class Store:
    def __init__(self, path):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.conn.executescript(SCHEMA)

    def log_request(self, **row):
        row.setdefault("ts", time.time())
        row["violations"] = json.dumps(row.get("violations") or [])
        cols = ",".join(row)
        with self.lock:
            self.conn.execute(f"INSERT INTO requests ({cols}) VALUES ({','.join('?' * len(row))})", list(row.values()))
            self.conn.commit()

    def log_alert(self, uid, kind, detail):
        with self.lock:
            self.conn.execute("INSERT INTO alerts (ts, uid, kind, detail) VALUES (?,?,?,?)", (time.time(), uid, kind, detail))
            self.conn.commit()

    def recent(self, limit=50):
        with self.lock:
            rows = self.conn.execute("SELECT * FROM requests ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{**dict(r), "violations": json.loads(r["violations"])} for r in rows]

    def alerts(self, limit=20):
        with self.lock:
            rows = self.conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def stats(self):
        with self.lock:
            total = self.conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
            by = dict(self.conn.execute("SELECT decision, COUNT(*) FROM requests GROUP BY decision").fetchall())
            avg = self.conn.execute("SELECT AVG(latency_ms) FROM requests").fetchone()[0]
            vio = self.conn.execute("SELECT COALESCE(SUM(json_array_length(violations)),0) FROM requests").fetchone()[0]
            alerts = self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            types = self.conn.execute(
                "SELECT json_extract(v.value,'$.type') t, COUNT(*) FROM requests, json_each(requests.violations) v GROUP BY t").fetchall()
        return {"total": total, "allowed": by.get("allowed", 0), "redacted": by.get("redacted", 0),
                "blocked": by.get("blocked", 0), "violations": vio, "alerts": alerts,
                "avg_latency_ms": round(avg or 0, 2), "violations_by_type": {t: c for t, c in types if t}}

    def clear(self):
        with self.lock:
            self.conn.executescript("DELETE FROM requests; DELETE FROM alerts;")
            self.conn.commit()
