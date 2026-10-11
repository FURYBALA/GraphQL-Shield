import sqlite3

from app.database import get_db_connection

_INSERT_SQL = '''
    INSERT INTO audit_logs (user_id, role, operation, object_type, object_id, path, decision, reason, risk_score, risk_level)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
'''


def log_decision(user_id: int, role: str, operation: str, object_type: str, object_id: int, path: str, decision: str, reason: str, risk_score: int, risk_level: str):
    """
    Writes the full security context, decision, and risk metrics to the audit log.

    Audit events must never be lost and must never crash the enforcement path:
    requests referencing objects that do not exist (e.g. reconnaissance probes)
    are still recorded even though the objects table cannot reference them.
    """
    values = (user_id, role, operation, object_type, object_id, path, decision, reason, risk_score, risk_level)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        try:
            cursor.execute(_INSERT_SQL, values)
            conn.commit()
        except sqlite3.IntegrityError:
            # Foreign key on audit_logs.object_id points at existing objects.
            # Security events about non-existent objects are still recorded.
            conn.rollback()
            conn.execute("PRAGMA foreign_keys = OFF")
            cursor.execute(_INSERT_SQL, values)
            conn.commit()
    finally:
        conn.close()
