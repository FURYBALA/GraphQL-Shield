from .database import get_db

def log_audit(user_id: int, object_id: int, decision: str, reason: str):
    """
    Simple audit log to track security decisions.
    Required by professor to show detection and prevention.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO audit_logs (user_id, object_id, decision, reason)
        VALUES (?, ?, ?, ?)
    ''', (user_id, object_id, decision, reason))
    conn.commit()
    conn.close()
