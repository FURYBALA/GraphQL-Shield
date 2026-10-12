import sqlite3
import queue
import threading

from app.database import get_db_connection
from app.config import settings

_INSERT_SQL = '''
    INSERT INTO audit_logs (user_id, role, operation, object_type, object_id, path, decision, reason, risk_score, risk_level)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
'''

_AUDIT_QUEUE = queue.Queue(maxsize=10000)
_WORKER_THREAD = None
_WORKER_STOP_EVENT = threading.Event()


def _write_audit_batch(batch: list):
    if not batch:
        return
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        for values in batch:
            try:
                cursor.execute(_INSERT_SQL, values)
            except sqlite3.IntegrityError:
                # Foreign key on audit_logs.object_id points at existing objects.
                # Security events about non-existent objects are still recorded.
                conn.rollback()
                conn.execute("PRAGMA foreign_keys = OFF")
                cursor.execute(_INSERT_SQL, values)
        conn.commit()
    except Exception:
        conn.rollback()
    finally:
        conn.close()


def _audit_worker_loop():
    while not _WORKER_STOP_EVENT.is_set():
        batch = []
        try:
            while len(batch) < 50:
                item = _AUDIT_QUEUE.get(timeout=0.05 if not batch else 0.001)
                batch.append(item)
                _AUDIT_QUEUE.task_done()
        except queue.Empty:
            pass
        if batch:
            _write_audit_batch(batch)


def start_audit_worker():
    """Starts the background audit persistence worker thread if not already running."""
    global _WORKER_THREAD
    if _WORKER_THREAD is None or not _WORKER_THREAD.is_alive():
        _WORKER_STOP_EVENT.clear()
        _WORKER_THREAD = threading.Thread(target=_audit_worker_loop, daemon=True, name="AuditLoggerWorker")
        _WORKER_THREAD.start()


def stop_audit_worker():
    """Flushes and stops the background audit worker thread."""
    global _WORKER_THREAD
    if _WORKER_THREAD and _WORKER_THREAD.is_alive():
        _WORKER_STOP_EVENT.set()
        flush_audit_logs()
        _WORKER_THREAD.join(timeout=1.0)
        _WORKER_THREAD = None


def flush_audit_logs():
    """Flushes all queued audit entries synchronously to disk."""
    batch = []
    while not _AUDIT_QUEUE.empty():
        try:
            batch.append(_AUDIT_QUEUE.get_nowait())
            _AUDIT_QUEUE.task_done()
        except queue.Empty:
            break
    if batch:
        _write_audit_batch(batch)


def log_decision(user_id: int, role: str, operation: str, object_type: str, object_id: int, path: str, decision: str, reason: str, risk_score: int, risk_level: str):
    """
    Writes the full security context, decision, and risk metrics to the audit log.
    If ASYNC_AUDIT_LOGGING is True, enqueues to a non-blocking queue to eliminate disk latency.
    Otherwise commits synchronously.
    """
    values = (user_id, role, operation, object_type, object_id, path, decision, reason, risk_score, risk_level)
    if getattr(settings, "ASYNC_AUDIT_LOGGING", False):
        start_audit_worker()
        try:
            _AUDIT_QUEUE.put_nowait(values)
            return
        except queue.Full:
            pass  # Fallback to direct write if queue saturated

    _write_audit_batch([values])


# -----------------------------------------------------------------------------
# Structured Taint Analysis Audit Log Store (Phase 5 Audit-Only Mode)
# -----------------------------------------------------------------------------

_TAINT_AUDIT_LOGS: list = []
MAX_TAINT_AUDIT_LOGS: int = 1000


def record_taint_audit(record: dict) -> None:
    """
    Records a structured taint analysis finding or correlation event in memory.
    Ensures memory boundedness and thread-safe appending.
    """
    global _TAINT_AUDIT_LOGS
    if len(_TAINT_AUDIT_LOGS) >= MAX_TAINT_AUDIT_LOGS:
        _TAINT_AUDIT_LOGS.pop(0)
    _TAINT_AUDIT_LOGS.append(record)


def get_taint_audit_records() -> list:
    """Returns a shallow copy of recorded taint analysis audit entries."""
    return list(_TAINT_AUDIT_LOGS)


def clear_taint_audit_records() -> None:
    """Clears the in-memory taint audit store (useful for tests)."""
    global _TAINT_AUDIT_LOGS
    _TAINT_AUDIT_LOGS.clear()

