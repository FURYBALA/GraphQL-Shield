import os
import sys

# Ensure the root directory is in the path to import app correctly when run directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.database import get_db_connection, init_db
from app.config import settings
from app.security.ownership import clear_ownership_cache

# Seed Users: (id, username, password_hash, role)
SEED_USERS = [
    (101, 'alice', 'hash_alice123', 'user'),
    (102, 'bob', 'hash_bob123', 'user'),
    (103, 'charlie', 'hash_charlie123', 'admin')
]

# Seed Objects (with some nested relationships): (id, object_type, owner_id, name, parent_id)
SEED_OBJECTS = [
    (101, 'document', 101, "Alice's Secret Note", None),
    (102, 'document', 102, "Bob's Financial Record", None),
    (103, 'document', 103, "Charlie's Admin Log", None),
    # Nested relationship: Alice has a folder that contains another document
    (201, 'folder', 101, "Alice's Projects", None),
    (202, 'document', 101, "Project Alpha Plan", 201),
    (203, 'document', 101, "Project Beta Plan", 201)
]


def restore_seed_rows():
    """
    Restores the seed users/objects in place (renamed, transferred or deleted rows come back)
    without dropping the database, so audit logs and any other data are preserved.
    Used by the ownership-gateway benchmark to undo mutation attacks between runs.
    """
    clear_ownership_cache()
    conn = get_db_connection()
    try:
        conn.executemany(
            "INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET username=excluded.username, password_hash=excluded.password_hash, role=excluded.role",
            SEED_USERS
        )
        conn.executemany(
            "INSERT INTO objects (id, object_type, owner_id, name, parent_id) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET object_type=excluded.object_type, owner_id=excluded.owner_id, "
            "name=excluded.name, parent_id=excluded.parent_id",
            SEED_OBJECTS
        )
        conn.commit()
    finally:
        conn.close()
    return {"users": len(SEED_USERS), "objects": len(SEED_OBJECTS)}


def seed_database():
    clear_ownership_cache()
    db_file = settings.DATABASE_URL.replace("sqlite:///", "")
    # Start fresh for development
    if os.path.exists(db_file):
        os.remove(db_file)
        
    init_db()
    # Research tables are otherwise only created at app startup; a fresh seed must include them too
    from app.security.research.persistence import init_research_db
    init_research_db()

    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.executemany(
        "INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
        SEED_USERS
    )
    cursor.executemany(
        "INSERT INTO objects (id, object_type, owner_id, name, parent_id) VALUES (?, ?, ?, ?, ?)",
        SEED_OBJECTS
    )
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    seed_database()
    print("Database successfully seeded.")
