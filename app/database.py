import sqlite3
import os

DB_FILE = "database.db"

def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    # Remove existing db for clean demo start
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        
    conn = get_db()
    cursor = conn.cursor()
    
    # Create Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT,
            email TEXT,
            password TEXT
        )
    ''')
    
    # Create Objects table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS objects (
            id INTEGER PRIMARY KEY,
            name TEXT,
            owner_id INTEGER,
            data TEXT
        )
    ''')
    
    # Create Audit Logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            object_id INTEGER,
            decision TEXT,
            reason TEXT
        )
    ''')
    
    # Insert sample users
    users = [
        (101, "Alice", "alice@example.com", "alice123"),
        (102, "Bob", "bob@example.com", "bob123")
    ]
    cursor.executemany("INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)", users)
    
    # Insert sample objects
    objects = [
        (501, "Alice's Secret Note 1", 101, "Confidential data A1"),
        (502, "Alice's Secret Note 2", 101, "Confidential data A2"),
        (601, "Bob's Financial Record 1", 102, "Confidential data B1"),
        (602, "Bob's Financial Record 2", 102, "Confidential data B2")
    ]
    cursor.executemany("INSERT INTO objects (id, name, owner_id, data) VALUES (?, ?, ?, ?)", objects)
    
    conn.commit()
    conn.close()
