import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "compliance.db")

conn = sqlite3.connect(DB_PATH)

tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
print("Tables found:", tables)
print()

for (table_name,) in tables:
    count = conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
    print(f"{table_name}: {count} rows")

conn.close()