import sqlite3, os

DB = os.path.join("database", "event_logs.db")
conn = sqlite3.connect(DB)
cur = conn.cursor()

cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
tables = [r[0] for r in cur.fetchall()]
print("所有表：")
for t in tables:
    print(" -", t)

print()
for t in tables:
    cur.execute(f"SELECT COUNT(*) FROM {t}")
    print(f"{t}: {cur.fetchone()[0]} 条")

conn.close()