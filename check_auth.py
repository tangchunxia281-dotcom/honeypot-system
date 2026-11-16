import sqlite3, os

DB = os.path.join("database", "event_logs.db")
conn = sqlite3.connect(DB)
cur = conn.cursor()

print("=== 最近 15 条 SSH 认证相关事件 ===")
cur.execute("""
    SELECT id, timestamp, source, severity, event_type, src_ip, session_id, payload
    FROM event_log
    WHERE source='ssh'
      AND (event_type LIKE '%auth%' OR event_type LIKE '%login%')
    ORDER BY id DESC
    LIMIT 15
""")
for r in cur.fetchall():
    print(r)

conn.close()