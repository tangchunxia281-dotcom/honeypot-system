import sqlite3, os

conn = sqlite3.connect(os.path.join("database", "event_logs.db"))
cur = conn.cursor()
cur.execute("SELECT id, timestamp, extra FROM event_log WHERE event_type='ssh_login_success' ORDER BY id DESC LIMIT 10")
for r in cur.fetchall():
    print(r)
conn.close()