import sqlite3, os

DB = os.path.join("database", "event_logs.db")
conn = sqlite3.connect(DB)
cur = conn.cursor()

def q(sql):
    cur.execute(sql)
    return cur.fetchone()[0]

print("全部事件:", q("SELECT COUNT(*) FROM event_log"))
print("low:", q("SELECT COUNT(*) FROM event_log WHERE severity='low'"))
print("medium:", q("SELECT COUNT(*) FROM event_log WHERE severity='medium'"))
print("high:", q("SELECT COUNT(*) FROM event_log WHERE severity='high'"))
print("medium+high:", q("SELECT COUNT(*) FROM event_log WHERE severity IN ('medium','high')"))
print()
print("SSH 全部:", q("SELECT COUNT(*) FROM event_log WHERE source='ssh'"))
print("SSH medium+high:", q("SELECT COUNT(*) FROM event_log WHERE source='ssh' AND severity IN ('medium','high')"))
print("Web 全部:", q("SELECT COUNT(*) FROM event_log WHERE source='web'"))
print("Web medium+high:", q("SELECT COUNT(*) FROM event_log WHERE source='web' AND severity IN ('medium','high')"))
print()
print("按来源+风险等级:")
cur.execute("SELECT source, severity, COUNT(*) FROM event_log GROUP BY source, severity ORDER BY source, severity")
for r in cur.fetchall():
    print(r)
print()
print("按事件类型:")
cur.execute("SELECT event_type, severity, COUNT(*) FROM event_log GROUP BY event_type, severity ORDER BY COUNT(*) DESC")
for r in cur.fetchall():
    print(r)

conn.close()