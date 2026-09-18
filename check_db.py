import sqlite3
import os

DB = os.path.join("database", "event_logs.db")
conn = sqlite3.connect(DB)
cur = conn.cursor()

def count(table, where=""):
    sql = f"SELECT COUNT(*) FROM {table}"
    if where:
        sql += f" WHERE {where}"
    cur.execute(sql)
    return cur.fetchone()[0]

print("数据库:", DB)
print("event_log 总数:", count("event_log"))
print("  web 事件:", count("event_log", "source='web'"))
print("  ssh 事件:", count("event_log", "source='ssh'"))
print("raw_request 总数:", count("raw_request"))
print("session_track 总数:", count("session_track"))
print("geo_ip 总数:", count("geo_ip"))
print()

print("=== 最近 10 条 web 事件 ===")
cur.execute("""
    SELECT id, timestamp, source, severity, event_type, src_ip, raw_ref
    FROM event_log
    WHERE source='web'
    ORDER BY id DESC
    LIMIT 10
""")
for r in cur.fetchall():
    print(r)

print()
print("=== 最近 10 条原始请求 raw_request ===")
cur.execute("""
    SELECT id, src_ip, method, path, query_string, threat_score, is_suspicious, create_time
    FROM raw_request
    ORDER BY id DESC
    LIMIT 10
""")
for r in cur.fetchall():
    print(r)

print()
print("=== 最近 5 条会话追踪 session_track ===")
cur.execute("""
    SELECT session_id, src_ip, first_seen, last_seen, request_count, threat_level
    FROM session_track
    ORDER BY last_seen DESC
    LIMIT 5
""")
for r in cur.fetchall():
    print(r)

conn.close()