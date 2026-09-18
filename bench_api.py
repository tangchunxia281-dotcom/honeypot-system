import requests
import time
import statistics

URL = "http://127.0.0.1:5001/api/get_event_stats"
N = 500
times = []
ok = 0

for i in range(N):
    t0 = time.time()
    try:
        r = requests.get(URL, timeout=5, allow_redirects=False)
        if r.status_code < 500:
            ok += 1
        times.append((time.time() - t0) * 1000)
    except Exception:
        times.append((time.time() - t0) * 1000)

print("总数:", N)
print("成功:", ok)
print("成功率: %.1f%%" % (ok / N * 100))
print("平均响应: %.2f ms" % statistics.mean(times))
print("95%% 响应: %.2f ms" % sorted(times)[int(N * 0.95)])