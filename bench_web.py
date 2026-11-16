import concurrent.futures
import requests
import time
import statistics

URL = "http://127.0.0.1:5000/"
N = 100

def one(i):
    t0 = time.time()
    try:
        r = requests.get(URL, timeout=5)
        return r.status_code, (time.time() - t0) * 1000
    except Exception:
        return 0, (time.time() - t0) * 1000

with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
    results = list(ex.map(one, range(N)))

times = [t for _, t in results]
ok = sum(1 for s, _ in results if s and s < 500)

print("总数:", N)
print("成功:", ok)
print("完成率: %.1f%%" % (ok / N * 100))
print("平均响应: %.2f ms" % statistics.mean(times))
print("95%% 响应: %.2f ms" % sorted(times)[int(N * 0.95)])