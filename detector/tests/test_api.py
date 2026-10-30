# tests/test_api.py
from fastapi.testclient import TestClient

from src.api import app

client = TestClient(app)


def test_root():
    r = client.get("/")
    assert r.status_code == 200


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_model_info():
    r = client.get("/model/info")
    assert r.status_code == 200
    data = r.json()
    assert "version" in data
    assert "labels" in data
    assert "model_path" in data


def test_predict_xss():
    r = client.post("/predict", json={"text": "<script>alert(1)</script>"})
    assert r.status_code == 200
    data = r.json()
    assert data["label"] == "xss"
    # 旧字段是 is_xss，新版改为 is_attack
    assert data["is_attack"] is True


def test_predict_normal():
    r = client.post("/predict", json={"text": "hello world"})
    assert r.status_code == 200
    data = r.json()
    assert data["label"] == "normal"
    # 旧字段是 is_xss，新版改为 is_attack
    assert data["is_attack"] is False


def test_batch():
    r = client.post("/predict/batch", json={
        "texts": [
            "<script>alert(1)</script>",
            "hello world",
            "<img src=x onerror=alert(1)>",
        ]
    })
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 3
    # 旧字段是 xss_count，新版改为 attack_count
    assert data["attack_count"] == 2
    assert len(data["results"]) == 3


def test_detect_main_endpoint_sqli():
    """对外主接口：SQL 注入，且应按字段分段命中。"""
    r = client.post("/api/v1/detect", json={"path": "/search", "query": "id=1 and 1=1"})
    assert r.status_code == 200
    d = r.json()
    assert d["attack_type"] == "sqli"
    assert d["is_attack"] is True
    assert d["ai_points"] > 0
    assert d["reasons"], "应给出可读理由"
    # 命中位置应指向具体参数
    assert any(s["field"].startswith("query") for s in d["signals"])


def test_detect_main_endpoint_traversal():
    r = client.post("/api/v1/detect", json={
        "path": "/download", "query": "file=../../../../etc/passwd"})
    assert r.status_code == 200
    d = r.json()
    assert d["attack_type"] == "path_traversal"
    assert d["is_attack"] is True


def test_detect_main_endpoint_full_url():
    """只传完整 url 也应能识别（内部会自动拆分查询串）。"""
    r = client.post("/api/v1/detect", json={"url": "/search?id=1 and 1=1&Submit=Submit"})
    assert r.status_code == 200
    assert r.json()["attack_type"] == "sqli"


def test_detect_normal_paths_not_flagged():
    """正常路径不应被误判——这是曾经的系统性缺陷。"""
    for path in ["/", "/index.php", "/about", "/api/users", "/static/css/style.css"]:
        r = client.post("/api/v1/detect", json={"path": path})
        assert r.status_code == 200
        d = r.json()
        assert d["is_attack"] is False, f"正常路径被误判: {path} -> {d}"


def test_detect_without_any_input_returns_400():
    r = client.post("/api/v1/detect", json={})
    assert r.status_code == 400


def test_detect_user_agent_scanner():
    r = client.post("/api/v1/detect", json={
        "path": "/index.php", "user_agent": "sqlmap/1.7#stable"})
    assert r.status_code == 200
    assert r.json()["attack_type"] == "scanner"


if __name__ == "__main__":
    # 手动执行模式，保留你原来的习惯
    test_root()
    test_health()
    test_model_info()
    test_predict_xss()
    test_predict_normal()
    test_batch()
    print("test_api.py 全部通过")