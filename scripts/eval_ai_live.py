#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用真实攻击载荷验证请求级 AI 模型（不经过蜜罐规则层）。

复用了 attack_eval.web_cases() 的 34 条攻击 + 6 条正常载荷，直接调用
POST /api/v1/detect，统计模型自身的攻击召回、类型匹配与正常误报。
"""
from __future__ import annotations

import json
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from attack_eval import web_cases  # noqa: E402

URL = "http://127.0.0.1:8000/api/v1/detect"


def main():
    rows = []
    latencies = []
    per_family = defaultdict(lambda: {"total": 0, "detected": 0, "type_ok": 0})
    benign_total = benign_wrong = 0
    attack_total = attack_detected = 0

    print(f"{'家族':18s} {'载荷':16s} {'预测':18s} {'攻击':5s} {'概率':5s} {'AI分':4s} {'耗时':8s}")
    print("-" * 88)
    for family, label, method, path, query, body, headers, is_attack in web_cases():
        payload = {
            "method": method,
            "path": path,
            "query": query,
            "body": body,
            "user_agent": headers.get("User-Agent", ""),
            "headers": {"Content-Type": headers.get("Content-Type", "")},
            "source": "web",
            "ip": "203.0.113.200",
        }
        started = time.perf_counter()
        result = requests.post(URL, json=payload, timeout=10).json()
        latency = (time.perf_counter() - started) * 1000
        latencies.append(latency)
        predicted = result.get("attack_type") or ""
        detected = bool(result.get("is_attack"))
        type_ok = detected and (predicted == family)
        if is_attack:
            attack_total += 1
            attack_detected += int(detected)
            per_family[family]["total"] += 1
            per_family[family]["detected"] += int(detected)
            per_family[family]["type_ok"] += int(type_ok)
        else:
            benign_total += 1
            benign_wrong += int(detected)
        rows.append({
            "family": family, "label": label, "path": path, "query": query,
            "expected_attack": is_attack, "predicted_type": predicted,
            "is_attack": detected, "attack_prob": result.get("attack_prob"),
            "ai_points": result.get("ai_points"), "type_ok": type_ok,
            "latency_ms": round(latency, 1), "reasons": result.get("reasons"),
        })
        print(f"{family:18s} {label:16s} {predicted:18s} {str(detected):5s} "
              f"{result.get('attack_prob', 0):.2f} {result.get('ai_points', 0):4d} {latency:7.0f}ms")

    metrics = {
        "attack_total": attack_total,
        "attack_detected": attack_detected,
        "recall": round(attack_detected / attack_total, 4) if attack_total else 0,
        "benign_total": benign_total,
        "benign_false_positive": benign_wrong,
        "false_positive_rate": round(benign_wrong / benign_total, 4) if benign_total else 0,
        "avg_latency_ms": round(statistics.mean(latencies), 2),
        "p95_latency_ms": round(sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)], 2),
        "family": {
            name: {
                **value,
                "rate": round(value["detected"] / value["total"], 4) if value["total"] else 0,
            }
            for name, value in per_family.items()
        },
    }
    print("-" * 88)
    print(f"模型对真实载荷：攻击检出 {attack_detected}/{attack_total} "
          f"({metrics['recall'] * 100:.1f}%)，正常误报 {benign_wrong}/{benign_total} "
          f"({metrics['false_positive_rate'] * 100:.1f}%)，平均 {metrics['avg_latency_ms']} ms")
    for name, value in per_family.items():
        print(f"  {name:18s} 检出 {value['detected']}/{value['total']}，类型命中 {value['type_ok']}")

    output = ROOT / "reports" / "ai_model_live.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "endpoint": URL,
        "metrics": metrics,
        "records": rows,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果已写入: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
