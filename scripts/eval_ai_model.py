#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""请求级 AI 攻击检测模型验收脚本。

读取 evaluation/fixtures.jsonl 的 test 划分，逐条提交到
POST /api/v1/detect，统计：
  * 二分类（攻击/正常）准确率、召回率、误报率
  * 各攻击家族命中率
  * 五分类模型标签与规则融合结果
  * 平均延迟与 ai_points 分布

注意：fixtures 是项目自建样本，仅用于本机功能验收，不等同独立第三方评测。
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = ROOT / "evaluation" / "fixtures.jsonl"
DEFAULT_URL = "http://127.0.0.1:8000/api/v1/detect"


def load_rows(path: Path, split: str):
    rows = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if split and row.get("split") != split:
                continue
            rows.append(row)
    return rows


def post_detect(url: str, row: dict, timeout: float):
    fields = row.get("fields") or {}
    payload = {
        "method": fields.get("method") or "GET",
        "path": fields.get("path") or "/",
        "query": fields.get("query") or "",
        "body": fields.get("body") or "",
        "user_agent": fields.get("user_agent") or "",
        "referer": fields.get("referer") or "",
        "headers": {"Content-Type": fields.get("content_type") or ""},
        "source": "web",
        "ip": "203.0.113.200",
    }
    started = time.perf_counter()
    resp = requests.post(url, json=payload, timeout=timeout)
    latency = (time.perf_counter() - started) * 1000
    resp.raise_for_status()
    data = resp.json()
    data["_latency_ms"] = latency
    return data


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
    parser.add_argument("--split", default="test")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--output", default=str(ROOT / "reports" / "ai_model_eval.json"))
    args = parser.parse_args(argv)

    rows = load_rows(Path(args.dataset), args.split)
    if args.limit:
        rows = rows[: args.limit]
    if not rows:
        print("没有可评测样本")
        return 2

    print(f"模型接口: {args.url}")
    print(f"样本: {len(rows)} 条（split={args.split}）")
    print("-" * 78)

    records = []
    latencies = []
    family_stats = defaultdict(lambda: {"total": 0, "hit": 0})
    conf = Counter()
    binaries = []

    for index, row in enumerate(rows, 1):
        try:
            result = post_detect(args.url, row, 10)
        except Exception as exc:  # noqa: BLE001
            print(f"[{index:02d}] ERROR {row['id']} {type(exc).__name__}: {exc}")
            records.append({"id": row["id"], "error": str(exc)})
            continue

        label = row.get("label")
        truth_attack = label == "attack"
        truth_type = row.get("attack_type") or ("normal" if label == "benign" else "")
        predicted = result.get("attack_type") or ""
        is_attack = bool(result.get("is_attack"))
        hit = (is_attack == truth_attack) if label in ("attack", "benign") else None

        if label in ("attack", "benign"):
            binaries.append(hit)
        if truth_attack:
            family = truth_type or "unknown"
            family_stats[family]["total"] += 1
            if is_attack:
                family_stats[family]["hit"] += 1
        conf[(truth_type or label, predicted)] += 1
        latencies.append(float(result.get("_latency_ms") or 0))

        records.append(
            {
                "id": row["id"],
                "group": row.get("group"),
                "truth_label": label,
                "truth_type": truth_type,
                "predicted_type": predicted,
                "is_attack": is_attack,
                "hit": hit,
                "attack_prob": result.get("attack_prob"),
                "ai_points": result.get("ai_points"),
                "confidence": result.get("confidence"),
                "latency_ms": round(float(result.get("_latency_ms") or 0), 2),
                "reasons": result.get("reasons"),
                "model_label": result.get("model_label"),
            }
        )
        print(
            f"[{index:02d}] {truth_type or label:16s} -> {predicted:16s} "
            f"attack={str(is_attack):5s} prob={result.get('attack_prob', 0):.2f} "
            f"ai+{result.get('ai_points', 0):<2d} {float(result.get('_latency_ms') or 0):6.1f}ms"
        )

    if not binaries:
        print("没有可计算二分类指标的样本")
        return 1

    tp = sum(1 for r in records if r.get("hit") is True)
    fp = sum(1 for r in records if r.get("hit") is False)
    total_binary = len(binaries)
    attack_total = sum(1 for r in records if r.get("truth_label") == "attack")
    benign_total = sum(1 for r in records if r.get("truth_label") == "benign")
    benign_wrong = sum(
        1 for r in records if r.get("truth_label") == "benign" and not r.get("hit")
    )
    attack_wrong = sum(
        1 for r in records if r.get("truth_label") == "attack" and not r.get("hit")
    )

    metrics = {
        "samples": len(records),
        "binary_samples": total_binary,
        "accuracy": round(tp / total_binary, 4) if total_binary else 0,
        "attack_total": attack_total,
        "attack_detected": attack_total - attack_wrong,
        "recall": round((attack_total - attack_wrong) / attack_total, 4) if attack_total else 0,
        "benign_total": benign_total,
        "false_positive": benign_wrong,
        "false_positive_rate": round(benign_wrong / benign_total, 4) if benign_total else 0,
        "avg_latency_ms": round(statistics.mean(latencies), 2) if latencies else 0,
        "max_latency_ms": round(max(latencies), 2) if latencies else 0,
        "family": {
            name: {
                "total": value["total"],
                "detected": value["hit"],
                "rate": round(value["hit"] / value["total"], 4) if value["total"] else 0,
            }
            for name, value in sorted(family_stats.items())
        },
    }

    print("-" * 78)
    print(
        f"二分类准确率 {metrics['accuracy'] * 100:.1f}%  "
        f"攻击召回 {metrics['recall'] * 100:.1f}%  "
        f"正常误报 {metrics['false_positive_rate'] * 100:.1f}%  "
        f"平均延迟 {metrics['avg_latency_ms']} ms"
    )
    for name, value in metrics["family"].items():
        print(f"  {name:18s} {value['detected']:2d}/{value['total']:2d}  {value['rate'] * 100:5.1f}%")
    print("混淆（真值 -> 预测）:")
    for (truth, predicted), count in sorted(conf.items()):
        print(f"  {truth:18s} -> {predicted:18s} {count}")

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            {
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "endpoint": args.url,
                "dataset": str(Path(args.dataset)),
                "split": args.split,
                "metrics": metrics,
                "confusion": [{"truth": t, "predicted": p, "count": c} for (t, p), c in sorted(conf.items())],
                "records": records,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"结果已写入: {output}")
    return 0


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
