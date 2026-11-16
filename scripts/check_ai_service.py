#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AI 检测服务（Docker）连通性检查。

用途：
    在「蜜罐所在设备」或「任意一台能访问 Docker 宿主机的机器」上，
    验证请求级检测服务是否可用、模型是否加载、判定是否正常。

用法：
    # 读取 honeypot.ini 的 [ai] 配置（推荐，与蜜罐实际调用一致）
    python scripts/check_ai_service.py

    # 临时指定 Docker 宿主机（跨设备排查时最常用）
    python scripts/check_ai_service.py --url http://192.168.31.41:8000

    # 也可以直接给完整接口地址
    python scripts/check_ai_service.py --url http://192.168.31.41:8000/api/v1/detect

退出码：0 = 全部通过；1 = 有失败项。
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Windows 控制台/管道默认按本地代码页编码，统一成 UTF-8 避免中文乱码
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import requests  # noqa: E402

from app_config import env_bool, env_float, env_str  # noqa: E402

DEFAULT_DETECT_URL = 'http://127.0.0.1:8000/api/v1/detect'

# (名称, 请求体, 期望 attack_type, 期望 is_attack)
CASES = [
    ('XSS', {'path': '/comment', 'body': '<script>alert(1)</script>'}, 'xss', True),
    ('SQL 注入', {'path': '/search', 'query': 'id=1 and 1=1'}, 'sqli', True),
    ('目录穿越', {'path': '/download', 'query': 'file=../../../../etc/passwd'},
     'path_traversal', True),
    ('正常请求', {'path': '/index.php', 'query': 'page=1'}, 'normal', False),
]


def _base_from(url: str) -> str:
    """从 detect/info URL 中取出服务根地址。"""
    text = str(url or '').strip().rstrip('/')
    for suffix in ('/api/v1/detect', '/model/info', '/health'):
        if text.endswith(suffix):
            return text[: -len(suffix)].rstrip('/')
    return text


def _print_hints(base: str) -> None:
    print('\n排查建议：')
    print('  1) 在 Docker 宿主机上确认容器在跑：docker compose ps（healthy）')
    print('  2) 确认端口发布：docker port xss-detector（应为 0.0.0.0:8000）')
    print('  3) 跨设备访问要用 http://<宿主机IP>:8000，不能用 127.0.0.1')
    print('  4) 防火墙需放行 8000/TCP（Windows 防火墙默认可能拦截入站）')
    print(f'  5) 宿主机自测：curl.exe {base}/health')


def main() -> int:
    parser = argparse.ArgumentParser(description='AI 检测服务（Docker）连通性检查')
    parser.add_argument('--url', default='', help='Docker 服务地址，如 http://192.168.31.41:8000')
    parser.add_argument('--timeout', type=float, default=5.0, help='单次请求超时秒数（默认 5）')
    args = parser.parse_args()

    configured_enabled = env_bool('AI_XSS_ENABLED', False)
    if args.url:
        detect_url = args.url.strip()
    else:
        detect_url = env_str('AI_XSS_URL', DEFAULT_DETECT_URL).strip() or DEFAULT_DETECT_URL
    info_url = env_str(
        'AI_XSS_INFO_URL', 'http://127.0.0.1:8000/model/info'
    ).strip() or 'http://127.0.0.1:8000/model/info'

    base = _base_from(detect_url)
    detect_url = base + '/api/v1/detect'
    info_url = base + '/model/info'

    print('=' * 74)
    print('AI 检测服务（Docker）连通性检查')
    print('=' * 74)
    print(f'  honeypot.ini [ai] enabled : {configured_enabled}')
    print(f'  检测接口                  : {detect_url}')
    print(f'  来源                      : {"命令行 --url" if args.url else "honeypot.ini / 环境变量"}')
    print()

    failures = 0

    # 1) 健康检查
    health_url = base + '/health'
    print(f'[1/3] 健康检查  GET {health_url}')
    try:
        started = time.perf_counter()
        response = requests.get(health_url, timeout=args.timeout)
        latency = (time.perf_counter() - started) * 1000
        response.raise_for_status()
        health = response.json() or {}
        if health.get('model_loaded') is True:
            print(f'      OK  模型已加载（{latency:.0f} ms）  path={health.get("model_path", "")}')
        else:
            print(f'      FAIL  服务可达但模型未加载: {health}')
            failures += 1
    except Exception as exc:
        print(f'      FAIL  无法访问: {exc}')
        _print_hints(base)
        return 1

    # 2) 模型信息
    print(f'\n[2/3] 模型信息  GET {info_url}')
    try:
        info = requests.get(info_url, timeout=args.timeout).json() or {}
        print(f'      version={info.get("version")}  trained_at={info.get("trained_at")}')
        print(f'      labels={info.get("labels")}')
    except Exception as exc:
        print(f'      WARN  模型信息读取失败: {exc}')

    # 3) 判定用例
    print('\n[3/3] 检测用例')
    print(f'      {"用例":<8} {"期望":<16} {"实际":<16} {"ai_points":>9} {"prob":>6} {"耗时":>7}  结果')
    for name, payload, want_type, want_attack in CASES:
        try:
            started = time.perf_counter()
            body = dict(payload, source='web', ip='203.0.113.9', session_id='check-ai')
            response = requests.post(detect_url, json=body, timeout=args.timeout)
            latency = (time.perf_counter() - started) * 1000
            response.raise_for_status()
            data = response.json() or {}
            actual_type = str(data.get('attack_type') or '')
            actual_attack = data.get('is_attack')
            ok = actual_type == want_type and actual_attack is want_attack
            mark = 'PASS' if ok else 'FAIL'
            print(f'      {name:<8} {want_type:<16} {actual_type:<16} '
                  f'{int(data.get("ai_points") or 0):>9} '
                  f'{float(data.get("attack_prob") or 0):>6.2f} {latency:>6.0f}ms  {mark}')
            failures += 0 if ok else 1
        except Exception as exc:
            print(f'      {name:<8} {want_type:<16} {"ERROR":<16} {"-":>9} {"-":>6} {"-":>7}  FAIL  {exc}')
            failures += 1

    print('\n' + '=' * 74)
    if failures:
        print(f'结果：{failures} 项失败')
        return 1
    print('结果：全部通过 —— 该地址可被蜜罐直接接入')
    return 0


if __name__ == '__main__':
    sys.exit(main())
