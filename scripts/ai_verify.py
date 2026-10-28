# -*- coding: utf-8 -*-
"""通用大模型推理接口连通性验收。

默认只做：配置自检 -> 健康检查 -> 一次真实调用（写入 AI 审计库）。
加 `--full` 会用独立临时库再跑一遍完整链路（报告/问答/研判/交互），
不会污染现有 AI 运行数据。

用法：
    uv run python scripts/ai_verify.py
    uv run python scripts/ai_verify.py --full
    uv run python scripts/ai_verify.py --model deepseek-chat

退出码：0 成功；1 调用失败；2 未配置。
"""
import argparse
import json
import os
import secrets
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _mask(value: str) -> str:
    text = str(value or '')
    if not text:
        return ''
    if len(text) <= 8:
        return '*' * len(text)
    return text[:4] + '*' * (len(text) - 8) + text[-4:]


def _full_checks():
    """在独立临时库里跑完整 AI 链路，避免污染现有运行数据。"""
    from unittest.mock import patch
    from utils import local_ai, ai_analyst, ai_detection, ai_interaction

    workers = [patch.object(ai_analyst, 'start_worker'), patch.object(ai_detection, 'start_worker')]
    for item in workers:
        item.start()
    # 验收需要立即处理，跳过生产用的排队延迟与节流
    timing = {key: local_ai.SETTINGS.get(key) for key in ('detection_delay', 'interactive_wait', 'min_interval', 'analysis_flush')}
    local_ai.SETTINGS.update(detection_delay=0, interactive_wait=0, min_interval=0, analysis_flush=0)
    checks = []

    def check(name, ok, detail=''):
        checks.append((name, bool(ok), str(detail)))

    record = {
        'id': 'f' * 24,
        'locator': 'acceptance/raw_request:1',
        'timestamp': '2026-10-28 10:00:00',
        'src_ip': '192.0.2.90',
        'channel': 'web',
        'session_id': 'acceptance-session',
        'kind': 'http_request',
        'rule_level': 'medium',
        'excerpt': 'GET /search?q=<script>alert(1)</script>',
    }
    try:
        store = ai_analyst.get_store()
        store.index_batch('acceptance', 1, 1, [record])
        job = ai_analyst.queue_report(force=True)
        check('报告任务入队', bool(job and job.get('id')), (job or {}).get('reason', ''))
        ai_analyst.process_one()
        row = store.get(job['id']) if job and job.get('id') else {}
        result = (row or {}).get('result') or {}
        check('日志分析报告', (row or {}).get('status') == 'completed',
              (row or {}).get('status', '') + ' ' + str((row or {}).get('reason', '')))
        evidence = result.get('evidence') or []
        check('报告引用可追溯', bool(evidence) and bool(evidence[0].get('quote'))
              and evidence[0].get('quote', '') in record['excerpt'],
              evidence[0].get('quote', '') if evidence else 'no evidence')

        question = ai_analyst.ask('acceptance-owner', 'c' * 32, '这段记录反映什么攻击目的？', ip='192.0.2.90')
        ai_analyst.process_one()
        chat = store.get(question['id'], 'acceptance-owner') if question.get('id') else {}
        check('日志问答', (chat or {}).get('status') == 'completed',
              (chat or {}).get('status', '') + ' ' + str((chat or {}).get('reason', '')))

        submitted = ai_detection.submit(
            1, '192.0.2.90', 'acceptance-session', 'GET', '/search',
            'q=<script>alert(1)</script>', {'User-Agent': 'Mozilla/5.0'}, '',
            25, ['疑似XSS特征'], '2026-10-28 10:00:00', 'acceptance', force=True,
        )
        check('规则-AI 研判入队', submitted.get('status') == 'queued',
              submitted.get('status', '') + ' ' + str(submitted.get('reason', '')))
        ai_detection.process_one()
        detection = ai_detection.STORE.listing(limit=1)['records'][0]
        check('规则-AI 研判', detection.get('status') == 'completed',
              detection.get('status', '') + ' ' + str(detection.get('reason', '')))
        check('研判结论与证据', detection.get('verdict') == 'suspicious'
              and bool((detection.get('result') or {}).get('evidence')), detection.get('verdict', ''))

        web = ai_interaction.web_reply('192.0.2.90', 'http://169.254.169.254/latest/meta-data/')
        check('Web 预览策略', web.get('source') == 'model' and web.get('strategy') == 'preview_pending',
              web.get('source', '') + '/' + str(web.get('reason', '')))

        from ssh_honeypot.server import VirtualShell
        shell = VirtualShell('192.0.2.90', 'root', client_port=42000)
        output = shell.execute_command('sysinfo')
        check('SSH 未知命令策略', 'hostname:' in output and 'kernel:' in output, output.splitlines()[:1])
    finally:
        local_ai.SETTINGS.update({k: v for k, v in timing.items() if v is not None})
        try:
            ai_analyst.stop_worker()
            ai_detection.stop_worker()
        except Exception:
            pass
        for item in reversed(workers):
            try:
                item.stop()
            except Exception:
                pass

    failed = 0
    print('\n[完整链路]（独立临时库）')
    for name, ok, detail in checks:
        print(('PASS' if ok else 'FAIL'), name.ljust(20), '' if ok else detail)
        failed += 0 if ok else 1
    print('RESULT:', 'PASS' if not failed else f'FAIL {failed}/{len(checks)}')
    return 0 if not failed else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description='大模型推理连通性验收')
    parser.add_argument('--model', default='', help='临时覆盖模型名')
    parser.add_argument('--full', action='store_true', help='额外执行报告/问答/研判/交互的完整链路验收')
    args = parser.parse_args(argv)

    if args.full and not os.environ.get('HONEYPOT_AI_DB'):
        import tempfile
        holder = tempfile.mkdtemp(prefix='ai-accept-')
        os.environ['HONEYPOT_AI_DB'] = os.path.join(holder, 'ai.db')

    from utils import local_ai
    settings = local_ai.SETTINGS
    if args.model:
        local_ai.SETTINGS['model'] = args.model

    view = {
        'provider': settings.get('provider'),
        'model': local_ai.SETTINGS.get('model'),
        'enabled': bool(settings.get('enabled')),
        'configured': bool(settings.get('configured')),
        'api_key': _mask(settings.get('api_key')),
        'base_url': settings.get('base_url'),
        'configuration_error': settings.get('configuration_error'),
        'ssh_enabled': bool(settings.get('ssh_enabled')),
        'web_interaction_enabled': bool(settings.get('web_interaction_enabled')),
        'detection_enabled': bool(settings.get('detection_enabled')),
        'analysis_enabled': bool(settings.get('analysis_enabled')),
    }
    print('[1/3] 配置')
    print(json.dumps(view, ensure_ascii=False, indent=2))

    if not settings.get('enabled') or not settings.get('configured'):
        print('\n[未就绪] 请在 ai.local.ini 填写 api_key（sk- 开头），')
        print('          或设置环境变量 HONEYPOT_AI_API_KEY 后重试。')
        return 2

    print('\n[2/3] 健康检查')
    health = local_ai.health(force=True)
    print(json.dumps(health, ensure_ascii=False, indent=2))

    print('\n[3/3] 真实调用')
    started = time.monotonic()
    result = local_ai.probe('verify-' + secrets.token_hex(8))
    elapsed = round((time.monotonic() - started) * 1000)
    print(json.dumps({k: v for k, v in result.items() if k != 'data'}, ensure_ascii=False, indent=2))
    if result.get('status') == 'success':
        print('\n模型回复：' + str(result.get('reply', '')))
        print(f'\n[通过] 端到端可用（{elapsed} ms）。AI 工作区与 SSH/Web 受控交互将使用该服务。')
        if args.full:
            return _full_checks()
        print('提示：加 --full 可继续验证 报告/问答/研判/交互 完整链路。')
        return 0
    print('\n[失败] ' + str(result.get('reason') or 'unknown'))
    print('排查：1) Key 是否有效 2) 网络能否访问 base_url 3) 模型名是否正确')
    return 1


if __name__ == '__main__':
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')
    raise SystemExit(main())
