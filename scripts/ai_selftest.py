# -*- coding: utf-8 -*-
"""AI 工作区离线端到端自检（不需要真实 API Key）。

用本地伪 OpenAI 兼容端点驱动真实的 `utils.local_ai` deepseek 传输分支，
依次验证：健康检查 → 连接探针 → 日志分析报告 → 日志问答 → 请求级 AI 复核
→ Web 预览策略 → SSH 未知命令策略。

它验证的是「接线与协议」，不验证真实模型质量；填入真实 Key 后请改用
`scripts/ai_verify.py` 做真实调用验收。

用法：
    uv run python scripts/ai_selftest.py
退出码：0 全部通过；1 有失败项。
"""
import json
import os
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_STATE = {'requests': 0}
_MODEL_NAMES = ('deepseek-chat', 'selftest-model')


def _strategy_reply(system, user):
    """策略选择任务：从 allowed_strategies 中挑一个合法项。"""
    try:
        payload = json.loads(user)
    except (TypeError, ValueError):
        payload = {}
    allowed = payload.get('allowed_strategies') or []
    if 'profile_summary' in allowed:
        return {'strategy': 'profile_summary'}
    if 'preview_pending' in allowed:
        return {'strategy': 'preview_pending'}
    return {'strategy': allowed[0] if allowed else 'not_found'}


def _review_reply(user):
    """请求级研判：引用真实字段片段，满足证据逐字匹配。"""
    try:
        payload = json.loads(user)
    except (TypeError, ValueError):
        payload = {}
    fields = payload.get('fields') or {}
    for name in ('query', 'path', 'body', 'user_agent', 'method'):
        value = str(fields.get(name) or '').strip()
        if value:
            return {
                'verdict': 'suspicious',
                'attack_types': ['xss'],
                'summary': '疑似输入攻击，需结合上下文人工复核。',
                'evidence': [{'field': name, 'quote': value[:24]}],
            }
    return {'verdict': 'no_clear_attack', 'attack_types': [], 'summary': '可见片段未发现明确攻击。', 'evidence': []}


def _answer(system, user):
    system = str(system or '')
    if 'honeypot connection test' in system or '本地模型连接验收' in user:
        return {'reply': '离线自检通过：模型协议链路正常'}
    if '响应策略选择器' in system:
        return _strategy_reply(system, user)
    if system.startswith('You review one captured honeypot HTTP request'):
        return _review_reply(user)
    if '蜜罐日志分析员' in system:
        try:
            payload = json.loads(user)
        except (TypeError, ValueError):
            payload = {}
        # 报告与问答的载荷都有 question；用问答独有的 history/saved_reports 区分。
        if 'saved_reports' in payload or 'history' in payload:
            return {'answer': '根据可见证据，这是一次可疑输入探测，建议人工复核。',
                    'refs': ['E1'], 'limitations': '仅基于抽取的代表证据。'}
        return {
            'title': '离线自检报告',
            'risk': 'medium',
            'summary': '可见记录显示存在可疑输入探测，未发现成功利用证据。',
            'intent': '试探输入处理逻辑。',
            'risk_reason': '输入包含可执行浏览器片段。',
            'timeline': [{'evidence_id': 'E1', 'description': '提交可疑脚本输入。'}],
            'recommendations': ['复核来源 IP 的后续行为'],
            'limitations': '仅基于抽样证据，未覆盖全部日志。',
            'refs': ['E1'],
        }
    if '本机聊天助手' in system:
        return {'reply': '普通本地聊天链路正常。'}
    return {'reply': 'ok'}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, payload, code=200):
        data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == '/v1/models':
            return self._send({'data': [{'id': name} for name in _MODEL_NAMES]})
        if self.path in ('/api/tags', '/api/ps'):
            return self._send({'models': [{'name': name} for name in _MODEL_NAMES]})
        return self._send({'error': 'not_found'}, 404)

    def do_POST(self):
        length = int(self.headers.get('Content-Length') or 0)
        raw = self.rfile.read(length) or b'{}'
        if self.path == '/api/generate':
            return self._send({'done': True, 'response': ''})
        if self.path not in ('/v1/chat/completions', '/api/chat'):
            return self._send({'error': 'not_found'}, 404)
        try:
            payload = json.loads(raw)
        except ValueError:
            return self._send({'error': 'bad_request'}, 400)
        _STATE['requests'] += 1
        messages = payload.get('messages') or []
        system = messages[0].get('content', '') if messages else ''
        user = messages[-1].get('content', '') if messages else ''
        content = json.dumps(_answer(system, user), ensure_ascii=False)
        if self.path == '/api/chat':
            return self._send({'message': {'content': content}, 'done': True, 'done_reason': 'stop'})
        return self._send({
            'choices': [{'message': {'content': content}, 'finish_reason': 'stop'}],
            'usage': {'total_tokens': 64},
        })


def _evidence(identifier, excerpt='GET /search?q=<script>alert(1)</script>'):
    return {
        'id': identifier,
        'locator': 'selftest/raw_request:1',
        'timestamp': '2026-10-28 10:00:00',
        'src_ip': '192.0.2.90',
        'channel': 'web',
        'session_id': 'selftest-session',
        'kind': 'http_request',
        'rule_level': 'medium',
        'excerpt': excerpt,
    }


def main():
    tmp = tempfile.mkdtemp(prefix='ai-selftest-')
    os.environ['HONEYPOT_AI_DB'] = str(Path(tmp) / 'ai.db')
    os.environ['HONEYPOT_AI_ANALYSIS_ENABLED'] = 'true'
    os.environ['HONEYPOT_AI_DETECTION_ENABLED'] = 'true'

    server = HTTPServer(('127.0.0.1', 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_port

    from utils import local_ai, ai_analyst, ai_detection, ai_interaction
    from unittest.mock import patch

    # 固定由本脚本串行驱动，避免后台 worker 并发抢占任务
    _workers = [patch.object(ai_analyst, 'start_worker'), patch.object(ai_detection, 'start_worker')]
    for item in _workers:
        item.start()

    local_ai.SETTINGS.update(
        provider='deepseek',
        enabled=True,
        configured=True,
        base_url=f'http://127.0.0.1:{port}',
        api_key='sk-selftest0123456789abcdef012345',
        model='deepseek-chat',
        ssh_enabled=True,
        web_interaction_enabled=True,
        analysis_enabled=True,
        detection_enabled=True,
        analysis_timeout=10,
        timeout=10,
        min_interval=0,
        concurrency=1,
        detection_delay=0,
        interactive_wait=0,
        normal_sample_every=1,
    )

    checks = []

    def check(name, ok, detail=''):
        checks.append((name, bool(ok), str(detail)))

    try:
        health = local_ai.health(force=True)
        check('健康检查 /v1/models', health.get('model_available'), health.get('reason'))

        probe = local_ai.probe('selftest-probe')
        check('连接探针', probe.get('status') == 'success', probe.get('reply') or probe.get('reason'))

        store = ai_analyst.get_store()
        record = _evidence('a' * 24)
        store.index_batch('selftest', 1, 1, [record])
        job = ai_analyst.queue_report(force=True)
        check('报告任务入队', bool(job and job.get('id')), job.get('id', '') if job else 'no job')
        ai_analyst.process_one()
        row = store.get(job['id']) if job and job.get('id') else {}
        result = (row or {}).get('result') or {}
        check('日志分析报告完成', row.get('status') == 'completed', row.get('status', '') + ' ' + str(row.get('reason', '')))
        check('报告引用可追溯', bool(result.get('evidence')) and result['evidence'][0]['quote'] in record['excerpt'],
              (result.get('evidence') or [{}])[0].get('quote', ''))

        question = ai_analyst.ask('selftest-owner', 'b' * 32, '这段记录反映什么攻击目的？', ip='192.0.2.90')
        ai_analyst.process_one()
        chat = store.get(question['id'], 'selftest-owner') if question.get('id') else {}
        check('日志问答完成', (chat or {}).get('status') == 'completed',
              (chat or {}).get('status', '') + ' ' + str((chat or {}).get('reason', '')))
        check('问答带证据引用', bool(((chat or {}).get('result') or {}).get('evidence')),
              ((chat or {}).get('result') or {}).get('answer', '')[:40])

        submitted = ai_detection.submit(
            1, '192.0.2.90', 'selftest-session', 'GET', '/search',
            'q=<script>alert(1)</script>', {'User-Agent': 'Mozilla/5.0'}, '',
            25, ['疑似XSS特征'], '2026-10-28 10:00:00', 'selftest', force=True,
        )
        check('规则-AI 研判入队', submitted.get('status') == 'queued', submitted.get('status', '') + ' ' + str(submitted.get('reason', '')))
        ai_detection.process_one()
        detection = ai_detection.STORE.listing(limit=1)['records'][0]
        check('规则-AI 研判完成', detection.get('status') == 'completed', detection.get('status', ''))
        check('研判结论与证据', detection.get('verdict') == 'suspicious' and bool(detection.get('result', {}).get('evidence')),
              detection.get('verdict', ''))

        web = ai_interaction.web_reply('192.0.2.90', 'http://169.254.169.254/latest/meta-data/')
        check('Web 预览策略由模型选择', web.get('source') == 'model' and web.get('strategy') == 'preview_pending',
              web.get('source', '') + '/' + web.get('strategy', ''))

        from ssh_honeypot.server import VirtualShell
        shell = VirtualShell('192.0.2.90', 'root', client_port=41000)
        output = shell.execute_command('sysinfo')
        check('SSH 未知命令由模型选择策略', 'hostname:' in output and 'kernel:' in output, output.splitlines()[:1])
        interaction = ai_interaction.get_store().listing(1)['records'][0]
        check('SSH 策略来源=model', interaction.get('source') == 'model',
              interaction.get('source', '') + '/' + interaction.get('strategy', ''))
    finally:
        server.shutdown()
        server.server_close()
        try:
            ai_analyst.stop_worker()
            ai_detection.stop_worker()
            local_ai._pool.shutdown(wait=True)
        except Exception:
            pass
        for item in reversed(_workers):
            try:
                item.stop()
            except Exception:
                pass
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

    failed = 0
    for name, ok, detail in checks:
        print(('PASS' if ok else 'FAIL'), name.ljust(26), detail if not ok else '')
        failed += 0 if ok else 1
    print(f"\n模型请求次数: {_STATE['requests']}")
    print('RESULT:', 'PASS' if not failed else f'FAIL {failed}/{len(checks)}')
    return 0 if not failed else 1


if __name__ == '__main__':
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')
    raise SystemExit(main())
