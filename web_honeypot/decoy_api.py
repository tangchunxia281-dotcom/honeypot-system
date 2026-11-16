# -*- coding: utf-8 -*-
"""诱饵业务接口：Web 受控预览 + 虚拟 ERP。

设计约束：
- 所有状态都是合成数据，绝不访问提交的目标地址，也不执行任何命令；
- 任务/会话按浏览器 cookie 绑定，换一个 cookie 读不到别人的任务；
- 模型只选择封闭策略，正文由程序模板渲染；
- 模型不可用或被关闭时仍然返回一致的任务对象（source=program/fallback）。
"""
import re
import secrets
import threading
import time

from flask import jsonify, request, make_response

_PREVIEW_COOKIE = 'cms_preview_sid'
_ERP_COOKIE = 'cms_erp_sid'
_SID_RE = re.compile(r'^[0-9a-f]{32}$')
_JOB_RE = re.compile(r'^[0-9a-f]{24}$')

_PREVIEW_MAX_BODY = 4096
_PREVIEW_MAX_URL = 2048
_STATE_TTL = 1800
_STATE_MAX = 2048

_STATE_LOCK = threading.Lock()
_PREVIEW_STATE = {}
_ERP_STATE = {}


def _now():
    return time.time()


def _gc_locked():
    cutoff = _now() - _STATE_TTL
    for store in (_PREVIEW_STATE, _ERP_STATE):
        if len(store) <= _STATE_MAX:
            stale = [key for key, value in store.items() if float(value.get('touched', 0)) < cutoff]
        else:
            stale = [key for key, _ in sorted(store.items(), key=lambda item: item[1].get('touched', 0))[:256]]
        for key in stale:
            store.pop(key, None)


def _sid(cookie_name):
    raw = str(request.cookies.get(cookie_name, '') or '').strip()
    if _SID_RE.match(raw):
        return raw, False
    return secrets.token_hex(16), True


def _attach_cookie(response, cookie_name, sid, created):
    if created:
        response.set_cookie(cookie_name, sid, max_age=_STATE_TTL, httponly=True, samesite='Lax')
    return response


def _preview_url():
    """读取 url 参数；非法返回 (None, 错误响应)。"""
    raw = None
    if request.method == 'POST':
        try:
            body_len = int(request.content_length or 0)
        except Exception:
            body_len = 0
        if body_len > _PREVIEW_MAX_BODY:
            return None, (jsonify({'error': 'payload_too_large'}), 413)
        payload = request.get_json(silent=True)
        if isinstance(payload, dict):
            raw = payload.get('url')
        elif payload is not None:
            return None, (jsonify({'error': 'invalid_payload'}), 400)
        else:
            raw = request.form.get('url')
    else:
        raw = request.args.get('url')

    if not isinstance(raw, str):
        return None, (jsonify({'error': 'url_required'}), 400)
    value = raw.strip()
    if not value or len(value) > _PREVIEW_MAX_URL:
        return None, (jsonify({'error': 'url_invalid'}), 400)
    return value, None


def register(app, helpers):
    get_client_ip = helpers['get_client_ip']
    safe_log_event = helpers.get('_safe_log_event') or (lambda *a, **k: None)
    logger = helpers.get('logger')

    # === Web 受控预览（AI 只选择策略，正文由模板渲染） ===
    @app.route('/api/preview', methods=['GET', 'POST'])
    def api_preview():
        url, error = _preview_url()
        if error is not None:
            return error

        sid, created = _sid(_PREVIEW_COOKIE)
        client_ip = get_client_ip()
        from utils import ai_interaction
        outcome = ai_interaction.web_reply(client_ip, url, sid)

        with _STATE_LOCK:
            _gc_locked()
            previous = _PREVIEW_STATE.get(sid) or {}
            job_id = previous.get('job_id') if previous.get('url') == url and previous.get('job_id') else secrets.token_hex(12)
            _PREVIEW_STATE[sid] = {
                'job_id': job_id,
                'url': url,
                'status': 'ready',
                'strategy': outcome.get('strategy', 'preview_pending'),
                'source': outcome.get('source', 'program'),
                'reply': outcome.get('reply', ''),
                'touched': _now(),
            }
        safe_log_event(client_ip, f"虚拟预览: {url[:120]} -> {outcome.get('strategy')}", 'decoy_preview')
        response = make_response(jsonify({
            'job_id': job_id,
            'poll': '/api/preview/jobs/' + job_id,
            'status': 'ready',
            'strategy': outcome.get('strategy', 'preview_pending'),
            'source': outcome.get('source', 'program'),
            'reply': outcome.get('reply', ''),
        }), 202)
        return _attach_cookie(response, _PREVIEW_COOKIE, sid, created)

    def _preview_job_payload(job_id):
        sid = str(request.cookies.get(_PREVIEW_COOKIE, '') or '').strip()
        if not _SID_RE.match(sid) or not _JOB_RE.match(str(job_id or '')):
            return jsonify({'error': 'not_found'}), 404
        with _STATE_LOCK:
            state = _PREVIEW_STATE.get(sid)
            if not state or state.get('job_id') != job_id:
                return jsonify({'error': 'not_found'}), 404
            payload = {
                'job_id': job_id,
                'status': state.get('status', 'ready'),
                'strategy': state.get('strategy', ''),
                'source': state.get('source', ''),
                'reply': state.get('reply', ''),
                'url': state.get('url', ''),
            }
        return jsonify(payload)

    @app.route('/api/preview/jobs/<job_id>', methods=['GET'])
    def api_preview_job(job_id):
        return _preview_job_payload(job_id)

    # 兼容旧调用方：同一任务也可从 /api/jobs/<id> 读取
    @app.route('/api/jobs/<job_id>', methods=['GET'])
    def api_preview_job_alias(job_id):
        return _preview_job_payload(job_id)

    # === 虚拟 ERP 业务（合成数据，按 cookie 隔离） ===
    def _erp_state():
        sid, created = _sid(_ERP_COOKIE)
        with _STATE_LOCK:
            _gc_locked()
            state = _ERP_STATE.get(sid)
            if state is None:
                state = {
                    'persona_seed': secrets.token_hex(8),
                    'business_authenticated': False,
                    'touched': _now(),
                }
                _ERP_STATE[sid] = state
            state['touched'] = _now()
        return sid, created, state

    def _erp_reply(resource, action=None):
        from utils.decoy_profiles import business_payload
        sid, created, state = _erp_state()
        try:
            payload, status = business_payload(state, resource, action)
        except Exception:
            payload, status = {'error': 'unsupported_resource'}, 404
        response = make_response(jsonify(payload), status)
        return _attach_cookie(response, _ERP_COOKIE, sid, created)

    @app.route('/api/erp/status', methods=['GET'])
    def api_erp_status():
        return _erp_reply('status')

    @app.route('/api/erp/catalog', methods=['GET'])
    def api_erp_catalog():
        return _erp_reply('catalog')

    @app.route('/api/erp/orders', methods=['GET'])
    def api_erp_orders():
        return _erp_reply('orders')

    @app.route('/api/erp/login', methods=['POST'])
    def api_erp_login():
        return _erp_reply('login')

    @app.route('/api/erp/export', methods=['POST'])
    def api_erp_export():
        return _erp_reply('export')

    @app.route('/api/erp/jobs/<job_id>', methods=['GET'])
    def api_erp_job(job_id):
        sid = str(request.cookies.get(_ERP_COOKIE, '') or '').strip()
        if not _SID_RE.match(sid) or not _JOB_RE.match(str(job_id or '')):
            return jsonify({'error': 'not_found'}), 404
        with _STATE_LOCK:
            state = _ERP_STATE.get(sid)
            if not state or state.get('export_id') != job_id:
                return jsonify({'error': 'not_found'}), 404
            state['touched'] = _now()
        return _erp_reply('job')

    return True
