# -*- coding: utf-8 -*-
"""
管理端 - 态势感知可视化系统
"""
from flask import Flask, request, render_template, jsonify, redirect, url_for, session, send_from_directory
from datetime import timedelta
from functools import wraps
from collections import deque
import secrets
import logging
import ipaddress
import json
import os
import sys
import time
import threading
import random
import re
from threading import Lock
from werkzeug.serving import make_server
from werkzeug.middleware.proxy_fix import ProxyFix
from urllib.parse import urlparse

_APP_DIR = os.path.abspath(os.path.dirname(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_APP_DIR, '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
from env_utils import env_bool as _env_bool, env_int as _env_int, env_str as _env_str
_DASHBOARD_CSP = "; ".join([
    "default-src 'self'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "img-src 'self' data:",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "font-src 'self' data:",
    "connect-src 'self'",
])

from app_config import config
from db import (
    get_event_geo_data,
    get_geo_info,
    get_suspicious_requests,
    get_ssh_suspicious_commands,
    get_session_analysis,
    get_event_logs,
    get_event_stats,
    has_real_data,
    calculate_threat_score,
    derive_risk_targets,
    list_risk_targets,
    get_risk_target,
    upsert_risk_target,
    update_risk_target,
    delete_risk_target,
)
from utils.http_fingerprint import FAKE_SERVER_HEADERS, FINGERPRINT_STRIP_HEADERS, StealthRequestHandler, spoof_http_fingerprint
from utils.ip_location import build_geo_location, normalize_geo_fields
from utils.logger import get_dashboard_logger
from dashboard.system_info import get_server_info, get_system_status
from utils import local_ai
from utils import ai_detection
from utils import ai_analyst
from utils.investigations import InvestigationStore, Conflict

logger = get_dashboard_logger()
app = Flask(
    __name__,
    template_folder=os.path.join(_APP_DIR, 'templates'),
    static_folder=os.path.join(_APP_DIR, 'static')
)

def _env_flag(name: str, default: str = '0') -> bool:
    return _env_bool(name, str(default).strip().lower() in ('1', 'true', 'yes', 'on'))


def _split_csv(raw: str):
    return [item.strip() for item in str(raw or '').split(',') if item.strip()]


def _normalize_origin(raw: str) -> str:
    value = str(raw or '').strip()
    if not value:
        return ''
    try:
        parsed = urlparse(value)
    except Exception:
        return ''
    scheme = str(parsed.scheme or '').strip().lower()
    netloc = str(parsed.netloc or '').strip().lower()
    if scheme not in ('http', 'https') or not netloc:
        return ''
    return f"{scheme}://{netloc}"


def _normalize_ip_text(raw: str) -> str:
    try:
        return str(ipaddress.ip_address(str(raw or '').strip()))
    except Exception:
        return ''


def _build_trusted_proxy_networks(raw: str):
    networks = []
    for item in _split_csv(raw):
        try:
            if '/' in item:
                networks.append(ipaddress.ip_network(item, strict=False))
            else:
                ip_obj = ipaddress.ip_address(item)
                prefix = 32 if ip_obj.version == 4 else 128
                networks.append(ipaddress.ip_network(f"{ip_obj}/{prefix}", strict=False))
        except Exception:
            continue
    return tuple(networks)


def _format_host_with_port(host: str, port: int) -> str:
    host_text = str(host or '').strip().strip('[]')
    if not host_text or host_text in ('0.0.0.0', '::'):
        return ''
    try:
        ip_obj = ipaddress.ip_address(host_text)
        if ip_obj.version == 6:
            return f"[{host_text}]:{port}"
        return f"{host_text}:{port}"
    except Exception:
        pass
    if host_text.count(':') == 1:
        host_part, maybe_port = host_text.rsplit(':', 1)
        if host_part and maybe_port.isdigit():
            return host_text.lower()
    return f"{host_text}:{port}"


def _build_dashboard_allowed_origins():
    configured = {
        origin for origin in (
            _normalize_origin(item) for item in _split_csv(_env_str('DASHBOARD_ALLOWED_ORIGINS', ''))
        ) if origin
    }
    if configured:
        return configured

    bind_host = _env_str('DASHBOARD_HOST', '127.0.0.1') or '127.0.0.1'
    bind_port = _env_int('DASHBOARD_PORT', 5001, 1, 65535)
    hosts = {
        _format_host_with_port('127.0.0.1', bind_port),
        _format_host_with_port('localhost', bind_port),
        _format_host_with_port('::1', bind_port),
    }
    host_with_port = _format_host_with_port(bind_host, bind_port)
    if host_with_port:
        hosts.add(host_with_port)

    return {
        f"{scheme}://{host}"
        for scheme in ('http', 'https')
        for host in hosts
        if host
    }


_DASHBOARD_TRUSTED_PROXY_NETWORKS = _build_trusted_proxy_networks(
    _env_str('DASHBOARD_TRUSTED_PROXY_IPS', '')
    or _env_str('TRUSTED_PROXY_IPS', '127.0.0.1,::1')
)
_DASHBOARD_ALLOWED_ORIGINS = _build_dashboard_allowed_origins()

# 只有显式声明信任代理头时才启用，默认不再直接吃客户端伪造的 X-Forwarded-*。
if _env_bool('DASHBOARD_TRUST_PROXY_HEADERS', _env_bool('TRUST_PROXY_HEADERS', False)):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.config.from_object(config['default'])
_SESSION_LIFETIME_MINUTES = _env_int('DASHBOARD_SESSION_LIFETIME_MINUTES', 1440, 30, 43200)
app.permanent_session_lifetime = timedelta(minutes=_SESSION_LIFETIME_MINUTES)
app.config.setdefault('SESSION_COOKIE_NAME', 'DASHSESSID')
app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')
app.config.setdefault('SESSION_REFRESH_EACH_REQUEST', True)
app.config.setdefault(
    'SESSION_COOKIE_SECURE',
    _env_bool('DASHBOARD_SESSION_COOKIE_SECURE', False)
)

ADMIN_USER = app.config.get('REAL_ADMIN_USER')
ADMIN_PASS = app.config.get('REAL_ADMIN_PASS')


def _coerce_int(value, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _normalize_dashboard_window_hours(hours, default: int = 24) -> int:
    hours_v = _coerce_int(hours, default)
    if hours_v not in (24, 24 * 7, 24 * 30):
        return int(default)
    return hours_v


def _dashboard_window_panel_limits(hours):
    hours_v = _normalize_dashboard_window_hours(hours)
    if hours_v >= 24 * 30:
        return {
            'geo_limit': 140,
            'suspicious_limit': 120,
            'session_limit': 120,
            'session_min_count': 3,
        }
    if hours_v >= 24 * 7:
        return {
            'geo_limit': 100,
            'suspicious_limit': 80,
            'session_limit': 80,
            'session_min_count': 3,
        }
    return {
        'geo_limit': 60,
        'suspicious_limit': 50,
        'session_limit': 50,
        'session_min_count': 2,
    }

# 用户字典
USERS = {
    ADMIN_USER: ADMIN_PASS
}

# 登录限速（管理端）
_LOGIN_RATE_WINDOW_SECONDS = _env_int('DASHBOARD_LOGIN_RATE_WINDOW', 60, 1, 86400)
_LOGIN_RATE_MAX = _env_int('DASHBOARD_LOGIN_RATE_MAX', 8, 1, 10000)
_LOGIN_BLOCK_SECONDS = _env_int('DASHBOARD_LOGIN_BLOCK_SECONDS', 300, 1, 86400)
_login_rate_lock = Lock()
_login_rate_state = {}

_LOGIN_AUDIT_MAX = _env_int('DASHBOARD_LOGIN_AUDIT_MAX', 200, 10, 100000)
_LOGIN_AUDIT_RECENT = _env_int('DASHBOARD_LOGIN_AUDIT_RECENT', 30, 1, 100000)
_login_audit_lock = Lock()
_login_audit_logs = deque(maxlen=_LOGIN_AUDIT_MAX)
_login_fail_counts = {}
_login_fail_last = {}


class _StealthRequestHandler(StealthRequestHandler):
    pass

    def send_response(self, code, message=None):
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header('Date', self.date_time_string())


def _build_asset_version() -> str:
    forced = _env_str('DASHBOARD_ASSET_VERSION', '')
    if forced:
        return forced

    asset_candidates = [
        os.path.join(_APP_DIR, 'static', 'css', 'dashboard.css'),
        os.path.join(_APP_DIR, 'static', 'js', 'dashboard.js'),
        os.path.join(_APP_DIR, 'static', 'js', 'dashboard_data_flow.js'),
        os.path.join(_APP_DIR, 'templates', 'dashboard.html'),
    ]
    mtimes = []
    for path in asset_candidates:
        try:
            mtimes.append(int(os.path.getmtime(path)))
        except OSError:
            continue
    return str(max(mtimes) if mtimes else int(time.time()))


@app.context_processor
def _inject_template_globals():
    return {
        'ASSET_VERSION': _build_asset_version(),
    }


@app.after_request
def _spoof_http_fingerprint(response):
    spoof_http_fingerprint(response, FINGERPRINT_STRIP_HEADERS)
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    # 同源鉴权依赖 Referer/Origin，使用更平衡的策略避免浏览器全部去除 Referer 导致误判 403
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    response.headers.setdefault('Content-Security-Policy', _DASHBOARD_CSP)
    if request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'no-store, max-age=0, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    else:
        response.headers.setdefault('Cache-Control', 'no-store')
    return response

def _to_safe_text(value) -> str:
    """仅做字符串标准化，不进行 HTML 转义。"""
    if value is None:
        return ''
    return str(value)

def _sanitize_records(records, fields):
    safe = []
    for rec in records or []:
        if not isinstance(rec, dict):
            safe.append(rec)
            continue
        item = dict(rec)
        for f in fields:
            if f in item and item[f] is not None:
                if isinstance(item[f], (list, tuple)):
                    item[f] = [_to_safe_text(v) for v in item[f] if v is not None]
                else:
                    item[f] = _to_safe_text(item[f])
        safe.append(item)
    return safe


def _safe_parse_json_object(raw):
    if isinstance(raw, dict):
        return dict(raw)
    text = str(raw or '').strip()
    if not text or not text.startswith('{'):
        return {}
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _attach_suspicious_signals(item):
    if not isinstance(item, dict):
        return item
    method = str(item.get('method') or '').strip().upper()
    if not method or method == 'SSH':
        return item
    try:
        headers = _safe_parse_json_object(item.get('headers'))
        path = str(item.get('path') or '')
        query = str(item.get('query_string') or '')
        body = str(item.get('body') or '')
        calc_score, _is_suspicious, calc_signals = calculate_threat_score(method, path, query, headers, body)
    except Exception:
        return item
    if calc_signals:
        item['signals'] = [str(x) for x in list(calc_signals or [])[:6] if str(x or '').strip()]
    try:
        stored_score = int(item.get('threat_score') or 0)
    except Exception:
        stored_score = 0
    if stored_score <= 0 and calc_score > 0:
        item['threat_score'] = int(calc_score)
    return item

def _sanitize_stats(stats: dict) -> dict:
    if not isinstance(stats, dict):
        return stats
    safe = dict(stats)
    safe['top_ips'] = _sanitize_records(safe.get('top_ips', []), ['src_ip', 'location'])
    safe['top_locations'] = _sanitize_records(safe.get('top_locations', []), ['location'])
    return safe


def _get_ip_geo_view(ip: str, cache: dict = None) -> dict:
    key = str(ip or '').strip()
    if not key:
        return {'location': '未知', 'latitude': 0.0, 'longitude': 0.0}
    if isinstance(cache, dict) and key in cache:
        cached = cache.get(key)
        if isinstance(cached, dict):
            return dict(cached)
        if cached:
            return {'location': str(cached), 'latitude': 0.0, 'longitude': 0.0}
    try:
        info = get_geo_info(key, allow_online=False) or {}
    except Exception:
        info = {}
    country_v, region_v, city_v = normalize_geo_fields(
        info.get('country'),
        info.get('province') or info.get('region'),
        info.get('city'),
    )
    try:
        lat = float(info.get('latitude') or 0)
    except Exception:
        lat = 0.0
    try:
        lon = float(info.get('longitude') or 0)
    except Exception:
        lon = 0.0
    summary = {
        'location': build_geo_location(country_v, region_v, city_v),
        'latitude': lat,
        'longitude': lon,
    }
    if isinstance(cache, dict):
        cache[key] = dict(summary)
    return summary


def _format_ip_location(ip: str, cache: dict = None) -> str:
    return str(_get_ip_geo_view(ip, cache).get('location') or '未知')


def _is_trusted_proxy_addr(addr: str) -> bool:
    ip_text = _normalize_ip_text(addr)
    if not ip_text:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except Exception:
        return False
    return any(ip_obj in network for network in _DASHBOARD_TRUSTED_PROXY_NETWORKS)


def _get_client_ip() -> str:
    remote = _normalize_ip_text(request.remote_addr) or str(request.remote_addr or '').strip()
    if not _is_trusted_proxy_addr(remote):
        return remote

    forwarded_chain = [
        ip_text for ip_text in (
            _normalize_ip_text(item) for item in _split_csv(request.headers.get('X-Forwarded-For'))
        ) if ip_text
    ]
    while forwarded_chain and _is_trusted_proxy_addr(forwarded_chain[-1]):
        forwarded_chain.pop()
    if forwarded_chain:
        return forwarded_chain[-1]

    real_ip = _normalize_ip_text(request.headers.get('X-Real-IP'))
    if real_ip:
        return real_ip
    return remote


def _is_same_origin_request() -> bool:
    origin = _normalize_origin(request.headers.get('Origin'))
    if origin:
        return origin in _DASHBOARD_ALLOWED_ORIGINS

    referer = _normalize_origin(request.headers.get('Referer'))
    if referer:
        return referer in _DASHBOARD_ALLOWED_ORIGINS
    try:
        sfs = str(request.headers.get('Sec-Fetch-Site') or '').strip().lower()
        return sfs == 'same-origin'
    except Exception:
        return False

@app.before_request
def _response_jitter():
    try:
        if request.path.startswith('/static/'):
            return None
        if request.method == 'OPTIONS':
            return None
        time.sleep(random.uniform(0.02, 0.09))
    except Exception:
        return None


def _check_login_rate_limit(client_ip: str) -> int:
    """
    返回 0 表示允许登录，返回 >0 表示需等待秒数。
    """
    now = time.monotonic()
    key = (client_ip or '').strip() or 'unknown'
    with _login_rate_lock:
        # 清理过期记录，避免内存增长
        if _login_rate_state:
            cutoff = now - max(_LOGIN_RATE_WINDOW_SECONDS, _LOGIN_BLOCK_SECONDS) * 2
            for k, v in list(_login_rate_state.items()):
                if v and v[2] and v[2] < cutoff:
                    _login_rate_state.pop(k, None)
        state = _login_rate_state.get(key)
        if state:
            window_start, count, blocked_until = state
        else:
            window_start, count, blocked_until = now, 0, 0.0

        if blocked_until and blocked_until > now:
            return int(blocked_until - now)

        if now - window_start > _LOGIN_RATE_WINDOW_SECONDS:
            window_start, count, blocked_until = now, 0, 0.0

        count += 1
        if count > _LOGIN_RATE_MAX:
            blocked_until = now + _LOGIN_BLOCK_SECONDS
            _login_rate_state[key] = (window_start, count, blocked_until)
            return int(_LOGIN_BLOCK_SECONDS)

        _login_rate_state[key] = (window_start, count, blocked_until)
        return 0

def _clear_login_rate_limit(client_ip: str) -> None:
    key = (client_ip or '').strip() or 'unknown'
    with _login_rate_lock:
        _login_rate_state.pop(key, None)

def _record_login_audit(client_ip: str, username: str, success: bool, reason: str = '') -> None:
    now_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    ip = (client_ip or '').strip() or 'unknown'
    user = (username or '').strip() or '-'
    entry = {
        'time': now_str,
        'ip': ip,
        'username': user,
        'success': bool(success),
        'reason': (reason or '').strip()
    }
    with _login_audit_lock:
        _login_audit_logs.appendleft(entry)
        if not success:
            _login_fail_counts[ip] = _login_fail_counts.get(ip, 0) + 1
            _login_fail_last[ip] = time.time()
            # 清理过期失败记录，避免长期堆积
            cutoff = time.time() - 24 * 3600
            for k, ts in list(_login_fail_last.items()):
                if ts < cutoff:
                    _login_fail_last.pop(k, None)
                    _login_fail_counts.pop(k, None)

def generate_csrf_token():
    if 'csrf_token' not in session: session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']
app.jinja_env.globals['csrf_token'] = generate_csrf_token

def enhanced_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            # 如果是 API 接口请求，返回 401 JSON，防止前端解析 HTML 报错
            if request.path.startswith('/api/'):
                return jsonify({'code': 401, 'msg': '未登录或会话已过期', 'data': None}), 401

            # 如果是普通页面请求，跳转到登录页
            return redirect(url_for('super_login'))
        if request.path.startswith('/api/') and not _is_same_origin_request():
            return jsonify({'code': 403, 'msg': 'Forbidden', 'data': None}), 403
        return f(*args, **kwargs)
    return decorated_function

# API接口CSRF保护装饰器
def csrf_protect_api(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            form_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token', '')
            session_token = session.get('csrf_token', '')
            if not session_token or not form_token or session_token != form_token:
                return jsonify({'code': 403, 'msg': 'CSRF 验证失败', 'data': None}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index(): return redirect(url_for('dashboard'))

@app.route('/favicon.ico')
def favicon():
    static_dir = app.static_folder or os.path.join(app.root_path, 'static')
    favicon_svg = os.path.join(static_dir, 'favicon.svg')
    favicon_ico = os.path.join(static_dir, 'favicon.ico')
    if os.path.exists(favicon_svg):
        return send_from_directory(static_dir, 'favicon.svg', mimetype='image/svg+xml')
    if os.path.exists(favicon_ico):
        return send_from_directory(static_dir, 'favicon.ico', mimetype='image/vnd.microsoft.icon')
    return ('', 204)

@app.route('/dashboard')
@enhanced_login_required
def dashboard(): return render_template('dashboard.html')

@app.route('/super/login', methods=['GET', 'POST'])
def super_login():
    if 'csrf_token' not in session: session['csrf_token'] = secrets.token_urlsafe(32)
    if request.method == 'POST':
        client_ip = _get_client_ip()
        wait_seconds = _check_login_rate_limit(client_ip)
        if wait_seconds > 0:
            _record_login_audit(client_ip, request.form.get('username', ''), False, 'rate_limited')
            return render_template(
                'admin_login.html',
                error=f"操作过于频繁，请 {wait_seconds} 秒后重试"
            ), 429
        form_token = request.form.get('csrf_token', '')
        session_token = session.get('csrf_token', '')
        if not session_token or not form_token or session_token != form_token:
            _record_login_audit(client_ip, request.form.get('username', ''), False, 'csrf_failed')
            return render_template('admin_login.html', error="CSRF 验证失败，请刷新页面重试"), 403
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if username in USERS and password == USERS[username]:
            session.clear()
            session.permanent = True
            session['is_admin'] = True
            session['admin_user'] = username
            session['login_at'] = int(time.time())
            _clear_login_rate_limit(client_ip)
            _record_login_audit(client_ip, username, True, '')
            return redirect(url_for('dashboard'))
        else:
            _record_login_audit(client_ip, username, False, 'bad_credentials')
            return render_template('admin_login.html', error="用户名或密码错误")
    return render_template('admin_login.html')

@app.route('/logout', methods=['GET'])
def logout_get():
    # 仅允许 POST 登出，GET 保持幂等跳转避免被跨站触发注销
    return redirect(url_for('dashboard'))


@app.route('/logout', methods=['POST'])
def logout():
    client_ip = _get_client_ip()
    if not session.get('is_admin'):
        return redirect(url_for('super_login'))
    username = str(session.get('admin_user') or '').strip() or '-'
    form_token = request.form.get('csrf_token', '') or request.headers.get('X-CSRF-Token', '')
    session_token = session.get('csrf_token', '')
    if not session_token or not form_token or session_token != form_token:
        _record_login_audit(client_ip, username, False, 'logout_csrf_failed')
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'code': 403, 'msg': 'CSRF 验证失败', 'data': None}), 403
        return render_template('admin_login.html', error="CSRF 验证失败，请重新登录"), 403
    _record_login_audit(client_ip, username, True, 'logout')
    session.clear()
    return redirect(url_for('super_login'))

@app.route('/api/get_event_logs')
@enhanced_login_required
def api_get_event_logs():
    try:
        limit = request.args.get('limit', '100')
        offset = request.args.get('offset', '0')
        hours = request.args.get('hours', '')
        source = request.args.get('source', '')
        severity = request.args.get('severity', '')
        event_type = request.args.get('event_type', '')
        keyword = request.args.get('q', '')
        rows = get_event_logs(
            limit=limit,
            offset=offset,
            source=source,
            severity=severity,
            event_type=event_type,
            keyword=keyword,
            hours=hours,
        )
        geo_cache = {}
        for item in rows or []:
            if isinstance(item, dict):
                item['location'] = _format_ip_location(item.get('src_ip', ''), geo_cache)
        rows = _sanitize_records(rows, [
            'timestamp', 'source', 'severity', 'event_type', 'src_ip',
            'session_id', 'tags', 'payload', 'raw_ref', 'raw_request_id', 'extra', 'location'
        ])
        return jsonify({'code': 0, 'msg': 'success', 'data': rows})
    except Exception as e:
        logger.exception(f"get_event_logs failed: {e}")
        return jsonify({'code': -1, 'msg': '服务异常', 'data': []})


@app.route('/api/get_event_stats')
@enhanced_login_required
def api_get_event_stats():
    try:
        hours = request.args.get('hours', '24')
        data = get_event_stats(hours=hours)
        data = _sanitize_stats(data) if isinstance(data, dict) else data
        if isinstance(data, dict):
            data['top_event_types'] = _sanitize_records(data.get('top_event_types', []), ['event_type'])
            data['top_tags'] = _sanitize_records(data.get('top_tags', []), ['tag'])
            geo_cache = {}
            top_ips = list(data.get('top_ips', []) or [])
            for item in top_ips:
                if isinstance(item, dict):
                    item['location'] = _format_ip_location(item.get('src_ip', ''), geo_cache)
            data['top_ips'] = top_ips
            data['top_ips'] = _sanitize_records(data.get('top_ips', []), ['src_ip', 'location'])
            data['unique_ips'] = int(data.get('unique_ips') or 0)
            data['by_source'] = {str(k): int(v) for k, v in dict(data.get('by_source', {})).items()}
            data['by_severity'] = {str(k): int(v) for k, v in dict(data.get('by_severity', {})).items()}
        return jsonify({'code': 0, 'msg': 'success', 'data': data})
    except Exception as e:
        logger.exception(f"get_event_stats failed: {e}")
        return jsonify({'code': -1, 'msg': '服务异常', 'data': {}})

@app.route('/api/get_geo_data')
@enhanced_login_required
def api_get_geo_data():
    try:
        hours = request.args.get('hours', '24')
        focus_ip = str(request.args.get('focus_ip', '') or '').strip()
        panel_limits = _dashboard_window_panel_limits(hours)
        limit = request.args.get('limit', '')
        geo_limit = _coerce_int(limit, panel_limits['geo_limit']) if str(limit).strip() else panel_limits['geo_limit']
        geo_limit = max(10, min(geo_limit, 300))
        data = get_event_geo_data(hours=hours, focus_ip=focus_ip, limit=geo_limit)
        data = _sanitize_records(data, ['src_ip', 'location'])
        return jsonify({'code': 0, 'msg': 'success', 'data': data})
    except Exception as e:
        logger.exception(f"get_geo_data failed: {e}")
        return jsonify({'code': -1, 'msg': '服务异常', 'data': []})

@app.route('/api/realtime')
@enhanced_login_required
def api_realtime():
    try:
        rows = get_event_logs(limit=5, offset=0)
        geo_cache = {}
        for item in rows or []:
            if isinstance(item, dict):
                item['location'] = _format_ip_location(item.get('src_ip', ''), geo_cache)
        rows = _sanitize_records(rows, [
            'id', 'timestamp', 'source', 'severity', 'event_type', 'src_ip',
            'session_id', 'tags', 'payload', 'raw_ref', 'raw_request_id', 'extra', 'location'
        ])
        return jsonify({'code': 0, 'data': rows})
    except Exception as e:
        logger.exception(f"realtime failed: {e}")
        return jsonify({'code': 0, 'data': []})

@app.route('/api/server_info')
@enhanced_login_required
def api_server_info():
    try:
        include_system_raw = str(request.args.get('include_system', '1')).strip().lower()
        include_system = include_system_raw in ('1', 'true', 'yes', 'on')
        return jsonify({'code': 0, 'data': get_server_info(include_system=include_system)})
    except Exception as e:
        logger.exception(f"server_info failed: {e}")
        return jsonify({'code': -1, 'data': None})

@app.route('/api/system_status')
@enhanced_login_required
def api_system_status():
    try:
        return jsonify({'code': 0, 'data': get_system_status()})
    except Exception as e:
        logger.exception(f"system_status failed: {e}")
        return jsonify({'code': -1, 'data': None})

# === 未知攻击分析 API ===
@app.route('/api/suspicious_requests')
@enhanced_login_required
def api_suspicious_requests():
    """获取可疑请求列表（基于行为分析，非规则匹配）"""
    try:
        real = has_real_data()
        hours = request.args.get('hours', '24')
        panel_limits = _dashboard_window_panel_limits(hours)
        limit = request.args.get('limit', '')
        total_limit = _coerce_int(limit, panel_limits['suspicious_limit']) if str(limit).strip() else panel_limits['suspicious_limit']
        total_limit = max(10, min(total_limit, 300))

        # 统一池化拉取：避免固定配额造成某一类被人为截断
        primary_fetch_limit = max(total_limit, min(300, int(total_limit * 3)))

        web_data = get_suspicious_requests(limit=primary_fetch_limit, hours=hours)
        ssh_data = get_ssh_suspicious_commands(limit=primary_fetch_limit, hours=hours)
        suspicious_data = list(web_data or []) + list(ssh_data or [])
        geo_cache = {}

        def _safe_int(v, default=0):
            try:
                return int(v)
            except Exception:
                return default

        def _row_core_key(item):
            d = item if isinstance(item, dict) else {}
            return "|".join([
                str(d.get('src_ip') or '').strip(),
                str(d.get('method') or '').strip().upper(),
                str(d.get('path') or '').strip(),
                str(d.get('query_string') or '').strip(),
            ])

        def _row_unique_key(item, panel):
            d = item if isinstance(item, dict) else {}
            rid = str(d.get('id') or d.get('raw_request_id') or '').strip()
            if rid:
                return f"{panel}|id:{rid}"
            return "|".join([
                panel,
                _row_core_key(d),
                str(d.get('create_time') or '').strip(),
                str(_safe_int(d.get('threat_score') or 0)),
            ])

        # 可疑层：仅展示 >=20（不再返回 12~19 观察项）
        filtered_suspicious = []
        for item in suspicious_data:
            if isinstance(item, dict):
                item = _attach_suspicious_signals(item)
            score = _safe_int((item or {}).get('threat_score') or 0, 0)
            if score < 20:
                continue
            if score >= 40:
                level = 'high'
            else:
                level = 'medium'
            item['risk_level'] = str(level or 'low')
            item['panel_level'] = 'suspicious'
            geo_view = _get_ip_geo_view((item or {}).get('src_ip', ''), geo_cache)
            item['location'] = str(geo_view.get('location') or '未知')
            item['latitude'] = geo_view.get('latitude', 0)
            item['longitude'] = geo_view.get('longitude', 0)
            filtered_suspicious.append(item)
        suspicious_data = filtered_suspicious

        # 按时间+分数倒序并去重后截断
        suspicious_data.sort(
            key=lambda x: (
                str((x or {}).get('create_time') or ''),
                _safe_int((x or {}).get('threat_score') or 0, 0)
            ),
            reverse=True
        )
        dedup_suspicious = []
        seen_suspicious = set()
        for item in suspicious_data:
            key = _row_unique_key(item, 'suspicious')
            if key in seen_suspicious:
                continue
            seen_suspicious.add(key)
            dedup_suspicious.append(item)
        suspicious_data = dedup_suspicious[:total_limit]
        data = suspicious_data

        data = _sanitize_records(data, [
            'session_id', 'src_ip', 'method', 'path', 'query_string',
            'headers', 'body', 'user_agent', 'referer', 'content_type', 'location', 'panel_level', 'risk_level',
            'latitude', 'longitude'
        ])
        return jsonify({'code': 0, 'msg': 'success', 'data': data, 'demo': (not real)})
    except Exception as e:
        logger.exception(f"suspicious_requests failed: {e}")
        return jsonify({'code': -1, 'msg': '服务异常', 'data': []})

@app.route('/api/session_analysis')
@enhanced_login_required
def api_session_analysis():
    """获取会话行为分析（攻击链追踪）"""
    try:
        real = has_real_data()
        hours = request.args.get('hours', '24')
        panel_limits = _dashboard_window_panel_limits(hours)
        limit = request.args.get('limit', '')
        min_count = request.args.get('min_count', '')
        limit_v = _coerce_int(limit, panel_limits['session_limit']) if str(limit).strip() else panel_limits['session_limit']
        min_count_v = _coerce_int(min_count, panel_limits['session_min_count']) if str(min_count).strip() else panel_limits['session_min_count']
        limit_v = max(10, min(limit_v, 300))
        min_count_v = max(1, min(min_count_v, 20))
        data = get_session_analysis(limit=limit_v, hours=hours, min_count=min_count_v)
        geo_cache = {}
        for item in data or []:
            if isinstance(item, dict):
                geo_view = _get_ip_geo_view(item.get('src_ip', ''), geo_cache)
                item['location'] = str(geo_view.get('location') or '未知')
                item['latitude'] = geo_view.get('latitude', 0)
                item['longitude'] = geo_view.get('longitude', 0)
        data = _sanitize_records(data, ['session_id', 'src_ip', 'path_sequence', 'path_steps', 'path_steps_full', 'threat_level', 'chain_type', 'location', 'latitude', 'longitude'])
        return jsonify({'code': 0, 'msg': 'success', 'data': data, 'demo': (not real)})
    except Exception as e:
        logger.exception(f"session_analysis failed: {e}")
        return jsonify({'code': -1, 'msg': '服务异常', 'data': []})

# === 管理端登录审计 ===
@app.route('/api/login_audit')
@enhanced_login_required
def api_login_audit():
    with _login_audit_lock:
        recent = list(_login_audit_logs)[:_LOGIN_AUDIT_RECENT]
        recent = _sanitize_records(recent, ['ip', 'username', 'reason', 'time'])
        top_failed = sorted(
            [{'ip': ip, 'count': count} for ip, count in _login_fail_counts.items()],
            key=lambda x: x['count'],
            reverse=True
        )[:8]
        top_failed = _sanitize_records(top_failed, ['ip'])
    return jsonify({'code': 0, 'msg': 'success', 'data': {'recent': recent, 'top_failed': top_failed}})

# === 风险目标标注 API ===
_RISK_TARGET_VIEW_FIELDS = [
    'id', 'target_type', 'target_value', 'risk_level', 'status', 'tags',
    'note', 'source', 'first_seen', 'last_seen', 'event_count',
    'created_at', 'updated_at', 'location'
]


def _risk_target_payload():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    out = dict(request.form)
    for k, v in data.items():
        out[k] = v
    return out


def _parse_tag_list(raw):
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set)):
        items = [str(x or '').strip() for x in raw]
    else:
        text = str(raw or '').strip()
        if text.startswith('[') or text.startswith('{'):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    items = [str(x or '').strip() for x in parsed]
                else:
                    items = [str(parsed or '').strip()] if parsed else []
            except Exception:
                items = [text]
        else:
            items = [x.strip() for x in text.split(',')]
    return [x for x in items if x]


@app.route('/api/risk_targets')
@enhanced_login_required
def api_risk_targets():
    try:
        target_type = request.args.get('target_type', '')
        risk_level = request.args.get('risk_level', '')
        status = request.args.get('status', '')
        keyword = request.args.get('q', '')
        limit = request.args.get('limit', '100')
        offset = request.args.get('offset', '0')
        rows = list_risk_targets(
            target_type=target_type,
            risk_level=risk_level,
            status=status,
            keyword=keyword,
            limit=limit,
            offset=offset,
        )
        geo_cache = {}
        for item in rows or []:
            if isinstance(item, dict):
                item['location'] = _format_ip_location(item.get('target_value', ''), geo_cache)
                item['tags'] = _parse_tag_list(item.get('tags'))
        data = _sanitize_records(rows, _RISK_TARGET_VIEW_FIELDS)
        return jsonify({'code': 0, 'msg': 'success', 'data': data})
    except Exception as e:
        logger.exception(f"risk_targets list failed: {e}")
        return jsonify({'code': -1, 'msg': '服务异常', 'data': []})


@app.route('/api/risk_targets/derive', methods=['POST'])
@enhanced_login_required
@csrf_protect_api
def api_risk_targets_derive():
    try:
        hours = request.args.get('hours', '')
        touched = derive_risk_targets(hours=hours)
        return jsonify({'code': 0, 'msg': 'success', 'data': {'touched': int(touched)}})
    except Exception as e:
        logger.exception(f"risk_targets derive failed: {e}")
        return jsonify({'code': -1, 'msg': '服务异常', 'data': {'touched': 0}})


@app.route('/api/risk_targets', methods=['POST'])
@enhanced_login_required
@csrf_protect_api
def api_risk_targets_create():
    body = _risk_target_payload()
    target_value = str(body.get('target_value') or '').strip()
    if not target_value:
        return jsonify({'code': -1, 'msg': 'target_value 不能为空', 'data': None})
    result = upsert_risk_target(
        target_value=target_value,
        target_type=body.get('target_type', 'ip'),
        risk_level=body.get('risk_level'),
        status=body.get('status'),
        tags=body.get('tags'),
        note=body.get('note'),
        source=body.get('source', 'manual'),
    )
    if result.get('ok'):
        return jsonify({'code': 0, 'msg': 'success', 'data': result})
    return jsonify({'code': -1, 'msg': result.get('msg', '保存失败'), 'data': None})


@app.route('/api/risk_targets/<int:target_id>', methods=['POST'])
@enhanced_login_required
@csrf_protect_api
def api_risk_targets_update(target_id):
    body = _risk_target_payload()
    fields = {}
    for key in ('target_type', 'target_value', 'risk_level', 'status', 'tags', 'note', 'source'):
        if key in body:
            fields[key] = body.get(key)
    if not fields:
        return jsonify({'code': -1, 'msg': '无可更新字段', 'data': None})
    result = update_risk_target(target_id, **fields)
    if result.get('ok'):
        return jsonify({'code': 0, 'msg': 'success', 'data': result})
    return jsonify({'code': -1, 'msg': result.get('msg', '更新失败'), 'data': None})


@app.route('/api/risk_targets/<int:target_id>/delete', methods=['POST'])
@enhanced_login_required
@csrf_protect_api
def api_risk_targets_delete(target_id):
    result = delete_risk_target(target_id)
    if result.get('ok'):
        return jsonify({'code': 0, 'msg': 'success', 'data': result})
    return jsonify({'code': -1, 'msg': result.get('msg', '删除失败'), 'data': None})

# ============================================
# round 9 合并：AI 工作区路由（检测 / 交互 / 分析 / 调查 / 团队中心桥接）
# ============================================
@app.route('/ai/center')
@enhanced_login_required
def ai_center_bridge():
    from utils.team_collector import endpoint_ok
    endpoint=os.environ.get('HONEYPOT_CENTER_URL','http://127.0.0.1:5169')
    if not endpoint_ok(endpoint,True):return '团队中心地址配置无效',400
    return redirect(endpoint.rstrip('/')+'/')


@app.route('/ai')
@enhanced_login_required
def ai_monitor():
    return render_template('ai.html')


@app.route('/api/ai/status')
@enhanced_login_required
def api_ai_status():
    return jsonify({'code': 0, 'data': local_ai.status()})


@app.route('/api/ai/probe', methods=['POST'])
@enhanced_login_required
@csrf_protect_api
def api_ai_probe():
    # Fixed safe test input; never accept a URL, prompt or model name from the browser.
    identity = str(session.get('username') or 'operator')
    import hashlib
    actor = hashlib.sha256(identity.encode()).hexdigest()[:12]
    probe_session = 'probe:' + actor + ':' + time.strftime('%Y%m%d%H', time.gmtime())
    result = local_ai.probe(probe_session, _get_client_ip())
    return jsonify({'code': 0, 'data': result})


@app.route('/ai/analysis')
@enhanced_login_required
def ai_analysis_page():
    ai_analyst.start_worker()
    return render_template('ai_analysis.html')


@app.route('/api/ai/analysis')
@enhanced_login_required
def api_ai_analysis():
    try:
        limit=max(1,min(30,int(request.args.get('limit',12))))
        risk=request.args.get('risk','');state=request.args.get('state','')
        before=request.args.get('before','')
        if before:
            value,identifier=before.split(':',1)
            if not re.fullmatch(r'[a-f0-9]{24}',identifier):raise ValueError()
            before=(float(value),identifier)
        else:before=None
        if risk and risk not in ai_analyst.RISKS:raise ValueError()
        if state and state not in ('queued','running','completed','fallback','cancelled'):raise ValueError()
        data=ai_analyst.status(limit,before,risk,state)
        return jsonify(code=0,data=data)
    except ValueError:return jsonify(code=1,msg='筛选参数无效'),400
    except Exception:return jsonify(code=1,msg='分析记录暂不可用'),503


@app.route('/api/ai/analysis/scan',methods=['POST'])
@enhanced_login_required
@csrf_protect_api
def api_ai_analysis_scan():
    try:
        ai_analyst.ingest_once();job=ai_analyst.queue_report(force=True);ai_analyst.start_worker();ai_analyst._wake.set()
        return jsonify(code=0,data={'job':job,'scan':dict(ai_analyst._state)})
    except Exception:return jsonify(code=1,msg='日志索引暂不可用'),503


@app.route('/api/ai/analysis/mode',methods=['POST'])
@enhanced_login_required
@csrf_protect_api
def api_ai_analysis_mode():
    data=request.get_json(silent=True)
    if not isinstance(data,dict) or data.get('mode') not in ('interactive','automatic'):return jsonify(code=1,msg='模式无效'),400
    try:return jsonify(code=0,data={'pause_until':local_ai.STORE.pause_background(600 if data['mode']=='interactive' else 0)})
    except Exception:return jsonify(code=1,msg='调度状态暂不可用'),503


@app.route('/api/ai/analysis/<identifier>')
@enhanced_login_required
def api_ai_analysis_detail(identifier):
    if not re.fullmatch(r'[a-f0-9]{24}',identifier):return jsonify(code=1,msg='编号无效'),400
    try:
        row=ai_analyst.get_store().get(identifier)
        if not row or row['task']!='report':return jsonify(code=1,msg='报告不存在'),404
        row['reviews']=ai_analyst.get_store().reviews(identifier)
        return jsonify(code=0,data=row)
    except Exception:return jsonify(code=1,msg='报告暂不可用'),503


@app.route('/api/ai/analysis/<identifier>/export')
@enhanced_login_required
def api_ai_analysis_export(identifier):
    if not re.fullmatch(r'[a-f0-9]{24}',identifier):return jsonify(code=1,msg='编号无效'),400
    try:
        from flask import make_response
        row=ai_analyst.get_store().get(identifier)
        if not row or row['task']!='report':return jsonify(code=1,msg='报告不存在'),404
        if row['status']!='completed':return jsonify(code=1,msg='报告尚未完成'),409
        from utils.markdown_export import literal
        r=row['result'];safe=literal
        parts=['# '+safe(r['title']),f'AI 风险：{safe(r["risk"])} · 报告 {identifier} · 调用 {row["call_id"]}',
            '## 概述',safe(r['summary']),'## 攻击意图',safe(r['intent']),'## 风险理由',safe(r['risk_reason']),
            '## 行为过程',*['- '+safe(v['description'])+' · 证据 '+v['evidence_id'] for v in r['timeline']],
            '## 复核建议',*['- '+safe(v) for v in r['recommendations']],'## 判断局限',safe(r['limitations']),
            '## 引用证据',*['- '+v['id']+'：'+safe(v['quote']) for v in r['evidence']],
            '## 本次可见原文',*['- '+safe(v['locator'])+' · '+safe(v['timestamp'])+' · '+safe(v['src_ip'])+' · 原规则 '+safe(v['rule_level'])+'\n  '+safe(v['excerpt']) for v in row['context']['records']]]
        response=make_response('\n\n'.join(parts));response.headers['Content-Type']='text/markdown; charset=utf-8'
        response.headers['Content-Disposition']='attachment; filename="ai-report-'+identifier+'.md"';return response
    except Exception:return jsonify(code=1,msg='报告导出暂不可用'),503


def _ai_safe_endpoint(f):
    @wraps(f)
    def guarded(*args,**kwargs):
        try:return f(*args,**kwargs)
        except Exception as error:
            logger.error('AI endpoint unavailable: %s',type(error).__name__)
            return jsonify(code=1,msg='AI 数据服务暂不可用，原规则继续运行'),503
    return guarded


def _chat_owner():
    if 'ai_chat_owner' not in session:session['ai_chat_owner']=secrets.token_hex(16)
    return session['ai_chat_owner']


@app.route('/api/ai/recover',methods=['POST'])
@enhanced_login_required
@csrf_protect_api
def api_ai_recover():
    result=local_ai.call_model('probe',[{'role':'system','content':'Return JSON {"reply":"..."}; local service recovery test, no tools.'},
        {'role':'user','content':'请用一句中文确认模型可以正常回答。'}],'recovery:'+_chat_owner()+':'+str(int(time.time()//3600)),_get_client_ip(),options={'bypass_circuit':True})
    return jsonify(code=0,data=result)


@app.route('/api/ai/analysis/<identifier>/retry',methods=['POST'])
@enhanced_login_required
@csrf_protect_api
@_ai_safe_endpoint
def api_ai_report_retry(identifier):
    if not re.fullmatch(r'[a-f0-9]{24}',identifier):return jsonify(code=1,msg='编号无效'),400
    store=ai_analyst.get_store();row=store.get(identifier)
    if not row or row['task']!='report':return jsonify(code=1,msg='报告不存在'),404
    status=store.retry_task(identifier);ai_analyst._wake.set()
    return jsonify(code=0,data={'status':status})


@app.route('/api/ai/analysis/<identifier>/review',methods=['POST'])
@enhanced_login_required
@csrf_protect_api
@_ai_safe_endpoint
def api_ai_report_review(identifier):
    data=request.get_json(silent=True)
    if not re.fullmatch(r'[a-f0-9]{24}',identifier) or not isinstance(data,dict):return jsonify(code=1,msg='参数无效'),400
    verdict=data.get('verdict','');risk=data.get('risk','');note=data.get('note','')
    if verdict not in ('agree','false_positive','missed','needs_review') or risk not in ai_analyst.RISKS or not isinstance(note,str) or len(note)>500:return jsonify(code=1,msg='复核内容无效'),400
    if not ai_analyst.get_store().review(identifier,_chat_owner(),verdict,risk,ai_analyst._clean(note,500)):return jsonify(code=1,msg='报告未完成或不存在'),409
    return jsonify(code=0,data={'saved':True})


@app.route('/api/ai/chat/history')
@enhanced_login_required
@_ai_safe_endpoint
def api_ai_chat_history():
    conversation=request.args.get('conversation','')
    if not re.fullmatch(r'[a-f0-9]{32}',conversation):return jsonify(code=1,msg='会话无效'),400
    return jsonify(code=0,data=ai_analyst.get_store().conversations(_chat_owner(),conversation))


@app.route('/api/ai/archives')
@enhanced_login_required
def api_ai_archives():
    try:return jsonify(code=0,data=ai_analyst.get_store().archives())
    except Exception:return jsonify(code=1,msg='档案暂不可用'),503


@app.route('/api/ai/archives/<name>')
@enhanced_login_required
def api_ai_archive(name):
    try:
        rows=ai_analyst.get_store().archived(name)
        if rows is None:return jsonify(code=1,msg='档案不存在'),404
        from flask import make_response
        response=make_response(json.dumps(rows,ensure_ascii=False,indent=2));response.headers['Content-Type']='application/json; charset=utf-8'
        response.headers['Content-Disposition']='attachment; filename="analysis-'+name+'.json"';return response
    except Exception:return jsonify(code=1,msg='档案读取失败'),503


@app.route('/api/ai/chat/<identifier>/cancel',methods=['POST'])
@enhanced_login_required
@csrf_protect_api
@_ai_safe_endpoint
def api_ai_chat_cancel(identifier):
    if not re.fullmatch(r'[a-f0-9]{24}',identifier):return jsonify(code=1,msg='编号无效'),400
    if not ai_analyst.get_store().cancel(identifier,_chat_owner()):return jsonify(code=1,msg='问答不存在'),404
    return jsonify(code=0,data={'status':'cancelled'})


@app.route('/api/ai/chat',methods=['POST'])
@enhanced_login_required
@csrf_protect_api
def api_ai_chat():
    if not local_ai.SETTINGS.get('analysis_enabled') or not local_ai.SETTINGS['enabled']:return jsonify(code=1,msg='AI 分析已关闭'),409
    try:
        payload=request.get_json(silent=True)
        if not isinstance(payload,dict):raise ValueError()
        conversation=payload.get('conversation','');question=payload.get('question','');ip=payload.get('src_ip','');term=payload.get('term','');mode=payload.get('mode','logs');report_id=payload.get('report_id','');case_id=payload.get('case_id','');evidence_id=payload.get('evidence_id','')
        if case_id and (not isinstance(case_id,str) or not re.fullmatch(r'[a-f0-9]{24}',case_id)):raise ValueError()
        if evidence_id and (not isinstance(evidence_id,str) or not re.fullmatch(r'[a-f0-9]{24}',evidence_id)):raise ValueError()
        if sum(bool(v) for v in (report_id,case_id,evidence_id))>1:raise ValueError()
        if not all(isinstance(v,str) for v in (conversation,question,ip,term,mode,report_id,case_id,evidence_id)) or not re.fullmatch(r'[a-f0-9]{32}',conversation) or mode not in ('logs','general') or (report_id and not re.fullmatch(r'[a-f0-9]{24}',report_id)):raise ValueError()
        job=ai_analyst.ask(_chat_owner(),conversation,question,ip,term,mode,report_id,case_id,evidence_id)
        if job['status']=='rejected':return jsonify(code=1,msg='问答额度或队列已满'),429
        return jsonify(code=0,data=job),202
    except ValueError:return jsonify(code=1,msg='问题、会话编号或来源地址无效'),400
    except Exception:return jsonify(code=1,msg='问答暂不可用'),503


@app.route('/api/ai/chat/<identifier>')
@enhanced_login_required
def api_ai_chat_result(identifier):
    if not re.fullmatch(r'[a-f0-9]{24}',identifier):return jsonify(code=1,msg='编号无效'),400
    try:
        row=ai_analyst.get_store().get(identifier,_chat_owner())
        if not row or row['task'] not in ('chat','general_chat'):return jsonify(code=1,msg='问答不存在'),404
        return jsonify(code=0,data=row)
    except Exception:return jsonify(code=1,msg='问答暂不可用'),503


@app.route('/ai/investigations')
@enhanced_login_required
def ai_investigations_page():
    return render_template('investigations.html')


def _investigations():
    return InvestigationStore(ai_analyst.get_store())


@app.route('/api/ai/source-profile')
@enhanced_login_required
@_ai_safe_endpoint
def api_ai_source_profile():
    try:return jsonify(code=0,data=_investigations().profile(request.args.get('ip','')))
    except ValueError as e:return jsonify(code=1,msg=str(e)),400


@app.route('/api/ai/investigations')
@enhanced_login_required
@_ai_safe_endpoint
def api_ai_investigations():
    try:
        raw=request.args.get('before','');before=None
        if raw:
            if not re.fullmatch(r'[0-9]{1,12}(?:\.[0-9]{1,10})?:[a-f0-9]{24}',raw):raise ValueError('分页编号无效')
            stamp,identifier=raw.split(':');before=(float(stamp),identifier)
        return jsonify(code=0,data=_investigations().listing(request.args.get('state',''),request.args.get('ip',''),before=before,term=request.args.get('term','')))
    except ValueError as e:return jsonify(code=1,msg=str(e)),400


@app.route('/api/ai/investigations',methods=['POST'])
@enhanced_login_required
@csrf_protect_api
@_ai_safe_endpoint
def api_ai_investigation_create():
    try:
        p=request.get_json(silent=True)
        if not isinstance(p,dict):raise ValueError('请求格式无效')
        report=p.get('report_id','')
        if not isinstance(report,str) or (report and not re.fullmatch(r'[a-f0-9]{24}',report)):raise ValueError('报告编号无效')
        return jsonify(code=0,data=_investigations().create(p.get('title',''),p.get('src_ip',''),_chat_owner(),report)),201
    except ValueError as e:return jsonify(code=1,msg=str(e)),400


@app.route('/api/ai/investigations/<identifier>')
@enhanced_login_required
@_ai_safe_endpoint
def api_ai_investigation_detail(identifier):
    if not re.fullmatch(r'[a-f0-9]{24}',identifier):return jsonify(code=1,msg='编号无效'),400
    row=_investigations().get(identifier)
    if not row:return jsonify(code=1,msg='调查不存在'),404
    return jsonify(code=0,data=row)


@app.route('/api/ai/investigations/<identifier>',methods=['POST'])
@enhanced_login_required
@csrf_protect_api
@_ai_safe_endpoint
def api_ai_investigation_update(identifier):
    if not re.fullmatch(r'[a-f0-9]{24}',identifier):return jsonify(code=1,msg='编号无效'),400
    try:
        p=request.get_json(silent=True)
        if not isinstance(p,dict):raise ValueError('请求格式无效')
        for k in ('state','risk','report_id'):
            if not isinstance(p.get(k,''),str):raise ValueError('字段类型无效')
        if p.get('report_id') and not re.fullmatch(r'[a-f0-9]{24}',p['report_id']):raise ValueError('报告编号无效')
        return jsonify(code=0,data=_investigations().update(identifier,p.get('revision'),_chat_owner(),p.get('state',''),p.get('risk',''),p.get('note',''),p.get('report_id','')))
    except Conflict as e:return jsonify(code=1,msg=str(e)),409
    except ValueError as e:return jsonify(code=1,msg=str(e)),400


@app.route('/api/ai/investigations/<identifier>/export')
@enhanced_login_required
@_ai_safe_endpoint
def api_ai_investigation_export(identifier):
    if not re.fullmatch(r'[a-f0-9]{24}',identifier):return jsonify(code=1,msg='编号无效'),400
    try:text=_investigations().export(identifier)
    except ValueError:return jsonify(code=1,msg='调查不存在'),404
    return app.response_class(text,mimetype='text/markdown',headers={'Content-Disposition':'attachment; filename="investigation-'+identifier+'.md"'})

@app.route('/ai/interactions')
@enhanced_login_required
def ai_interactions_page():
    return render_template('ai_interactions.html')


@app.route('/api/ai/interactions')
@enhanced_login_required
def api_ai_interactions():
    from utils.ai_interaction import get_store
    try:
        limit=max(1,min(100,int(request.args.get('limit',50))))
        sid=request.args.get('session_id','').strip()
        channel=request.args.get('channel','').strip()
        if sid and not re.fullmatch(r'[0-9a-f]{32}',sid):return jsonify(code=1,msg='会话编号无效'),400
        if channel not in ('','ssh','web'):return jsonify(code=1,msg='协议无效'),400
        return jsonify(code=0,data=get_store().listing(limit,sid,channel))
    except ValueError:
        return jsonify(code=1,msg='参数无效'),400
    except Exception:
        return jsonify(code=1,msg='交互记录暂不可用'),503


@app.route('/ai/detection')
@enhanced_login_required
def ai_detection_page():
    return render_template('ai_detection.html')


@app.route('/api/ai/detections')
@enhanced_login_required
def api_ai_detections():
    try:
        limit=max(1,min(100,int(request.args.get('limit',50))))
        ip=request.args.get('src_ip','').strip()
        if ip:ip=str(ipaddress.ip_address(ip))
        data=ai_detection.STORE.listing(limit,ip)
        from db.event_logs import severity_from_score
        for row in data['records']:row['rule_level']=severity_from_score(row['snapshot']['rule_score'])
        data['policy']={k:local_ai.SETTINGS[k] for k in ('enabled','detection_enabled','detection_queue_max','detection_per_ip_hour','normal_sample_every')}
        return jsonify({'code':0,'data':data})
    except ValueError:
        return jsonify({'code':400,'msg':'来源地址或查询数量无效'}),400
    except Exception:
        return jsonify({'code':503,'msg':'AI 研判记录暂不可用；原有规则仍继续处理'}),503


@app.route('/api/ai/detections/<identifier>')
@enhanced_login_required
def api_ai_detection_detail(identifier):
    if len(identifier)!=24 or any(c not in '0123456789abcdef' for c in identifier):
        return jsonify({'code':404,'msg':'记录不存在'}),404
    try:
        row=ai_detection.STORE.get(identifier)
        if row is None:return jsonify({'code':404,'msg':'记录不存在'}),404
        return jsonify({'code':0,'data':row})
    except Exception:
        return jsonify({'code':503,'msg':'记录暂不可用'}),503


@app.route('/api/ai/detections/<identifier>/retry',methods=['POST'])
@enhanced_login_required
@csrf_protect_api
def api_ai_detection_retry(identifier):
    if len(identifier)!=24 or any(c not in '0123456789abcdef' for c in identifier):
        return jsonify({'code':404,'msg':'记录不存在'}),404
    if not local_ai.SETTINGS['enabled'] or not local_ai.SETTINGS['detection_enabled']:
        return jsonify({'code':409,'msg':'AI 研判已关闭'}),409
    try:
        state=ai_detection.STORE.retry(identifier,local_ai.SETTINGS)
        if state is None:return jsonify({'code':404,'msg':'记录不存在'}),404
        if state=='queue_full':return jsonify({'code':429,'msg':'分析队列已满，原结果保留'}),429
        ai_detection.start_worker()
        return jsonify({'code':0,'data':{'status':state}})
    except Exception:
        return jsonify({'code':503,'msg':'无法提交分析任务'}),503


@app.route('/api/ai/analyze-recent',methods=['POST'])
@enhanced_login_required
@csrf_protect_api
def api_ai_analyze_recent():
    try:
        return jsonify({'code':0,'data':{'outcomes':ai_detection.review_recent_requests(5)}})
    except Exception:
        return jsonify({'code':503,'msg':'无法读取原请求或提交分析；原记录保持可用'}),503


# === 后台任务：自动归档（仅 Dashboard 执行） ===
from db import archive_old_logs_sqlite, USE_MYSQL

from dashboard.team_api import register as register_team_api
register_team_api(app, enhanced_login_required, csrf_protect_api, _ai_safe_endpoint, _chat_owner)

class BackgroundArchiver(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        # 归档任务按小时执行，降低 I/O 干扰
        self.interval = _env_int('ARCHIVE_BACKGROUND_INTERVAL_SECONDS', 3600, 60, 86400)

    def run(self):
        logger.info(f"后台归档任务已启动 (周期: {self.interval}s)")
        while True:
            try:
                time.sleep(self.interval)
                # MySQL 有自己的运维策略，这里只处理 SQLite 文件膨胀问题
                if not USE_MYSQL:
                    logger.info("开始执行定期日志归档...")
                    archive_old_logs_sqlite()
                    logger.info("日志归档完成")
            except Exception as e:
                logger.error(f"归档任务异常: {e}")

if __name__ == '__main__':
    ai_analyst.start_worker()
    import argparse

    # 降低 Flask/Werkzeug 启动日志噪声
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    parser = argparse.ArgumentParser(description='管理端')
    parser.add_argument('-H', '--host', default=_env_str('DASHBOARD_HOST', '127.0.0.1'), help='监听地址')
    parser.add_argument('-p', '--port', type=int, default=_env_int('DASHBOARD_PORT', 5001, 1, 65535), help='监听端口')
    args = parser.parse_args()

    logger.info(f"管理端就绪 | 访问: http://{args.host}:{args.port}")

    # 启动后台归档线程
    archiver = BackgroundArchiver()
    archiver.start()

    server = make_server(
        args.host,
        args.port,
        app,
        threaded=True,
        request_handler=_StealthRequestHandler,
    )
    try:
        server._server_version = FAKE_SERVER_HEADERS.get('Server', 'nginx/1.24.0')
    except Exception:
        pass
    server.serve_forever()



