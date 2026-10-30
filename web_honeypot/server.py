# -*- coding: utf-8 -*-
"""
蜜罐端 - Web 诱捕系统
端口：5000
功能：伪造后台登录、SQL注入陷阱、XSS陷阱、文件包含陷阱
"""
from flask import Flask, request, render_template, make_response, jsonify, session
from markupsafe import Markup
import os
import sys

import re
import random
import time

import secrets
import ipaddress
from collections import deque
from threading import Lock
from typing import Optional, Dict, Tuple
from urllib.parse import unquote, urlparse, quote
import html
import logging
from werkzeug.serving import make_server

_APP_DIR = os.path.abspath(os.path.dirname(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_APP_DIR, '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


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

from app_config import env_bool as _env_bool, env_int as _env_int, env_str as _env_str, config
from db import generate_session_id, log_raw_request
from utils.http_fingerprint import FAKE_SERVER_HEADERS, FINGERPRINT_STRIP_HEADERS, StealthRequestHandler, spoof_http_fingerprint
from utils.logger import get_web_logger
from web_honeypot import routes_public
from web_honeypot import routes_traps
from web_honeypot import admin_views
from web_honeypot import admin_api
from web_honeypot import errors

logger = get_web_logger()

app = Flask(
    __name__,
    template_folder=os.path.join(_APP_DIR, 'templates'),
    static_folder=os.path.join(_APP_DIR, 'static')
)
app.config.from_object(config['default'])
# 伪装 PHP 会话 cookie 名称，避免默认 session 暴露框架痕迹
app.config.setdefault('SESSION_COOKIE_NAME', 'PHPSESSID')
app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')
app.config.setdefault('MAX_FORM_MEMORY_SIZE', _env_int('WEB_MAX_FORM_MEMORY_SIZE', 512 * 1024, 64 * 1024, 8 * 1024 * 1024))
app.config.setdefault('MAX_FORM_PARTS', _env_int('WEB_MAX_FORM_PARTS', 200, 20, 2000))
# 核心指纹伪装：覆盖默认 Server 头（Werkzeug/Python）
# 统一呈现 Nginx + PHP 风格，降低框架暴露风险
# 具体逻辑由 _spoof_http_fingerprint 统一处理

_SERVER_STARTED_TS = time.time()
_SERVER_STARTED_AT = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(_SERVER_STARTED_TS))
_FAKE_APP_ENV = 'production'
_APP_VERSION = '2.6.4'
_APP_BUILD = '2026.01.20'
_ADMIN_SID_COOKIE = _env_str('ADMIN_SID_COOKIE', 'cms_admin_sid') or 'cms_admin_sid'
_ADMIN_LOGIN_CSRF_SESSION_KEY = 'admin_login_csrf_token'

_admin_access_logs = deque(maxlen=200)
_admin_access_lock = Lock()

_admin_data_lock = Lock()
_admin_content_items = []
_admin_users = []
_admin_settings = {
    'site_name': '华盛内容管理',
    'admin_email': 'admin@huasheng-tech.com',
    'updated_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
}

# 伪造 Root 显示（仅前端展示，不参与真实认证）
_DECOY_ROOT_ENABLED = _env_bool('DECOY_ROOT_ENABLED', True)
_DECOY_ROOT_USERNAME = _env_str('DECOY_ROOT_USERNAME', 'root') or 'root'
_DECOY_ROOT_ROLE = _env_str('DECOY_ROOT_ROLE', '超级管理员') or '超级管理员'
_DECOY_ROOT_STATUS = _env_str('DECOY_ROOT_STATUS', '启用') or '启用'
_DECOY_ROOT_EMAIL = _env_str('DECOY_ROOT_EMAIL', 'root@company.com') or 'root@company.com'
_DECOY_ROOT_LAST_LOGIN = _env_str('DECOY_ROOT_LAST_LOGIN', 'auto') or 'auto'
_DECOY_ROOT_ID = _env_str('DECOY_ROOT_ID', '0') or '0'
_DECOY_ROOT_ACTIVE_RECENT_MINUTES = _env_int('DECOY_ROOT_ACTIVE_RECENT_MINUTES', 15, 1, 1440)

# 管理端访问日志动作中文映射（避免英文动作名出现在日志里）
_ADMIN_ACTION_LABELS = {
    'review_request': '审核请求',
    'create': '新建',
    'open_modal': '打开弹窗',
    'edit': '编辑',
    'delete': '删除',
    'export_logs': '访问日志导出',
    'export_logs_denied': '访问日志导出(拒绝)',
    'backup_download': '备份下载',
    'backup_download_denied': '备份下载(拒绝)',
    'backup_job': '备份任务',
    'upload_submit': '上传提交',
    'upload_denied': '上传被拒绝',
}

# 定义精选的弱口令池，用于随机分配给不同用户
_WEAK_PASSWORD_POOL = [
    '123456', '12345678', 'password', '111111', 'qwerty',
    'admin123', 'admin888', 'Admin@123', 'System123',
    'Aa123456', 'Welcome1', 'Pass1234', 'admin2026'
]
_SHOW_CREDENTIAL_LOGS = _env_bool('SHOW_CREDENTIAL_LOGS', False)
_EMIT_CREDENTIAL_LINES = _env_bool('EMIT_CREDENTIAL_LINES', False)

def _emit_credential_line(username: str, password: str) -> None:
    """仅用于 main.py 解析汇总，不写入 logger"""
    if not _EMIT_CREDENTIAL_LINES:
        return
    try:
        print(f"CRED::{username}::{password}", flush=True)
    except Exception:
        logger.debug("emit credential line failed", exc_info=True)


_admin_session_lock = Lock()
_admin_sessions: Dict[str, Tuple[str, float, str, str]] = {}
_ADMIN_SESSION_TTL_SECONDS = 6 * 3600
_ADMIN_SESSION_GC_INTERVAL_SECONDS = 30.0
_ADMIN_SESSION_GC_SIZE_THRESHOLD = 128
_admin_session_last_gc = 0.0

_admin_login_bind_lock = Lock()
_admin_ip_login_bind: Dict[str, Tuple[str, float]] = {}
_ADMIN_IP_BIND_TTL_SECONDS = 2 * 3600


def _push_admin_access_log(src_ip: str, username: str, action: str, result: str):
    try:
        now = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        item = {
            'time': now,
            'user': (username or 'admin')[:32],
            'ip': (src_ip or '')[:64],
            'action': (action or '')[:120],
            'result': (result or '')[:32],
        }
        with _admin_access_lock:
            _admin_access_logs.appendleft(item)
    except Exception:
        logger.debug("push admin access log failed", exc_info=True)


def _push_admin_access_log_with_time(time_str: str, src_ip: str, username: str, action: str, result: str):
    try:
        item = {
            'time': (time_str or '')[:32],
            'user': (username or 'admin')[:32],
            'ip': (src_ip or '')[:64],
            'action': (action or '')[:120],
            'result': (result or '')[:32],
        }
        with _admin_access_lock:
            _admin_access_logs.append(item)
    except Exception:
        logger.debug("push admin access log with time failed", exc_info=True)


def _seed_admin_access_logs():
    try:
        with _admin_access_lock:
            if len(_admin_access_logs) > 0:
                return

        now = int(time.time())
        seeds = [
            (now - 3600 * 24 * 2 - 1800, '10.0.12.21', 'root', '登录系统', '成功'),
            (now - 3600 * 24 * 2 - 1380, '10.0.12.21', 'root', '访问模块:系统维护', '成功'),
            (now - 3600 * 24 - 2400, '10.0.0.55', 'editor', '登录系统', '成功'),
            (now - 3600 * 24 - 2100, '10.0.0.55', 'editor', '访问模块:内容管理', '成功'),
            (now - 3600 * 12 - 900, '127.0.0.1', 'admin', '登录系统', '成功'),
            (now - 3600 * 6 - 600, '127.0.0.1', 'admin', '导入配置包', '成功'),
            (now - 3600 * 2 - 420, '192.168.56.1', 'deploy', '登录系统', '失败'),
            (now - 3600 * 2 - 390, '192.168.56.1', 'deploy', '登录系统', '失败'),
            (now - 3600 * 1 - 300, '127.0.0.1', 'root', '导出访问日志', '成功'),
        ]

        for ts, ip, user, action, result in seeds:
            t = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
            _push_admin_access_log_with_time(t, ip, user, action, result)
    except Exception:
        logger.debug("seed admin access logs failed", exc_info=True)


_seed_admin_access_logs()


def _seed_admin_fake_data():
    try:
        with _admin_data_lock:
            if _admin_content_items and _admin_users:
                return

            _admin_content_items.clear()
            _admin_content_items.extend([
                {
                    'id': 1,
                    'title': '华盛科技通过 ISO 27001 信息安全管理体系认证',
                    'author': '合规办公室',
                    'status': '已发布',
                    'publish_time': '2024-12-15 10:30:00',
                    'public_url': '/news?id=1',
                    'summary': '认证范围覆盖研发、交付与运维流程。公司将持续完善权限治理、审计留痕与供应链安全管理机制。',
                    'content': '本次认证覆盖信息资产管理、访问控制、变更管理、日志审计与应急响应等关键环节。下一阶段，公司将围绕最小权限、配置基线与供应链安全持续推进标准化落地，并在核心项目中引入定期演练与第三方评估。',
                },
                {
                    'id': 2,
                    'title': '发布“统一指标体系”组件，支持多源数据对齐与口径治理',
                    'author': '产品研发中心',
                    'status': '已发布',
                    'publish_time': '2024-12-10 09:00:00',
                    'public_url': '/news?id=2',
                    'summary': '新版本提供指标管理、口径追溯与变更审批，帮助业务、数仓与报表实现统一口径对齐。',
                    'content': '该组件支持指标分层、口径版本管理与血缘追踪，并提供审批流与变更影响分析。配合权限模型与审计能力，可用于财务、运营、风控等跨部门场景的口径统一与治理闭环。',
                },
                {
                    'id': 3,
                    'title': '与高校共建联合实验室，推进大模型工程化与数据安全研究',
                    'author': '战略合作部',
                    'status': '已发布',
                    'publish_time': '2024-12-05 14:20:00',
                    'public_url': '/news?id=3',
                    'summary': '围绕数据脱敏、访问审计与模型推理效率优化开展合作，建设可复用的工程化工具链。',
                    'content': '联合实验室将聚焦数据脱敏与访问审计策略、模型推理性能优化与工程化落地工具链建设。合作成果将优先在产业项目中验证，以提升模型在企业生产环境中的可用性与合规性。',
                },
                {
                    'id': 1004,
                    'title': '系统维护窗口通知（核心服务）',
                    'author': '运维团队',
                    'status': '草稿',
                    'publish_time': '2026-01-05 09:10:00',
                    'public_url': '/page?name=maintenance',
                    'summary': '预计 02:00-03:00 对核心服务进行例行维护，期间可能出现短暂抖动或重试。',
                    'content': '维护内容包括：配置基线核验、日志落盘策略调整、规则库增量更新与证书轮换演练。请业务方提前确认定时任务与对外依赖，避免在窗口期执行批量导入与发布操作。',
                },
            ])

            _admin_users.clear()
            # 预定义用户基础数据
            base_users = [
                {'id': 1, 'username': 'admin', 'email': 'admin@company.com', 'role': '管理员', 'status': '启用', 'last_login': '2026-01-19 00:15'},
                {'id': 2, 'username': 'editor', 'email': 'editor@company.com', 'role': '编辑', 'status': '启用', 'last_login': '2026-01-17 14:20'},
                {'id': 3, 'username': 'ops', 'email': 'ops@company.com', 'role': '运维', 'status': '启用', 'last_login': '2026-01-16 09:00'},
                {'id': 4, 'username': 'auditor', 'email': 'audit@company.com', 'role': '审计', 'status': '启用', 'last_login': '2026-01-15 11:20'},
            ]

            # 打乱密码池
            pool = list(_WEAK_PASSWORD_POOL)
            random.shuffle(pool)

            # 打印日志头，与 SSH 保持风格统一
            if _SHOW_CREDENTIAL_LOGS:
                logger.info("========= Web 凭证初始化 =========")

            for i, u in enumerate(base_users):
                # 循环分配密码
                pwd = pool[i % len(pool)]
                u['password'] = pwd

                _emit_credential_line(u['username'], pwd)
                # 记录当前分配的诱饵口令，便于核对演示凭证
                if _SHOW_CREDENTIAL_LOGS:
                    logger.info(f"用户: {u['username']:<10} | 密码: {pwd}")

                _admin_users.append(u)

            if _SHOW_CREDENTIAL_LOGS:
                logger.info("==================================")

            _admin_settings['site_name'] = _admin_settings.get('site_name') or '华盛内容管理'
            _admin_settings['admin_email'] = _admin_settings.get('admin_email') or 'admin@huasheng-tech.com'
    except Exception:
        logger.debug("seed admin fake data failed", exc_info=True)


def _cleanup_admin_sessions_locked(now_ts: float, force: bool = False) -> None:
    global _admin_session_last_gc
    if not _admin_sessions:
        _admin_session_last_gc = now_ts
        return
    if (not force) and len(_admin_sessions) < _ADMIN_SESSION_GC_SIZE_THRESHOLD and (
        (now_ts - _admin_session_last_gc) < _ADMIN_SESSION_GC_INTERVAL_SECONDS
    ):
        return
    expired_sids = [
        sid for sid, rec in list(_admin_sessions.items())
        if float((rec or ('', 0.0, ''))[1] or 0.0) <= now_ts
    ]
    for sid in expired_sids:
        _admin_sessions.pop(sid, None)
    _admin_session_last_gc = now_ts


def _pack_admin_session(username: str, exp: float, bind_ip: str, csrf_token: str):
    return (
        (username or 'admin')[:32],
        float(exp or 0.0),
        (bind_ip or '')[:64],
        (csrf_token or '')[:96],
    )


def _unpack_admin_session(rec) -> Tuple[str, float, str, str]:
    if not isinstance(rec, tuple):
        return '', 0.0, '', ''
    if len(rec) >= 4:
        username, exp, bind_ip, csrf_token = rec[:4]
        return str(username or ''), float(exp or 0.0), str(bind_ip or ''), str(csrf_token or '')
    if len(rec) == 3:
        username, exp, bind_ip = rec
        return str(username or ''), float(exp or 0.0), str(bind_ip or ''), ''
    return '', 0.0, '', ''


def _create_admin_session(username: str, src_ip: str) -> str:
    sid = secrets.token_hex(16)
    now_ts = time.time()
    exp = now_ts + float(_ADMIN_SESSION_TTL_SECONDS)
    csrf_token = secrets.token_urlsafe(32)
    with _admin_session_lock:
        _cleanup_admin_sessions_locked(now_ts)
        _admin_sessions[sid] = _pack_admin_session(username, exp, src_ip, csrf_token)
    return sid


def _clear_admin_session():
    sid = (request.cookies.get(_ADMIN_SID_COOKIE) or request.cookies.get('admin_sid') or '').strip()
    if not sid:
        return '', False
    with _admin_session_lock:
        rec = _admin_sessions.pop(sid, None)
    username, _, _, _ = _unpack_admin_session(rec or ())
    return (username or '')[:32], bool(rec)


def _get_admin_session_record(refresh_ttl: bool = True):
    sid = (request.cookies.get(_ADMIN_SID_COOKIE) or request.cookies.get('admin_sid') or '').strip()
    if not sid:
        return None

    now = time.time()
    src_ip = get_client_ip()
    with _admin_session_lock:
        _cleanup_admin_sessions_locked(now)
        rec = _admin_sessions.get(sid)
        if not rec:
            return None
        username, exp, bind_ip, csrf_token = _unpack_admin_session(rec)
        if exp <= now:
            try:
                del _admin_sessions[sid]
            except Exception:
                logger.debug("delete expired admin session failed", exc_info=True)
            return None
        if bind_ip and bind_ip != src_ip:
            return None
        if not csrf_token:
            csrf_token = secrets.token_urlsafe(32)
        refreshed_exp = now + float(_ADMIN_SESSION_TTL_SECONDS) if refresh_ttl else exp
        _admin_sessions[sid] = _pack_admin_session(username, refreshed_exp, bind_ip, csrf_token)
        return {
            'sid': sid,
            'username': (username or '')[:32],
            'bind_ip': (bind_ip or '')[:64],
            'csrf_token': csrf_token,
        }


def _get_authenticated_admin_username() -> str:
    session_record = _get_admin_session_record(refresh_ttl=True)
    if not session_record:
        return ''
    return str(session_record.get('username') or '')[:32]


def _get_admin_csrf_token() -> str:
    session_record = _get_admin_session_record(refresh_ttl=True)
    if not session_record:
        return ''
    return str(session_record.get('csrf_token') or '')


def _get_admin_login_csrf_token(refresh: bool = False) -> str:
    token = str(session.get(_ADMIN_LOGIN_CSRF_SESSION_KEY) or '')
    if refresh or not token:
        token = secrets.token_urlsafe(32)
        session[_ADMIN_LOGIN_CSRF_SESSION_KEY] = token
    return token


def _extract_request_csrf_token() -> str:
    header_token = str(request.headers.get('X-CSRF-Token') or '').strip()
    if header_token:
        return header_token

    form_token = str(request.form.get('csrf_token', '') or '').strip()
    if form_token:
        return form_token

    payload = request.get_json(silent=True)
    if isinstance(payload, dict):
        return str(payload.get('csrf_token', '') or '').strip()
    return ''


def _validate_admin_csrf_request() -> bool:
    session_record = _get_admin_session_record(refresh_ttl=True)
    if not session_record:
        return False

    request_token = _extract_request_csrf_token()
    session_token = str(session_record.get('csrf_token') or '')
    if not session_token or not request_token or not secrets.compare_digest(session_token, request_token):
        return False

    if any(request.headers.get(name) for name in ('Origin', 'Referer', 'Sec-Fetch-Site')):
        return _is_same_origin_request()
    return True


def _validate_admin_login_csrf_request() -> bool:
    session_token = str(session.get(_ADMIN_LOGIN_CSRF_SESSION_KEY) or '')
    request_token = _extract_request_csrf_token()
    if not session_token or not request_token or not secrets.compare_digest(session_token, request_token):
        return False

    if any(request.headers.get(name) for name in ('Origin', 'Referer', 'Sec-Fetch-Site')):
        return _is_same_origin_request()
    return True


def _get_admin_role_by_username(username: str) -> str:
    uname = (username or '').strip().lower()
    if not uname:
        return '管理员'
    with _admin_data_lock:
        for u in _admin_users:
            if str(u.get('username', '') or '').strip().lower() == uname:
                role = str(u.get('role', '') or '').strip()
                return role or '管理员'
    return '管理员'


def _build_decoy_root_user() -> Dict[str, str]:
    last_login = _DECOY_ROOT_LAST_LOGIN
    if str(last_login).strip().lower() == 'auto':
        minutes = max(0, _DECOY_ROOT_ACTIVE_RECENT_MINUTES)
        minutes_ago = random.randint(0, minutes) if minutes > 0 else 0
        jitter = random.randint(0, 40)
        ts = time.time() - (minutes_ago * 60 + jitter)
        last_login = time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))
    return {
        'id': _DECOY_ROOT_ID,
        'username': _DECOY_ROOT_USERNAME,
        'email': _DECOY_ROOT_EMAIL,
        'role': _DECOY_ROOT_ROLE,
        'status': _DECOY_ROOT_STATUS,
        'last_login': last_login,
        'is_virtual': True,
        'is_active': True,
    }


def _is_admin_authed() -> bool:
    return bool(_get_authenticated_admin_username())


def _is_same_origin_request() -> bool:
    allowed_origins = set(_WEB_ADMIN_ALLOWED_ORIGINS)
    current_origin = _normalize_origin(request.host_url)
    if current_origin:
        allowed_origins.add(current_origin)

    origin = _normalize_origin(request.headers.get('Origin'))
    if origin:
        return origin in allowed_origins

    referer = _normalize_origin(request.headers.get('Referer'))
    if referer:
        return referer in allowed_origins
    try:
        sfs = str(request.headers.get('Sec-Fetch-Site') or '').strip().lower()
        return sfs == 'same-origin'
    except Exception:
        logger.debug("sec-fetch-site parse failed", exc_info=True)
        return False


def _normalize_public_url(raw: str) -> str:
    s = str(raw or '').strip()
    if not s:
        return ''
    if len(s) > 160:
        s = s[:160]
    if not s.startswith('/'):
        return ''
    if s.startswith('//'):
        return ''
    if '\\' in s:
        return ''
    if '\x00' in s:
        return ''
    lower = s.lower()
    if lower.startswith('/\\'):
        return ''
    if lower.startswith('/javascript:'):
        return ''
    if lower.startswith('/http:') or lower.startswith('/https:'):
        return ''
    return s


def _wants_debug_hint() -> bool:
    try:
        q = (request.args.get('debug') or '').strip()
        if q == '1':
            return True
    except Exception:
        logger.debug("parse debug query failed", exc_info=True)
    try:
        h = (request.headers.get('X-Debug') or '').strip()
        if h == '1':
            return True
    except Exception:
        logger.debug("parse debug header failed", exc_info=True)
    return False


def _attach_fake_debug(payload: dict, err_code: str, detail: str) -> dict:
    if not isinstance(payload, dict):
        payload = {}
    if not _wants_debug_hint():
        return payload

    try:
        trace_id = secrets.token_hex(12)
    except Exception:
        trace_id = str(int(time.time()))

    fake = {
        'trace_id': trace_id,
        'error_code': str(err_code or 'E500')[:24],
        'detail': str(detail or '')[:240],
        'stack': [
            'SQLSTATE[HY000] [1045] Access denied for user',
            'at /var/www/html/app/Service/ContentService.php:214',
            'at /var/www/html/app/Controller/AdminController.php:88',
            'at /var/www/html/vendor/laravel/framework/src/Illuminate/Routing/Controller.php:54',
        ],
    }
    payload['debug'] = fake
    return payload


_seed_admin_fake_data()

app.config['MAX_CONTENT_LENGTH'] = _env_int('WEB_MAX_CONTENT_LENGTH', 2 * 1024 * 1024, 64 * 1024, 128 * 1024 * 1024)

_TRUSTED_PROXY_NETWORKS = _build_trusted_proxy_networks(
    _env_str('WEB_TRUSTED_PROXY_IPS', '')
    or _env_str('TRUSTED_PROXY_IPS', '127.0.0.1,::1')
)
_WEB_ADMIN_ALLOWED_ORIGINS = {
    origin for origin in (
        _normalize_origin(item) for item in _split_csv(_env_str('WEB_ADMIN_ALLOWED_ORIGINS', ''))
    ) if origin
}

_CAPTURE_BODY_MAX = _env_int('CAPTURE_BODY_MAX', 8192, 512, 1024 * 1024)

_RATE_WINDOW_SECONDS = 10.0
_RATE_MAX_PER_WINDOW = 30
_rate_state: Dict[str, Tuple[float, int, float]] = {}
_rate_state_lock = Lock()
_RATE_STATE_GC_INTERVAL_SECONDS = 3.0
_RATE_STATE_GC_SIZE_THRESHOLD = 256
_rate_state_last_gc = 0.0
_endpoint_rate_lock = Lock()
_endpoint_rate_state: Dict[str, Tuple[float, int, float]] = {}
_ENDPOINT_RATE_GC_INTERVAL_SECONDS = 3.0
_ENDPOINT_RATE_GC_SIZE_THRESHOLD = 256
_endpoint_rate_last_gc = 0.0
_MAX_URL_PATH_LEN = _env_int('WEB_MAX_URL_PATH_LEN', 1024, 128, 8192)
_MAX_QUERY_LEN = _env_int('WEB_MAX_QUERY_LEN', 4096, 256, 32768)
_MAX_HEADERS_TOTAL = _env_int('WEB_MAX_HEADERS_TOTAL', 16384, 1024, 262144)
_MAX_HEADERS_COUNT = _env_int('WEB_MAX_HEADERS_COUNT', 100, 10, 1000)

# 需要剥离的框架指纹头（避免被 Wappalyzer/扫描器识别）
_FINGERPRINT_STRIP_HEADERS = {
    'Server',
    'X-Powered-By',
    'X-Generator',
    'X-Runtime',
    'X-Request-Id',
    'X-Framework',
    'X-Backend',
    'X-Application-Context',
    'X-Python',
    'X-Werkzeug',
    'X-Debug-Toolbar',
    'X-AspNet-Version',
    'X-AspNetMvc-Version',
}
_FINGERPRINT_STRIP_HEADERS.update(FINGERPRINT_STRIP_HEADERS)

class _StealthRequestHandler(StealthRequestHandler):
    pass


# XSS 检测增强规则
XSS_PATTERNS = [
    r'<script[^>]*>.*?</script>',
    r'javascript:',
    r'on\w+\s*=',
    r'<img[^>]+onerror',
    r'<iframe[^>]*>.*?</iframe>',
    r'alert\s*\(',
    r'eval\s*\(',
    r'document\.cookie',
    r'window\.location',
    r'<svg[^>]*>.*?</svg>',
    r'<object[^>]*>.*?</object>',
    r'<embed[^>]*>.*?</embed>',
    r'<link[^>]*>.*?</link>',
    r'<style[^>]*>.*?</style>',
    r'expression\s*\(',
    r'@import\s+url',
    r'vbscript:',
    r'fromCharCode',
    r'&#x',
    r'&#\d+',
    r'%3c',
    r'%3e',
    r'<\?php'
]
XSS_REGEX = re.compile('|'.join(XSS_PATTERNS), re.IGNORECASE | re.DOTALL)

def enhanced_xss_detection(payload: str) -> bool:
    """增强版 XSS 检测函数。"""
    if not payload:
        return False
    try:
        decoded = unquote(payload)
    except Exception as e:
        logger.debug(f"XSS payload decode failed: {e}")
        decoded = payload
    return bool(XSS_REGEX.search(decoded))

def escape_html(text: str) -> str:
    """HTML 转义函数，防止 XSS。"""
    if not text:
        return ''
    return html.escape(text, quote=True)


def _as_safe_html(html_text: str) -> Markup:
    return Markup(html_text or '')


def _is_trusted_proxy_addr(addr: str) -> bool:
    ip_text = _normalize_ip_text(addr)
    if not ip_text:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except Exception:
        return False
    return any(ip_obj in network for network in _TRUSTED_PROXY_NETWORKS)


def get_client_ip() -> str:
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


def _safe_log_event(client_ip: str, payload: str, event_type: str = 'web_activity_note') -> None:
    try:
        # 备注类事件不再进入攻击事件库，避免污染大屏统计口径
        logger.info(f"[note:{event_type}] {payload} - IP: {client_ip}")
    except Exception as e:
        logger.debug(f"note log failed (ignored): {e}")


def _honeypot_delay(min_seconds: float, max_seconds: Optional[float] = None) -> None:
    try:
        if max_seconds is None:
            time.sleep(min_seconds)
        else:
            time.sleep(random.uniform(min_seconds, max_seconds))
    except Exception as e:
        logger.debug(f"honeypot delay failed (ignored): {e}")


def _log_event(client_ip: str, payload: str, level: str = 'warning') -> None:
    _safe_log_event(client_ip, payload)
    log_func = getattr(logger, level, logger.warning)
    log_func(f"{payload} - IP: {client_ip}")


def _rand_hex(n: int) -> str:
    alphabet = '0123456789abcdef'
    return ''.join(random.choice(alphabet) for _ in range(n))


def _cleanup_rate_state_locked(now: float) -> None:
    global _rate_state_last_gc
    if not _rate_state:
        _rate_state_last_gc = now
        return
    if len(_rate_state) < _RATE_STATE_GC_SIZE_THRESHOLD and (
        (now - _rate_state_last_gc) < _RATE_STATE_GC_INTERVAL_SECONDS
    ):
        return
    stale_cutoff = now - max(0.0, float(_RATE_WINDOW_SECONDS))
    stale_keys = [
        key for key, value in list(_rate_state.items())
        if float((value or (0.0, 0, 0.0))[2] or 0.0) <= stale_cutoff
    ]
    for stale_key in stale_keys:
        _rate_state.pop(stale_key, None)
    _rate_state_last_gc = now


def _rate_limit_endpoint(key: str, limit: int, window_seconds: float) -> bool:
    """简单限流：返回 True 表示允许，False 表示触发限流"""
    global _endpoint_rate_last_gc
    now = time.monotonic()
    with _endpoint_rate_lock:
        if _endpoint_rate_state and (
            len(_endpoint_rate_state) >= _ENDPOINT_RATE_GC_SIZE_THRESHOLD
            or (now - _endpoint_rate_last_gc) >= _ENDPOINT_RATE_GC_INTERVAL_SECONDS
        ):
            expired_keys = [
                k for k, v in list(_endpoint_rate_state.items())
                if (now - float((v or (0.0, 0, 0.0))[0])) > max(0.0, float((v or (0.0, 0, 0.0))[2]))
            ]
            for stale_key in expired_keys:
                _endpoint_rate_state.pop(stale_key, None)
            _endpoint_rate_last_gc = now
        state = _endpoint_rate_state.get(key)
        if state:
            start, count, saved_window = state
            effective_window = max(0.0, float(saved_window or window_seconds or 0.0))
            if effective_window <= 0:
                _endpoint_rate_state[key] = (now, 1, max(0.0, float(window_seconds or 0.0)))
                return True
            if now - start <= window_seconds:
                if count >= limit:
                    return False
                _endpoint_rate_state[key] = (start, count + 1, effective_window)
                return True
            _endpoint_rate_state[key] = (now, 1, max(0.0, float(window_seconds or 0.0)))
            return True
        _endpoint_rate_state[key] = (now, 1, max(0.0, float(window_seconds or 0.0)))
        return True


def _redact_body(text: str) -> str:
    if not text:
        return ''
    redacted = text
    # 简单遮罩常见敏感字段
    patterns = [
        r'(?i)(token|apikey|api_key|secret)\s*=\s*([^&\s]+)',
        r'(?i)"(token|apikey|api_key|secret)"\s*:\s*"([^"]*)"',
    ]
    for p in patterns:
        try:
            redacted = re.sub(p, r'\1=***', redacted)
            redacted = re.sub(p, r'"\1":"***"', redacted)
        except Exception:
            logger.debug("redact body failed", exc_info=True)
    return redacted


def _capture_request_body_for_audit() -> str:
    if request.method not in ['POST', 'PUT', 'PATCH']:
        return ''
    try:
        cl = request.content_length
    except Exception:
        cl = None
    if cl is None or cl < 0 or cl > _CAPTURE_BODY_MAX:
        return ''
    try:
        return _redact_body(request.get_data(as_text=True)[:5000])
    except Exception as e:
        logger.debug(f"读取请求体失败: {e}")
        logger.debug("capture request body failed", exc_info=True)
        return ''


def _make_forbidden_response():
    resp = _render_http_error(403, 'Forbidden', 'Access denied.')
    return resp


def _make_auth_failed_json():
    resp = jsonify({'code': 401, 'msg': '身份校验失败', 'data': {'status': 'auth_failed'}})
    resp.headers['Cache-Control'] = 'no-store'
    return resp


def _map_admin_action_label(action: str) -> str:
    if not action:
        return action
    key = action.strip().lower()
    if key in _ADMIN_ACTION_LABELS:
        return _ADMIN_ACTION_LABELS[key]
    return action


def _make_auth_failed_page():
    # 保持原有“业务层失败”语义（HTTP 200），但页面风格统一
    resp = _render_http_error(401, 'Unauthorized', '身份校验失败')
    resp.status_code = 200
    resp.headers['Cache-Control'] = 'no-store'
    return resp


def _render_http_error(code: int, error_type: str, error_msg: str):
    current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    app_fw = FAKE_SERVER_HEADERS.get('Server', 'nginx')
    if code == 404:
        resp = make_response(render_template('404.html', current_time=current_time, app_framework=app_fw), 404)
        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
        return resp
    resp = make_response(
        render_template(
            'error.html',
            error_type=error_type,
            error_msg=error_msg,
            current_time=current_time,
            app_framework=app_fw,
        ),
        int(code) if code else 500,
    )
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    return resp


@app.after_request
def _spoof_http_fingerprint(response):
    spoof_http_fingerprint(response, _FINGERPRINT_STRIP_HEADERS)

    if request.path.startswith('/admin'):
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        admin_csp = str(response.headers.get('Content-Security-Policy') or '').strip()
        if 'frame-ancestors' not in admin_csp.lower():
            response.headers['Content-Security-Policy'] = (
                f"{admin_csp}; frame-ancestors 'none'" if admin_csp else "frame-ancestors 'none'"
            )

    if request.path == '/' and request.method == 'GET':
        if 'PHPSESSID' not in request.cookies:
            response.set_cookie(
                'PHPSESSID',
                _rand_hex(26),
                max_age=7 * 24 * 3600,
                httponly=True,
                samesite='Lax',
                path='/',
            )
    return response


def _safe_request_query_text() -> str:
    try:
        return request.query_string.decode('utf-8', errors='ignore')
    except Exception:
        return ''


def _safe_request_headers_snapshot() -> dict:
    try:
        return dict(request.headers)
    except Exception:
        return {}


def _audit_rejected_request(session_id: str, src_ip: str, query_text: str, headers_snapshot: dict, signal: str):
    try:
        return log_raw_request(
            session_id=session_id,
            src_ip=src_ip,
            method=request.method,
            path=request.path,
            query_string=query_text,
            headers=headers_snapshot,
            body='',
            extra_signals=[signal],
            min_risk_score=20,
        )
    except Exception as e:
        logger.debug(f"rejected request audit failed: {e}")
        return 0, []


# === 全量请求捕获（捕获未知攻击） ===
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

@app.before_request
def _capture_all_requests():
    """
    全量请求审计入口。
    阶段：静态探测判定 -> 资源上限保护 -> IP 级速率控制 -> 原始请求落库与风险评分。
    """
    # 跳过静态资源（但对可疑静态探测仍捕获）
    if request.path.startswith('/static/'):
        p = request.path.lower()
        q = ''
        try:
            q = request.query_string.decode('utf-8', errors='ignore').lower()
        except Exception:
            q = ''

        safe_exts = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.map', '.woff', '.woff2', '.ttf', '.eot')
        risky_exts = ('.php', '.asp', '.aspx', '.jsp', '.cgi', '.py', '.sh', '.pl', '.rb', '.zip', '.rar', '.7z', '.tar', '.gz', '.sql', '.bak', '.old', '.swp', '.log', '.ini', '.conf', '.yml', '.yaml', '.key', '.pem', '.crt')

        suspicious = False
        if '..' in p or '%2e%2e' in q:
            suspicious = True
        elif any(tok in p for tok in ('/.env', '/.git', '/config', '/backup', '/admin')):
            suspicious = True
        elif any(p.endswith(ext) for ext in risky_exts):
            suspicious = True
        elif (request.method != 'GET'):
            suspicious = True
        elif (not any(p.endswith(ext) for ext in safe_exts)):
            suspicious = True

        if not suspicious:
            return None

    try:
        client_ip = get_client_ip()
        user_agent = request.headers.get('User-Agent', '')
        session_id = generate_session_id(client_ip, user_agent)
        query_text = _safe_request_query_text()
        headers_snapshot = _safe_request_headers_snapshot()

        # 阶段1：统一资源上限（避免长路径/大头部/超大查询拖垮服务）
        path_len = len(request.path or '')
        if path_len > _MAX_URL_PATH_LEN:
            threat_score, signals = _audit_rejected_request(
                session_id,
                client_ip,
                query_text,
                headers_snapshot,
                '请求异常: 路径长度超限',
            )
            logger.warning(f"[拒绝] 路径过长 {client_ip} {request.method} {request.path[:120]} score={threat_score} signals={signals[:2]}")
            return _render_http_error(414, 'URI Too Long', 'Request URI too long.')

        query_len = 0
        try:
            query_len = len(request.query_string or b'')
        except Exception:
            query_len = 0
        if query_len > _MAX_QUERY_LEN:
            threat_score, signals = _audit_rejected_request(
                session_id,
                client_ip,
                query_text,
                headers_snapshot,
                '请求异常: 查询字符串过长',
            )
            logger.warning(f"[拒绝] 查询过长 {client_ip} {request.method} {request.path} score={threat_score} signals={signals[:2]}")
            return _render_http_error(414, 'URI Too Long', 'Query string too long.')

        try:
            header_count = len(request.headers)
            headers_total = sum(len(str(k)) + len(str(v)) for k, v in request.headers.items())
        except Exception:
            header_count = 0
            headers_total = 0
        if header_count > _MAX_HEADERS_COUNT or headers_total > _MAX_HEADERS_TOTAL:
            threat_score, signals = _audit_rejected_request(
                session_id,
                client_ip,
                query_text,
                headers_snapshot,
                '请求异常: 请求头过大',
            )
            logger.warning(
                f"[拒绝] 请求头过大 {client_ip} {request.method} {request.path} "
                f"headers={header_count}/{headers_total} score={threat_score} signals={signals[:2]}"
            )
            return _render_http_error(431, 'Request Header Fields Too Large', 'Request headers too large.')

        # 阶段2：IP 维度轻量限流（命中后仍保留审计，再返回 429）
        now = time.monotonic()
        limited = False
        with _rate_state_lock:
            _cleanup_rate_state_locked(now)
            state = _rate_state.get(client_ip)
            if state is not None:
                window_start, count, _last_seen = state
                if now - window_start <= _RATE_WINDOW_SECONDS:
                    if count >= _RATE_MAX_PER_WINDOW:
                        limited = True
                    else:
                        _rate_state[client_ip] = (window_start, count + 1, now)
                else:
                    _rate_state[client_ip] = (now, 1, now)
            else:
                _rate_state[client_ip] = (now, 1, now)

        # 阶段3：请求体采集（仅采样小体积，避免放大内存占用）
        body = _capture_request_body_for_audit()

        # 阶段4：落库 + 风险评分（可疑请求将进入 event_log）
        threat_score, signals = log_raw_request(
            session_id=session_id,
            src_ip=client_ip,
            method=request.method,
            path=request.path,
            query_string=query_text,
            headers=headers_snapshot,
            body=body
        )

        # 阶段5：日志分级输出（仅作为观察，不阻断正常响应）
        if threat_score >= 40:
            logger.critical(f"[高危] 分数:{threat_score} {client_ip} {request.method} {request.path} - {', '.join(signals[:3])}")
        elif threat_score >= 20:
            logger.warning(f"[可疑] 分数:{threat_score} {client_ip} {request.method} {request.path} - {', '.join(signals[:2])}")
        if limited:
            logger.warning(f"[限流] 已记录高频请求 {client_ip} {request.method} {request.path} score={threat_score}")
            return _render_http_error(429, 'Too Many Requests', 'Request rate too high.')
    except Exception as e:
        logger.debug(f"全量请求捕获失败(不影响正常请求): {e}")
        logger.debug("capture all requests failed", exc_info=True)

    return None


@app.before_request
def _cve_probe_trap():
    raw = request.path
    if request.query_string:
        raw = raw + '?' + request.query_string.decode('utf-8', errors='ignore')
    raw_decoded = unquote(raw)

    thinkphp_patterns = [
        r"/index\.php\?s=/index/\\think\\app/invokefunction",
        r"/index\.php\?s=/index/\\think\\Container/invokefunction",
        r"invokefunction",
    ]
    struts2_markers = [
        '%{',
        'redirect:',
        'action:',
        'ognl',
    ]

    if any(re.search(p, raw_decoded, re.IGNORECASE) for p in thinkphp_patterns) or any(
        m.lower() in raw_decoded.lower() for m in struts2_markers
    ):
        client_ip = get_client_ip()
        _log_event(client_ip, f"漏洞探测: {raw_decoded[:100]}", level='warning')
        body = (
            "<br />\n"
            "<b>Fatal error</b>:  Uncaught Exception: Permission denied in <b>/var/www/html/index.php</b> on line <b>1</b><br />\n"
        )
        resp = make_response(body, 500)
        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
        return resp
    return None


SQLI_PATTERNS = [
    r"(\s|%20)*(or|and)(\s|%20)+", r"(union)(\s|%20)+(select)",
    r"(select)(\s|%20)+.*(\s|%20)+(from)", r"(insert|update|delete|drop|truncate|alter)",
    r"(sleep|benchmark|waitfor)", r"(load_file|into\s+outfile)",
    r"(@@version|version\(\))", r"(information_schema)", r"(1\s*=\s*1|1\s*=\s*'1')",
    r"(order\s+by\s+\d+)", r"(extractvalue|updatexml)", r"(concat|concat_ws)\s*\(",
]
SQLI_REGEX = re.compile('|'.join(SQLI_PATTERNS), re.IGNORECASE)


def detect_sqli(payload: str) -> bool:
    if not payload:
        return False
    try:
        decoded = unquote(payload)
    except Exception as e:
        logger.debug(f"SQLi payload decode failed: {e}")
        decoded = payload
    return bool(SQLI_REGEX.search(decoded))


FAKE_MYSQL_ERRORS = [
    "You have an error in your SQL syntax near '{payload}' at line 1",
    "Unknown column '{payload}' in 'where clause'",
    "Table 'webapp.news' doesn't exist",
]


def get_fake_mysql_error(payload: str) -> str:
    error_template = random.choice(FAKE_MYSQL_ERRORS)
    short_payload = payload[:30] + '...' if len(payload) > 30 else payload
    return error_template.format(payload=short_payload)


routes_public.register(app, {
    'get_client_ip': get_client_ip,
    '_safe_log_event': _safe_log_event,
    '_rand_hex': _rand_hex,
    '_as_safe_html': _as_safe_html,
    'escape_html': escape_html,
    'detect_sqli': detect_sqli,
    'get_fake_mysql_error': get_fake_mysql_error,
    'enhanced_xss_detection': enhanced_xss_detection,
    'logger': logger,
})
routes_traps.register(app, {
    'get_client_ip': get_client_ip,
    '_log_event': _log_event,
    '_make_forbidden_response': _make_forbidden_response,
    '_safe_log_event': _safe_log_event,
    '_honeypot_delay': _honeypot_delay,
    '_render_http_error': _render_http_error,
    '_as_safe_html': _as_safe_html,
    'escape_html': escape_html,
    'logger': logger,
})
admin_views.register(app, {
    'get_client_ip': get_client_ip,
    '_safe_log_event': _safe_log_event,
    '_honeypot_delay': _honeypot_delay,
    '_create_admin_session': _create_admin_session,
    '_clear_admin_session': _clear_admin_session,
    '_is_admin_authed': _is_admin_authed,
    '_get_authenticated_admin_username': _get_authenticated_admin_username,
    '_get_admin_role_by_username': _get_admin_role_by_username,
    '_make_auth_failed_page': _make_auth_failed_page,
    '_make_forbidden_response': _make_forbidden_response,
    '_render_http_error': _render_http_error,
    '_is_same_origin_request': _is_same_origin_request,
    '_get_admin_csrf_token': _get_admin_csrf_token,
    '_get_admin_login_csrf_token': _get_admin_login_csrf_token,
    '_validate_admin_csrf_request': _validate_admin_csrf_request,
    '_validate_admin_login_csrf_request': _validate_admin_login_csrf_request,
    '_rate_limit_endpoint': _rate_limit_endpoint,
    '_attach_fake_debug': _attach_fake_debug,
    '_push_admin_access_log': _push_admin_access_log,
    '_admin_data_lock': _admin_data_lock,
    '_admin_users': _admin_users,
    '_admin_login_bind_lock': _admin_login_bind_lock,
    '_admin_ip_login_bind': _admin_ip_login_bind,
    '_ADMIN_IP_BIND_TTL_SECONDS': _ADMIN_IP_BIND_TTL_SECONDS,
    '_admin_content_items': _admin_content_items,
    '_admin_settings': _admin_settings,
    '_ADMIN_SID_COOKIE': _ADMIN_SID_COOKIE,
    'logger': logger,
    'log_raw_request': log_raw_request,
})
admin_api.register(app, {
    'get_client_ip': get_client_ip,
    '_safe_log_event': _safe_log_event,
    '_is_admin_authed': _is_admin_authed,
    '_get_authenticated_admin_username': _get_authenticated_admin_username,
    '_get_admin_role_by_username': _get_admin_role_by_username,
    '_make_auth_failed_json': _make_auth_failed_json,
    '_push_admin_access_log': _push_admin_access_log,
    '_rate_limit_endpoint': _rate_limit_endpoint,
    '_admin_access_lock': _admin_access_lock,
    '_admin_access_logs': _admin_access_logs,
    '_admin_data_lock': _admin_data_lock,
    '_admin_content_items': _admin_content_items,
    '_admin_users': _admin_users,
    '_admin_settings': _admin_settings,
    '_DECOY_ROOT_ENABLED': _DECOY_ROOT_ENABLED,
    '_DECOY_ROOT_USERNAME': _DECOY_ROOT_USERNAME,
    '_DECOY_ROOT_ID': _DECOY_ROOT_ID,
    '_build_decoy_root_user': _build_decoy_root_user,
    '_attach_fake_debug': _attach_fake_debug,
    '_is_same_origin_request': _is_same_origin_request,
    '_validate_admin_csrf_request': _validate_admin_csrf_request,
    '_normalize_public_url': _normalize_public_url,
    '_SERVER_STARTED_TS': _SERVER_STARTED_TS,
    '_SERVER_STARTED_AT': _SERVER_STARTED_AT,
    '_FAKE_APP_ENV': _FAKE_APP_ENV,
    '_APP_VERSION': _APP_VERSION,
    '_APP_BUILD': _APP_BUILD,
    '_map_admin_action_label': _map_admin_action_label,
    '_ADMIN_SID_COOKIE': _ADMIN_SID_COOKIE,
    'logger': logger,
    'log_raw_request': log_raw_request,
})
errors.register(app, {
    'get_client_ip': get_client_ip,
    '_safe_log_event': _safe_log_event,
    '_log_event': _log_event,
    '_render_http_error': _render_http_error,
    'app_framework': FAKE_SERVER_HEADERS.get('Server', 'nginx'),
    'logger': logger,
})

























from web_honeypot.ai_decoy import register as register_ai_decoy
register_ai_decoy(app, get_client_ip)
from web_honeypot.business_decoy import register as register_business_decoy
register_business_decoy(app,get_client_ip)

if __name__ == '__main__':
    from utils.ai_detection import start_worker
    start_worker()
    import argparse

    # 降低 Flask/Werkzeug 启动日志噪声
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    parser = argparse.ArgumentParser(description='Web 蜜罐')
    parser.add_argument('-H', '--host', default=_env_str('WEB_HOST', '0.0.0.0'), help='监听地址')
    parser.add_argument('-p', '--port', type=int, default=_env_int('WEB_PORT', 5000, 1, 65535), help='监听端口')
    args = parser.parse_args()

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
        logger.debug("set server version failed", exc_info=True)
    server.serve_forever()



