# -*- coding: utf-8 -*-
"""
原始请求捕获与会话分析
"""
import json
import os
import time
import hashlib
import re
import math
from collections import Counter
from threading import Lock
from datetime import datetime, timedelta
from urllib.parse import unquote_plus
try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None

from env_utils import env_bool as _env_bool
from utils.alerting import (
    alert_web_high_risk,
    ALERT_RISK_THRESHOLD,
    ALERT_HIGH_THRESHOLD,
    ALERT_CRITICAL_THRESHOLD,
)
from utils.ai_client import (
    detect_request,
    get_ai_metrics,
)
from .event_logs import log_event
from .connection import (
    USE_MYSQL,
    get_connection,
    has_real_data,
    _SESSION_ID_WINDOW_SECONDS,
    _redact_sensitive_text,
    _truncate_text,
    _sqlite_run_with_retry,
    logger,
)
from .archive import _maybe_archive_old_logs, archive_has_real_data, fetch_archive_rows
from .demo_data import build_mock_suspicious_requests, build_mock_session_analysis

_ALLOW_DASHBOARD_MOCK_DATA = _env_bool('ALLOW_DASHBOARD_MOCK_DATA', False)

_SQLI_MARKERS = (
    "' or ",
    '" or ',
    'union select',
    'information_schema',
    'sleep(',
    'benchmark(',
    'updatexml',
    'extractvalue',
)

_SQL_COMMENT_TOKEN_RE = re.compile(r"(--|#|/\*|\*/)", re.IGNORECASE)
_SQL_COMMENT_COMBO_RE = re.compile(
    r"""(?:union\s+select|select\s+.+\s+from|(?:or|and)\s+['"\w]+\s*=\s*['"\w]+|sleep\s*\(|benchmark\s*\(|updatexml|extractvalue|information_schema|order\s+by\s+\d+)""",
    re.IGNORECASE,
)

# 针对弱特征变体：例如  token') OR ('1'='1
_SQLI_WEAK_PATTERN_RE = re.compile(
    # 兼容不闭合引号变体：例如 token') OR ('1'='1
    r"""['"]\)\s*(?:or|and)\s*\(\s*['"][^'"]+['"]\s*=\s*['"][^'"]+['"]?""",
    re.IGNORECASE,
)

_XSS_MARKER_RE = re.compile(
    r"""(?:<\s*script\b|javascript\s*:|on(?:error|load|mouseover|focus)\s*=|<\s*svg\b|<\s*img\b[^>]{0,120}onerror\s*=|document\.cookie|alert\s*\()""",
    re.IGNORECASE,
)

_JNDI_INJECTION_RE = re.compile(
    r"""\$\{[^}]{0,240}?jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|http|https|nis|corba|nds|jar)\s*://""",
    re.IGNORECASE,
)

_EXPR_INJECTION_RE = re.compile(
    r"""(?:\$\{[^}]{1,240}\}|#\{[^}]{1,240}\})""",
    re.IGNORECASE,
)

# SSRF：必须同时出现“URL 形态参数”与“内网/云元数据目标”，
# 仅在文本中提及一个地址不构成 SSRF 证据。
_SSRF_PARAM_RE = re.compile(
    r"""(?i)(?:^|[?&;,\s])["']?(?:url|uri|target|dest|destination|redirect|redirect_uri|next|callback|cb|fetch|preview|link|src|source|host|domain|path|file|proxy|image|avatar)["']?\s*="""
)
_SSRF_JSON_PARAM_RE = re.compile(
    r"""(?i)"(?:url|uri|target|dest|destination|redirect|next|callback|src|source|host|domain|path|file|proxy)"\s*:"""
)
_SSRF_TARGET_RE = re.compile(
    r"""(?i)(?:"""
    r"""(?:https?|ftp|gopher|dict|ldap|file)://(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200|127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})"""
    r"""|/latest/meta-data|/metadata/v1|computemetadata|169\.254\.169\.254"""
    r""")"""
)

# SSTI：只认表达式/算术模板，普通占位名（如 {{username}}）不算。
_SSTI_RE = re.compile(
    r"""(?i)(?:\{\{\s*\d+\s*[-+*/%]\s*\d+\s*\}\}|\$\{\s*\d+\s*[-+*/%]\s*\d+\s*\}|#\{\s*\d+\s*[-+*/%]\s*\d+\s*\}"""
    r"""|\{\{\s*(?:config|self|request|application|session|__class__|__mro__|__globals__)\b|\b__class__\b|\b__mro__\b|\b__globals__\b|\blipsum\b|\bcycler\b|\bjoiner\b)"""
)

# XXE：DTD 外部实体声明。
_XXE_RE = re.compile(
    r"""(?is)<!DOCTYPE[^>]{0,400}<!ENTITY|<!ENTITY\s+(?:%|[\w.-]+)\s+(?:SYSTEM|PUBLIC)\b"""
)

_SCANNER_HEADER_FINGERPRINTS = {
    # 你关心的 5 类扫描器
    'sqlmap': ('sqlmap',),
    'nmap': ('nmap scripting engine', 'nmap'),
    'nessus': ('nessus',),
    'awvs': ('acunetix', 'awvs', 'acunetix web vulnerability scanner'),
    'masscan': ('masscan',),
}

_SCAN_PATH_PATTERNS = (
    re.compile(r"^/hnap1(?:/|$)", re.IGNORECASE),
    re.compile(r"^/sdk(?:/|$)", re.IGNORECASE),
    re.compile(r"/nmaplowercheck\d*", re.IGNORECASE),
    re.compile(r"^/squid-internal-mgr(?:/|$)", re.IGNORECASE),
    re.compile(r"^/boaform(?:/|$)", re.IGNORECASE),
    re.compile(r"^/cgi-bin(?:/|$)", re.IGNORECASE),
    re.compile(r"^/wls-wsat(?:/|$)", re.IGNORECASE),
    re.compile(r"^/actuator(?:/|$)", re.IGNORECASE),
)

_WEBSHELL_PATH_TOKENS = (
    '/shell.php', '/cmd.php', '/webshell.php', '/wso.php',
    '/antsword.php', '/caidao.php', '/aspxshell.aspx',
)

_WEBSHELL_PARAM_KEY_RE = re.compile(
    r"""(?:^|[?&;\s])(?:cmd|exec|command|shell|code|run|payload|ant|antsword|caidao)=""",
    re.IGNORECASE,
)

_COMMAND_EXEC_MARKER_RE = re.compile(
    r"""(?:\b(?:cmd\.exe\s*/c|/bin/(?:sh|bash)|powershell(?:\.exe)?(?:\s+-enc|\s+-encodedcommand)?|bash\s+-c|sh\s+-c)\b|(?:\b(?:system|passthru|shell_exec|exec|popen|proc_open|assert|eval)\s*\()|(?:base64_decode\s*\())""",
    re.IGNORECASE,
)

_SHELL_META_HINT_RE = re.compile(
    r"""(?:;|\|\||&&|`|\$\(|\b(?:whoami|uname\s+-a|cat\s+/etc/passwd|ipconfig|ifconfig)\b)""",
    re.IGNORECASE,
)

_TRAVERSAL_TOKEN_RE = re.compile(r"""(?:\.\./|\.\.\\|%2e%2e(?:%2f|%5c)|%252e%252e(?:%252f|%255c))""", re.IGNORECASE)
_LFI_TARGET_HINT_RE = re.compile(
    r"""(?:/etc/passwd|/etc/shadow|/proc/self/environ|win\.ini|boot\.ini|web\.config|php\.ini|id_rsa|\.env|\.git/config)""",
    re.IGNORECASE,
)

_LOW_SCORE_ACCUM_WINDOW_SECONDS = 300
_LOW_SCORE_ACCUM_STATE = {}
_LOW_SCORE_ACCUM_LOCK = Lock()

_SINGLETON_HEADERS = {
    'host',
    'content-length',
    'content-type',
    'user-agent',
    'referer',
    'origin',
    'authorization',
    'cookie',
}

_COMMON_HEADER_NAMES = {
    'accept',
    'accept-charset',
    'accept-encoding',
    'accept-language',
    'authorization',
    'cache-control',
    'connection',
    'content-length',
    'content-type',
    'cookie',
    'dnt',
    'host',
    'if-modified-since',
    'if-none-match',
    'origin',
    'pragma',
    'proxy-authorization',
    'range',
    'referer',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
    'user-agent',
    'via',
    'warning',
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-proto',
    'x-real-ip',
    'x-requested-with',
    'x-csrf-token',
    'x-xsrf-token',
    'x-api-key',
    'x-request-id',
    'x-correlation-id',
    'forwarded',
    'sec-fetch-dest',
    'sec-fetch-mode',
    'sec-fetch-site',
    'sec-fetch-user',
    'sec-gpc',
    'sec-websocket-key',
    'sec-websocket-version',
    'sec-websocket-extensions',
    'upgrade-insecure-requests',
    'accept-patch',
    'accept-ranges',
    'access-control-request-method',
    'access-control-request-headers',
}


def _is_header_name_known(name: str) -> bool:
    n = str(name or '').strip().lower()
    if not n:
        return False
    if n in _COMMON_HEADER_NAMES:
        return True
    # 常见生态前缀，避免把网关/CDN/代理透传头一刀切为“未知”
    known_prefixes = (
        'sec-ch-',
        'x-amzn-',
        'x-b3-',
        'x-envoy-',
        'x-client-',
        'x-request-',
        'x-http-',
        'x-original-',
        'x-rewrite-',
        'x-auth-',
        'x-cdn-',
        'cf-',
        'cdn-',
    )
    return n.startswith(known_prefixes)


def _text_entropy(text: str) -> float:
    s = str(text or '')
    if not s:
        return 0.0
    total = len(s)
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for v in counts.values():
        p = v / total
        entropy -= p * math.log2(p)
    return entropy


def _non_printable_ratio(text: str) -> float:
    s = str(text or '')
    if not s:
        return 0.0
    bad = 0
    for ch in s:
        code = ord(ch)
        if code == 9:  # tab
            continue
        if code < 32 or code == 127:
            bad += 1
    return bad / max(1, len(s))


def header_anomaly_score(headers: dict, allow_sparse: bool = False) -> tuple:
    """
    请求头异常度评分（弱信号，不单独定义为攻击）。
    返回: (score, signals)。
    """
    h = headers or {}
    score = 0
    signals = []

    # 1) 头部数量异常（过多/过少）
    header_count = len(h)
    if header_count >= 40:
        score += 6
        signals.append("头异常: 头字段数量异常偏多(>=40)")
    elif header_count >= 26:
        score += 4
        signals.append("头异常: 头字段数量偏多(>=26)")
    elif header_count <= 2 and not allow_sparse:
        score += 3
        signals.append("头异常: 头字段数量偏少(<=2)")

    # 2) 单值超长 + 非可打印字符比例
    header_blob = []
    max_val_len = 0
    for k, v in h.items():
        value = str(v or '')
        header_blob.append(value)
        max_val_len = max(max_val_len, len(value))
    if max_val_len >= 1024:
        score += 6
        signals.append("头异常: 头值超长(>=1024)")
    elif max_val_len >= 512:
        score += 4
        signals.append("头异常: 头值偏长(>=512)")
    elif max_val_len >= 256:
        score += 2
        signals.append("头异常: 头值较长(>=256)")

    # 不把内部拼接分隔符算作“非可打印字符”，避免正常请求被抬高基础分。
    np_ratio = _non_printable_ratio(''.join(header_blob))
    if np_ratio >= 0.05:
        score += 5
        signals.append("头异常: 非可打印字符比例高")
    elif np_ratio >= 0.02:
        score += 3
        signals.append("头异常: 非可打印字符比例偏高")

    # 3) 重复冲突头（如多个 Host）/ 单值头格式异常
    lower_name_count = {}
    for k in h.keys():
        lk = str(k or '').strip().lower()
        if not lk:
            continue
        lower_name_count[lk] = lower_name_count.get(lk, 0) + 1
    duplicated_singletons = [k for k, c in lower_name_count.items() if c > 1 and k in _SINGLETON_HEADERS]
    if duplicated_singletons:
        score += 6
        signals.append(f"头异常: 重复冲突头({','.join(duplicated_singletons[:3])})")

    host_val = str(h.get('Host') or h.get('host') or '')
    if host_val and (',' in host_val or ' ' in host_val or '/' in host_val):
        score += 3
        signals.append("头异常: Host格式异常")

    cl_val = str(h.get('Content-Length') or h.get('content-length') or '').strip()
    if cl_val and (not cl_val.isdigit() or ',' in cl_val):
        score += 4
        signals.append("头异常: Content-Length格式异常")

    # 4) 代理链异常（XFF/Forwarded）
    xff_val = str(h.get('X-Forwarded-For') or h.get('x-forwarded-for') or '')
    forwarded_val = str(h.get('Forwarded') or h.get('forwarded') or '')
    xff_ips = [x.strip() for x in xff_val.split(',') if x.strip()]
    if len(xff_ips) >= 6:
        score += 4
        signals.append("头异常: X-Forwarded-For链过长")
    elif len(xff_ips) >= 4:
        score += 2
        signals.append("头异常: X-Forwarded-For链偏长")
    bad_xff_items = [x for x in xff_ips if not re.match(r'^[0-9a-fA-F:\.]+$', x)]
    if bad_xff_items:
        score += 2
        signals.append("头异常: X-Forwarded-For含异常节点")

    if forwarded_val:
        for_count = len(re.findall(r'(?:^|[;,]\s*)for=', forwarded_val, re.IGNORECASE))
        if for_count >= 6:
            score += 4
            signals.append("头异常: Forwarded链过长")
        elif for_count >= 4:
            score += 2
            signals.append("头异常: Forwarded链偏长")
        if '\n' in forwarded_val or '\r' in forwarded_val:
            score += 3
            signals.append("头异常: Forwarded含控制字符")

    if xff_val and forwarded_val:
        for_count = len(re.findall(r'(?:^|[;,]\s*)for=', forwarded_val, re.IGNORECASE))
        if for_count > 0 and abs(len(xff_ips) - for_count) >= 3:
            score += 2
            signals.append("头异常: 代理链口径不一致")

    # 5) 未知头仅作为弱信号
    valid_header_names = [str(k or '').strip().lower() for k in h.keys() if str(k or '').strip()]
    unknown_names = [n for n in valid_header_names if not _is_header_name_known(n)]
    total_names = len(valid_header_names)
    if total_names >= 4:
        unknown_ratio = len(unknown_names) / total_names
        if unknown_ratio >= 0.6:
            score += 4
            signals.append("头异常: 未知头占比高")
        elif unknown_ratio >= 0.4:
            score += 2
            signals.append("头异常: 未知头占比偏高")

    # 未知头值高熵且超长：额外弱信号
    entropy_hits = 0
    for k, v in h.items():
        nk = str(k or '').strip().lower()
        if not nk or _is_header_name_known(nk):
            continue
        vv = str(v or '')
        if len(vv) < 64:
            continue
        if _text_entropy(vv) >= 3.8:
            entropy_hits += 1
    if entropy_hits >= 2:
        score += 3
        signals.append("头异常: 未知头高熵长值")
    elif entropy_hits == 1:
        score += 2
        signals.append("头异常: 未知头高熵值")

    # 头部仅作“异常度”弱信号，上限收敛，避免单维度拉爆总分
    score = min(score, 16)
    return score, signals


def _apply_low_score_escalation(session_id: str, src_ip: str, risk_score: int, signals: list) -> tuple:
    """
    会话累积抬升：
    - 对“低分异常”做 5 分钟窗口累计
    - 满足累计阈值时抬升分数，减少漏报
    """
    now_ts = time.time()
    expire_before = now_ts - _LOW_SCORE_ACCUM_WINDOW_SECONDS
    key = str(session_id or '').strip() or f"ip:{str(src_ip or '').strip()}"
    if not key:
        return risk_score, signals

    has_header_anomaly = any(str(s or '').startswith('头异常:') for s in (signals or []))
    is_low_score = int(risk_score or 0) < 20
    with _LOW_SCORE_ACCUM_LOCK:
        expired_keys = [
            k for k, v in list(_LOW_SCORE_ACCUM_STATE.items())
            if float((v or {}).get('last_ts', 0)) < expire_before
        ]
        for k in expired_keys:
            _LOW_SCORE_ACCUM_STATE.pop(k, None)

        if not (has_header_anomaly and is_low_score):
            _LOW_SCORE_ACCUM_STATE.pop(key, None)
            return risk_score, signals

        state = dict(_LOW_SCORE_ACCUM_STATE.get(key) or {})
        if not state or float(state.get('last_ts', 0)) < expire_before:
            state = {'count': 0, 'sum_score': 0, 'last_ts': now_ts}
        state['count'] = int(state.get('count', 0)) + 1
        state['sum_score'] = int(state.get('sum_score', 0)) + int(risk_score or 0)
        state['last_ts'] = now_ts
        _LOW_SCORE_ACCUM_STATE[key] = state

        boost = 0
        if state['count'] >= 3 and state['sum_score'] >= 18:
            boost = 8
        elif state['count'] >= 2 and state['sum_score'] >= 12:
            boost = 4

        if boost > 0:
            new_score = int(risk_score) + boost
            new_signals = list(signals or [])
            new_signals.append(f"会话累积异常抬升:5分钟内{state['count']}次(+{boost})")
            # 达到抬升后清空窗口，避免连续重复放大
            _LOW_SCORE_ACCUM_STATE.pop(key, None)
            return new_score, new_signals

    return risk_score, signals


def _now_text() -> str:
    try:
        if ZoneInfo is not None:
            return datetime.now(ZoneInfo('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        pass
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _parse_hours(hours):
    try:
        value = int(hours) if hours not in (None, '') else None
    except Exception:
        value = None
    if value is None:
        return None
    return max(1, min(value, 24 * 30))


def _request_sort_key(item: dict):
    row = item if isinstance(item, dict) else {}
    try:
        score = int(row.get('threat_score') or 0)
    except Exception:
        score = 0
    try:
        row_id = int(row.get('id') or 0)
    except Exception:
        row_id = 0
    return (str(row.get('create_time') or ''), score, row_id)


def _session_sort_key(item: dict):
    row = item if isinstance(item, dict) else {}
    try:
        request_count = int(row.get('request_count') or 0)
    except Exception:
        request_count = 0
    try:
        row_id = int(row.get('id') or 0)
    except Exception:
        row_id = 0
    return (str(row.get('last_seen') or ''), request_count, row_id)


def _event_sort_key(item: dict):
    row = item if isinstance(item, dict) else {}
    try:
        row_id = int(row.get('id') or 0)
    except Exception:
        row_id = 0
    return (str(row.get('timestamp') or ''), row_id)


def _safe_parse_content_length(raw_value) -> int:
    try:
        value = int(str(raw_value or '').strip() or 0)
    except Exception:
        return 0
    return max(0, value)


def _decode_for_match(text: str) -> str:
    """
    为检测规则提供稳态匹配文本：
    - 处理 1~2 次 URL 编码，降低编码绕过风险
    - 统一转小写，便于大小写无关匹配
    """
    s = str(text or '')
    if not s:
        return ''
    prev = s
    for _ in range(2):
        try:
            cur = unquote_plus(prev)
        except Exception:
            break
        if cur == prev:
            prev = cur
            break
        prev = cur
    return prev.lower()


def _decode_for_display(text: str) -> str:
    """
    为展示层提供可读文本：
    - 最多解码 2 次 URL 编码
    - 保留原有大小写（仅用于日志展示，不用于匹配）
    """
    s = str(text or '')
    if not s:
        return ''
    prev = s
    for _ in range(2):
        try:
            cur = unquote_plus(prev)
        except Exception:
            break
        if cur == prev:
            prev = cur
            break
        prev = cur
    return prev


def _build_header_match_blob(headers: dict) -> str:
    if not headers:
        return ''
    parts = []
    for k, v in headers.items():
        key = str(k or '').strip().lower()
        value = _decode_for_match(v)
        if not key and not value:
            continue
        parts.append(f"{key}:{value}")
    return '\n'.join(parts)


def _contains_sqli_weak_pattern(text: str) -> bool:
    s = str(text or '')
    if not s:
        return False
    return bool(_SQLI_WEAK_PATTERN_RE.search(s))


def _contains_sqli_comment_combo(text: str) -> bool:
    s = str(text or '')
    if not s:
        return False
    return bool(_SQL_COMMENT_TOKEN_RE.search(s) and _SQL_COMMENT_COMBO_RE.search(s))


def _detect_scanner_from_headers(headers: dict) -> list:
    """
    基于请求头做扫描器指纹识别（低成本、可解释）。
    返回命中的扫描器名称列表，例如 ['sqlmap', 'awvs']。
    """
    h = headers or {}
    ua = str(h.get('User-Agent') or '').lower()
    referer = str(h.get('Referer') or '').lower()
    # 统一拼接头名+头值，兼容 X-Scanner、X-Requested-With 等自定义头
    header_blob = ' '.join(
        f"{str(k or '').lower()}:{str(v or '').lower()}"
        for k, v in h.items()
    )
    hit_names = []
    for scanner, tokens in _SCANNER_HEADER_FINGERPRINTS.items():
        if any((tok in ua) or (tok in referer) or (tok in header_blob) for tok in tokens):
            hit_names.append(scanner)
    return hit_names


def _detect_scanner_from_path(path: str, query_decoded: str) -> bool:
    p = str(path or '').strip()
    q = str(query_decoded or '')
    if not p:
        return False
    if any(pat.search(p) for pat in _SCAN_PATH_PATTERNS):
        return True
    # 少量探测会把特征放在 query 上
    if 'nmaplowercheck' in q:
        return True
    return False


def _detect_webshell_signals(path: str, query_decoded: str, body_decoded: str) -> list:
    """
    WebShell/命令执行行为识别（面向 HTTP 参数与 payload）。
    """
    p = str(path or '').lower()
    q = str(query_decoded or '')
    b = str(body_decoded or '')
    qb = f"{q}\n{b}"
    hits = []

    if any(tok in p for tok in _WEBSHELL_PATH_TOKENS):
        hits.append('webshell_path')

    has_cmd_key = bool(_WEBSHELL_PARAM_KEY_RE.search(qb))
    has_exec_marker = bool(_COMMAND_EXEC_MARKER_RE.search(qb))
    has_shell_meta = bool(_SHELL_META_HINT_RE.search(qb))

    if has_cmd_key and (has_exec_marker or has_shell_meta):
        hits.append('cmd_exec_combo')
    elif has_exec_marker:
        hits.append('cmd_exec_marker')
    elif has_cmd_key and has_shell_meta:
        hits.append('cmd_param_abuse')

    return hits


def _detect_expression_signals(query_decoded: str, body_decoded: str, header_blob: str) -> list:
    merged = '\n'.join(
        part for part in (str(query_decoded or ''), str(body_decoded or ''), str(header_blob or '')) if part
    )
    if not merged:
        return []

    hits = []
    if _JNDI_INJECTION_RE.search(merged):
        hits.append('jndi_injection')
    elif _EXPR_INJECTION_RE.search(merged):
        hits.append('expr_injection')
    return hits


def _detect_ssrf_signals(query_raw: str, query_decoded: str, body_raw: str, body_decoded: str) -> list:
    """SSRF 探测：URL 形态参数携带内网/云元数据目标时才命中。"""
    for text in (query_raw, query_decoded, body_raw, body_decoded):
        value = str(text or '')
        if not value:
            continue
        has_param = bool(_SSRF_PARAM_RE.search(value) or _SSRF_JSON_PARAM_RE.search(value))
        if has_param and _SSRF_TARGET_RE.search(value):
            return ['ssrf']
    return []


def _detect_ssti_signals(query_decoded: str, body_decoded: str) -> list:
    """SSTI：模板表达式/算术求值特征。"""
    merged = '\n'.join(part for part in (str(query_decoded or ''), str(body_decoded or '')) if part)
    if merged and _SSTI_RE.search(merged):
        return ['ssti']
    return []


def _detect_xxe_signals(query_decoded: str, body_raw: str, body_decoded: str) -> list:
    """XXE：XML 外部实体声明。"""
    merged = '\n'.join(part for part in (str(body_raw or ''), str(body_decoded or ''), str(query_decoded or '')) if part)
    if merged and _XXE_RE.search(merged):
        return ['xxe']
    return []


def _has_lfi_traversal_signal(path: str, query_raw: str, body_raw: str, query_decoded: str, body_decoded: str) -> bool:
    """
    目录穿越/LFI 判定（收敛版）：
    - 出现 traversal token（../、..\\ 或编码变体）
    - 且满足“高风险目标文件命中”或“深层穿越(>=2 次)”之一
    """
    p = str(path or '')
    q_raw = str(query_raw or '')
    b_raw = str(body_raw or '')
    q_dec = str(query_decoded or '')
    b_dec = str(body_decoded or '')
    merged = "\n".join([p, q_raw, b_raw, q_dec, b_dec])
    token_hit = bool(_TRAVERSAL_TOKEN_RE.search(merged))
    if not token_hit:
        return False

    lowered = merged.lower()
    deep_traversal = (lowered.count('../') + lowered.count('..\\')) >= 2
    target_hit = bool(_LFI_TARGET_HINT_RE.search(merged))
    return bool(target_hit or deep_traversal)


def _is_low_value_root_request(method: str, path: str, query: str, headers: dict, body: str) -> bool:
    """
    根路径常规访问例外：
    - 仅用于降噪，避免将首页探活/浏览器预检误判为可疑
    - 不覆盖带参数、带请求体、或非根路径请求
    """
    m = str(method or '').upper()
    p = str(path or '').strip()
    q = str(query or '').strip()
    b = str(body or '').strip()
    if p not in ('', '/') or m not in ('GET', 'HEAD', 'OPTIONS') or q or b:
        return False

    h = headers or {}
    ua = str(h.get('User-Agent') or '').lower()
    accept = str(h.get('Accept') or '').lower()
    sec_fetch_mode = str(h.get('Sec-Fetch-Mode') or '').lower()
    acrm = str(h.get('Access-Control-Request-Method') or '').upper()

    known_probe_ua = (
        'mozilla/', 'curl/', 'wget/', 'python-requests', 'okhttp',
        'postmanruntime', 'go-http-client', 'kube-probe', 'elb-healthchecker',
        'prometheus'
    )
    if any(tok in ua for tok in known_probe_ua):
        return True
    if m == 'OPTIONS' and acrm:
        return True
    if 'text/html' in accept or '*/*' in accept:
        return True
    if sec_fetch_mode in ('navigate', 'cors', 'no-cors'):
        return True
    # 无 UA 的根路径探活请求，按低价值噪声处理
    if not ua:
        return True
    return False


def _event_label(event_type: str) -> str:
    et = str(event_type or '').strip().lower()
    mapping = {
        'sqli_probe': '疑似SQL注入',
        'xss_probe': '疑似XSS攻击',
        'lfi_probe': '疑似目录穿越',
        'ssrf_probe': '疑似SSRF探测',
        'ssti_probe': '疑似模板注入',
        'xxe_probe': '疑似XXE注入',
        'file_probe': '疑似敏感文件访问',
        'admin_probe': '疑似后台探测',
        'upload_probe': '疑似上传探测',
        'webshell_probe': '疑似WebShell访问',
        'scanner_probe': '疑似扫描器探测',
        'exploit_attempt': '疑似漏洞利用',
        'web_probe': '疑似Web探测',
    }
    return mapping.get(et, '疑似Web异常')


def _severity_for_web_score(score: int, is_suspicious: bool) -> str:
    """
    Web 事件分级策略：
    - critical/high 仍由高分阈值决定
    - 进入可疑阈值的事件，最低标记为 medium（用于大屏色条区分）
    """
    try:
        n = int(score)
    except Exception:
        n = 0
    if n >= ALERT_CRITICAL_THRESHOLD:
        return 'critical'
    if n >= ALERT_HIGH_THRESHOLD:
        return 'high'
    if is_suspicious:
        return 'medium'
    return 'low'


def _is_redundant_signal(event_type: str, signal: str) -> bool:
    et = str(event_type or '').strip().lower()
    s = str(signal or '').strip().lower()
    if not s:
        return True
    if et == 'sqli_probe' and ('sql' in s or '注入' in s):
        return True
    if et == 'xss_probe' and 'xss' in s:
        return True
    if et == 'lfi_probe' and ('目录' in s or '路径' in s or 'lfi' in s):
        return True
    if et == 'scanner_probe' and ('扫描' in s or 'scanner' in s):
        return True
    if et == 'admin_probe' and ('admin' in s or '后台' in s):
        return True
    if et == 'file_probe' and ('敏感文件' in s or 'file' in s):
        return True
    if et == 'webshell_probe' and ('webshell' in s or '命令执行' in s):
        return True
    if et == 'ssrf_probe' and 'ssrf' in s:
        return True
    if et == 'ssti_probe' and ('ssti' in s or '模板' in s):
        return True
    if et == 'xxe_probe' and 'xxe' in s:
        return True
    return False


def generate_session_id(ip: str, user_agent: str) -> str:
    """基于 IP 与 UA 生成会话 ID。"""
    window = 0
    if _SESSION_ID_WINDOW_SECONDS > 0:
        window = int(time.time() // _SESSION_ID_WINDOW_SECONDS)
    raw = f"{ip}:{user_agent or 'unknown'}:{window}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def calculate_threat_score(method: str, path: str, query: str, headers: dict, body: str) -> tuple:
    """
    计算风险分数（基于行为特征，非规则匹配）。
    返回: (risk_score, is_suspicious, signals)。
    """
    risk_score = 0
    suspicious_signals = []
    is_low_value_root = _is_low_value_root_request(method, path, query, headers, body)
    header_score, header_signals = header_anomaly_score(headers, allow_sparse=is_low_value_root)
    if header_score > 0:
        risk_score += header_score
        suspicious_signals.extend(header_signals)

    path_lower = path.lower()
    sensitive_paths = ['/admin', '/backup', '/config', '/.env', '/.git', '/wp-', '/phpmyadmin', '/shell', '/cmd']
    for sp in sensitive_paths:
        if sp in path_lower:
            risk_score += 15
            suspicious_signals.append(f"敏感路径: {sp}")

    ql = _decode_for_match(query) if query else ''
    bl = _decode_for_match(body) if body else ''
    header_blob = _build_header_match_blob(headers)

    if _has_lfi_traversal_signal(path, query, body, ql, bl):
        risk_score += 22
        suspicious_signals.append("目录穿越/LFI特征")

    if _detect_ssrf_signals(query, ql, body, bl):
        risk_score += 30
        suspicious_signals.append("疑似SSRF特征(内网/云元数据)")
    if _detect_ssti_signals(ql, bl):
        risk_score += 20
        suspicious_signals.append("疑似SSTI模板注入")
    if _detect_xxe_signals(ql, body, bl):
        risk_score += 24
        suspicious_signals.append("疑似XXE外部实体注入")

    if query:
        if len(query) > 500:
            risk_score += 10
            suspicious_signals.append("超长查询参数")
        special_chars = sum(1 for c in ql if c in "'\";|&$`<>{}[]\\")
        if special_chars > 5:
            # 收敛上限，避免复杂但正常参数被过度放大
            risk_score += min(12, special_chars * 2)
            suspicious_signals.append(f"特殊字符异常: {special_chars}个")
        if '%00' in str(query).lower() or '%0a' in str(query).lower() or '%0d' in str(query).lower() or '\x00' in ql or '\n' in ql or '\r' in ql:
            risk_score += 20
            suspicious_signals.append("空字节/换行注入")
        if _contains_sqli_comment_combo(ql):
            risk_score += 18
            suspicious_signals.append("SQL注释组合特征")
        # 显式 SQL 注入特征：确保 URL 注入语句可直接进入可疑阈值
        if any(x in ql for x in _SQLI_MARKERS):
            risk_score += 25
            suspicious_signals.append("疑似SQL注入特征")
        elif _contains_sqli_weak_pattern(ql):
            # 弱特征 SQLi：提高到可疑阈值，避免被降噪漏掉
            risk_score += 22
            suspicious_signals.append("疑似SQL注入弱特征")
        if _XSS_MARKER_RE.search(ql):
            risk_score += 22
            suspicious_signals.append("疑似XSS特征")

    if body:
        if len(body) > 10000:
            risk_score += 10
            suspicious_signals.append("超大请求体")
        if 'O:' in body and ':"' in body:
            risk_score += 25
            suspicious_signals.append("疑似PHP反序列化")
        if _contains_sqli_comment_combo(bl):
            risk_score += 18
            suspicious_signals.append("SQL注释组合特征")
        if any(x in bl for x in _SQLI_MARKERS):
            risk_score += 25
            suspicious_signals.append("疑似SQL注入特征")
        elif _contains_sqli_weak_pattern(bl):
            risk_score += 22
            suspicious_signals.append("疑似SQL注入弱特征")
        if _XSS_MARKER_RE.search(bl):
            risk_score += 22
            suspicious_signals.append("疑似XSS特征")

    webshell_hits = _detect_webshell_signals(path, ql, bl)
    if 'webshell_path' in webshell_hits:
        risk_score += 22
        suspicious_signals.append("疑似WebShell路径")
    if 'cmd_exec_combo' in webshell_hits:
        risk_score += 28
        suspicious_signals.append("疑似命令执行/WebShell特征")
    elif 'cmd_exec_marker' in webshell_hits:
        risk_score += 24
        suspicious_signals.append("疑似命令执行特征")
    elif 'cmd_param_abuse' in webshell_hits:
        risk_score += 18
        suspicious_signals.append("可疑命令参数滥用")

    expr_hits = _detect_expression_signals(ql, bl, header_blob)
    if 'jndi_injection' in expr_hits:
        risk_score += 24
        suspicious_signals.append("疑似JNDI注入特征")
    elif 'expr_injection' in expr_hits:
        risk_score += 20
        suspicious_signals.append("疑似表达式注入特征")

    if _detect_scanner_from_path(path, ql):
        risk_score += 16
        suspicious_signals.append("扫描路径特征")

    ua = headers.get('User-Agent', '')
    if not ua:
        if not is_low_value_root:
            risk_score += 8
            suspicious_signals.append("无User-Agent")
    elif len(ua) > 500:
        risk_score += 15
        suspicious_signals.append("超长User-Agent")

    scanner_hits = _detect_scanner_from_headers(headers)
    if scanner_hits:
        risk_score += 22
        suspicious_signals.append(f"扫描工具特征: {','.join(scanner_hits)}")
    elif any(tool in str(ua).lower() for tool in ['nikto', 'zgrab', 'gobuster', 'dirbuster']):
        risk_score += 20
        suspicious_signals.append("扫描工具特征")

    xff = headers.get('X-Forwarded-For', '')
    if xff and xff.count(',') > 3:
        risk_score += 10
        suspicious_signals.append("多层代理")

    # 分数统一封顶 100：多特征叠加（敏感路径 × 多种注入）不应越界，
    # 否则严重度映射与前端色条会失真。
    risk_score = max(0, min(100, int(risk_score)))
    is_suspicious = risk_score >= 20
    return risk_score, is_suspicious, suspicious_signals


def _classify_web_event_type(method: str, path: str, query_string: str, body: str, signals: list) -> str:
    p = str(path or '').lower()
    q = _decode_for_match(query_string)
    b = _decode_for_match(body)
    sig = ' '.join(str(x or '').lower() for x in (signals or []))

    # 攻击技术优先于路径形状：/admin 上的 XSS/SSTI 必须记录技术类型，
    # 否则后台探测会掩盖真实攻击手法。
    if 'ssrf' in sig:
        return 'ssrf_probe'
    if 'ssti' in sig or '模板注入' in sig:
        return 'ssti_probe'
    if 'xxe' in sig:
        return 'xxe_probe'
    if '疑似webshell路径' in sig or '疑似命令执行/webshell特征' in sig or '疑似命令执行特征' in sig:
        return 'webshell_probe'
    if '疑似jndi注入特征' in sig or '疑似表达式注入特征' in sig:
        return 'exploit_attempt'
    if '疑似xss特征' in sig:
        return 'xss_probe'

    if any(x in q for x in _SQLI_MARKERS) or any(x in b for x in _SQLI_MARKERS):
        return 'sqli_probe'
    if _contains_sqli_weak_pattern(q) or _contains_sqli_weak_pattern(b):
        return 'sqli_probe'
    if _contains_sqli_comment_combo(q) or _contains_sqli_comment_combo(b):
        return 'sqli_probe'
    if any(x in q for x in ('<script', 'javascript:', 'onerror=')) or any(x in b for x in ('<script', 'javascript:', 'onerror=')):
        return 'xss_probe'

    sensitive_files = ('.env', '.git', 'config.php', '.bak', 'backup', 'dump.sql')
    if any(x in p for x in sensitive_files):
        return 'file_probe'
    if '/admin' in p:
        return 'admin_probe'
    if '/upload' in p:
        return 'upload_probe'

    if any(x in q for x in ('../', '..\\')) or any(x in p for x in ('../', '..\\')):
        return 'lfi_probe'
    if '扫描工具特征' in sig or '扫描路径特征' in sig:
        return 'scanner_probe'
    if str(method or '').upper() in ('POST', 'PUT', 'PATCH') and ('敏感路径' in sig or '特殊字符异常' in sig):
        return 'exploit_attempt'
    return 'web_probe'


def _signals_to_tags(signals: list, event_type: str) -> list:
    tags = ['web', event_type]
    mapping = {
        '敏感路径': 'sensitive_path',
        '超长查询参数': 'long_query',
        '特殊字符异常': 'special_chars',
        'SQL注释组合特征': 'sqli_comment_combo',
        '空字节/换行注入': 'nullbyte',
        '疑似PHP反序列化': 'php_deser',
        '疑似表达式注入': 'expr_injection',
        '疑似表达式注入特征': 'expr_injection',
        '疑似JNDI注入特征': 'jndi_injection',
        '疑似XSS特征': 'xss',
        '疑似WebShell路径': 'webshell_path',
        '疑似命令执行/WebShell特征': 'cmd_exec',
        '疑似命令执行特征': 'cmd_exec',
        '可疑命令参数滥用': 'cmd_param',
        '疑似SQL注入弱特征': 'sqli_weak',
        '疑似SSRF特征(内网/云元数据)': 'ssrf',
        '疑似SSTI模板注入': 'ssti',
        '疑似XXE外部实体注入': 'xxe',
        '无User-Agent': 'missing_ua',
        '超长User-Agent': 'long_ua',
        '扫描工具特征': 'scanner',
        '扫描路径特征': 'scanner_path',
        '目录穿越/LFI特征': 'lfi_traversal',
        '多层代理': 'multi_proxy',
        '头异常': 'header_anomaly',
        '会话累积异常抬升': 'session_escalate',
    }
    for sig in (signals or []):
        s = str(sig or '')
        for k, v in mapping.items():
            if k in s and v not in tags:
                tags.append(v)
                break
    return tags[:12]


def _resolve_web_final_decision(
    rule_score: int,
    rule_is_suspicious: bool,
    ai_result
) -> tuple:
    """
    AI v2 加权融合：
    final_score = rule_score + ai_points

    ai_points 是 AI 返回的 0~25 加权分，不覆盖原规则分数。
    """
    if isinstance(ai_result, dict):
        try:
            ai_points = int(ai_result.get('ai_points') or 0)
        except Exception:
            ai_points = 0
        ai_points = max(0, min(25, ai_points))
        ai_is_attack = bool(ai_result.get('is_attack'))
        ai_high_risk = bool(ai_result.get('high_risk'))
        ai_type = str(ai_result.get('attack_type') or '').strip().lower()
        # 模型判 normal 时不加分：normal 的 ai_points 是概率映射值，
        # 直接累加会把正常流量（例如静态资源路径命中 "/admin" 子串）
        # 推过 20 分可疑阈值。AI 仍参与判定，只是加分为 0。
        effective_points = ai_points if (ai_is_attack or ai_type not in ('', 'normal')) else 0
        final_score = min(
            100,
            max(0, int(rule_score or 0) + effective_points)
        )
        # AI 内部已完成规则+模型融合；如果它明确判定攻击，
        # 用双阈值下界保证蜜罐不会因两套规则差异而漏掉该事件。
        if ai_is_attack:
            final_score = max(final_score, 20)
        if ai_high_risk:
            final_score = max(final_score, 40)
        ai_applied = ai_points > 0 or ai_is_attack or ai_high_risk
        return (
            final_score,
            final_score >= 20,
            'rule+ai' if ai_applied else 'rule',
            ai_applied,
            effective_points,
        )

    return (
        int(rule_score or 0),
        bool(rule_is_suspicious),
        'rule',
        False,
        0,
    )


def log_raw_request(session_id: str, src_ip: str, method: str, path: str,
                    query_string: str, headers: dict, body: str,
                    extra_signals=None, min_risk_score: int = 0):
    """
    记录原始请求（raw_request）并返回 (risk_score, signals)。
    说明：
    - 所有请求都会入 raw_request 与 session_track
    - 仅当 risk_score >= 20 时，写入 event_log 作为可疑事件
    - 企业微信告警仅在 risk_score 达到阈值时触发
    """
    try:
        risk_score, is_suspicious, signals = calculate_threat_score(method, path, query_string, headers, body)
        risk_score, signals = _apply_low_score_escalation(session_id, src_ip, risk_score, signals)
        if not isinstance(signals, list):
            signals = list(signals or [])
        if extra_signals:
            for signal in extra_signals:
                text = str(signal or '').strip()
                if text and text not in signals:
                    signals.append(text)
        try:
            risk_score = max(int(risk_score or 0), int(min_risk_score or 0))
        except Exception:
            risk_score = int(risk_score or 0)
        is_suspicious = risk_score >= 20

        safe_query = _redact_sensitive_text(query_string or '')
        safe_body = _redact_sensitive_text(body or '')

        user_agent = _redact_sensitive_text(headers.get('User-Agent', ''))[:500]
        referer = _redact_sensitive_text(headers.get('Referer', ''))[:500]
        content_type = _redact_sensitive_text(headers.get('Content-Type', ''))[:100]
        content_length = _safe_parse_content_length(headers.get('Content-Length', 0))

        safe_headers = {
            k: _redact_sensitive_text(str(v))
            for k, v in headers.items()
            if k.lower() not in ['cookie', 'authorization']
        }
        headers_json = _truncate_text(json.dumps(safe_headers, ensure_ascii=False), 2000)
        body_truncated = _truncate_text(safe_body, 5000)

        conn = get_connection()
        raw_request_id = None
        try:
            cursor = conn.cursor()
            placeholder = '%s' if USE_MYSQL else '?'
            now_text = _now_text()
            sql = (
                "INSERT INTO raw_request "
                "(session_id, src_ip, method, path, query_string, headers, body, "
                "user_agent, referer, content_type, content_length, is_suspicious, threat_score, create_time) "
                f"VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, "
                f"{placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, "
                f"{placeholder}, {placeholder}, {placeholder}, {placeholder})"
            )
            params = (
                session_id, src_ip, method, path, safe_query, headers_json, body_truncated,
                user_agent, referer, content_type, content_length,
                1 if is_suspicious else 0, risk_score, now_text
            )
            if USE_MYSQL:
                cursor.execute(sql, params)
                conn.commit()
                raw_request_id = cursor.lastrowid
            else:
                def _insert_action(c):
                    c.execute(sql, params)
                    return c.lastrowid
                raw_request_id = _sqlite_run_with_retry(conn, _insert_action)
            rule_risk_score = int(risk_score or 0)
            rule_is_suspicious = bool(is_suspicious)

            ai_result = detect_request(
                path=path,
                query=query_string,
                body=body,
                method=method,
                user_agent=user_agent,
                source='web',
                ip=src_ip,
                session_id=session_id,
                request_id=(
                    f'raw_request:{raw_request_id}'
                    if raw_request_id else ''
                )
            )

            (
                risk_score,
                is_suspicious,
                final_source,
                ai_applied,
                ai_points,
            ) = _resolve_web_final_decision(
                rule_score=rule_risk_score,
                rule_is_suspicious=rule_is_suspicious,
                ai_result=ai_result
            )

            if (
                raw_request_id
                and (
                    risk_score != rule_risk_score
                    or is_suspicious != rule_is_suspicious
                )
            ):
                update_sql = (
                    "UPDATE raw_request "
                    f"SET is_suspicious = {placeholder}, "
                    f"threat_score = {placeholder} "
                    f"WHERE id = {placeholder}"
                )
                update_params = (
                    1 if is_suspicious else 0,
                    risk_score,
                    raw_request_id,
                )
                if USE_MYSQL:
                    cursor.execute(update_sql, update_params)
                    conn.commit()
                else:
                    def _update_action(c):
                        c.execute(update_sql, update_params)
                    _sqlite_run_with_retry(conn, _update_action)

            if ai_applied and ai_result:
                attack_type = str(
                    ai_result.get('attack_type') or 'unknown'
                )
                ai_signal = (
                    f"AI判定{attack_type}(+{ai_points}分)"
                )
                reasons = ai_result.get('reasons') or []
                if isinstance(reasons, list) and reasons:
                    ai_signal += f": {str(reasons[0])[:200]}"
                if ai_signal not in signals:
                    signals.append(ai_signal)
            
            update_session_track(session_id, src_ip, path, is_suspicious, risk_score)
            # 仅可疑请求进入统一事件流，避免 event_log 被普通流量淹没
            if is_suspicious:
                if ai_applied and ai_result and ai_result.get('is_attack'):
                    ai_attack_type = str(
                        ai_result.get('attack_type') or 'normal'
                    )
                    event_type_map = {
                        'xss': 'xss_ai_detected',
                        'sqli': 'sqli_ai_detected',
                        'path_traversal': 'path_traversal_ai_detected',
                        'sensitive_path': 'sensitive_path_ai_detected',
                        'scanner': 'scanner_ai_detected',
                    }
                    event_type = event_type_map.get(
                        ai_attack_type,
                        'web_ai_detected'
                    )
                    event_tags = ['web', ai_attack_type, 'ai']
                    label = f"AI判定{ai_attack_type}"
                else:
                    event_type = _classify_web_event_type(method, path, query_string, body, signals)
                    event_tags = _signals_to_tags(signals, event_type)
                    label = _event_label(event_type)
                method_text = str(method or '').upper()
                decoded_query = _decode_for_display(query_string)
                safe_decoded_query = _truncate_text(_redact_sensitive_text(decoded_query), 180)
                payload = f"[{label}] {method_text} {path}"
                if safe_decoded_query:
                    payload += f"?{safe_decoded_query}"
                if ai_applied and ai_result:
                    reasons = ai_result.get('reasons') or []
                    if isinstance(reasons, list) and reasons:
                        payload += f" | {str(reasons[0])[:240]}"
                elif signals:
                    for sig in signals:
                        if not _is_redundant_signal(event_type, sig):
                            payload += f" | {str(sig)}"
                            break
                ai_metrics = get_ai_metrics()
                extra = {
                    'score': int(risk_score),
                    'signals': [str(x) for x in (signals or [])[:6]],
                    'method': str(method or '').upper(),
                    'path': str(path or '')[:240],
                    'ua': str(user_agent or '')[:200],
                    'rule': {
                        'score': int(rule_risk_score),
                        'is_suspicious': bool(rule_is_suspicious),
                    },
                    'ai': ai_result or {},
                    'ai_applied': bool(ai_applied),
                    'ai_points': int(ai_points),
                    'ai_service_points': int((ai_result or {}).get('ai_points') or 0),
                    'ai_input': {
                        'path_length': len(str(path or '')),
                        'query_length': len(str(query_string or '')),
                        'body_length': len(str(body or '')),
                        'user_agent_length': len(str(user_agent or '')),
                    },
                    'ai_error': (
                        ''
                        if ai_result
                        else str(ai_metrics.get('last_error') or '')
                    ),
                    'ai_backoff_remaining_seconds': float(
                        ai_metrics.get('backoff_remaining_seconds') or 0.0
                    ),
                    'final_source': final_source,
                }
                log_event(
                    source='web',
                    severity=_severity_for_web_score(risk_score, is_suspicious),
                    event_type=event_type,
                    src_ip=src_ip,
                    session_id=session_id,
                    tags=event_tags,
                    payload=payload,
                    raw_ref=f"raw_request:{raw_request_id}" if raw_request_id else '',
                    raw_request_id=raw_request_id if raw_request_id else None,
                    extra=extra,
                )
            _maybe_archive_old_logs()
        finally:
            conn.close()

        if risk_score >= ALERT_RISK_THRESHOLD:
            try:
                alert_web_high_risk(src_ip, method, path, risk_score, signals, headers.get('User-Agent', ''))
            except Exception:
                pass

        # 规则先落库，AI 复核异步排队（不阻塞请求、不改变规则分数）。
        try:
            if raw_request_id:
                from utils import ai_detection as _ai_detection
                from .connection import _config as _db_config
                if USE_MYSQL:
                    db_key = str(getattr(_db_config, 'DB_HOST', '')) + '|' + str(getattr(_db_config, 'DB_NAME', ''))
                else:
                    db_key = str(getattr(_db_config, 'DB_PATH', ''))
                _ai_detection.submit(
                    raw_request_id,
                    src_ip,
                    session_id,
                    method,
                    path,
                    query_string,
                    headers if isinstance(headers, dict) else {},
                    body,
                    int(rule_risk_score),
                    list(signals or []),
                    now_text,
                    db_key,
                )
        except Exception as ai_error:
            logger.debug(f"AI 复核入队失败(保留规则结果): {ai_error}")

        return risk_score, signals
    except Exception as e:
        logger.debug(f"原始请求记录失败: {e}")
        return 0, []


def update_session_track(session_id: str, src_ip: str, path: str, is_suspicious: bool, risk_score: int):
    """更新会话追踪信息。"""
    try:
        conn = get_connection()
        try:
            cursor = conn.cursor()
            now_text = _now_text()
            if USE_MYSQL:
                threat_level = 'low'
                if risk_score >= 50:
                    threat_level = 'high'
                elif risk_score >= 20:
                    threat_level = 'medium'

                cursor.execute(
                    """INSERT INTO session_track
                    (session_id, src_ip, path_sequence, is_attacker, threat_level, request_count, first_seen, last_seen)
                    VALUES (%s, %s, %s, %s, %s, 1, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        last_seen = %s,
                        request_count = request_count + 1,
                        path_sequence = CONCAT(
                            CASE
                                WHEN path_sequence IS NULL OR path_sequence = '' THEN ''
                                ELSE
                                    SUBSTRING_INDEX(
                                        CONCAT(path_sequence, '|', VALUES(path_sequence)),
                                        '|',
                                        -20
                                    )
                            END,
                            CASE
                                WHEN path_sequence IS NULL OR path_sequence = '' THEN ''
                                ELSE '|'
                            END,
                            VALUES(path_sequence)
                        ),
                        is_attacker = IF(VALUES(is_attacker) = 1, 1, is_attacker),
                        threat_level = CASE
                            WHEN VALUES(threat_level) = 'high' OR threat_level = 'high' OR (request_count + 1) >= 50 THEN 'high'
                            WHEN VALUES(threat_level) = 'medium' OR threat_level = 'medium' OR (request_count + 1) >= 20 THEN 'medium'
                            WHEN threat_level IN ('low', 'unknown') THEN 'low'
                            ELSE threat_level
                        END
                    """,
                    (session_id, src_ip, path, 1 if is_suspicious else 0, threat_level, now_text, now_text, now_text)
                )
            else:
                placeholder = '?'
                cursor.execute(
                    f"""SELECT id, path_sequence, request_count, is_attacker, threat_level
                    FROM session_track WHERE session_id = {placeholder}""",
                    (session_id,)
                )
                row = cursor.fetchone()

                if row:
                    old_seq = row[1]
                    old_seq = old_seq or ''
                    old_count = row[2]
                    old_is_attacker = int(row[3] or 0)
                    old_threat_level = str(row[4] or 'unknown').lower()

                    paths = old_seq.split('|') if old_seq else []
                    paths.append(path)
                    new_seq = '|'.join(paths[-20:])
                    new_count = old_count + 1

                    incoming_threat_level = 'low'
                    if risk_score >= 50 or new_count >= 50:
                        incoming_threat_level = 'high'
                    elif risk_score >= 20 or new_count >= 20:
                        incoming_threat_level = 'medium'

                    # 与 MySQL 分支保持一致：攻击标记与威胁等级只能升级，不回退
                    is_attacker_flag = 1 if (old_is_attacker == 1 or is_suspicious) else 0
                    if incoming_threat_level == 'high' or old_threat_level == 'high':
                        threat_level = 'high'
                    elif incoming_threat_level == 'medium' or old_threat_level == 'medium':
                        threat_level = 'medium'
                    elif old_threat_level in ('low', 'unknown'):
                        threat_level = 'low'
                    else:
                        threat_level = incoming_threat_level

                    def _update_action(c):
                        c.execute(
                            f"""UPDATE session_track
                            SET last_seen = {placeholder}, request_count = {placeholder},
                                path_sequence = {placeholder}, is_attacker = {placeholder}, threat_level = {placeholder}
                            WHERE session_id = {placeholder}""",
                            (now_text, new_count, new_seq, is_attacker_flag, threat_level, session_id)
                        )
                    _sqlite_run_with_retry(conn, _update_action)
                else:
                    def _insert_action(c):
                        incoming_threat_level = 'low'
                        if risk_score >= 50:
                            incoming_threat_level = 'high'
                        elif risk_score >= 20:
                            incoming_threat_level = 'medium'
                        c.execute(
                            f"""INSERT INTO session_track
                            (session_id, src_ip, first_seen, last_seen, path_sequence, is_attacker, threat_level)
                            VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder})""",
                            (
                                session_id,
                                src_ip,
                                now_text,
                                now_text,
                                path,
                                1 if is_suspicious else 0,
                                incoming_threat_level,
                            )
                        )
                    _sqlite_run_with_retry(conn, _insert_action)

            if USE_MYSQL:
                conn.commit()
        finally:
            conn.close()
    except Exception as e:
        logger.debug(f"会话追踪更新失败: {e}")


def get_suspicious_requests(limit=50, offset=0, hours=None):
    """获取可疑请求列表"""
    try:
        limit = int(limit)
    except Exception:
        limit = 50
    if limit <= 0:
        limit = 1
    if limit > 500:
        limit = 500

    try:
        offset = int(offset)
    except Exception:
        offset = 0
    if offset < 0:
        offset = 0
    if offset > 50000:
        offset = 50000
    hours_v = _parse_hours(hours)
    cutoff = (datetime.now() - timedelta(hours=hours_v)).strftime('%Y-%m-%d %H:%M:%S') if hours_v is not None else ''
    real_available = has_real_data() or (not USE_MYSQL and archive_has_real_data(cutoff))
    if not real_available and _ALLOW_DASHBOARD_MOCK_DATA:
        mock = build_mock_suspicious_requests()
        return mock[offset:offset + limit]
    if not real_available:
        return []

    conn = get_connection()
    try:
        cursor = conn.cursor()
        placeholder = '%s' if USE_MYSQL else '?'
        where = "WHERE is_suspicious = 1"
        params = []
        if hours_v is not None:
            where += f" AND create_time >= {placeholder}"
            params.append(cutoff)
        query_limit = limit if USE_MYSQL else min(50500, offset + limit)
        sql = (
            f"SELECT * FROM raw_request {where} "
            f"ORDER BY create_time DESC, threat_score DESC "
            + (f"LIMIT {limit} OFFSET {offset}" if USE_MYSQL else f"LIMIT {query_limit}")
        )
        cursor.execute(sql, tuple(params))
        rows = cursor.fetchall()
        if rows and not isinstance(rows[0], dict):
            cols = [d[0] for d in cursor.description]
            rows = [dict(zip(cols, row)) for row in rows]
        if not USE_MYSQL:
            archive_rows = fetch_archive_rows(
                'raw_request',
                '*',
                where=where[6:] if where.startswith('WHERE ') else where,
                params=tuple(params),
                order_by='create_time DESC, threat_score DESC',
                limit=min(50500, offset + limit),
                window_cutoff=cutoff,
            )
            rows = list(rows or []) + archive_rows
            rows.sort(key=_request_sort_key, reverse=True)
            rows = rows[offset:offset + limit]
        return rows
    finally:
        conn.close()


def get_observed_requests(limit=30, offset=0, hours=None, min_score=12, max_score=19):
    """获取观察请求列表（低于可疑阈值但值得展示）。"""
    try:
        limit = int(limit)
    except Exception:
        limit = 30
    if limit <= 0:
        limit = 1
    if limit > 500:
        limit = 500

    try:
        offset = int(offset)
    except Exception:
        offset = 0
    if offset < 0:
        offset = 0
    if offset > 50000:
        offset = 50000

    try:
        min_score_v = int(min_score)
    except Exception:
        min_score_v = 12
    try:
        max_score_v = int(max_score)
    except Exception:
        max_score_v = 19
    min_score_v = max(0, min(min_score_v, 100))
    max_score_v = max(0, min(max_score_v, 100))
    if min_score_v > max_score_v:
        min_score_v, max_score_v = max_score_v, min_score_v

    hours_v = _parse_hours(hours)
    cutoff = (datetime.now() - timedelta(hours=hours_v)).strftime('%Y-%m-%d %H:%M:%S') if hours_v is not None else ''
    if not (has_real_data() or (not USE_MYSQL and archive_has_real_data(cutoff))):
        return []

    conn = get_connection()
    try:
        cursor = conn.cursor()
        placeholder = '%s' if USE_MYSQL else '?'
        where = (
            f"WHERE (is_suspicious = 0 OR is_suspicious IS NULL) "
            f"AND threat_score >= {placeholder} AND threat_score <= {placeholder}"
        )
        params = [min_score_v, max_score_v]
        if hours_v is not None:
            where += f" AND create_time >= {placeholder}"
            params.append(cutoff)
        query_limit = limit if USE_MYSQL else min(50500, offset + limit)
        sql = (
            f"SELECT * FROM raw_request {where} "
            f"ORDER BY create_time DESC, threat_score DESC "
            + (f"LIMIT {limit} OFFSET {offset}" if USE_MYSQL else f"LIMIT {query_limit}")
        )
        cursor.execute(sql, tuple(params))
        rows = cursor.fetchall()
        if rows and not isinstance(rows[0], dict):
            cols = [d[0] for d in cursor.description]
            rows = [dict(zip(cols, row)) for row in rows]
        if not USE_MYSQL:
            archive_rows = fetch_archive_rows(
                'raw_request',
                '*',
                where=where[6:] if where.startswith('WHERE ') else where,
                params=tuple(params),
                order_by='create_time DESC, threat_score DESC',
                limit=min(50500, offset + limit),
                window_cutoff=cutoff,
            )
            rows = list(rows or []) + archive_rows
            rows.sort(key=_request_sort_key, reverse=True)
            rows = rows[offset:offset + limit]
        return rows
    finally:
        conn.close()


_SSH_CHAIN_EVENT_TYPES = (
    'ssh_login_failed',
    'ssh_login_success',
    'ssh_bruteforce_ban',
    'ssh_cmd_audit',
    'ssh_cmd_suspicious',
    'ssh_cmd_high_risk',
    'scp_upload',
    'scp_upload_rejected',
    'ssh_port_scan_probe',
)

_CHAIN_LEVEL_WEIGHT = {
    'unknown': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
}


def _parse_event_extra(extra_value):
    if isinstance(extra_value, dict):
        return extra_value
    raw = str(extra_value or '').strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _short_chain_text(value: str, limit: int = 48) -> str:
    text = re.sub(r'\s+', ' ', str(value or '').strip())
    if len(text) <= limit:
        return text
    return text[:max(8, limit - 3)] + '...'


def _merge_chain_level(current: str, incoming: str) -> str:
    current_v = str(current or 'unknown').strip().lower() or 'unknown'
    incoming_v = str(incoming or 'unknown').strip().lower() or 'unknown'
    if _CHAIN_LEVEL_WEIGHT.get(incoming_v, 0) > _CHAIN_LEVEL_WEIGHT.get(current_v, 0):
        return incoming_v
    return current_v


def _ssh_event_level(row: dict) -> str:
    severity = str((row or {}).get('severity') or '').strip().lower()
    event_type = str((row or {}).get('event_type') or '').strip().lower()
    if severity in ('critical', 'high'):
        return 'high'
    if severity in ('warning', 'warn', 'medium'):
        return 'medium'
    if event_type in ('ssh_bruteforce_ban', 'ssh_cmd_high_risk'):
        return 'high'
    if event_type in ('ssh_login_failed', 'ssh_cmd_suspicious', 'scp_upload_rejected', 'ssh_port_scan_probe'):
        return 'medium'
    return 'low'


def _ssh_chain_command_key(row: dict) -> str:
    event_type = str((row or {}).get('event_type') or '').strip().lower()
    if event_type not in ('ssh_cmd_audit', 'ssh_cmd_suspicious', 'ssh_cmd_high_risk'):
        return ''
    extra = _parse_event_extra((row or {}).get('extra'))
    command_sha1 = str(extra.get('command_sha1') or '').strip().lower()
    if command_sha1:
        return f"sha1:{command_sha1[:8]}"
    raw_command = re.sub(r'\s+', ' ', str(extra.get('raw_command') or '')).strip()
    if raw_command:
        return raw_command[:1200]
    payload = re.sub(r'\s+', ' ', str((row or {}).get('payload') or '')).strip()
    payload_sha1 = re.search(r'sha1=([0-9a-fA-F]{8,40})', payload)
    if payload_sha1:
        return f"sha1:{payload_sha1.group(1).lower()[:8]}"
    return payload[:1200]


def _format_ssh_chain_step(row: dict, truncate: bool = True) -> str:
    event_type = str((row or {}).get('event_type') or '').strip().lower()
    payload = str((row or {}).get('payload') or '').strip()
    extra = _parse_event_extra((row or {}).get('extra'))
    username = str(extra.get('username') or '').strip()
    file_name = str(extra.get('file_name') or '').strip()
    payload_text = _short_chain_text(payload, 88) if truncate else re.sub(r'\s+', ' ', payload).strip()
    file_text = _short_chain_text(file_name or payload, 72) if truncate else re.sub(r'\s+', ' ', str(file_name or payload or '')).strip()

    if event_type == 'ssh_login_failed':
        return f"认证失败({username or 'unknown'})"
    if event_type == 'ssh_login_success':
        return f"认证成功({username or 'unknown'})"
    if event_type == 'ssh_bruteforce_ban':
        ban_seconds = int(extra.get('ban_seconds') or 0)
        return f"触发封禁({ban_seconds}s)" if ban_seconds > 0 else "触发封禁"
    if event_type == 'ssh_cmd_audit':
        return f"命令:{payload_text}" if payload_text else "命令审计"
    if event_type == 'ssh_cmd_suspicious':
        return f"可疑命令:{payload_text}" if payload_text else "可疑命令"
    if event_type == 'ssh_cmd_high_risk':
        return f"高危命令:{payload_text}" if payload_text else "高危命令"
    if event_type == 'scp_upload':
        return f"SCP上传:{file_text}"
    if event_type == 'scp_upload_rejected':
        return f"SCP拒绝:{file_text}"
    if event_type == 'ssh_port_scan_probe':
        return "高频探测"
    return _short_chain_text(payload, 40) if truncate and payload else (re.sub(r'\s+', ' ', payload).strip() if payload else event_type)


def _append_ssh_chain_step(step_list, row: dict, text: str, full_text: str) -> None:
    if not text:
        return
    event_type = str((row or {}).get('event_type') or '').strip().lower()
    command_key = _ssh_chain_command_key(row)

    if command_key:
        recent_indexes = range(len(step_list) - 1, max(-1, len(step_list) - 4), -1)
        if event_type == 'ssh_cmd_audit':
            for idx in recent_indexes:
                prev = step_list[idx]
                if prev.get('command_key') != command_key:
                    continue
                if prev.get('event_type') in ('ssh_cmd_high_risk', 'ssh_cmd_suspicious'):
                    return
        elif event_type in ('ssh_cmd_high_risk', 'ssh_cmd_suspicious'):
            for idx in recent_indexes:
                prev = step_list[idx]
                if prev.get('command_key') != command_key:
                    continue
                if prev.get('event_type') == 'ssh_cmd_audit':
                    del step_list[idx]
                    break

    if step_list and step_list[-1].get('full_text') == full_text:
        return
    step_list.append({
        'text': text,
        'full_text': full_text,
        'priority': _ssh_chain_step_priority(row),
        'event_type': event_type,
        'command_key': command_key,
    })


def _ssh_chain_step_priority(row: dict) -> int:
    event_type = str((row or {}).get('event_type') or '').strip().lower()
    if event_type in ('ssh_cmd_high_risk', 'scp_upload', 'scp_upload_rejected'):
        return 5
    if event_type in ('ssh_login_success', 'ssh_cmd_suspicious', 'ssh_cmd_audit', 'ssh_bruteforce_ban'):
        return 4
    if event_type == 'ssh_port_scan_probe':
        return 3
    if event_type == 'ssh_login_failed':
        return 1
    return 2


def _ssh_chain_signal_score(row: dict) -> int:
    event_type = str((row or {}).get('event_type') or '').strip().lower()
    if event_type == 'ssh_cmd_high_risk':
        return 48
    if event_type in ('ssh_cmd_suspicious', 'scp_upload', 'scp_upload_rejected'):
        return 36
    if event_type in ('ssh_login_success', 'ssh_cmd_audit'):
        return 28
    if event_type == 'ssh_bruteforce_ban':
        return 20
    if event_type == 'ssh_port_scan_probe':
        return 10
    return 0


def _ssh_gap_summary_entry(text: str) -> dict:
    summary = str(text or '').strip()
    return {
        'text': summary,
        'full_text': summary,
        'priority': 0,
        'event_type': 'summary',
        'command_key': '',
    }


def _ssh_gap_event_label(event_type: str) -> str:
    mapping = {
        'ssh_login_failed': '认证失败',
        'ssh_login_success': '认证成功',
        'ssh_bruteforce_ban': '触发封禁',
        'ssh_cmd_high_risk': '高危命令',
        'ssh_cmd_suspicious': '可疑命令',
        'ssh_cmd_audit': '命令',
        'scp_upload': 'SCP上传',
        'scp_upload_rejected': 'SCP拒绝',
        'ssh_port_scan_probe': '高频探测',
    }
    return mapping.get(str(event_type or '').strip().lower(), '行为')


def _summarize_ssh_chain_gap(entries) -> dict | None:
    gap_entries = [item for item in (entries or []) if isinstance(item, dict) and str(item.get('text') or '').strip()]
    total = len(gap_entries)
    if total <= 0:
        return None

    event_counts = Counter(str(item.get('event_type') or '').strip().lower() for item in gap_entries)
    if set(event_counts.keys()) == {'ssh_login_failed'}:
        user_counts = Counter()
        for item in gap_entries:
            text = str(item.get('text') or '').strip()
            match = re.match(r'^认证失败\((.*)\)$', text)
            user = (match.group(1) if match else text).strip() or 'unknown'
            user_counts[user] += 1
        top_parts = [f"{name}×{count}" for name, count in user_counts.most_common(4)]
        shown = sum(count for _, count in user_counts.most_common(4))
        if total > shown:
            top_parts.append(f"其他×{total - shown}")
        text = f"认证失败 {total} 次"
        if top_parts:
            text += f"（{', '.join(top_parts)}）"
        return _ssh_gap_summary_entry(text)

    parts = []
    for event_type, count in event_counts.most_common(4):
        label = _ssh_gap_event_label(event_type)
        unit = '次' if event_type in ('ssh_login_failed', 'ssh_login_success', 'ssh_bruteforce_ban', 'ssh_port_scan_probe') else '条'
        parts.append(f"{label} {count} {unit}")
    text = f"省略 {total} 条行为"
    if parts:
        text += f"（{'，'.join(parts)}）"
    return _ssh_gap_summary_entry(text)


def _compress_ssh_chain_steps(step_entries, max_steps: int = 24):
    entries = []
    for item in step_entries or []:
        if not isinstance(item, dict):
            continue
        text = str(item.get('text') or '').strip()
        full_text = str(item.get('full_text') or text).strip()
        if not text:
            continue
        entries.append({
            'text': text,
            'full_text': full_text,
            'priority': int(item.get('priority') or 0),
            'event_type': str(item.get('event_type') or '').strip().lower(),
            'command_key': str(item.get('command_key') or '').strip(),
        })
    if len(entries) <= max_steps:
        return entries

    total = len(entries)
    auth_event_types = {'ssh_login_failed', 'ssh_login_success', 'ssh_bruteforce_ban'}
    command_event_types = {'ssh_cmd_audit', 'ssh_cmd_suspicious', 'ssh_cmd_high_risk', 'scp_upload', 'scp_upload_rejected'}
    high_priority_indexes = [
        idx for idx, item in enumerate(entries)
        if int(item.get('priority') or 0) >= 5
    ]
    medium_priority_indexes = [
        idx for idx, item in enumerate(entries)
        if int(item.get('priority') or 0) == 4
    ]

    if not high_priority_indexes and not medium_priority_indexes:
        head_keep = list(range(0, min(2, total)))
        tail_start = max(len(head_keep), total - 4)
        tail_keep = list(range(tail_start, total))
        keep = sorted(set(head_keep + tail_keep))
        result = []
        prev_idx = -1
        for idx in keep:
            gap_summary = _summarize_ssh_chain_gap(entries[prev_idx + 1:idx])
            if gap_summary:
                result.append(gap_summary)
            result.append(entries[idx])
            prev_idx = idx
        tail_summary = _summarize_ssh_chain_gap(entries[prev_idx + 1:])
        if tail_summary:
            result.append(tail_summary)
        return result

    required_indexes = set()
    candidate_indexes = []

    def _add_index(idx: int):
        if idx < 0 or idx >= total:
            return
        candidate_indexes.append(idx)
        required_indexes.add(idx)

    def _append_context_indexes(indexes, before: int, after: int):
        for idx in indexes:
            start = max(0, idx - before)
            end = min(total, idx + after + 1)
            for pos in range(start, end):
                _add_index(pos)

    def _append_auth_context(idx: int, max_auth_steps: int = 4, lookback: int = 10):
        found = 0
        cursor = idx - 1
        while cursor >= 0 and (idx - cursor) <= lookback:
            event_type = str(entries[cursor].get('event_type') or '').strip().lower()
            if event_type in auth_event_types:
                _add_index(cursor)
                found += 1
                if found >= max_auth_steps:
                    break
            elif found > 0:
                break
            cursor -= 1

    def _append_forward_context(idx: int, max_steps_after: int = 2):
        for pos in range(idx + 1, min(total, idx + max_steps_after + 1)):
            _add_index(pos)

    _append_context_indexes(high_priority_indexes, before=2, after=2)
    for idx in high_priority_indexes:
        _append_auth_context(idx, max_auth_steps=4, lookback=12)
        _append_forward_context(idx, max_steps_after=2)

    _append_context_indexes(medium_priority_indexes, before=1, after=1)
    for idx in medium_priority_indexes:
        event_type = str(entries[idx].get('event_type') or '').strip().lower()
        if event_type in command_event_types:
            _append_auth_context(idx, max_auth_steps=3, lookback=8)
            _append_forward_context(idx, max_steps_after=1)
        elif event_type in auth_event_types:
            _append_forward_context(idx, max_steps_after=2)

    effective_max = min(max(max_steps, len(required_indexes)), 36)
    candidate_indexes.extend(range(0, min(2, total)))
    candidate_indexes.extend(range(max(0, total - 4), total))
    candidate_indexes.extend(range(total - 1, -1, -1))

    keep = []
    seen = set()
    for idx in candidate_indexes:
        if idx < 0 or idx >= total or idx in seen:
            continue
        keep.append(idx)
        seen.add(idx)
        if len(keep) >= effective_max:
            break
    keep.sort()
    result = []
    prev_idx = -1
    for idx in keep:
        gap_summary = _summarize_ssh_chain_gap(entries[prev_idx + 1:idx])
        if gap_summary:
            result.append(gap_summary)
        result.append(entries[idx])
        prev_idx = idx
    tail_summary = _summarize_ssh_chain_gap(entries[prev_idx + 1:])
    if tail_summary:
        result.append(tail_summary)
    return result


def _session_chain_value_score(item: dict) -> int:
    base_score = int((item or {}).get('_chain_value_score') or 0)
    path_sequence = str((item or {}).get('path_sequence') or '')
    if base_score > 0:
        return base_score
    score = 0
    if '认证成功(' in path_sequence:
        score += 30
    if any(token in path_sequence for token in ('高危命令:', '可疑命令:', '命令:')):
        score += 40
    if '触发封禁' in path_sequence:
        score += 18
    if any(token in path_sequence for token in ('SCP上传:', 'SCP拒绝:')):
        score += 24
    if '高频探测' in path_sequence:
        score += 8
    return score


def _session_chain_sort_key(item: dict):
    item = item if isinstance(item, dict) else {}
    level = str(item.get('threat_level') or 'unknown').strip().lower() or 'unknown'
    level_weight = _CHAIN_LEVEL_WEIGHT.get(level, 0)
    path_sequence = str(item.get('path_sequence') or '')
    has_success = 1 if item.get('_has_success') or '认证成功(' in path_sequence else 0
    has_command = 1 if item.get('_has_command') or any(token in path_sequence for token in ('高危命令:', '可疑命令:', '命令:')) else 0
    has_ban = 1 if item.get('_has_ban') or '触发封禁' in path_sequence else 0
    value_score = _session_chain_value_score(item)
    try:
        request_count = int(item.get('request_count') or 0)
    except Exception:
        request_count = 0
    last_seen = str(item.get('last_seen') or '')
    first_seen = str(item.get('first_seen') or '')
    return (
        level_weight,
        1 if value_score > 0 else 0,
        has_command,
        has_success,
        has_ban,
        value_score,
        min(request_count, 9999),
        last_seen,
        first_seen,
    )


def _get_ssh_session_analysis(limit: int, hours_v, min_count_v: int):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        placeholder = '%s' if USE_MYSQL else '?'
        scan_limit = max(300, min(limit * 80, 5000))
        params = ['ssh']
        event_placeholders = ','.join([placeholder] * len(_SSH_CHAIN_EVENT_TYPES))
        params.extend(list(_SSH_CHAIN_EVENT_TYPES))
        where = (
            f"WHERE source = {placeholder} "
            f"AND event_type IN ({event_placeholders}) "
            f"AND src_ip IS NOT NULL AND src_ip != ''"
        )
        cutoff = ''
        if hours_v is not None:
            cutoff = (datetime.now() - timedelta(hours=hours_v)).strftime('%Y-%m-%d %H:%M:%S')
            where += f" AND timestamp >= {placeholder}"
            params.append(cutoff)
        sql = (
            "SELECT timestamp, src_ip, session_id, severity, event_type, payload, extra "
            f"FROM event_log {where} "
            "ORDER BY timestamp DESC "
            f"LIMIT {scan_limit}"
        )
        cursor.execute(sql, tuple(params))
        rows = cursor.fetchall()
        if rows and not isinstance(rows[0], dict):
            cols = [d[0] for d in cursor.description]
            rows = [dict(zip(cols, row)) for row in rows]
        if not USE_MYSQL:
            archive_rows = fetch_archive_rows(
                'event_log',
                ['id', 'timestamp', 'src_ip', 'session_id', 'severity', 'event_type', 'payload', 'extra'],
                where=where[6:] if where.startswith('WHERE ') else where,
                params=tuple(params),
                order_by='timestamp DESC, id DESC',
                limit=scan_limit,
                window_cutoff=cutoff,
            )
            rows = list(rows or []) + archive_rows
            rows.sort(key=_event_sort_key, reverse=True)
            rows = rows[:scan_limit]

        grouped = {}
        for row in reversed(rows or []):
            item = row if isinstance(row, dict) else {}
            ip = str(item.get('src_ip') or '').strip()
            if not ip:
                continue
            session_id = str(item.get('session_id') or '').strip()
            group_key = f"ssh:{ip}"
            group = grouped.setdefault(group_key, {
                'session_id': '',
                'src_ip': ip,
                'first_seen': '',
                'last_seen': '',
                'path_sequence': '',
                'request_count': 0,
                'threat_level': 'unknown',
                'chain_type': 'ssh',
                '_steps': [],
                '_chain_value_score': 0,
                '_has_success': 0,
                '_has_command': 0,
                '_has_ban': 0,
            })
            ts = str(item.get('timestamp') or '').strip()
            if ts and (not group['first_seen'] or ts < group['first_seen']):
                group['first_seen'] = ts
            if ts and (not group['last_seen'] or ts > group['last_seen']):
                group['last_seen'] = ts
            group['request_count'] += 1
            group['threat_level'] = _merge_chain_level(group['threat_level'], _ssh_event_level(item))
            step = _format_ssh_chain_step(item, truncate=True)
            step_full = _format_ssh_chain_step(item, truncate=False)
            event_type = str(item.get('event_type') or '').strip().lower()
            signal_score = _ssh_chain_signal_score(item)
            if signal_score > 0:
                group['_chain_value_score'] = min(100, int(group.get('_chain_value_score') or 0) + signal_score)
            if event_type == 'ssh_login_success':
                group['_has_success'] = 1
            if event_type in ('ssh_cmd_audit', 'ssh_cmd_suspicious', 'ssh_cmd_high_risk'):
                group['_has_command'] = 1
            if event_type == 'ssh_bruteforce_ban':
                group['_has_ban'] = 1
            if step:
                _append_ssh_chain_step(group['_steps'], item, step, step_full)

        out = []
        for group in grouped.values():
            important_chain = bool(
                int(group.get('_has_success') or 0)
                or int(group.get('_has_command') or 0)
                or int(group.get('_has_ban') or 0)
            )
            if (
                int(group.get('request_count') or 0) < min_count_v
                and str(group.get('threat_level') or '').strip().lower() != 'high'
                and not important_chain
            ):
                continue
            path_steps = _compress_ssh_chain_steps(group.pop('_steps', []))
            group['path_steps'] = [str(step.get('text') or '').strip() for step in path_steps if str(step.get('text') or '').strip()]
            group['path_steps_full'] = [str(step.get('full_text') or step.get('text') or '').strip() for step in path_steps if str(step.get('full_text') or step.get('text') or '').strip()]
            group['path_sequence'] = '|'.join(group['path_steps'])
            out.append(group)
        out.sort(key=_session_chain_sort_key, reverse=True)
        return out[:limit]
    finally:
        conn.close()


def get_session_analysis(limit=50, hours=None, min_count=3):
    """获取会话分析数据"""
    try:
        limit = int(limit)
    except Exception:
        limit = 50
    if limit <= 0:
        limit = 1
    if limit > 500:
        limit = 500
    try:
        min_count_v = int(min_count)
    except Exception:
        min_count_v = 3
    if min_count_v < 0:
        min_count_v = 0
    if min_count_v > 100:
        min_count_v = 100
    hours_v = _parse_hours(hours)
    cutoff = (datetime.now() - timedelta(hours=hours_v)).strftime('%Y-%m-%d %H:%M:%S') if hours_v is not None else ''
    real_available = has_real_data() or (not USE_MYSQL and archive_has_real_data(cutoff))
    if not real_available and _ALLOW_DASHBOARD_MOCK_DATA:
        return build_mock_session_analysis()[:limit]
    if not real_available:
        return []
    conn = get_connection()
    try:
        cursor = conn.cursor()
        placeholder = '%s' if USE_MYSQL else '?'
        scan_limit = max(200, min(limit * 20, 5000))
        # 语义统一为“达到阈值即展示”
        where = f"WHERE request_count >= {min_count_v}"
        params = []
        if hours_v is not None:
            where += f" AND last_seen >= {placeholder}"
            params.append(cutoff)
        sql = f"SELECT * FROM session_track {where} ORDER BY last_seen DESC, request_count DESC LIMIT {scan_limit}"
        cursor.execute(sql, tuple(params))
        rows = cursor.fetchall()
        if rows and not isinstance(rows[0], dict):
            cols = [d[0] for d in cursor.description]
            rows = [dict(zip(cols, row)) for row in rows]
        if not USE_MYSQL:
            archive_rows = fetch_archive_rows(
                'session_track',
                '*',
                where=where[6:] if where.startswith('WHERE ') else where,
                params=tuple(params),
                order_by='last_seen DESC, request_count DESC',
                limit=scan_limit,
                window_cutoff=cutoff,
            )
            rows = list(rows or []) + archive_rows
            rows.sort(key=_session_sort_key, reverse=True)
            rows = rows[:scan_limit]
        web_rows = []
        for row in rows or []:
            if isinstance(row, dict):
                item = dict(row)
                item['chain_type'] = 'web'
                item['path_steps'] = [
                    str(step or '').strip()
                    for step in str(item.get('path_sequence') or '').split('|')
                    if str(step or '').strip()
                ]
                item['path_steps_full'] = list(item['path_steps'])
                web_rows.append(item)
        ssh_rows = _get_ssh_session_analysis(limit=limit, hours_v=hours_v, min_count_v=min_count_v)
        merged = web_rows + ssh_rows
        merged.sort(key=_session_chain_sort_key, reverse=True)
        return merged[:limit]
    finally:
        conn.close()


__all__ = [
    'generate_session_id',
    'calculate_threat_score',
    'log_raw_request',
    'update_session_track',
    'get_suspicious_requests',
    'get_observed_requests',
    'get_session_analysis',
]
