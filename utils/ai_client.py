# -*- coding: utf-8 -*-
"""
Web 攻击检测 AI 服务客户端。

最新 AI 主接口：
    POST /api/v1/detect

请求字段：
    path、query、body、method、user_agent、
    source、ip、session_id、extra

响应字段：
    attack_type、is_attack、attack_prob、ai_points、
    confidence、high_risk、reasons、signals、model_label

AI 返回的 ai_points 是 0 到 25 的加权分，由蜜罐累加到规则分。
"""
from __future__ import annotations

import copy
import re
import threading
import time
from typing import Optional

import requests

from env_utils import env_bool, env_float, env_int, env_str
from utils.logger import setup_logger


logger = setup_logger(
    'ai_client',
    'ai_client.log',
    console_output=False
)

AI_XSS_ENABLED = env_bool('AI_XSS_ENABLED', False)
AI_XSS_URL = (
    env_str(
        'AI_XSS_URL',
        'http://127.0.0.1:8003/api/v1/detect'
    ).strip()
    or 'http://127.0.0.1:8003/api/v1/detect'
)
AI_XSS_INFO_URL = (
    env_str('AI_XSS_INFO_URL', 'http://127.0.0.1:8003/model/info').strip()
    or 'http://127.0.0.1:8003/model/info'
)
AI_XSS_TIMEOUT = env_float('AI_XSS_TIMEOUT', 1.0, 0.1, 10.0)
AI_XSS_THRESHOLD = env_float('AI_XSS_THRESHOLD', 0.90, 0.0, 1.0)
AI_XSS_TEXT_MAX = env_int('AI_XSS_TEXT_MAX', 5000, 128, 100000)
AI_XSS_FAILURE_THRESHOLD = env_int('AI_XSS_FAILURE_THRESHOLD', 3, 1, 100)
AI_XSS_BACKOFF_SECONDS = env_float('AI_XSS_BACKOFF_SECONDS', 30.0, 0.0, 3600.0)
AI_XSS_MODEL_INFO_TTL = env_int('AI_XSS_MODEL_INFO_TTL', 300, 0, 86400)

_state_lock = threading.Lock()
_failure_state = {
    'consecutive_failures': 0,
    'backoff_until': 0.0,
    'last_error': '',
}
_metrics = {
    'attempts': 0,
    'successes': 0,
    'failures': 0,
    'timeouts': 0,
    'invalid_responses': 0,
    'backoff_skips': 0,
    'model_info_successes': 0,
    'model_info_failures': 0,
    'latency_count': 0,
    'latency_sum_ms': 0.0,
    'last_latency_ms': 0.0,
}
_model_info_state = {
    'data': {},
    'expires_at': 0.0,
    'next_retry_at': 0.0,
    'last_error': '',
}

_AI_SENSITIVE_KV_RE = re.compile(
    r'(?i)(\b(?:password|passwd|pwd|token|secret|api_key|apikey|authorization)\b'
    r'\s*[:=]\s*)([^&\s;,\r\n]+)'
)
_AI_SENSITIVE_JSON_RE = re.compile(
    r'(?i)("(?:password|passwd|pwd|token|secret|api_key|apikey|authorization)"'
    r'\s*:\s*)(?:"[^"]*"|\'[^\']*\'|[^,\s}\]]+)'
)


def _increment_metric(name: str, delta: int = 1) -> None:
    with _state_lock:
        _metrics[name] = int(_metrics.get(name, 0)) + int(delta)


def _record_failure(reason: str, metric: str = 'failures') -> None:
    now = time.monotonic()
    safe_reason = str(reason or 'unknown')[:200]
    with _state_lock:
        _metrics['failures'] = int(_metrics.get('failures', 0)) + 1
        if metric != 'failures':
            _metrics[metric] = int(_metrics.get(metric, 0)) + 1
        _metrics['last_error'] = safe_reason
        _failure_state['last_error'] = safe_reason
        _failure_state['consecutive_failures'] += 1

        if (
            AI_XSS_FAILURE_THRESHOLD > 0
            and _failure_state['consecutive_failures'] >= AI_XSS_FAILURE_THRESHOLD
            and AI_XSS_BACKOFF_SECONDS > 0
        ):
            _failure_state['backoff_until'] = now + AI_XSS_BACKOFF_SECONDS


def _record_success(latency_ms: float) -> None:
    with _state_lock:
        _metrics['successes'] += 1
        _metrics['latency_count'] += 1
        _metrics['latency_sum_ms'] += float(latency_ms)
        _metrics['last_latency_ms'] = round(float(latency_ms), 3)
        _failure_state['consecutive_failures'] = 0
        _failure_state['backoff_until'] = 0.0
        _failure_state['last_error'] = ''


def _backoff_remaining() -> float:
    now = time.monotonic()
    with _state_lock:
        return max(0.0, float(_failure_state.get('backoff_until') or 0.0) - now)


def get_ai_metrics() -> dict:
    """返回 AI 客户端进程内运行指标快照。"""
    now = time.monotonic()
    with _state_lock:
        metrics = copy.deepcopy(_metrics)
        failure_state = copy.deepcopy(_failure_state)
        model_info = copy.deepcopy(_model_info_state)

    latency_count = int(metrics.get('latency_count') or 0)
    latency_sum = float(metrics.get('latency_sum_ms') or 0.0)
    metrics.update({
        'enabled': bool(AI_XSS_ENABLED),
        'url': AI_XSS_URL,
        'info_url': AI_XSS_INFO_URL,
        'scoring_mode': 'weighted_points',
        'ai_points_max': 25,
        # Deprecated compatibility value.
        'threshold': float(AI_XSS_THRESHOLD),
        'timeout': float(AI_XSS_TIMEOUT),
        'failure_threshold': int(AI_XSS_FAILURE_THRESHOLD),
        'backoff_seconds': float(AI_XSS_BACKOFF_SECONDS),
        'consecutive_failures': int(
            failure_state.get('consecutive_failures') or 0
        ),
        'backoff_remaining_seconds': round(
            max(0.0, float(failure_state.get('backoff_until') or 0.0) - now),
            3
        ),
        'last_error': str(failure_state.get('last_error') or ''),
        'avg_latency_ms': round(
            latency_sum / latency_count,
            3
        ) if latency_count else 0.0,
        'model_info': copy.deepcopy(model_info.get('data') or {}),
        'model_info_last_error': str(model_info.get('last_error') or ''),
    })
    return metrics


def build_ai_text(
    path: str,
    query_string: str,
    body: str,
    max_length: int = None
) -> str:
    """
    从请求中选择模型需要的文本。

    优先使用查询字符串和请求体。两者都为空时，才使用非根路径。
    URL/HTML 解码交给 AI 服务中的 normalize_text 处理。
    """
    query_text = str(query_string or '').strip()
    body_text = str(body or '').strip()
    path_text = str(path or '').strip()

    parts = []
    if query_text:
        parts.append(query_text)
    if body_text:
        parts.append(body_text)
    if not parts and path_text and path_text != '/':
        parts.append(path_text)

    text = '\n'.join(parts).strip()
    text = _redact_ai_text(text)
    limit = int(max_length or AI_XSS_TEXT_MAX)
    return text[:max(1, limit)]


def _redact_ai_text(text: str) -> str:
    """对即将发送给 AI 的文本做敏感字段遮蔽。"""
    text = str(text or '')
    text = _AI_SENSITIVE_JSON_RE.sub(r'\1"<redacted>"', text)
    text = _AI_SENSITIVE_KV_RE.sub(r'\1<redacted>', text)
    return text


_ALLOWED_ATTACK_TYPES = {
    'xss',
    'sqli',
    'path_traversal',
    'sensitive_path',
    'scanner',
    'normal',
}


def _normalize_ai_result(payload) -> Optional[dict]:
    """
    校验 AI v2 /api/v1/detect 响应。

    异常或不完整响应返回 None，让蜜罐回退原规则。
    """
    if not isinstance(payload, dict):
        return None

    attack_type = str(
        payload.get('attack_type') or ''
    ).strip().lower()
    if attack_type not in _ALLOWED_ATTACK_TYPES:
        return None

    is_attack = payload.get('is_attack')
    if not isinstance(is_attack, bool):
        return None

    # attack_type 和 is_attack 必须保持语义一致。
    if (attack_type == 'normal') == is_attack:
        return None

    attack_prob = payload.get('attack_prob')
    if isinstance(attack_prob, bool) or not isinstance(
        attack_prob,
        (int, float)
    ):
        return None
    attack_prob = float(attack_prob)
    if not 0.0 <= attack_prob <= 1.0:
        return None

    ai_points = payload.get('ai_points')
    if isinstance(ai_points, bool):
        return None
    try:
        ai_points = int(ai_points)
    except Exception:
        return None
    if not 0 <= ai_points <= 25:
        return None

    confidence = payload.get('confidence')
    if isinstance(confidence, bool) or not isinstance(
        confidence,
        (int, float)
    ):
        return None
    confidence = float(confidence)
    if not 0.0 <= confidence <= 1.0:
        return None

    high_risk = payload.get('high_risk')
    if not isinstance(high_risk, bool):
        return None

    raw_reasons = payload.get('reasons') or []
    if isinstance(raw_reasons, str):
        raw_reasons = [raw_reasons]
    if not isinstance(raw_reasons, list):
        return None
    reasons = []
    for item in raw_reasons[:20]:
        text = str(item or '').strip()
        if text:
            reasons.append(text[:500])

    raw_signals = payload.get('signals') or []
    if not isinstance(raw_signals, list):
        return None
    signals = []
    for item in raw_signals[:20]:
        if not isinstance(item, dict):
            continue
        try:
            signal_prob = float(item.get('attack_prob') or 0.0)
        except Exception:
            signal_prob = 0.0
        try:
            signal_ai_points = int(item.get('ai_points') or 0)
        except Exception:
            signal_ai_points = 0
        try:
            signal_fusion_score = int(item.get('fusion_score') or 0)
        except Exception:
            signal_fusion_score = 0
        signals.append({
            'field': str(item.get('field') or '')[:120],
            'value': str(item.get('value') or '')[:1000],
            'attack_type': str(
                item.get('attack_type') or ''
            ).strip().lower()[:64],
            'attack_prob': signal_prob,
            'ai_points': signal_ai_points,
            'fusion_score': signal_fusion_score,
            'high_risk': bool(item.get('high_risk')),
            'reason': str(item.get('reason') or '')[:500],
        })

    model_label = str(
        payload.get('model_label') or ''
    ).strip().lower()[:64]

    return {
        'attack_type': attack_type,
        'is_attack': is_attack,
        'attack_prob': round(attack_prob, 6),
        'ai_points': ai_points,
        'confidence': round(confidence, 6),
        'high_risk': high_risk,
        'reasons': reasons,
        'signals': signals,
        'model_label': model_label,
        'source': str(payload.get('source') or '')[:32],
        'ip': str(payload.get('ip') or '')[:64],
        'session_id': str(payload.get('session_id') or '')[:64],
    }


def _normalize_model_info(payload) -> dict:
    if not isinstance(payload, dict):
        return {}

    labels = payload.get('labels')
    if not isinstance(labels, list):
        labels = []

    version = str(payload.get('version') or '').strip()
    trained_at = str(payload.get('trained_at') or '').strip()
    if not any((version, trained_at, labels)):
        return {}

    return {
        'version': version,
        'trained_at': trained_at,
        'labels': [str(item) for item in labels[:32]],
    }


def get_model_info(force: bool = False) -> dict:
    """
    获取并缓存 AI 模型信息。

    AI 服务不可用或返回异常时返回空字典，不影响预测主流程。
    """
    if not AI_XSS_ENABLED or not AI_XSS_INFO_URL or AI_XSS_MODEL_INFO_TTL <= 0:
        return {}

    now = time.monotonic()
    with _state_lock:
        cached = copy.deepcopy(_model_info_state.get('data') or {})
        expires_at = float(_model_info_state.get('expires_at') or 0.0)
        next_retry_at = float(_model_info_state.get('next_retry_at') or 0.0)
        if not force and cached and now < expires_at:
            return cached
        if not force and now < next_retry_at:
            return cached

    try:
        response = requests.get(
            AI_XSS_INFO_URL,
            timeout=min(float(AI_XSS_TIMEOUT), 0.5)
        )
        response.raise_for_status()
        info = _normalize_model_info(response.json())
        if not info:
            raise ValueError('模型信息字段为空或不完整')
    except Exception as exc:
        with _state_lock:
            _model_info_state['last_error'] = str(exc)[:200]
            _model_info_state['next_retry_at'] = (
                now + min(60.0, max(5.0, AI_XSS_BACKOFF_SECONDS))
            )
            _metrics['model_info_failures'] += 1
        logger.debug(f'AI 模型信息获取失败: {exc}')
        return cached

    with _state_lock:
        _model_info_state['data'] = copy.deepcopy(info)
        _model_info_state['expires_at'] = now + AI_XSS_MODEL_INFO_TTL
        _model_info_state['next_retry_at'] = 0.0
        _model_info_state['last_error'] = ''
        _metrics['model_info_successes'] += 1
    return info


def _post_detect(payload: dict) -> Optional[dict]:
    """调用 AI v2 detect 接口并校验响应。"""
    if not AI_XSS_ENABLED:
        return None

    remaining = _backoff_remaining()
    if remaining > 0:
        _increment_metric('backoff_skips')
        return None

    started_at = time.perf_counter()
    _increment_metric('attempts')

    try:
        response = requests.post(
            AI_XSS_URL,
            json=payload,
            timeout=AI_XSS_TIMEOUT
        )
        response.raise_for_status()
        payload = response.json()
    except requests.Timeout as exc:
        _record_failure(str(exc), metric='timeouts')
        logger.debug(f'AI XSS request timeout: {exc}')
        return None
    except requests.RequestException as exc:
        _record_failure(str(exc))
        logger.debug(f'AI XSS 请求失败: {exc}')
        return None
    except ValueError as exc:
        _record_failure(str(exc), metric='invalid_responses')
        logger.debug(f'AI XSS 响应不是有效 JSON: {exc}')
        return None
    except Exception as exc:
        _record_failure(str(exc))
        logger.debug(f'AI XSS 客户端异常: {exc}')
        return None

    normalized = _normalize_ai_result(payload)
    if normalized is None:
        _record_failure('AI response validation failed', metric='invalid_responses')
        return None

    latency_ms = (time.perf_counter() - started_at) * 1000.0
    model_info = get_model_info()
    _record_success(latency_ms)

    normalized.update({
        'request_id': str(payload.get('extra', {}).get('request_id') or ''),
        'latency_ms': round(latency_ms, 3),
        'model': model_info,
    })
    return normalized


def detect_request(
    path: str = '',
    query: str = '',
    body: str = '',
    method: str = '',
    user_agent: str = '',
    source: str = 'web',
    ip: str = '',
    session_id: str = '',
    request_id: str = '',
    timestamp: str = '',
) -> Optional[dict]:
    """
    调用 AI v2 请求级主接口。

    只发送检测需要的结构化请求字段，不发送 Cookie、
    Authorization 或完整原始请求。
    """
    if not AI_XSS_ENABLED:
        return None

    path_text = _redact_ai_text(str(path or '').strip())
    query_text = _redact_ai_text(str(query or '').strip())
    body_text = _redact_ai_text(str(body or '').strip())
    ua_text = _redact_ai_text(str(user_agent or '').strip())

    if not query_text and not body_text and (
        not path_text or path_text == '/'
    ):
        return None

    limit = max(128, int(AI_XSS_TEXT_MAX))
    request_payload = {
        'path': path_text[:limit],
        'query': query_text[:limit],
        'body': body_text[:limit],
        'method': str(method or '').upper()[:16],
        'user_agent': ua_text[:500],
        'source': str(source or 'web')[:32],
        'ip': str(ip or '')[:64],
        'session_id': str(session_id or '')[:64],
    }
    if timestamp:
        request_payload['timestamp'] = str(timestamp)[:64]
    if request_id:
        request_payload['extra'] = {
            'request_id': str(request_id)
        }

    return _post_detect(request_payload)


def predict_xss(
    text: str,
    source: str = 'web',
    ip: str = '',
    request_id: str = ''
) -> Optional[dict]:
    """兼容旧调用：把单段文本作为 query 交给 v2 detect 接口。"""
    return detect_request(
        query=text,
        source=source,
        ip=ip,
        request_id=request_id
    )


def is_ai_result_trusted(ai_result: Optional[dict]) -> bool:
    """兼容旧调用：v2 中只有 ai_points 大于 0 才视为额外加分。"""
    if not isinstance(ai_result, dict):
        return False

    try:
        return int(ai_result.get('ai_points') or 0) > 0
    except Exception:
        return False


__all__ = [
    'AI_XSS_ENABLED',
    'AI_XSS_URL',
    'AI_XSS_INFO_URL',
    'AI_XSS_TIMEOUT',
    'AI_XSS_THRESHOLD',
    'AI_XSS_TEXT_MAX',
    'AI_XSS_FAILURE_THRESHOLD',
    'AI_XSS_BACKOFF_SECONDS',
    'AI_XSS_MODEL_INFO_TTL',
    'build_ai_text',
    'detect_request',
    'get_model_info',
    'get_ai_metrics',
    'predict_xss',
    'is_ai_result_trusted',
]
