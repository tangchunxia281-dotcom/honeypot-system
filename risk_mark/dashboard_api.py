# -*- coding: utf-8 -*-
"""密标模块的 Dashboard HTTP 接口（Flask 蓝图）。

设计目标：与 dashboard/server.py 保持零耦合。
- 鉴权 / CSRF 装饰器由 register_dashboard_api(...) 参数注入，避免反向 import 造成循环依赖；
- 全部路由挂在 /api/risk_mark 前缀下，卸载模块只需不再调用 register_dashboard_api；
- 前端静态资源走蓝图自带 static 目录（对外路径 /api/risk_mark/static/），无需改动 dashboard/static。
"""
from flask import Blueprint, jsonify, request, session

from . import service
from .constants import STATUS_ACTIVE, TARGET_IP
from .detectors import detector_registry_info
from .log import logger

DEFAULT_URL_PREFIX = '/api/risk_mark'
# 蓝图 static 会叠加 url_prefix，最终对外路径为 /api/risk_mark/static/<filename>
STATIC_URL_PATH = '/static'
_TRUE_VALUES = {'1', 'true', 'yes', 'on', 'y'}


def _ok(data=None, msg: str = 'success'):
    return jsonify({'code': 0, 'msg': msg, 'data': data})


def _err(msg: str = '服务异常', data=None):
    return jsonify({'code': -1, 'msg': msg, 'data': data})


def _payload() -> dict:
    """兼容 JSON 与表单两种提交方式。"""
    data = {}
    try:
        body = request.get_json(silent=True)
    except Exception:
        body = None
    if isinstance(body, dict):
        data.update(body)
    try:
        data.update(dict(request.form.items()))
    except Exception:
        pass
    return data


def _int_arg(raw, default: int = 0) -> int:
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return default


def _operator() -> str:
    try:
        return str(session.get('admin_user') or '').strip()
    except Exception:
        return ''


def _to_bool(raw):
    if raw is None:
        return None
    if isinstance(raw, bool):
        return raw
    text = str(raw).strip().lower()
    if not text:
        return None
    return text in _TRUE_VALUES


def _attach_location(item, cache: dict):
    """为 IP 类型密标补充地理位置，失败时降级为"未知"。"""
    if not isinstance(item, dict) or str(item.get('target_type') or '') != TARGET_IP:
        return item
    ip = str(item.get('target_value') or '').strip()
    if not ip:
        return item
    view = cache.get(ip)
    if view is None:
        try:
            from db import get_geo_info
            from utils.ip_location import build_geo_location, normalize_geo_fields
            info = get_geo_info(ip, allow_online=False) or {}
            country_v, region_v, city_v = normalize_geo_fields(
                info.get('country'),
                info.get('province') or info.get('region'),
                info.get('city'),
            )
            view = {
                'location': build_geo_location(country_v, region_v, city_v) or '未知',
                'latitude': float(info.get('latitude') or 0),
                'longitude': float(info.get('longitude') or 0),
            }
        except Exception:
            view = {'location': '未知', 'latitude': 0.0, 'longitude': 0.0}
        cache[ip] = view
    item['location'] = view.get('location', '未知')
    item['latitude'] = view.get('latitude', 0.0)
    item['longitude'] = view.get('longitude', 0.0)
    return item


def register_dashboard_api(app, login_required, csrf_protect=None,
                           url_prefix: str = DEFAULT_URL_PREFIX) -> Blueprint:
    """把密标接口注册到 Dashboard 应用。

    Args:
        app: Flask 应用实例。
        login_required: 登录鉴权装饰器（由 dashboard/server.py 注入）。
        csrf_protect: POST 接口的 CSRF 装饰器，可选。
        url_prefix: 接口前缀，默认 /api/risk_mark。

    Returns:
        注册完成的 Blueprint。
    """
    bp = Blueprint(
        'risk_mark',
        __name__,
        url_prefix=url_prefix,
        static_folder='static',
        static_url_path=STATIC_URL_PATH,
    )

    def _guard(func):
        """所有接口都需要登录态；/api/ 前缀同时触发同源校验。"""
        return login_required(func)

    def _post(rule: str):
        def decorator(func):
            wrapped = csrf_protect(func) if csrf_protect else func
            wrapped = login_required(wrapped)
            return bp.route(rule, methods=['POST'])(wrapped)
        return decorator

    @bp.route('/meta')
    @_guard
    def risk_mark_meta():
        try:
            return _ok(service.meta())
        except Exception as e:
            logger.error(f"密标元数据接口异常: {e}")
            return _err()

    @bp.route('/summary')
    @_guard
    def risk_mark_summary():
        try:
            return _ok(service.summary())
        except Exception as e:
            logger.error(f"密标总览接口异常: {e}")
            return _err()

    @bp.route('/list')
    @_guard
    def risk_mark_list():
        try:
            args = request.args
            data = service.list_marks(
                target_type=args.get('target_type', ''),
                level=args.get('level', ''),
                status=args.get('status', STATUS_ACTIVE),
                keyword=args.get('q', '') or args.get('keyword', ''),
                limit=_int_arg(args.get('limit', 200), 200),
                offset=_int_arg(args.get('offset', 0), 0),
            )
            cache = {}
            for item in data.get('items', []):
                _attach_location(item, cache)
            return _ok(data)
        except Exception as e:
            logger.error(f"密标列表接口异常: {e}")
            return _err('服务异常', {'items': [], 'total': 0, 'stats': {}})

    @bp.route('/check')
    @_guard
    def risk_mark_check():
        """查询单个对象，或按 type:value 批量查询，用于事件列表打标。"""
        try:
            raw_targets = str(request.args.get('targets', '') or '').strip()
            if raw_targets:
                pairs = []
                for chunk in raw_targets.split(','):
                    chunk = chunk.strip()
                    if not chunk or ':' not in chunk:
                        continue
                    type_text, value_text = chunk.split(':', 1)
                    pairs.append((type_text.strip().lower(), value_text.strip()))
                ip_values = [v for t, v in pairs if t == TARGET_IP and v]
                marks = service.marks_for_ips(ip_values) if ip_values else {}
                cache = {}
                result = {}
                for type_text, value_text in pairs:
                    item = marks.get(value_text) if type_text == TARGET_IP else service.get_mark(type_text, value_text)
                    if item:
                        _attach_location(item, cache)
                    result[f"{type_text}:{value_text}"] = item
                return _ok(result)

            target_type = request.args.get('target_type', TARGET_IP)
            target_value = request.args.get('target_value', '')
            item = service.get_mark(target_type, target_value)
            if item:
                _attach_location(item, {})
            return _ok(item)
        except Exception as e:
            logger.error(f"密标查询接口异常: {e}")
            return _err()

    @_post('/create')
    def risk_mark_create():
        data = _payload()
        try:
            record = service.mark(
                target_type=data.get('target_type', TARGET_IP),
                target_value=data.get('target_value', ''),
                level=data.get('level', 'medium'),
                reason=data.get('reason', ''),
                created_by=str(data.get('created_by') or '').strip() or _operator(),
                mark_code=data.get('mark_code', ''),
                expires_at=data.get('expires_at', ''),
                ttl_days=data.get('ttl_days'),
            )
        except ValueError as e:
            return _err(str(e))
        except Exception as e:
            logger.error(f"密标创建接口异常: {e}")
            return _err('密标写入失败')
        _attach_location(record, {})
        return _ok(record)

    @_post('/remove')
    def risk_mark_remove():
        data = _payload()
        try:
            affected = service.unmark(
                mark_id=data.get('id'),
                target_type=data.get('target_type', ''),
                target_value=data.get('target_value', ''),
            )
        except Exception as e:
            logger.error(f"密标移除接口异常: {e}")
            return _err('密标移除失败')
        if affected <= 0:
            return _err('未找到对应的密标', {'removed': 0})
        return _ok({'removed': affected})

    @_post('/scan')
    def risk_mark_scan():
        data = _payload()
        try:
            result = service.auto_scan(
                hours=data.get('hours', 24),
                limit=data.get('limit'),
                apply=_to_bool(data.get('apply')),
                created_by=_operator() or 'scan',
            )
        except Exception as e:
            logger.error(f"密标自动识别接口异常: {e}")
            return _err('自动识别失败', {'proposals': [], 'applied': []})
        return _ok(result)

    @bp.route('/detectors')
    @_guard
    def risk_mark_detectors():
        try:
            return _ok({'detectors': detector_registry_info()})
        except Exception as e:
            logger.error(f"密标识别器接口异常: {e}")
            return _err('服务异常', {'detectors': []})

    app.register_blueprint(bp)
    logger.info(f"密标接口已挂载: {url_prefix}")
    return bp


__all__ = ['register_dashboard_api', 'DEFAULT_URL_PREFIX', 'STATIC_URL_PATH']
