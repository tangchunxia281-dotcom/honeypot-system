# -*- coding: utf-8 -*-
"""
Web 蜜罐 - 错误处理
"""
import time
import traceback
from flask import request, render_template, make_response
from werkzeug.exceptions import HTTPException


def register(app, ctx):
    get_client_ip = ctx['get_client_ip']
    _safe_log_event = ctx['_safe_log_event']
    _log_event = ctx['_log_event']
    _render_http_error = ctx['_render_http_error']
    logger = ctx['logger']
    app_framework = ctx.get('app_framework', 'nginx')

    @app.errorhandler(404)
    def page_not_found(e):
        client_ip = get_client_ip()
        path = request.path

        # 图标类自动请求：静默返回，不记录
        silent_ignore = ['favicon.ico', 'apple-touch-icon', 'browserconfig.xml']
        if any(s in path.lower() for s in silent_ignore):
            return make_response('', 404)

        # 浏览器自动请求：仅入库，不输出控制台日志
        browser_auto = ['.well-known', '.map', 'sourcemap']
        if any(s in path.lower() for s in browser_auto):
            _safe_log_event(client_ip, f"探测路径: {path}")  # 只写数据库
            return _render_http_error(404, 'Not Found', 'Resource not found')

        # 可疑路径探测：记录并输出警告日志
        _log_event(client_ip, f"探测路径: {path}", level='warning')
        return _render_http_error(404, 'Not Found', 'Resource not found')

    @app.errorhandler(HTTPException)
    def handle_http_exception(e):
        client_ip = get_client_ip()
        try:
            code = getattr(e, 'code', None)
        except Exception:
            code = None
        status = int(code or 500)
        method = str(request.method or '').upper()
        path = str(request.path or '/')
        path_l = path.lower()

        # 精确降噪：根路径的常规方法 405 仅保留运行日志，不进入威胁事件流
        is_low_value_root_405 = (
            status == 405 and
            path in ('', '/') and
            method in ('GET', 'HEAD', 'OPTIONS')
        )
        if is_low_value_root_405:
            logger.info(f"[降噪] HTTP异常: {status} {method} {path} - IP: {client_ip}")
        else:
            # 405 命中敏感路径时，按探测事件入库；其余仍走通用异常日志
            if status == 405:
                suspicious_path_tokens = (
                    '/admin', '/admin/api', '/api/login', '/api/auth/login',
                    '/login', '/signin', '/uploads',
                    '/.env', '/.git', '/backup', '/old'
                )
                if any(tok in path_l for tok in suspicious_path_tokens):
                    _safe_log_event(client_ip, f"HTTP异常(可疑路径): {status} {method} {path}", event_type='web_probe')
                    logger.warning(f"HTTP异常(可疑路径): {status} {method} {path} - IP: {client_ip}")
                else:
                    _log_event(client_ip, f"HTTP异常: {status} {method} {path}", level='warning')
            else:
                _log_event(client_ip, f"HTTP异常: {status} {method} {path}", level='warning')

        error_type = getattr(e, 'name', None) or 'Request Error'
        error_msg = 'The requested operation could not be completed.'
        if status == 400:
            error_msg = 'Invalid request.'
        elif status == 401:
            error_msg = 'Authentication required.'
        elif status == 403:
            error_msg = 'Access denied.'
        elif status == 404:
            error_msg = 'Resource not found.'
        elif status == 405:
            error_msg = 'Method not allowed.'
        elif status == 413:
            error_msg = 'Request entity too large.'
        elif status >= 500:
            error_type = 'System Error'
            error_msg = 'Uncaught exception while handling request'

        return _render_http_error(status, error_type, error_msg)

    @app.errorhandler(500)
    def internal_server_error(e):
        client_ip = get_client_ip()
        error_traceback = traceback.format_exc()
        logger.error(f"[错误] 500 {client_ip} {request.path}")
        logger.error(f"错误详情:\n{error_traceback}")
        resp = make_response(
            render_template(
                'error.html',
                error_type='Internal Server Error',
                current_time=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
                error_msg='An internal error occurred while processing your request.',
                error_framework='Portal Service',
                app_framework=app_framework,
            ),
            500,
        )
        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
        # 响应已在统一指纹层处理，这里仅返回页面
        return resp

    @app.errorhandler(Exception)
    def handle_exception(e):
        if isinstance(e, HTTPException):
            return e
        client_ip = get_client_ip()
        error_traceback = traceback.format_exc()
        logger.error(f"[异常] {type(e).__name__} {client_ip} {request.path}")
        logger.error(f"异常详情:\n{error_traceback}")
        return _render_http_error(500, 'System Error', 'Uncaught exception while handling request')


