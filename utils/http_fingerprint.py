# -*- coding: utf-8 -*-
"""
HTTP 指纹伪装工具
集中管理伪装响应头与 WSGI 请求处理器
"""
from typing import Dict, Iterable
from werkzeug.serving import WSGIRequestHandler

FAKE_SERVER_HEADERS: Dict[str, str] = {
    'Server': 'nginx/1.24.0',
    'X-Powered-By': 'PHP/7.4.33',
    'X-Frame-Options': 'SAMEORIGIN',
    'X-Content-Type-Options': 'nosniff',
    'X-XSS-Protection': '1; mode=block'
}

FINGERPRINT_STRIP_HEADERS = {
    'Server',
    'X-Powered-By',
    'X-Generator',
    'X-Runtime',
    'X-Request-Id',
    'X-AspNet-Version',
    'X-AspNetMvc-Version',
}


class StealthRequestHandler(WSGIRequestHandler):
    server_version = FAKE_SERVER_HEADERS.get('Server', 'nginx/1.24.0')
    sys_version = ''

    def version_string(self) -> str:
        return self.server_version


def spoof_http_fingerprint(response, strip_headers: Iterable[str] = None) -> None:
    """移除框架指纹并设置伪装头"""
    headers_to_strip = strip_headers or FINGERPRINT_STRIP_HEADERS
    for header_name in headers_to_strip:
        if header_name in response.headers:
            del response.headers[header_name]
    response.headers.update(FAKE_SERVER_HEADERS)

