# -*- coding: utf-8 -*-
"""scripts/system_test 公共工具函数"""
from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

import requests

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from env_utils import env_float as _env_float, env_int as _env_int, env_str as _env_str  # noqa: E402


def _extract_csrf_token(html: str) -> str:
    if not html:
        return ""
    m = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', html, re.IGNORECASE)
    return (m.group(1).strip() if m else "")


def _api_headers(base_url: str, csrf_token: str = "") -> Dict[str, str]:
    headers: Dict[str, str] = {
        "Referer": f"{base_url}/dashboard",
        "Origin": base_url,
    }
    if csrf_token:
        headers["X-CSRF-Token"] = csrf_token
    return headers


def _dashboard_login(
    base_url: str,
    username: str,
    password: str,
    timeout: float = 10.0,
) -> Tuple[bool, requests.Session]:
    """登录 Dashboard，返回 (是否成功, session)。"""
    session = requests.Session()
    try:
        login_url = f"{base_url}/super/login"
        resp = session.get(login_url, timeout=timeout, allow_redirects=False)
        csrf_token = _extract_csrf_token(resp.text)

        payload = {
            "username": username,
            "password": password,
            "csrf_token": csrf_token,
        }
        headers = _api_headers(base_url, csrf_token)
        resp = session.post(
            login_url,
            data=payload,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
        )
        if resp.status_code in (302, 200):
            dashboard_resp = session.get(
                f"{base_url}/dashboard",
                timeout=timeout,
                allow_redirects=False,
            )
            if dashboard_resp.status_code == 200:
                return True, session
    except Exception:
        pass
    return False, session
