# -*- coding: utf-8 -*-
"""
Web 蜜罐 - 管理端 API
"""
import time
from flask import request, jsonify


def register(app, ctx):
    get_client_ip = ctx['get_client_ip']
    _safe_log_event = ctx['_safe_log_event']
    _is_admin_authed = ctx['_is_admin_authed']
    _get_authenticated_admin_username = ctx['_get_authenticated_admin_username']
    _get_admin_role_by_username = ctx['_get_admin_role_by_username']
    _make_auth_failed_json = ctx['_make_auth_failed_json']
    _push_admin_access_log = ctx['_push_admin_access_log']
    _rate_limit_endpoint = ctx['_rate_limit_endpoint']
    _admin_access_lock = ctx['_admin_access_lock']
    _admin_access_logs = ctx['_admin_access_logs']
    _admin_data_lock = ctx['_admin_data_lock']
    _admin_content_items = ctx['_admin_content_items']
    _admin_users = ctx['_admin_users']
    _admin_settings = ctx['_admin_settings']
    _DECOY_ROOT_ENABLED = ctx['_DECOY_ROOT_ENABLED']
    _DECOY_ROOT_USERNAME = ctx['_DECOY_ROOT_USERNAME']
    _DECOY_ROOT_ID = ctx['_DECOY_ROOT_ID']
    _build_decoy_root_user = ctx['_build_decoy_root_user']
    _attach_fake_debug = ctx['_attach_fake_debug']
    _is_same_origin_request = ctx['_is_same_origin_request']
    _validate_admin_csrf_request = ctx['_validate_admin_csrf_request']
    _normalize_public_url = ctx['_normalize_public_url']
    _SERVER_STARTED_TS = ctx['_SERVER_STARTED_TS']
    _SERVER_STARTED_AT = ctx['_SERVER_STARTED_AT']
    _FAKE_APP_ENV = ctx['_FAKE_APP_ENV']
    _APP_VERSION = ctx['_APP_VERSION']
    _APP_BUILD = ctx['_APP_BUILD']
    _ADMIN_SID_COOKIE = ctx['_ADMIN_SID_COOKIE']
    logger = ctx['logger']
    _ROLE_PERMISSIONS = {
        '超级管理员': {
            'content_read', 'content_write',
            'users_read', 'users_write',
            'settings_read', 'settings_write',
            'logs_read',
        },
        '管理员': {
            'content_read', 'content_write',
            'users_read', 'users_write',
            'settings_read', 'settings_write',
            'logs_read',
        },
        '编辑': {
            'content_read', 'content_write',
        },
        '运维': {
            'settings_read', 'settings_write',
            'logs_read',
        },
        '审计': {
            'users_read',
            'logs_read',
        },
    }

    def _sanitize_user_row(row):
        """用户列表脱敏：移除不应暴露给前端的敏感字段。"""
        if not isinstance(row, dict):
            return row
        safe = dict(row)
        editor_username = str(safe.get('_pending_username', safe.get('username', '')) or '')
        editor_email = str(safe.get('_pending_email', safe.get('email', '')) or '')
        editor_role = str(safe.get('_pending_role', safe.get('role', '编辑')) or '编辑')
        editor_status = str(safe.get('_pending_status', safe.get('status', '启用')) or '启用')
        has_pending_review = False
        for key in list(safe.keys()):
            if str(key).startswith('_pending_'):
                has_pending_review = True
                safe.pop(key, None)
        for key in (
            'password', 'passwd', 'pwd', 'secret',
            'token', 'access_token', 'refresh_token', 'api_key'
        ):
            safe.pop(key, None)
        safe['editor_username'] = editor_username
        safe['editor_email'] = editor_email
        safe['editor_role'] = editor_role
        safe['editor_status'] = editor_status
        if has_pending_review:
            safe['review_state'] = '待复核'
        return safe

    def _sanitize_content_row(row):
        """内容列表脱敏：隐藏仅用于后台暂存审核的内部字段。"""
        if not isinstance(row, dict):
            return row
        safe = dict(row)
        editor_title = str(safe.get('_pending_title', safe.get('title', '')) or '')
        editor_summary = str(safe.get('_pending_summary', safe.get('summary', '')) or '')
        editor_content = str(safe.get('_pending_content', safe.get('content', '')) or '')
        editor_status = str(safe.get('_pending_status', safe.get('status', '')) or '')
        has_pending_review = False
        for key in list(safe.keys()):
            if str(key).startswith('_pending_'):
                has_pending_review = True
                safe.pop(key, None)
        safe['editor_title'] = editor_title
        safe['editor_summary'] = editor_summary
        safe['editor_content'] = editor_content
        safe['editor_status'] = editor_status
        if has_pending_review:
            safe['review_state'] = '待复核'
        return safe

    def _reject_root_session(client_ip: str, action: str):
        username = (_get_authenticated_admin_username() or '').strip().lower()
        if username != 'root':
            return None
        _safe_log_event(client_ip, f"检测到 root 会话越权尝试 - {action}")
        logger.warning(f"[越权] root 会话 {action} 尝试 {client_ip}")
        return _make_auth_failed_json()

    def _get_actor_context():
        username = (_get_authenticated_admin_username() or 'admin')[:32]
        role = _get_admin_role_by_username(username)
        return username, str(role or '管理员')

    def _role_allows(role: str, permission: str) -> bool:
        return permission in _ROLE_PERMISSIONS.get(str(role or '').strip(), set())

    def _forbidden_api_response(client_ip: str, username: str, action: str, message: str = 'Forbidden'):
        _push_admin_access_log(client_ip, (username or 'admin')[:32], f"拒绝操作:{action}", '失败')
        payload = _attach_fake_debug({'code': 403, 'msg': message}, 'E_FORBIDDEN', message)
        return jsonify(payload), 403

    @app.route('/admin/api/me')
    def admin_api_me():
        if not _is_admin_authed():
            return jsonify({'code': 403, 'msg': 'Forbidden'}), 403
        root_reject = _reject_root_session(get_client_ip(), '读取个人信息')
        if root_reject is not None:
            return root_reject
        username, role = _get_actor_context()
        display_username = username
        display_role = role
        return jsonify({
            'code': 0,
            'msg': 'success',
            'data': {
                'username': username,
                'role': role,
                'display_username': display_username,
                'display_role': display_role,
            }
        })

    @app.route('/admin/api/access_logs')
    def admin_api_access_logs():
        if not _is_admin_authed():
            return jsonify({'code': 403, 'msg': 'Forbidden'}), 403

        client_ip = get_client_ip()
        root_reject = _reject_root_session(client_ip, '查看访问日志')
        if root_reject is not None:
            return root_reject

        username, role = _get_actor_context()
        if not _role_allows(role, 'logs_read'):
            return _forbidden_api_response(client_ip, username, 'logs/read', 'Access Denied: Insufficient privileges')

        if not _rate_limit_endpoint(f"access_logs:{client_ip}", limit=6, window_seconds=10.0):
            return jsonify({'code': 429, 'msg': 'Too Many Requests'}), 429

        page_str = (request.args.get('page') or '').strip()
        size_str = (request.args.get('page_size') or '').strip()
        keyword = (request.args.get('q') or '').strip()
        if len(keyword) > 80:
            keyword = keyword[:80]

        try:
            page = int(page_str) if page_str else 1
        except Exception:
            page = 1
        if page < 1:
            page = 1
        if page > 2000:
            page = 2000

        try:
            page_size = int(size_str) if size_str else 20
        except Exception:
            page_size = 20
        if page_size < 5:
            page_size = 5
        if page_size > 50:
            page_size = 50

        kw = keyword.lower()
        with _admin_access_lock:
            rows = list(_admin_access_logs)

        if kw:
            rows = [
                r for r in rows
                if kw in str(r.get('time', '')).lower()
                or kw in str(r.get('user', '')).lower()
                or kw in str(r.get('ip', '')).lower()
                or kw in str(r.get('action', '')).lower()
                or kw in str(r.get('result', '')).lower()
            ]

        total = len(rows)
        total_pages = max(1, (total + page_size - 1) // page_size)
        if page > total_pages:
            page = total_pages
        start = (page - 1) * page_size
        end = start + page_size
        items = rows[start:end]

        resp = jsonify({
            'code': 0,
            'data': {
                'items': items,
                'total': int(total),
                'page': int(page),
                'page_size': int(page_size),
                'total_pages': int(total_pages),
                'keyword': keyword,
            }
        })
        resp.headers['Cache-Control'] = 'no-store'
        return resp

    @app.route('/admin/api/settings')
    def admin_api_settings_get():
        if not _is_admin_authed():
            return jsonify({'code': 403, 'msg': 'Forbidden'}), 403

        client_ip = get_client_ip()
        root_reject = _reject_root_session(client_ip, '系统设置')
        if root_reject is not None:
            return root_reject

        username, role = _get_actor_context()
        with _admin_data_lock:
            data = {
                'site_name': str(_admin_settings.get('site_name') or '')[:80],
                'updated_at': str(_admin_settings.get('updated_at') or '')[:32],
            }

        if _role_allows(role, 'settings_read'):
            now_ts = time.time()
            uptime_seconds = int(max(0, now_ts - float(_SERVER_STARTED_TS)))
            data.update({
                'admin_email': str(_admin_settings.get('admin_email') or '')[:80],
                'env': _FAKE_APP_ENV,
                'version': _APP_VERSION,
                'build': _APP_BUILD,
                'started_at': _SERVER_STARTED_AT,
                'server_time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now_ts)),
                'timezone': str((time.tzname[0] if getattr(time, 'tzname', None) else 'local') or 'local')[:32],
                'uptime_seconds': int(uptime_seconds),
            })

        resp = jsonify({'code': 0, 'data': data})
        resp.headers['Cache-Control'] = 'no-store'
        return resp

    @app.route('/admin/api/content')
    def admin_api_content_list():
        if not _is_admin_authed():
            return jsonify({'code': 403, 'msg': 'Forbidden'}), 403

        client_ip = get_client_ip()
        root_reject = _reject_root_session(client_ip, '内容管理')
        if root_reject is not None:
            return root_reject

        username, role = _get_actor_context()
        if not _role_allows(role, 'content_read'):
            return _forbidden_api_response(client_ip, username, 'content/read', 'Access Denied: Insufficient privileges')

        page_str = (request.args.get('page') or '').strip()
        size_str = (request.args.get('page_size') or '').strip()
        keyword = (request.args.get('q') or '').strip()
        if len(keyword) > 80:
            keyword = keyword[:80]

        try:
            page = int(page_str) if page_str else 1
        except Exception:
            page = 1
        if page < 1:
            page = 1
        if page > 2000:
            page = 2000

        try:
            page_size = int(size_str) if size_str else 20
        except Exception:
            page_size = 20
        if page_size < 5:
            page_size = 5
        if page_size > 50:
            page_size = 50

        kw = keyword.lower()
        with _admin_data_lock:
            rows = list(_admin_content_items)

        if kw:
            rows = [
                r for r in rows
                if kw in str(r.get('title', '')).lower()
                or kw in str(r.get('author', '')).lower()
                or kw in str(r.get('status', '')).lower()
                or kw in str(r.get('publish_time', '')).lower()
                or kw in str(r.get('id', '')).lower()
            ]

        rows = [_sanitize_content_row(r) for r in rows]

        total = len(rows)
        total_pages = max(1, (total + page_size - 1) // page_size)
        if page > total_pages:
            page = total_pages
        start = (page - 1) * page_size
        end = start + page_size
        items = rows[start:end]

        resp = jsonify({
            'code': 0,
            'data': {
                'items': items,
                'total': int(total),
                'page': int(page),
                'page_size': int(page_size),
                'total_pages': int(total_pages),
                'keyword': keyword,
            }
        })
        resp.headers['Cache-Control'] = 'no-store'
        return resp

    @app.route('/admin/api/users')
    def admin_api_users_list():
        if not _is_admin_authed():
            return jsonify({'code': 403, 'msg': 'Forbidden'}), 403

        client_ip = get_client_ip()
        root_reject = _reject_root_session(client_ip, '用户管理')
        if root_reject is not None:
            return root_reject

        username, role = _get_actor_context()
        if not _role_allows(role, 'users_read'):
            return _forbidden_api_response(client_ip, username, 'users/read', 'Access Denied: Insufficient privileges')

        page_str = (request.args.get('page') or '').strip()
        size_str = (request.args.get('page_size') or '').strip()
        keyword = (request.args.get('q') or '').strip()
        if len(keyword) > 80:
            keyword = keyword[:80]

        try:
            page = int(page_str) if page_str else 1
        except Exception:
            page = 1
        if page < 1:
            page = 1
        if page > 2000:
            page = 2000

        try:
            page_size = int(size_str) if size_str else 20
        except Exception:
            page_size = 20
        if page_size < 5:
            page_size = 5
        if page_size > 50:
            page_size = 50

        kw = keyword.lower()
        with _admin_data_lock:
            rows = list(_admin_users)

        if _DECOY_ROOT_ENABLED:
            decoy = _build_decoy_root_user()
            has_decoy = any(str(r.get('username', '') or '').lower() == _DECOY_ROOT_USERNAME.lower() for r in rows)
            if not has_decoy:
                rows.insert(0, decoy)

        if kw:
            rows = [
                r for r in rows
                if kw in str(r.get('username', '')).lower()
                or kw in str(r.get('email', '')).lower()
                or kw in str(r.get('role', '')).lower()
                or kw in str(r.get('status', '')).lower()
                or kw in str(r.get('last_login', '')).lower()
                or kw in str(r.get('id', '')).lower()
            ]

        rows = [_sanitize_user_row(r) for r in rows]

        total = len(rows)
        total_pages = max(1, (total + page_size - 1) // page_size)
        if page > total_pages:
            page = total_pages
        start = (page - 1) * page_size
        end = start + page_size
        items = rows[start:end]

        resp = jsonify({
            'code': 0,
            'data': {
                'items': items,
                'total': int(total),
                'page': int(page),
                'page_size': int(page_size),
                'total_pages': int(total_pages),
                'keyword': keyword,
            }
        })
        resp.headers['Cache-Control'] = 'no-store'
        return resp

    @app.route('/admin/api/submit_change', methods=['POST'])
    def admin_api_submit_change():
        """
        后台变更提交接口（蜜罐中交互）。
        流程：鉴权/限流 -> 反改包审计 -> 同源校验 -> 业务落库(内存态) -> 审核态返回。
        """
        client_ip = get_client_ip()
        if not _is_admin_authed():
            return jsonify({'code': 403, 'msg': 'Forbidden'}), 403

        # 先做请求节流，避免接口被高频打爆
        if not _rate_limit_endpoint(f"submit_change:{client_ip}", limit=5, window_seconds=10.0):
            return jsonify({'code': 429, 'msg': 'Too Many Requests'}), 429

        root_reject = _reject_root_session(client_ip, '提交变更')
        if root_reject is not None:
            return root_reject

        if not _validate_admin_csrf_request():
            username = (_get_authenticated_admin_username() or 'admin')[:32]
            _push_admin_access_log(client_ip, username, "拒绝操作:csrf_block", '失败')
            # 返回框架风格错误，保持站点指纹一致
            payload = _attach_fake_debug({'code': 403, 'msg': 'Token Mismatch'}, 'E_CSRF', 'Invalid CSRF token')
            return jsonify(payload), 403

        # 业务字段标准化，避免前端随意输入破坏后台态
        payload = request.get_json(silent=True) or {}
        module = str(payload.get('module', '') or '').strip().lower()[:32]
        action = str(payload.get('action', '') or '').strip().lower()[:32]
        item_id = str(payload.get('id', '') or '').strip()[:64]
        data = payload.get('data') if isinstance(payload.get('data'), dict) else {}

        username, role = _get_actor_context()

        module_permission_map = {
            'content': 'content_write',
            'users': 'users_write',
            'settings': 'settings_write',
        }
        required_permission = module_permission_map.get(module)
        if not required_permission or not _role_allows(role, required_permission):
            return _forbidden_api_response(client_ip, username, f"{module or 'unknown'}/{action or 'unknown'}", 'Access Denied: Insufficient privileges')

        if module == 'users':
            is_root_target = False
            if _DECOY_ROOT_ENABLED and item_id == _DECOY_ROOT_ID:
                is_root_target = True
            if str(data.get('username', '') or '').strip().lower() == _DECOY_ROOT_USERNAME.lower():
                is_root_target = True
            if is_root_target:
                _push_admin_access_log(client_ip, username, f"身份校验失败:{module}/{action}", '失败')
                # 伪装为鉴权失败，避免暴露 root 账号策略
                return _make_auth_failed_json()

        # 权限一致性：用户中心不提供删除能力（即便抓包也不能删）
        if module == 'users' and action == 'delete':
            _push_admin_access_log(client_ip, username, f"拒绝操作:{module}/{action}", '失败')
            return jsonify({'code': 403, 'msg': 'Forbidden'}), 403

        # 高危动作统一进入“待审核”，不直接执行破坏性操作
        if action == 'delete':
            _push_admin_access_log(client_ip, username, f"提交审核:{module}/{action}", '待审核')
            return jsonify({'code': 0, 'data': {'status': 'pending_review'}})

        ok = False
        pending_review = False
        result_id = ''
        msg = 'OK'
        try:
            with _admin_data_lock:
                if module == 'content' and action == 'create':
                    title = str(data.get('title', '') or '').strip()[:120]
                    summary = str(data.get('summary', '') or '').strip()[:240]
                    content = str(data.get('content', '') or '').strip()[:8000]
                    status_req = str(data.get('status', '') or '').strip()[:32]
                    if not title:
                        msg = '标题无效'
                    else:
                        if status_req == '下线':
                            status_req = '待下线'
                        next_id = 1
                        for r in _admin_content_items:
                            try:
                                rid = int(r.get('id'))
                                next_id = max(next_id, rid + 1)
                            except Exception:
                                continue

                        # 发布路径由系统统一分配，避免手填路径泄露规则
                        public_url = _normalize_public_url(f"/news?id={next_id}")

                        now_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
                        status_final = status_req if status_req in ('草稿', '待下线', '已发布') else '草稿'
                        if status_final == '已发布':
                            status_final = '待发布'
                            pending_review = True
                        elif status_final == '待下线':
                            pending_review = True
                        item = {
                            'id': next_id,
                            'title': title,
                            'author': username,
                            'status': status_final,
                            'publish_time': now_str,
                            'public_url': public_url,
                            'summary': summary,
                            'content': content,
                        }
                        _admin_content_items.insert(0, item)
                        ok = True
                        result_id = str(next_id)

                elif module == 'content' and action == 'edit':
                    title = str(data.get('title', '') or '').strip()[:120]
                    summary = str(data.get('summary', '') or '').strip()[:240]
                    content = str(data.get('content', '') or '').strip()[:8000]
                    status_req = str(data.get('status', '') or '').strip()[:32]
                    for r in _admin_content_items:
                        if str(r.get('id')) == item_id:
                            now_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
                            current_status = str(r.get('status', '') or '').strip()
                            current_title = str(r.get('title', '') or '')
                            current_summary = str(r.get('summary', '') or '')
                            current_content = str(r.get('content', '') or '')
                            next_title = title if title else current_title
                            next_summary = summary if summary else current_summary
                            next_content = content if content else current_content
                            next_status = current_status

                            if status_req == '下线':
                                status_req = '待下线'
                            if status_req:
                                if status_req == '已发布' and current_status != '已发布':
                                    next_status = '待发布'
                                elif status_req in ('待下线',) and current_status == '已发布':
                                    next_status = '待下线'
                                elif status_req in ('草稿', '已发布', '待发布', '待下线'):
                                    next_status = status_req

                            requires_review = (
                                str(role or '') != '超级管理员'
                                and current_status != '草稿'
                                and (
                                    next_title != current_title
                                    or next_summary != current_summary
                                    or next_content != current_content
                                    or next_status != current_status
                                )
                            )

                            if requires_review:
                                r['_pending_title'] = next_title
                                r['_pending_summary'] = next_summary
                                r['_pending_content'] = next_content
                                r['_pending_status'] = next_status
                                r['_pending_requested_by'] = username
                                r['_pending_requested_at'] = now_str
                                pending_review = True
                            else:
                                r['title'] = next_title
                                r['summary'] = next_summary
                                r['content'] = next_content
                                r['status'] = next_status
                                for key in (
                                    '_pending_title',
                                    '_pending_summary',
                                    '_pending_content',
                                    '_pending_status',
                                    '_pending_requested_by',
                                    '_pending_requested_at',
                                ):
                                    r.pop(key, None)

                                if str(role or '') != '超级管理员' and next_status in ('待发布', '待下线'):
                                    pending_review = True

                            ok = True
                            result_id = str(item_id)
                            break
                elif module == 'users' and action == 'edit':
                    username_new = str(data.get('username', '') or '').strip()[:32]
                    email_new = str(data.get('email', '') or '').strip()[:64]
                    role_new = str(data.get('role', '') or '').strip()[:16]
                    status_new = str(data.get('status', '') or '').strip()[:16]
                    target = None
                    for r in _admin_users:
                        if str(r.get('id')) == item_id:
                            target = r
                            break

                    if not target:
                        msg = '用户不存在'
                        ok = False
                    else:
                        target_username = str(target.get('username', '') or '').lower()
                        target_role = str(target.get('role', '') or '')
                        is_core = target_username in ('root', 'admin') or target_role in ('超级管理员', '管理员')

                        actor_role = str(role or '')
                        actor_username = str(username or '').lower()
                        now_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
                        next_username = username_new if username_new else str(target.get('username', '') or '')
                        next_email = email_new if email_new else str(target.get('email', '') or '')
                        next_role = (
                            role_new
                            if role_new in ('超级管理员', '管理员', '编辑', '运维', '审计')
                            else str(target.get('role', '') or '编辑')
                        )
                        next_status = (
                            status_new
                            if status_new in ('启用', '禁用')
                            else str(target.get('status', '') or '启用')
                        )

                        conflict = False
                        if username_new:
                            username_new_lower = username_new.lower()
                            for existing_user in _admin_users:
                                if str(existing_user.get('id')) != item_id:
                                    existing_name = str(existing_user.get('username', '') or '').lower()
                                    if existing_name == username_new_lower:
                                        msg = '用户名已存在'
                                        conflict = True
                                        break

                        if conflict:
                            ok = False
                        elif actor_role == '超级管理员':
                            target['_pending_username'] = next_username
                            target['_pending_email'] = next_email
                            target['_pending_role'] = next_role
                            target['_pending_status'] = next_status
                            target['_pending_requested_by'] = username
                            target['_pending_requested_at'] = now_str
                            pending_review = True
                            ok = True
                            result_id = str(item_id)
                        elif actor_role == '管理员':
                            if target_username == actor_username:
                                target['_pending_username'] = next_username
                                target['_pending_email'] = next_email
                                target['_pending_role'] = str(target.get('role', '') or next_role)
                                target['_pending_status'] = next_status
                                target['_pending_requested_by'] = username
                                target['_pending_requested_at'] = now_str
                                pending_review = True
                                ok = True
                                result_id = str(item_id)
                            elif is_core:
                                msg = 'Access Denied: Insufficient privileges'
                                ok = False
                            else:
                                target['username'] = next_username
                                target['email'] = next_email
                                target['status'] = next_status
                                for key in (
                                    '_pending_username',
                                    '_pending_email',
                                    '_pending_role',
                                    '_pending_status',
                                    '_pending_requested_by',
                                    '_pending_requested_at',
                                ):
                                    target.pop(key, None)
                                ok = True
                                result_id = str(item_id)
                        else:
                            msg = '不支持的操作'
                            ok = False
                elif module == 'settings' and action == 'edit':
                    site_name = str(data.get('site_name', '') or '').strip()[:80]
                    admin_email = str(data.get('admin_email', '') or '').strip()[:80]
                    if site_name:
                        _admin_settings['site_name'] = site_name
                    if admin_email:
                        _admin_settings['admin_email'] = admin_email
                    _admin_settings['updated_at'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
                    ok = True
                    result_id = 'settings'
                else:
                    msg = '不支持的操作'
        except Exception:
            ok = False
            msg = '内部错误'

        if ok and pending_review:
            _push_admin_access_log(client_ip, username, f"提交审核:{module}/{action}", '待审核')
            return jsonify({'code': 0, 'data': {'status': 'pending_review', 'id': result_id}})

        if ok:
            _push_admin_access_log(client_ip, username, f"执行变更:{module}/{action}", '成功')
            return jsonify({'code': 0, 'data': {'status': 'applied', 'id': result_id}})

        _push_admin_access_log(client_ip, username, f"执行变更:{module}/{action}", '失败')
        payload = _attach_fake_debug({'code': 400, 'msg': msg}, 'E_BAD_REQUEST', msg)
        return jsonify(payload), 400

    @app.route('/admin/audit/log')
    def fake_admin_audit_log():
        client_ip = get_client_ip()
        module_raw = (request.args.get('module') or request.args.get('action') or '').strip()
        if len(module_raw) > 120:
            _safe_log_event(client_ip, f"异常参数长度: /admin/audit/log module={module_raw[:120]}")
            module_raw = module_raw[:120]
        module = ctx['_map_admin_action_label'](module_raw)
        _safe_log_event(client_ip, f"访问后台模块: {module}")

        if _is_admin_authed():
            username = (_get_authenticated_admin_username() or 'admin')[:32]
            action = f"访问模块:{module}" if module else '访问模块'
            _push_admin_access_log(client_ip, username, action, '成功')
        return ('', 204)

