# -*- coding: utf-8 -*-
"""
Web 蜜罐 - 管理端页面路由
"""
import os
import time
import secrets
import hashlib
from flask import request, render_template, make_response, jsonify, redirect, session
from utils.alerting import alert_web_upload


def register(app, ctx):
    get_client_ip = ctx['get_client_ip']
    _safe_log_event = ctx['_safe_log_event']
    _honeypot_delay = ctx['_honeypot_delay']
    _create_admin_session = ctx['_create_admin_session']
    _clear_admin_session = ctx['_clear_admin_session']
    _is_admin_authed = ctx['_is_admin_authed']
    _get_authenticated_admin_username = ctx['_get_authenticated_admin_username']
    _get_admin_role_by_username = ctx['_get_admin_role_by_username']
    _make_auth_failed_page = ctx['_make_auth_failed_page']
    _make_forbidden_response = ctx['_make_forbidden_response']
    _render_http_error = ctx['_render_http_error']
    _is_same_origin_request = ctx['_is_same_origin_request']
    _get_admin_csrf_token = ctx['_get_admin_csrf_token']
    _get_admin_login_csrf_token = ctx['_get_admin_login_csrf_token']
    _validate_admin_csrf_request = ctx['_validate_admin_csrf_request']
    _validate_admin_login_csrf_request = ctx['_validate_admin_login_csrf_request']
    _rate_limit_endpoint = ctx['_rate_limit_endpoint']
    _attach_fake_debug = ctx['_attach_fake_debug']
    _push_admin_access_log = ctx['_push_admin_access_log']
    _admin_data_lock = ctx['_admin_data_lock']
    _admin_users = ctx['_admin_users']
    _admin_login_bind_lock = ctx['_admin_login_bind_lock']
    _admin_ip_login_bind = ctx['_admin_ip_login_bind']
    _ADMIN_IP_BIND_TTL_SECONDS = ctx['_ADMIN_IP_BIND_TTL_SECONDS']
    _admin_content_items = ctx['_admin_content_items']
    logger = ctx['logger']
    _admin_settings = ctx.get('_admin_settings')
    _ADMIN_SID_COOKIE = ctx['_ADMIN_SID_COOKIE']
    _ADMIN_LOGIN_BIND_GC_INTERVAL_SECONDS = 30.0
    _ADMIN_LOGIN_BIND_GC_SIZE_THRESHOLD = 128
    _admin_login_bind_last_gc = 0.0

    def _stable_metric(key: str, min_v: int, max_v: int) -> int:
        if max_v <= min_v:
            return min_v
        seed = f"{time.strftime('%Y-%m-%d')}|{key}"
        h = hashlib.md5(seed.encode('utf-8', errors='ignore')).hexdigest()
        n = int(h[:8], 16)
        return min_v + (n % (max_v - min_v + 1))

    def _reject_root_session(client_ip: str, action: str):
        username = (_get_authenticated_admin_username() or '').strip().lower()
        if username != 'root':
            return None
        _safe_log_event(client_ip, f"检测到 root 会话越权尝试 - {action}")
        logger.warning(f"[越权] root 会话 {action} 尝试 {client_ip}")
        return _make_auth_failed_page()

    def _get_current_admin_role() -> str:
        username = (_get_authenticated_admin_username() or 'admin')[:32]
        return str(_get_admin_role_by_username(username) or '管理员')

    def _cleanup_admin_login_bind_locked(now_ts: float, force: bool = False) -> None:
        nonlocal _admin_login_bind_last_gc
        if not _admin_ip_login_bind:
            _admin_login_bind_last_gc = now_ts
            return
        if (not force) and len(_admin_ip_login_bind) < _ADMIN_LOGIN_BIND_GC_SIZE_THRESHOLD and (
            (now_ts - _admin_login_bind_last_gc) < _ADMIN_LOGIN_BIND_GC_INTERVAL_SECONDS
        ):
            return

        expired_keys = []
        for bind_key, bind_value in list(_admin_ip_login_bind.items()):
            try:
                expires_at = float((bind_value or ('', 0.0))[1] or 0.0)
            except Exception:
                expires_at = 0.0
            if expires_at <= now_ts:
                expired_keys.append(bind_key)
        for expired_key in expired_keys:
            _admin_ip_login_bind.pop(expired_key, None)
        _admin_login_bind_last_gc = now_ts

    def _validate_admin_backup_request() -> bool:
        session_token = str(_get_admin_csrf_token() or '').strip()
        request_token = str(
            request.form.get('csrf_token')
            or request.headers.get('X-CSRF-Token')
            or ''
        ).strip()
        if not session_token or not request_token or not secrets.compare_digest(session_token, request_token):
            return False
        if any(request.headers.get(name) for name in ('Origin', 'Referer', 'Sec-Fetch-Site')):
            return _is_same_origin_request()
        return True

    def _wants_json_response() -> bool:
        requested_with = str(request.headers.get('X-Requested-With') or '').strip().lower()
        accept = str(request.headers.get('Accept') or '').strip().lower()
        return (
            requested_with == 'xmlhttprequest'
            or 'application/json' in accept
            or request.is_json
        )

    def _render_upload_page(alert_type: str = '', alert_msg: str = '', status_code: int = 200):
        resp = make_response(
            render_template(
                'admin_upload.html',
                admin_csrf_token=_get_admin_csrf_token(),
                alert_type=str(alert_type or '').strip(),
                alert_msg=str(alert_msg or '').strip(),
            ),
            status_code,
        )
        resp.headers['Cache-Control'] = 'no-store'
        return resp

    @app.route('/admin', methods=['GET', 'POST'])
    def admin_login():
        client_ip = get_client_ip()
        error_msg = None

        # 登录页仅重点记录 POST 提交内容

        if request.method == 'POST':
            is_ajax = (
                request.headers.get('X-Requested-With') == 'XMLHttpRequest'
                or request.is_json
                or 'application/json' in (request.headers.get('Accept') or '')
            )

            if not _rate_limit_endpoint(f"admin_login:{client_ip}", limit=8, window_seconds=60.0):
                _safe_log_event(client_ip, "后台登录频率过高，已触发限流")
                error_msg = "操作过于频繁，请稍后再试"
                if is_ajax:
                    return jsonify({'success': False, 'msg': error_msg}), 429
                return render_template(
                    'login.html',
                    error=error_msg,
                    login_action=request.path or '/admin',
                    login_csrf_token=_get_admin_login_csrf_token(),
                ), 429

            if not _validate_admin_login_csrf_request():
                _safe_log_event(client_ip, "后台登录请求 CSRF 校验失败")
                error_msg = "CSRF 验证失败，请刷新页面重试"
                if is_ajax:
                    return jsonify({'success': False, 'msg': error_msg}), 403
                return render_template(
                    'login.html',
                    error=error_msg,
                    login_action=request.path or '/admin',
                    login_csrf_token=_get_admin_login_csrf_token(refresh=True),
                ), 403

            _honeypot_delay(0.35, 0.9)

            data = request.get_json(silent=True) if request.is_json else None
            username = (data or {}).get('username', request.form.get('username', ''))
            password = (data or {}).get('password', request.form.get('password', ''))
            client_ip = get_client_ip()

            payload = f"登录尝试: 用户名={username}, 密码={password}"
            _safe_log_event(client_ip, payload)

            # 在内存用户表中查找目标账号
            target_user = None
            uname_lower = (username or '').strip().lower()

            with _admin_data_lock:
                for u in _admin_users:
                    if str(u.get('username', '')).lower() == uname_lower:
                        target_user = u
                        break

            # 统一鉴权流程
            login_success = False
            fail_reason = "用户名或密码错误"
            username_clean = uname_lower

            if uname_lower == 'root':
                # root 账号为诱饵账号，始终拒绝登录
                login_success = False
                fail_reason = "用户名或密码错误"  # 保持模糊提示
                logger.warning(f"[诱饵] 攻击者尝试登录 Root 账号 {client_ip} (已拦截)")
            elif not target_user:
                login_success = False
                fail_reason = "用户名或密码错误"
            elif str(target_user.get('status', '')) != '启用':
                # 禁用账号直接拒绝，保持与后台状态一致
                login_success = False
                fail_reason = "账户已被禁用，请联系管理员"
                logger.warning(f"[禁用] 已禁用账户尝试登录 {client_ip}: {username}")
            else:
                # 密码只与该用户分配的唯一口令比对

                now_ts = time.time()
                bind_key = f"{(client_ip or '')[:64]}|{uname_lower[:32] or '-'}"

                # 清理过期 IP 绑定，保持会话口令连贯
                with _admin_login_bind_lock:
                    _cleanup_admin_login_bind_locked(now_ts)

                    correct_password = str(target_user.get('password', '') or '')
                    input_password = str(password or '')

                    bound = _admin_ip_login_bind.get(bind_key)

                    if bound and float(bound[1]) > now_ts and str(bound[0]) == input_password:
                        # 已绑定口令在有效期内，允许登录
                        login_success = True
                    elif input_password == correct_password:
                        # 密码正确后写入短期绑定，维持攻击者体验一致
                        _admin_ip_login_bind[bind_key] = (input_password, now_ts + float(_ADMIN_IP_BIND_TTL_SECONDS))
                        login_success = True
                    else:
                        login_success = False

            password_log = str(password or '')

            if login_success:
                logger.critical(f"[入侵] 登录成功 {client_ip}: {username}/{password_log}")

                # 更新最后登录时间，增强后台行为一致性
                with _admin_data_lock:
                    if target_user:
                        target_user['last_login'] = time.strftime('%Y-%m-%d %H:%M', time.localtime())
                        username_clean = str(target_user.get('username', ''))[:32]

                if is_ajax:
                    resp = make_response(jsonify({'success': True, 'msg': '验证通过，正在跳转...', 'redirect': '/admin/dashboard'}))
                else:
                    resp = make_response(redirect('/admin/dashboard'))

                sid = _create_admin_session(username_clean, client_ip)
                resp.set_cookie(_ADMIN_SID_COOKIE, sid, path='/', samesite='Lax', httponly=True)
                if _ADMIN_SID_COOKIE != 'admin_sid':
                    resp.delete_cookie('admin_sid', path='/')
                # 清理旧版前端态 cookie，避免伪造字段干扰鉴权
                resp.delete_cookie('is_admin', path='/')
                resp.delete_cookie('admin_user', path='/')
                resp.delete_cookie('admin_role', path='/')
                resp.delete_cookie('login_time', path='/')

                _push_admin_access_log(client_ip, username_clean, '登录系统', '成功')
                return resp

            logger.warning(f"[失败] 登录尝试 {client_ip}: {username}/{password_log}")
            error_msg = fail_reason
            if is_ajax:
                return jsonify({'success': False, 'msg': error_msg})

        return render_template(
            'login.html',
            error=error_msg,
            login_action=request.path or '/admin',
            login_csrf_token=_get_admin_login_csrf_token(),
        )

    @app.route('/admin/dashboard')
    def fake_admin_dashboard():
        if not _is_admin_authed():
            return redirect('/admin')

        client_ip = get_client_ip()

        root_reject = _reject_root_session(client_ip, '访问后台')
        if root_reject is not None:
            return root_reject

        _safe_log_event(client_ip, "成功进入后台管理界面")
        logger.warning(f"[后台] 访问管理面板 {client_ip}")

        site_name = ''
        try:
            if _admin_settings:
                site_name = str(_admin_settings.get('site_name') or '')[:40]
        except Exception:
            site_name = ''

        stats = {
            'today_visits': f"{_stable_metric('today_visits', 8200, 15400):,}",
            'pending_tickets': str(_stable_metric('pending_tickets', 3, 18)),
            'system_load': str(_stable_metric('system_load', 8, 42)),
            'db_size': f"{3.6 + (_stable_metric('db_size', 0, 80) / 10.0):.1f}",
        }

        return render_template(
            'admin_dashboard.html',
            site_name=site_name,
            stats=stats,
            admin_csrf_token=_get_admin_csrf_token(),
        )

    @app.route('/admin/logout', methods=['GET', 'POST'])
    def fake_admin_logout():
        client_ip = get_client_ip()
        username = (_get_authenticated_admin_username() or 'admin')[:32]

        if request.method == 'POST' and _is_admin_authed():
            if not _validate_admin_csrf_request():
                _safe_log_event(client_ip, "后台退出请求 CSRF 校验失败")
                if _wants_json_response():
                    return jsonify({'success': False, 'msg': 'CSRF 验证失败，请刷新页面重试'}), 403
                return redirect('/admin/dashboard')

        cleared_username, had_session = _clear_admin_session()
        username = (cleared_username or username or 'admin')[:32]
        session.pop('admin_login_csrf_token', None)

        resp = make_response(redirect('/admin'))
        resp.delete_cookie(_ADMIN_SID_COOKIE, path='/')
        if _ADMIN_SID_COOKIE != 'admin_sid':
            resp.delete_cookie('admin_sid', path='/')
        resp.delete_cookie('is_admin', path='/')
        resp.delete_cookie('admin_user', path='/')
        resp.delete_cookie('admin_role', path='/')
        resp.delete_cookie('login_time', path='/')
        resp.headers['Cache-Control'] = 'no-store'

        if had_session:
            _safe_log_event(client_ip, f"后台账号退出登录: {username}")
            _push_admin_access_log(client_ip, username, '退出系统', '成功')
        else:
            _safe_log_event(client_ip, "访问后台退出入口")

        return resp

    @app.route('/admin/preview')
    def admin_preview_content():
        client_ip = get_client_ip()
        if not _is_admin_authed():
            _safe_log_event(client_ip, "未授权访问内容预览")
            return _make_forbidden_response()

        root_reject = _reject_root_session(client_ip, '内容预览')
        if root_reject is not None:
            return root_reject

        actor_role = _get_current_admin_role()
        if actor_role not in ('超级管理员', '管理员', '编辑'):
            username = (_get_authenticated_admin_username() or 'admin')[:32]
            _push_admin_access_log(client_ip, username, "拒绝操作:content/preview", '失败')
            return _render_http_error(403, 'Forbidden', 'Access denied.')

        cid = (request.args.get('id') or '').strip()[:64]
        if not cid:
            return _render_http_error(400, 'Bad Request', 'Invalid request.')

        with _admin_data_lock:
            row = None
            for r in _admin_content_items:
                if str(r.get('id')) == cid:
                    row = dict(r)
                    break

        if not row:
            return _render_http_error(404, 'Not Found', 'Resource not found')

        username = (_get_authenticated_admin_username() or 'admin')[:32]
        _push_admin_access_log(client_ip, username, f"内容预览:{cid}", '成功')

        news = {
            'title': row.get('title') or '内容预览',
            'summary': row.get('summary') or '该内容为后台预览视图，仅用于内部校对与审核。',
            'content': row.get('content') or '（正文为空）',
            'publish_time': row.get('publish_time') or time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            'views': '—',
            'author': row.get('author') or username,
            'category': 'internal',
            'category_name': '内部预览',
            'tags': ['预览'],
            'image': '/static/img/news-thumb-new.svg',
        }
        resp = make_response(render_template('news.html', news=news, news_id=str(cid)))
        resp.headers['Cache-Control'] = 'no-store'
        return resp

    @app.route('/admin/backup', methods=['POST'])
    def fake_backup_download():
        """
        蜜罐备份导出陷阱接口。
        - 记录导出行为并产生日志
        - 返回高仿真的 SQL 备份文件（全量/增量）
        """
        client_ip = get_client_ip()
        if not _is_admin_authed():
            _safe_log_event(client_ip, "未授权访问后台管理界面")
            return redirect('/admin')

        root_reject = _reject_root_session(client_ip, '备份导出')
        if root_reject is not None:
            return root_reject

        username = (_get_authenticated_admin_username() or 'admin')[:32]
        actor_role = _get_current_admin_role()
        if actor_role not in ('超级管理员', '管理员', '运维'):
            _push_admin_access_log(client_ip, username, '拒绝操作:backup/download', '失败')
            return _render_http_error(403, 'Forbidden', 'Access denied.')

        if not _validate_admin_backup_request():
            _push_admin_access_log(client_ip, username, '拒绝操作:backup/csrf_block', '失败')
            return _render_http_error(403, 'Forbidden', 'Access denied.')

        if not _rate_limit_endpoint(f"backup:{client_ip}", limit=3, window_seconds=10.0):
            _safe_log_event(client_ip, "备份导出频率过高，已触发限流")
            return _render_http_error(429, 'Too Many Requests', 'Request rate too high')

        task_id = (request.form.get('task') or '').strip()
        backup_type = (request.form.get('type') or '').strip().lower()
        if len(task_id) > 120:
            _safe_log_event(client_ip, f"异常参数长度: /admin/backup task={task_id[:120]}")
            return _render_http_error(400, 'Bad Request', 'Invalid request.')
        if len(backup_type) > 32:
            backup_type = backup_type[:32]
        if backup_type not in ('full', 'inc'):
            backup_type = 'full'

        _safe_log_event(client_ip, f"触发数据导出陷阱，疑似数据窃取 | task={task_id or '-'} type={backup_type}")
        _push_admin_access_log(client_ip, username, '备份导出', '成功')

        _honeypot_delay(0.45, 0.9)

        # 动态生成与任务 ID 对齐的日期，保证导出内容一致性
        now = time.localtime()
        target_date = now
        if task_id.startswith('BK-'):
            try:
                parts = task_id.split('-')
                if len(parts) >= 2 and len(parts[1]) == 8:
                    ymd = parts[1]
                    target_date = time.strptime(f"{ymd} 14:00:00", "%Y%m%d %H:%M:%S")
            except Exception:
                target_date = now

        ymd_str = time.strftime('%Y%m%d', target_date)
        generated_at = time.strftime('%Y-%m-%d %H:%M:%S', target_date)
        base_ts = time.mktime(target_date)

        def _fmt_backup_ts(ts: float) -> str:
            return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))

        t_login = _fmt_backup_ts(base_ts + 6 * 60)
        t_backup_req = _fmt_backup_ts(base_ts + 10 * 60)
        t_backup_done = _fmt_backup_ts(base_ts + 20 * 60)
        t_last_backup = _fmt_backup_ts(base_ts + 3 * 60)
        snapshot_utc = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(base_ts + 2 * 60))
        binlog_pos = 100000 + (int(base_ts) % 900000)

        filename = f"sys_export_{ymd_str}.sql"
        if task_id.startswith('BK-'):
            parts = task_id.split('-')
            seq = parts[2] if len(parts) >= 3 else '0001'
            if backup_type == 'inc':
                filename = f"cms_inc_backup_{ymd_str}_{seq}.sql"
            else:
                filename = f"cms_full_backup_{ymd_str}_{seq}.sql"

        # 增量备份模拟：仅输出变更片段，伪装 binlog 导出结果
        if backup_type == 'inc':
            sql_body = (
                "--\n"
                "-- Incremental backup (binlog-based simulation)\n"
                "--\n"
                "\n"
                "/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;\n"
                "/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;\n"
                "/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;\n"
                "/*!50503 SET NAMES utf8mb4 */;\n"
                "/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;\n"
                "/*!40103 SET TIME_ZONE='+00:00' */;\n"
                "/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;\n"
                "/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;\n"
                "/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;\n"
                "/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;\n"
                "\n"
                f"-- Snapshot boundary (UTC): {snapshot_utc}\n"
                f"SET @snapshot_utc='{snapshot_utc}';\n"
                "SET @binlog_file='mysql-bin.000987';\n"
                f"SET @binlog_pos={binlog_pos};\n"
                "\n"
                "--\n"
                "-- Data changes for table `cms_audit_log`\n"
                "--\n"
                "LOCK TABLES `cms_audit_log` WRITE;\n"
                "/*!40000 ALTER TABLE `cms_audit_log` DISABLE KEYS */;\n"
                "INSERT INTO `cms_audit_log` (`id`,`actor`,`ip`,`action`,`detail`,`created_at`) VALUES\n"
                f"(12031,'admin','127.0.0.1','EXPORT','备份导出请求','{t_backup_req}'),\n"
                f"(12032,'admin','127.0.0.1','LOGIN','登录成功','{t_login}');\n"
                "/*!40000 ALTER TABLE `cms_audit_log` ENABLE KEYS */;\n"
                "UNLOCK TABLES;\n"
                "\n"
                "--\n"
                "-- Data changes for table `cms_settings`\n"
                "--\n"
                "UPDATE `cms_settings` SET `value`='0' WHERE `name`='maintenance_mode';\n"
                f"UPDATE `cms_settings` SET `value`='{t_last_backup}' WHERE `name`='last_backup_at';\n"
                "\n"
                "/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;\n"
                "/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;\n"
                "/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;\n"
                "/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;\n"
                "/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;\n"
                "/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;\n"
                "/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;\n"
                "/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;\n"
            )
        # 全量备份模拟：输出完整表结构和示例数据
        else:
            sql_body = (
                "--\n"
                "-- Current Database: `hs_cms`\n"
                "--\n"
                "\n"
                "/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;\n"
                "/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;\n"
                "/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;\n"
                "/*!50503 SET NAMES utf8mb4 */;\n"
                "/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;\n"
                "/*!40103 SET TIME_ZONE='+00:00' */;\n"
                "/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;\n"
                "/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;\n"
                "/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;\n"
                "/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;\n"
                "\n"
                "--\n"
                "-- Table structure for table `cms_users`\n"
                "--\n"
                "DROP TABLE IF EXISTS `cms_users`;\n"
                "/*!40101 SET @saved_cs_client     = @@character_set_client */;\n"
                "/*!50503 SET character_set_client = utf8mb4 */;\n"
                "CREATE TABLE `cms_users` (\n"
                "  `id` int NOT NULL,\n"
                "  `username` varchar(64) NOT NULL,\n"
                "  `email` varchar(128) DEFAULT NULL,\n"
                "  `password_hash` varchar(255) NOT NULL,\n"
                "  `role` varchar(32) NOT NULL,\n"
                "  `status` varchar(16) NOT NULL DEFAULT '启用',\n"
                "  `last_login` datetime DEFAULT NULL,\n"
                "  `created_at` datetime NOT NULL,\n"
                "  PRIMARY KEY (`id`),\n"
                "  UNIQUE KEY `uniq_username` (`username`)\n"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;\n"
                "/*!40101 SET character_set_client = @saved_cs_client */;\n"
                "\n"
                "LOCK TABLES `cms_users` WRITE;\n"
                "/*!40000 ALTER TABLE `cms_users` DISABLE KEYS */;\n"
                "INSERT INTO `cms_users` (`id`,`username`,`email`,`password_hash`,`role`,`status`,`last_login`,`created_at`) VALUES\n"
                f"(1,'admin','admin@huasheng-tech.com','$2y$10$u5aYq0cH0m9m0c0sV9xE0Oa0k7m8xHhLq9wE0rTtHf3bJpYwN3G4C','管理员','启用','{t_login}','2025-08-01 09:00:00'),\n"
                "(2,'editor','editor@huasheng-tech.com','$2y$10$H7zq4a0YlD9s4xQ7f8b9uOrjQf0vQ2kQy0c0v0hH1Qf2m1x8c8c8W','编辑','启用','2026-01-10 11:20:02','2025-08-01 09:00:00'),\n"
                "(3,'ops','ops@huasheng-tech.com','$2y$10$V9xE0Oa0k7m8xHhLq9wE0rTtHf3bJpYwN3G4Cu5aYq0cH0m9m0c0s','运维','启用','2026-01-09 08:32:19','2025-08-15 10:30:00'),\n"
                "(4,'auditor','audit@huasheng-tech.com','$2y$10$Q2kQy0c0v0hH1Qf2m1x8c8c8WH7zq4a0YlD9s4xQ7f8b9uOrjQf0v','审计','启用','2026-01-06 16:08:45','2025-09-01 13:20:00');\n"
                "/*!40000 ALTER TABLE `cms_users` ENABLE KEYS */;\n"
                "UNLOCK TABLES;\n"
                "\n"
                "--\n"
                "-- Table structure for table `cms_settings`\n"
                "--\n"
                "DROP TABLE IF EXISTS `cms_settings`;\n"
                "CREATE TABLE `cms_settings` (\n"
                "  `name` varchar(64) NOT NULL,\n"
                "  `value` text,\n"
                "  `updated_at` datetime DEFAULT NULL,\n"
                "  PRIMARY KEY (`name`)\n"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;\n"
                "LOCK TABLES `cms_settings` WRITE;\n"
                "INSERT INTO `cms_settings` (`name`,`value`,`updated_at`) VALUES\n"
                "('site_name','华盛CMS后台','2026-01-12 09:10:00'),\n"
                "('maintenance_mode','0','2026-01-12 09:10:00'),\n"
                f"('last_backup_at','{t_last_backup}','{t_last_backup}');\n"
                "UNLOCK TABLES;\n"
                "\n"
                "--\n"
                "-- Table structure for table `cms_posts`\n"
                "--\n"
                "DROP TABLE IF EXISTS `cms_posts`;\n"
                "CREATE TABLE `cms_posts` (\n"
                "  `id` int NOT NULL,\n"
                "  `title` varchar(255) NOT NULL,\n"
                "  `summary` varchar(512) DEFAULT NULL,\n"
                "  `author` varchar(64) NOT NULL,\n"
                "  `status` varchar(16) NOT NULL DEFAULT '草稿',\n"
                "  `publish_time` datetime DEFAULT NULL,\n"
                "  `created_at` datetime NOT NULL,\n"
                "  PRIMARY KEY (`id`),\n"
                "  KEY `idx_status` (`status`),\n"
                "  KEY `idx_publish_time` (`publish_time`)\n"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;\n"
                "LOCK TABLES `cms_posts` WRITE;\n"
                "/*!40000 ALTER TABLE `cms_posts` DISABLE KEYS */;\n"
                "INSERT INTO `cms_posts` (`id`,`title`,`summary`,`author`,`status`,`publish_time`,`created_at`) VALUES\n"
                "(101,'华盛科技通过 ISO 27001 信息安全管理体系认证','认证范围覆盖研发、交付与运维流程。','editor','已发布','2024-12-15 10:30:00','2024-12-15 10:00:00'),\n"
                "(102,'发布统一指标体系组件','支持多源数据对齐与口径治理。','editor','已发布','2024-12-10 09:00:00','2024-12-10 08:40:00'),\n"
                "(103,'权限治理与审计留痕专项','推进最小权限与审批流程落地。','auditor','草稿',NULL,'2026-01-05 14:20:00');\n"
                "/*!40000 ALTER TABLE `cms_posts` ENABLE KEYS */;\n"
                "UNLOCK TABLES;\n"
                "\n"
                "--\n"
                "-- Table structure for table `cms_audit_log`\n"
                "--\n"
                "DROP TABLE IF EXISTS `cms_audit_log`;\n"
                "CREATE TABLE `cms_audit_log` (\n"
                "  `id` bigint NOT NULL,\n"
                "  `actor` varchar(64) NOT NULL,\n"
                "  `ip` varchar(64) DEFAULT NULL,\n"
                "  `action` varchar(128) NOT NULL,\n"
                "  `detail` text,\n"
                "  `created_at` datetime NOT NULL,\n"
                "  PRIMARY KEY (`id`),\n"
                "  KEY `idx_created_at` (`created_at`)\n"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;\n"
                "LOCK TABLES `cms_audit_log` WRITE;\n"
                "INSERT INTO `cms_audit_log` (`id`,`actor`,`ip`,`action`,`detail`,`created_at`) VALUES\n"
                f"(12001,'admin','127.0.0.1','LOGIN','登录成功','{t_login}'),\n"
                f"(12002,'admin','127.0.0.1','BACKUP','全量备份已生成','{t_backup_done}');\n"
                "UNLOCK TABLES;\n"
                "\n"
                "/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;\n"
                "/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;\n"
                "/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;\n"
                "/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;\n"
                "/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;\n"
                "/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;\n"
                "/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;\n"
                "/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;\n"
            )

        task_label = task_id or f"BK-{ymd_str}-0001"
        content = (
            "-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)\n"
            f"--\n"
            f"-- Host: 10.0.12.8    Database: hs_cms\n"
            f"-- ------------------------------------------------------\n"
            f"-- Server version\t8.0.34\n"
            f"--\n"
            f"-- Dumping data for task: {task_label}\n"
            f"-- Backup type: {backup_type}\n"
            f"-- Dump completed on {generated_at}\n"
            "\n"
            + sql_body
        )

        resp = make_response(content)
        resp.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        resp.headers['Content-Type'] = 'application/octet-stream'
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        return resp

    @app.route('/admin/upload', methods=['GET', 'POST'])
    def fake_upload():
        client_ip = get_client_ip()
        if not _is_admin_authed():
            _safe_log_event(client_ip, "未授权访问文件上传页面")
            return _make_forbidden_response()

        root_reject = _reject_root_session(client_ip, '上传配置')
        if root_reject is not None:
            return root_reject

        username = (_get_authenticated_admin_username() or 'admin')[:32]
        actor_role = _get_current_admin_role()
        if actor_role not in ('超级管理员', '管理员'):
            _push_admin_access_log(client_ip, username, '拒绝操作:upload/access', '失败')
            if request.method == 'POST':
                if _wants_json_response():
                    payload = _attach_fake_debug({'code': 403, 'msg': 'Forbidden'}, 'E_FORBIDDEN', 'Access denied')
                    return jsonify(payload), 403
                return _render_http_error(403, 'Forbidden', 'Access denied.')
            return _render_http_error(403, 'Forbidden', 'Access denied.')

        if request.method == 'POST' and (not _validate_admin_csrf_request()):
            _push_admin_access_log(client_ip, username, "拒绝操作:csrf_block", '失败')
            if _wants_json_response():
                payload = _attach_fake_debug({'code': 403, 'msg': 'Forbidden'}, 'E_CSRF', 'csrf validation failed')
                return jsonify(payload), 403
            return _render_upload_page('danger', 'CSRF 验证失败，请刷新页面后重试。', 403)

        if request.method == 'POST':
            wants_json = _wants_json_response()
            if not _rate_limit_endpoint(f"upload:{client_ip}", limit=4, window_seconds=10.0):
                _safe_log_event(client_ip, "上传频率过高，已触发限流")
                if wants_json:
                    payload = _attach_fake_debug({'code': 429, 'msg': 'Too Many Requests'}, 'E_RATE_LIMIT', 'Request rate too high')
                    return jsonify(payload), 429
                return _render_upload_page('warning', '操作过于频繁，请稍后再试。', 429)

            f = request.files.get('file')

            request_id = 'REQ-' + secrets.token_hex(8)
            trace_id = 'trace-' + secrets.token_hex(12)

            fn = ''
            try:
                fn = str(getattr(f, 'filename', '') or '')[:120]
            except Exception:
                fn = ''

            head = b''
            try:
                if f is not None:
                    head = f.read(4096) or b''
            except Exception:
                head = b''

            file_md5 = ''
            md5_partial = False
            try:
                h = hashlib.md5()
                h.update(head)
                read_bytes = len(head)
                max_bytes = 5 * 1024 * 1024
                while f is not None:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    if read_bytes + len(chunk) > max_bytes:
                        remain = max_bytes - read_bytes
                        if remain > 0:
                            h.update(chunk[:remain])
                            read_bytes += remain
                        md5_partial = True
                        break
                    h.update(chunk)
                    read_bytes += len(chunk)
                file_md5 = h.hexdigest()
            except Exception:
                file_md5 = ''
                md5_partial = False

            try:
                content_len = int(request.content_length or 0)
            except Exception:
                content_len = 0

            fp_src = (fn + '|' + str(content_len) + '|' + head.hex()).encode('utf-8', 'ignore')
            fp_hex = hashlib.sha256(fp_src).hexdigest()
            fp_idx = 0
            try:
                fp_idx = int(fp_hex[:8], 16)
            except Exception:
                fp_idx = 0

            if fn:
                _safe_log_event(client_ip, f"尝试导入配置包: {fn} | md5={file_md5 or '-'} | request_id={request_id} trace_id={trace_id}")
            else:
                _safe_log_event(client_ip, f"尝试导入配置包: (empty filename) | md5={file_md5 or '-'} | request_id={request_id} trace_id={trace_id}")

            _push_admin_access_log(client_ip, username, '配置导入', '失败')

            ext = ''
            try:
                ext = os.path.splitext(fn)[1].lower()
            except Exception:
                ext = ''
            if fn.lower().endswith('.tar.gz'):
                ext = '.tar.gz'

            if ext in ('.php', '.jsp', '.asp', '.aspx', '.py', '.sh', '.exe', '.dll'):
                msg = "安全策略拦截：检测到疑似 WebShell/可执行脚本文件，已拒绝导入。"
                try:
                    alert_web_upload(client_ip, fn, content_len, "blocked_script")
                except Exception as e:
                    logger.warning(f"alert_web_upload failed: {e}")
                if wants_json:
                    return jsonify({'code': 403, 'message': msg, 'request_id': request_id, 'trace_id': trace_id, 'file_md5': file_md5, 'md5_partial': md5_partial}), 403
                return _render_upload_page('danger', msg, 403)

            if ext in ('.zip', '.tar.gz', '.tgz'):
                candidates = [
                    "[S-5001] 配置包校验失败：数字签名无效或证书链不可信。",
                    "[B-1042] 导入中止：元数据文件(manifest.json)缺失或版本不兼容。",
                    "[S-5009] 完整性校验失败：ruleset.sig 签名不匹配，操作已记录。",
                ]
                msg = candidates[fp_idx % len(candidates)]
                try:
                    alert_web_upload(client_ip, fn, content_len, "package_invalid")
                except Exception as e:
                    logger.warning(f"alert_web_upload failed: {e}")
                if wants_json:
                    return jsonify({'code': 400, 'message': msg, 'request_id': request_id, 'trace_id': trace_id, 'file_md5': file_md5, 'md5_partial': md5_partial}), 400
                return _render_upload_page('danger', msg, 400)

            if ext in ('.yml', '.yaml', '.json'):
                msg = "解析配置文件失败：无效的 YAML/JSON 格式或文件头损坏。"
                try:
                    alert_web_upload(client_ip, fn, content_len, "config_parse_failed")
                except Exception as e:
                    logger.warning(f"alert_web_upload failed: {e}")
                if wants_json:
                    return jsonify({'code': 422, 'message': msg, 'request_id': request_id, 'trace_id': trace_id, 'file_md5': file_md5, 'md5_partial': md5_partial}), 422
                return _render_upload_page('danger', msg, 422)

            candidates = [
                "导入失败：CRC 校验不一致，文件可能已损坏。",
                "导入失败：配置包格式不受支持或缺少必要目录结构。",
                "导入失败：解压缩失败（unexpected EOF）。",
            ]
            msg = candidates[fp_idx % len(candidates)]
            try:
                alert_web_upload(client_ip, fn, content_len, "import_failed")
            except Exception as e:
                logger.warning(f"alert_web_upload failed: {e}")
            if wants_json:
                return jsonify({'code': 400, 'message': msg, 'request_id': request_id, 'trace_id': trace_id, 'file_md5': file_md5, 'md5_partial': md5_partial}), 400
            return _render_upload_page('danger', msg, 400)

        return _render_upload_page()


