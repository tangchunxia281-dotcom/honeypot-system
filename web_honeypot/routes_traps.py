# -*- coding: utf-8 -*-
"""
Web 蜜罐 - 诱捕/探测路由
"""
import time
import random
import hashlib
from flask import request, render_template, make_response, redirect, jsonify


def register(app, ctx):
    get_client_ip = ctx['get_client_ip']
    _log_event = ctx['_log_event']
    _make_forbidden_response = ctx['_make_forbidden_response']
    _safe_log_event = ctx['_safe_log_event']
    _honeypot_delay = ctx['_honeypot_delay']
    _render_http_error = ctx['_render_http_error']
    _as_safe_html = ctx['_as_safe_html']
    escape_html = ctx['escape_html']
    logger = ctx['logger']

    def _is_suspicious_input(text: str) -> bool:
        s = str(text or '').lower()
        markers = [
            "' or ",
            '" or ',
            "union select",
            "<script",
            "javascript:",
            "../",
            "..\\",
            "sleep(",
            "benchmark(",
        ]
        return any(m in s for m in markers)

    def _render_admin_login_like(error_msg: str = None, status_code: int = 200, action_path: str = None):
        action = action_path or request.path or '/admin'
        resp = make_response(render_template('login.html', error=error_msg, login_action=action), status_code)
        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
        return resp

    def _render_404():
        current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        return make_response(render_template('404.html', current_time=current_time), 404)

    @app.route('/backup/', defaults={'path': ''}, methods=['GET', 'POST'])
    @app.route('/backup/<path:path>', methods=['GET', 'POST'])
    def trap_backup(path):
        client_ip = get_client_ip()
        _log_event(client_ip, f"高危路径探测: /backup/{path}", level='warning')
        resp = _render_404()
        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
        return resp

    @app.route('/admin_v2/', defaults={'path': ''}, methods=['GET', 'POST'])
    @app.route('/admin_v2/<path:path>', methods=['GET', 'POST'])
    def trap_admin_v2(path):
        client_ip = get_client_ip()
        _log_event(client_ip, f"高危路径探测: /admin_v2/{path}", level='warning')
        resp = _render_404()
        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
        return resp

    @app.route('/.env')
    def trap_env():
        client_ip = get_client_ip()
        _log_event(client_ip, "访问配置文件: /.env", level='critical')
        return _make_forbidden_response()

    @app.route('/.git/config')
    def trap_git_config():
        client_ip = get_client_ip()
        _log_event(client_ip, "访问Git配置: /.git/config", level='critical')
        return _make_forbidden_response()

    @app.route('/page')
    def file_include_trap():
        client_ip = get_client_ip()
        page_param = (request.args.get('page') or '').strip()
        file_param = (request.args.get('file') or '').strip()

        target = page_param or file_param
        target_key = 'page' if page_param else ('file' if file_param else '')

        if len(target) > 500:
            return render_template('error.html', error_type="请求异常", error_msg="请求参数异常：路径长度超出系统限制"), 400

        lfi_patterns = ['../', '..\\', '/etc/', '/var/', '/proc/', 'php://', 'file://', 'data://', 'expect://']
        is_lfi = any(p in target.lower() for p in lfi_patterns)

        if not target:
            content = (
                "<h2>内容中心</h2>"
                "<p>这里汇总了站点的主要栏目入口。你可以从以下模块开始浏览：</p>"
                "<ul>"
                "  <li><a href=\"/about\">关于我们</a></li>"
                "  <li><a href=\"/products\">产品中心</a></li>"
                "  <li><a href=\"/solutions\">解决方案</a></li>"
                "  <li><a href=\"/news\">新闻中心</a></li>"
                "  <li><a href=\"/contact\">联系我们</a></li>"
                "</ul>"
                "<p style=\"margin-top:12px;\">也可以使用 <a href=\"/search\">站内搜索</a> 快速查找内容。</p>"
            )
            return render_template(
                'page.html',
                title='内容中心',
                subtitle='栏目导航与内容入口',
                breadcrumb=[{'name': '内容中心', 'url': '/page'}],
                content=_as_safe_html(content),
            )

        if target_key == 'page':
            page_map = {
                'about': '/about',
                'products': '/products',
                'solutions': '/solutions',
                'news': '/news',
                'contact': '/contact',
            }
            hit = page_map.get(target.strip('/'))
            if hit:
                return redirect(hit)

        if is_lfi:
            payload = f"文件包含(LFI)攻击: /page?{target_key or 'file'}={target}"
            _safe_log_event(client_ip, payload)
            logger.warning(f"[检测] LFI攻击 {client_ip}: {target[:50]}")

            safe_target = (target or '')[:220]
            current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            error_public_msg = (
                "Warning: include({target}): failed to open stream: Permission denied in /var/www/html/index.php on line 27 | "
                "Warning: include(): Failed opening '{target}' for inclusion (include_path='.:/usr/share/php')"
            ).format(target=safe_target)
            resp = make_response(
                render_template(
                    'error.html',
                    error_type='System Error',
                    error_public_msg=error_public_msg,
                    error_framework='Portal Service',
                    current_time=current_time,
                ),
                500,
            )
            resp.headers['Content-Type'] = 'text/html; charset=utf-8'
            return resp

        if target_key == 'file':
            return _render_http_error(404, 'Not Found', 'Resource not found')

        safe_target = escape_html(target)
        content = (
            "<h2>内容未找到</h2>"
            f"<p>请求标识：<code>{safe_target}</code></p>"
            "<p>该内容可能已下线、已迁移，或当前访问地址有误。</p>"
            "<ul>"
            "  <li><a href=\"/\">返回首页</a></li>"
            "  <li><a href=\"/search\">站内搜索</a></li>"
            "  <li><a href=\"/contact\">联系我们</a></li>"
            "</ul>"
        )
        return render_template(
            'page.html',
            title='内容未找到',
            subtitle='内容中心',
            breadcrumb=[{'name': '内容中心', 'url': '/page'}],
            content=_as_safe_html(content),
        )

    @app.route('/admin/<path:subpath>')
    def fake_admin_actions(subpath):
        client_ip = get_client_ip()
        safe_subpath = (subpath or '').strip()
        if len(safe_subpath) > 200:
            _safe_log_event(client_ip, f"异常参数长度: /admin/<path> subpath={safe_subpath[:200]}")
            safe_subpath = safe_subpath[:200]
        _safe_log_event(client_ip, f"探测后台路径: /admin/{safe_subpath}")

        _honeypot_delay(0.3, 0.8)

        # 常见后台路径返回登录页样式，维持可推进但不可控的交互体验
        lowered = safe_subpath.lower().strip('/')
        if lowered in ('login', 'signin', 'index', 'index.php', 'panel', 'console'):
            if request.method == 'GET':
                return _render_admin_login_like(action_path=request.path)

        # 默认返回 404，避免固定拒绝模式暴露蜜罐策略
        resp = _render_404()
        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
        return resp

    @app.route('/admin/login', methods=['GET', 'POST'])
    @app.route('/admin/signin', methods=['GET', 'POST'])
    @app.route('/admin/index.php', methods=['GET', 'POST'])
    def fake_admin_login_probe():
        client_ip = get_client_ip()
        probe_path = request.path
        _safe_log_event(client_ip, f"后台登录探测: {probe_path}")
        _honeypot_delay(0.35, 0.9)

        if request.method == 'GET':
            return _render_admin_login_like(action_path=request.path)

        username = (request.form.get('username') or request.form.get('user') or '').strip()[:80]
        password = (request.form.get('password') or request.form.get('pass') or '').strip()
        payload = f"后台登录探测提交: path={probe_path}, user={username or '-'}, pwd_len={len(password)}"
        _safe_log_event(client_ip, payload)

        if _is_suspicious_input(username) or _is_suspicious_input(password):
            err = "SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax"
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'code': 500, 'msg': err, 'trace': 'db-auth'}), 500
            return _render_http_error(500, 'Database Error', err)

        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'code': 401, 'msg': 'Invalid username or password', 'status': 'auth_failed'}), 401
        return _render_admin_login_like("用户名或密码错误", 200, action_path=request.path)

    @app.route('/admin/api/login', methods=['POST'])
    @app.route('/admin/api/auth/login', methods=['POST'])
    def fake_admin_api_login():
        client_ip = get_client_ip()
        _honeypot_delay(0.2, 0.6)
        data = request.get_json(silent=True) or {}
        username = str(data.get('username') or data.get('user') or '')[:80]
        password = str(data.get('password') or '')[:120]
        _safe_log_event(client_ip, f"后台API登录探测: user={username or '-'}, pwd_len={len(password)}")

        if _is_suspicious_input(username) or _is_suspicious_input(password):
            return jsonify({'code': 500, 'msg': 'SQLSTATE[42000]: Syntax error or access violation'}), 500

        # 始终鉴权失败，但保留真实接口风格的错误响应
        return jsonify({'code': 401, 'msg': 'Unauthorized', 'retry_after': random.randint(1, 3)}), 401

    @app.route('/uploads/', defaults={'path': ''}, methods=['GET'])
    @app.route('/uploads/<path:path>', methods=['GET'])
    def fake_uploads(path):
        client_ip = get_client_ip()
        p = (path or '').strip()
        lowered = p.lower()
        _safe_log_event(client_ip, f"目录探测: /uploads/{p}")
        _honeypot_delay(0.06, 0.25)

        if not p:
            now = time.strftime('%d-%b-%Y %H:%M', time.localtime())
            body = (
                "<html><head><title>Index of /uploads/</title></head>"
                "<body><h1>Index of /uploads/</h1><hr><pre>"
                "<a href=\"../\">../</a>\n"
                f"<a href=\"2026/\">2026/</a>{' ' * 17}{now}                   -\n"
                f"<a href=\"tmp/\">tmp/</a>{' ' * 18}{now}                   -\n"
                f"<a href=\"readme.txt\">readme.txt</a>{' ' * 8}{now}                 214\n"
                "</pre><hr></body></html>"
            )
            resp = make_response(body, 200)
            resp.headers['Content-Type'] = 'text/html; charset=utf-8'
            return resp

        if lowered in ('readme.txt', 'tmp/readme.txt', '2026/readme.txt'):
            resp = make_response(
                "uploads directory is for temporary package transfer only.\n"
                "auto clean job: enabled\n",
                200,
            )
            resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
            return resp

        if lowered.endswith(('.php', '.jsp', '.asp', '.aspx', '.sh', '.py')):
            _log_event(client_ip, f"上传目录脚本探测: /uploads/{p}", level='critical')
            return _make_forbidden_response()

        return _render_404()

    @app.route('/old/', defaults={'path': ''}, methods=['GET'])
    @app.route('/old/<path:path>', methods=['GET'])
    def fake_old_site(path):
        client_ip = get_client_ip()
        p = (path or '').strip()
        _safe_log_event(client_ip, f"历史目录探测: /old/{p}")
        _honeypot_delay(0.08, 0.22)

        if not p:
            body = (
                "<html><head><title>Index of /old/</title></head><body>"
                "<h1>Index of /old/</h1><hr><pre>"
                "<a href=\"../\">../</a>\n"
                "<a href=\"admin.php\">admin.php</a>\n"
                "<a href=\"site-2024.tar.gz\">site-2024.tar.gz</a>\n"
                "</pre><hr></body></html>"
            )
            resp = make_response(body, 200)
            resp.headers['Content-Type'] = 'text/html; charset=utf-8'
            return resp

        if p.lower() == 'admin.php':
            return _render_admin_login_like(action_path=request.path)

        if p.lower().endswith('.tar.gz'):
            digest = hashlib.md5(p.encode('utf-8', errors='ignore')).hexdigest()
            data = (f"PK\x03\x04{digest}\nCORRUPTED-ARCHIVE\n").encode('utf-8', errors='ignore')
            resp = make_response(data, 200)
            resp.headers['Content-Type'] = 'application/gzip'
            resp.headers['Content-Disposition'] = f'attachment; filename=\"{p}\"'
            return resp

        return _render_404()

    @app.route('/backup.zip', methods=['GET'])
    @app.route('/www.zip', methods=['GET'])
    @app.route('/dump.sql', methods=['GET'])
    @app.route('/config.php~', methods=['GET'])
    @app.route('/config.bak', methods=['GET'])
    def fake_sensitive_file_probe():
        client_ip = get_client_ip()
        p = request.path
        _log_event(client_ip, f"敏感文件探测: {p}", level='critical')
        _honeypot_delay(0.2, 0.5)
        # 返回“存在但不可读取”的结果，降低蜜罐识别概率
        if p.endswith(('.zip', '.sql')):
            return _make_forbidden_response()
        return _render_404()


