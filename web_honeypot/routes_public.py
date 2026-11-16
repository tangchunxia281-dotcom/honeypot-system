# -*- coding: utf-8 -*-
"""
Web 蜜罐 - 公共页面路由
"""
import os
import random
import time
import hashlib
from flask import render_template, request, make_response, send_from_directory


def register(app, ctx):
    get_client_ip = ctx['get_client_ip']
    _safe_log_event = ctx['_safe_log_event']
    _rand_hex = ctx['_rand_hex']
    _as_safe_html = ctx['_as_safe_html']
    escape_html = ctx['escape_html']
    detect_sqli = ctx['detect_sqli']
    get_fake_mysql_error = ctx['get_fake_mysql_error']
    enhanced_xss_detection = ctx['enhanced_xss_detection']
    logger = ctx['logger']

    def _format_time(ts: float) -> str:
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))

    def _format_date(ts: float) -> str:
        return time.strftime('%Y-%m-%d', time.localtime(ts))

    def _stable_number(seed: str, min_v: int, max_v: int) -> int:
        if max_v <= min_v:
            return min_v
        h = hashlib.md5(seed.encode('utf-8', errors='ignore')).hexdigest()
        n = int(h[:8], 16)
        return min_v + (n % (max_v - min_v + 1))

    def _fmt_views(seed: str, min_v: int, max_v: int) -> str:
        return f"{_stable_number(seed, min_v, max_v):,}"

    def _build_news_items(now_ts: float = None):
        base = now_ts if now_ts is not None else time.time()
        items = [
            {
                'id': 1,
                'title': '华盛科技通过 ISO 27001 信息安全管理体系认证',
                'summary': '认证范围覆盖研发、交付与运维流程。公司将持续完善权限治理、审计留痕与供应链安全管理机制。',
                'publish_time': _format_time(base - 6 * 24 * 3600 - 3 * 3600),
                'views': _fmt_views('news-iso27001', 6800, 9800),
                'category_name': '合规与治理',
                'author': '合规办公室',
                'category': 'compliance',
                'tags': ['信息安全', 'ISO27001', '审计留痕'],
                'image': '/static/img/news-thumb-funding.svg',
                'content': '本次认证覆盖信息资产管理、访问控制、变更管理、日志审计与应急响应等关键环节。下一阶段，公司将围绕最小权限、配置基线与供应链安全持续推进标准化落地，并在核心项目中引入定期演练与第三方评估。',
            },
            {
                'id': 2,
                'title': '发布“统一指标体系”组件，支持多源数据对齐与口径治理',
                'summary': '新版本提供指标管理、口径追溯与变更审批，帮助业务、数仓与报表实现统一口径对齐。',
                'publish_time': _format_time(base - 12 * 24 * 3600 - 1 * 3600),
                'views': _fmt_views('news-metrics', 4200, 7800),
                'category_name': '产品更新',
                'author': '产品研发中心',
                'category': 'product',
                'tags': ['指标治理', '数据对齐', '变更审批'],
                'image': '/static/img/news-thumb-new.svg',
                'content': '该组件支持指标分层、口径版本管理与血缘追踪，并提供审批流与变更影响分析。配合权限模型与审计能力，可用于财务、运营、风控等跨部门场景的口径统一与治理闭环。',
            },
            {
                'id': 3,
                'title': '与高校共建联合实验室，推进大模型工程化与数据安全研究',
                'summary': '围绕数据脱敏、访问审计与模型推理效率优化开展合作，建设可复用的工程化工具链。',
                'publish_time': _format_time(base - 24 * 24 * 3600 - 5 * 3600),
                'views': _fmt_views('news-lab', 2800, 5200),
                'category_name': '合作动态',
                'author': '战略合作部',
                'category': 'partner',
                'tags': ['联合实验室', '数据安全', '工程化'],
                'image': '/static/img/news-thumb-partner.svg',
                'content': '联合实验室将聚焦数据脱敏与访问审计策略、模型推理性能优化与工程化落地工具链建设。合作成果将优先在产业项目中验证，以提升模型在企业生产环境中的可用性与合规性。',
            },
        ]
        return items

    @app.route('/')
    def index():
        items = _build_news_items()
        return render_template('index.html', news_items=items)

    @app.route('/about')
    def about_page():
        return render_template('about.html')

    @app.route('/products')
    def products_page():
        return render_template('products.html')

    @app.route('/solutions')
    def solutions_page():
        return render_template('solutions.html')

    @app.route('/products/<path:slug>')
    def product_detail(slug):
        slug = (slug or '').strip('/')
        title = '产品详情'
        display_name_map = {
            'ai-platform': 'AI 数据分析平台',
            'cloud-service': '云计算服务',
            'security-solution': '安全解决方案',
            'bigdata': '大数据平台',
        }
        display_name = display_name_map.get(slug)
        if not display_name and slug:
            display_name = slug.replace('-', ' ').replace('_', ' ')
        if display_name:
            title = f"产品详情 - {display_name}"
        content = (
            f"<p>{escape_html(display_name or '该产品')}提供标准化能力组件与可选增值模块，支持按行业需求进行组合交付。</p>"
            f"<h3>适用场景</h3>"
            f"<ul>"
            f"  <li>数据治理与指标体系建设</li>"
            f"  <li>实时分析与告警联动</li>"
            f"  <li>审计合规与权限管理</li>"
            f"</ul>"
            f"<h3>交付与支持</h3>"
            f"<p>支持本地化部署与云上托管两种模式，交付周期与费用根据规模评估。</p>"
            f"<p>如需演示、试用或报价，请前往 <a href=\"/contact\">联系我们</a> 提交需求，我们会安排对接。</p>"
        )
        return render_template(
            'page.html',
            title=title,
            subtitle='企业级产品与服务',
            breadcrumb=[{'name': '产品中心', 'url': '/products'}],
            content=_as_safe_html(content),
        )

    @app.route('/solutions/<path:slug>')
    def solution_detail(slug):
        slug = (slug or '').strip('/')
        title = '方案详情'
        display_name_map = {
            'fin-risk': '金融风控与反欺诈',
            'manufacture-pdm': '制造预测性维护',
            'gov-data': '政企数据治理与共享',
            'security-audit': '安全审计与合规检查',
        }
        display_name = display_name_map.get(slug)
        if not display_name and slug:
            display_name = slug.replace('-', ' ').replace('_', ' ')
        if display_name:
            title = f"方案详情 - {display_name}"

        detail_map = {
            'fin-risk': {
                'intro': '面向交易反欺诈与风险预警场景，覆盖数据接入、特征加工、规则策略与联动处置。',
                'bullets': ['实时指标与风险画像', '规则引擎与名单管理', '告警分级与工单联动'],
            },
            'manufacture-pdm': {
                'intro': '面向设备健康管理与预测性维护，支持多源采集、异常检测与停机风险评估。',
                'bullets': ['传感/日志接入与清洗', '异常检测与趋势预测', '维保策略与报表归档'],
            },
            'gov-data': {
                'intro': '面向数据治理与共享交换，提供资产目录、质量校验、权限审计与合规留痕能力。',
                'bullets': ['数据标准与资产目录', '质量规则与口径治理', '权限模型与审计追溯'],
            },
            'security-audit': {
                'intro': '面向日志审计与合规检查，支持多源日志汇聚、检索分析、报表归档与追溯取证。',
                'bullets': ['日志汇聚与字段规范化', '检索分析与告警策略', '报表归档与审计留痕'],
            },
        }
        detail = detail_map.get(slug, {'intro': '面向行业客户的数字化建设需求，提供评估、方案设计与交付支持。', 'bullets': ['现网评估与需求梳理', '方案设计与实施计划', '上线验收与持续运营']})

        content = (
            f"<p>{escape_html(detail.get('intro') or '')}</p>"
            f"<h3>交付内容</h3>"
            f"<ul>"
            + ''.join(f"<li>{escape_html(x)}</li>" for x in (detail.get('bullets') or []))
            + f"</ul>"
            f"<h3>对接方式</h3>"
            f"<p>如需评估现网数据源、合规要求与交付范围，请前往 <a href=\"/contact\">联系我们</a> 提交需求，我们会安排对接。</p>"
        )
        return render_template(
            'page.html',
            title=title,
            subtitle='行业解决方案',
            breadcrumb=[{'name': '解决方案', 'url': '/solutions'}],
            content=_as_safe_html(content),
        )

    @app.route('/contact', methods=['GET', 'POST'])
    def contact_page():
        if request.method == 'POST':
            client_ip = get_client_ip()
            name = request.form.get('name', '')
            company = request.form.get('company', '')
            email = request.form.get('email', '')
            phone = request.form.get('phone', '')
            service = request.form.get('service', '')
            message = request.form.get('message', '')

            ticket = 'HS' + _rand_hex(8).upper()
            payload = (
                f"客户咨询提交: ticket={ticket}, name={name}, company={company}, email={email}, "
                f"phone={phone}, service={service}, message={message[:200]}"
            )
            _safe_log_event(client_ip, payload)

            content = (
                f"<p>我们已收到您的需求，工单编号：<strong>{escape_html(ticket)}</strong>。</p>"
                f"<p>工作人员将在 1 个工作日内通过邮箱或电话与您联系。</p>"
                f"<p><a href=\"/\">返回首页</a></p>"
            )
            return render_template(
                'page.html',
                title='提交成功',
                subtitle='感谢您的反馈，我们会尽快处理',
                breadcrumb=[{'name': '联系我们', 'url': '/contact'}],
                content=_as_safe_html(content),
            )

        return render_template('contact.html')

    @app.route('/subscribe', methods=['POST'])
    def subscribe():
        client_ip = get_client_ip()
        email = request.form.get('email', '')
        ticket = 'SUB' + _rand_hex(10).upper()
        _safe_log_event(client_ip, f"订阅请求: ticket={ticket}, email={email}")

        content = (
            f"<p>订阅已提交，编号：<strong>{escape_html(ticket)}</strong>。</p>"
            f"<p>如需取消订阅，请联系管理员。</p>"
            f"<p><a href=\"/news\">返回新闻中心</a></p>"
        )
        return render_template(
            'page.html',
            title='订阅成功',
            subtitle='感谢关注华盛科技集团',
            breadcrumb=[{'name': '新闻中心', 'url': '/news'}],
            content=_as_safe_html(content),
        )

    @app.route('/robots.txt')
    def robots_txt():
        body = "User-agent: *\nDisallow: /admin\nDisallow: /backup\nSitemap: /sitemap.xml\n"
        resp = make_response(body, 200)
        resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
        return resp

    @app.route('/sitemap.xml')
    def sitemap_xml():
        body = (
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"
            "  <url><loc>/</loc></url>\n"
            "  <url><loc>/news</loc></url>\n"
            "  <url><loc>/products</loc></url>\n"
            "  <url><loc>/solutions</loc></url>\n"
            "  <url><loc>/about</loc></url>\n"
            "  <url><loc>/contact</loc></url>\n"
            "</urlset>\n"
        )
        resp = make_response(body, 200)
        resp.headers['Content-Type'] = 'application/xml; charset=utf-8'
        return resp

    @app.route('/news')
    def news_page():
        client_ip = get_client_ip()
        news_id = request.args.get('id')
        if not news_id:
            items = _build_news_items()
            return render_template('news_list.html', items=items)

        if detect_sqli(news_id):
            logger.info(f"[检测] SQL注入 {client_ip}: {news_id}")
            fake_error = get_fake_mysql_error(news_id)
            return render_template(
                'error.html',
                error_type="Database Error",
                error_msg=fake_error,
                current_time=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            ), 500

        items = _build_news_items()
        item_map = {str(i.get('id')): i for i in items}
        news = item_map.get(str(news_id))
        if not news:
            resp = make_response(render_template('404.html', current_time=_format_time(time.time())), 404)
            resp.headers['Content-Type'] = 'text/html; charset=utf-8'
            return resp

        return render_template('news.html', news=news, news_id=news_id)

    @app.route('/search')
    def search_page():
        client_ip = get_client_ip()
        keyword = request.args.get('q', request.args.get('keyword', ''))

        search_type = (request.args.get('type') or '').strip().lower()
        page_str = (request.args.get('page') or '').strip()
        try:
            page = int(page_str) if page_str else 1
        except Exception:
            page = 1
        if page < 1:
            page = 1

        # 输入长度限制
        if len(keyword) > 200:
            return render_template('error.html', error_type="输入异常", error_msg="关键词长度超出限制，请缩短后重试"), 400

        # XSS 探测与记录
        if enhanced_xss_detection(keyword):
            logger.info(f"[检测] XSS攻击 {client_ip}: {keyword[:50]}")

        started = time.perf_counter()
        keyword_raw = (keyword or '').strip()
        kw = keyword_raw.lower()

        all_results = []
        if keyword_raw:
            news_items = []
            for n in _build_news_items():
                news_items.append({
                    'type': 'news',
                    'title': n.get('title'),
                    'url': f"/news?id={n.get('id')}",
                    'snippet': n.get('summary'),
                    'date': _format_date(time.mktime(time.strptime(n.get('publish_time'), '%Y-%m-%d %H:%M:%S'))),
                    'views': n.get('views'),
                    'category': n.get('category_name'),
                })

            product_map = {
                'ai-platform': 'AI 数据分析平台',
                'cloud-service': '云计算服务',
                'security-solution': '安全解决方案',
                'bigdata': '大数据平台',
            }
            solution_map = {
                'fin-risk': '金融风控与反欺诈',
                'manufacture-pdm': '制造预测性维护',
                'gov-data': '政企数据治理与共享',
                'security-audit': '安全审计与合规检查',
            }

            for n in news_items:
                hay = f"{n.get('title','')} {n.get('snippet','')}".lower()
                if kw in hay:
                    all_results.append(n)

            for slug, name in product_map.items():
                hay = f"{slug} {name}".lower()
                if kw in hay:
                    all_results.append({
                        'type': 'products',
                        'title': name,
                        'url': f"/products/{slug}",
                        'snippet': '提供标准化能力组件与可选增值模块，支持按行业需求进行组合交付。',
                        'date': _format_date(time.time() - 40 * 24 * 3600),
                        'views': _fmt_views(f"product-{slug}", 800, 6800),
                        'category': '产品中心',
                    })

            for slug, name in solution_map.items():
                hay = f"{slug} {name}".lower()
                if kw in hay:
                    all_results.append({
                        'type': 'solutions',
                        'title': name,
                        'url': f"/solutions/{slug}",
                        'snippet': '覆盖现网评估、方案设计、部署上线与运营迭代，可按行业数据规模与合规要求定制交付。',
                        'date': _format_date(time.time() - 55 * 24 * 3600),
                        'views': _fmt_views(f"solution-{slug}", 500, 4200),
                        'category': '解决方案',
                    })

            if search_type in ('news', 'products', 'solutions'):
                all_results = [r for r in all_results if r.get('type') == search_type]

        total_results = len(all_results)
        page_size = 5
        total_pages = (total_results + page_size - 1) // page_size
        if total_pages < 1:
            total_pages = 0
        if total_pages and page > total_pages:
            page = total_pages
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        results = all_results[start_idx:end_idx] if (keyword_raw and total_results) else []

        search_time = round(max(0.01, time.perf_counter() - started), 2)
        return render_template(
            'search.html',
            keyword=escape_html(keyword_raw),
            results=results,
            total_results=total_results,
            search_time=search_time,
            page=page,
            total_pages=total_pages,
            search_type=search_type,
        )

    @app.route('/favicon.ico')
    def favicon():
        """处理 favicon 请求，减少 404 日志噪音。"""
        static_dir = app.static_folder or os.path.join(app.root_path, 'static')
        favicon_svg = os.path.join(static_dir, 'favicon.svg')
        favicon_ico = os.path.join(static_dir, 'favicon.ico')
        if os.path.exists(favicon_svg):
            return send_from_directory(static_dir, 'favicon.svg', mimetype='image/svg+xml')
        if os.path.exists(favicon_ico):
            return send_from_directory(static_dir, 'favicon.ico', mimetype='image/vnd.microsoft.icon')
        return ('', 204)


