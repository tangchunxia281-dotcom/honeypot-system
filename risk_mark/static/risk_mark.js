/* 密标（Risk Mark）前端交互 —— 独立文件，可随 risk_mark/ 目录整体移除。
 *
 * 设计：脚本自行向页面注入"密标"入口与抽屉面板，不依赖 dashboard.js 的任何实现细节；
 * 同时对外暴露 window.RiskMark 接口，供 dashboard.js 或其他模块复用。
 *
 * 公开接口：
 *   window.RiskMark.open()               打开密标抽屉
 *   window.RiskMark.refresh()            刷新列表与统计
 *   window.RiskMark.isMarked(ip)         返回密标对象或 null（本地缓存）
 *   window.RiskMark.fetchMarks([ip,...]) 批量拉取密标，返回 Promise<{ip: mark|null}>
 */
(function () {
    'use strict';

    var API_BASE = '/api/risk_mark';
    var IP_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    var LEVEL_ORDER = ['low', 'medium', 'high', 'critical'];
    var LEVEL_TEXT = { low: '低危', medium: '中危', high: '高危', critical: '严重' };

    /* ---------- CSRF ---------- */
    function readCsrf() {
        try {
            var script = document.currentScript;
            if (script && script.dataset && script.dataset.csrf) {
                return script.dataset.csrf;
            }
        } catch (e) { /* 忽略：回退到表单读取 */ }
        var input = document.querySelector('input[name="csrf_token"]');
        return input ? (input.value || '') : '';
    }

    var CSRF = readCsrf();

    function csrfToken() {
        if (CSRF) { return CSRF; }
        CSRF = readCsrf();
        return CSRF;
    }

    /* ---------- 工具 ---------- */
    function escapeHtml(value) {
        return String(value === null || value === undefined ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function levelClass(level) {
        var text = String(level || '').toLowerCase();
        return LEVEL_ORDER.indexOf(text) >= 0 ? 'lvl-' + text : 'lvl-low';
    }

    function levelText(level) {
        var text = String(level || '').toLowerCase();
        return LEVEL_TEXT[text] || text || '未知';
    }

    function request(path, options) {
        options = options || {};
        var method = options.method || 'GET';
        var init = { method: method, credentials: 'same-origin', headers: {} };
        if (method === 'POST') {
            init.headers['X-CSRF-Token'] = csrfToken();
            init.headers['Content-Type'] = 'application/json';
            init.body = JSON.stringify(options.body || {});
        }
        return fetch(API_BASE + path, init).then(function (resp) {
            return resp.json().catch(function () {
                return { code: -1, msg: '响应格式异常', data: null };
            });
        });
    }

    /* ---------- 状态 ---------- */
    var state = {
        meta: null,
        items: [],
        stats: {},
        total: 0,
        tab: 'list',
        lastScan: null,
        markCache: {},
        pending: {}
    };

    var dom = {};

    /* ---------- DOM 构建 ---------- */
    function buildTrigger() {
        var host = document.querySelector('.status-indicator');
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'rm-trigger';
        btn.innerHTML = '🎯 密标 <span class="rm-trigger-count" style="display:none;">0</span>';
        btn.addEventListener('click', open);
        dom.trigger = btn;
        dom.triggerCount = btn.querySelector('.rm-trigger-count');
        if (host) {
            host.insertBefore(btn, host.firstChild);
        } else {
            btn.style.position = 'fixed';
            btn.style.top = '8px';
            btn.style.left = '12px';
            btn.style.zIndex = '1100';
            document.body.appendChild(btn);
        }
    }

    function buildDrawer() {
        var mask = document.createElement('div');
        mask.className = 'rm-mask';
        mask.addEventListener('click', close);

        var drawer = document.createElement('div');
        drawer.className = 'rm-drawer';
        drawer.innerHTML = [
            '<div class="rm-head">',
            '  <span class="rm-title">密标 · 风险对象标注</span>',
            '  <button type="button" class="rm-close">关闭</button>',
            '</div>',
            '<div class="rm-tabs">',
            '  <div class="rm-tab rm-active" data-tab="list">密标列表</div>',
            '  <div class="rm-tab" data-tab="create">新增密标</div>',
            '  <div class="rm-tab" data-tab="scan">风险识别</div>',
            '</div>',
            '<div class="rm-body" id="rmBody"></div>'
        ].join('');

        drawer.querySelector('.rm-close').addEventListener('click', close);
        Array.prototype.forEach.call(drawer.querySelectorAll('.rm-tab'), function (tab) {
            tab.addEventListener('click', function () { switchTab(tab.dataset.tab); });
        });

        dom.mask = mask;
        dom.drawer = drawer;
        dom.body = drawer.querySelector('#rmBody');
        document.body.appendChild(mask);
        document.body.appendChild(drawer);
    }

    function open() {
        dom.mask.classList.add('rm-show');
        dom.drawer.classList.add('rm-open');
        if (!state.meta) {
            loadMeta();
        }
        switchTab(state.tab || 'list');
    }

    function close() {
        dom.mask.classList.remove('rm-show');
        dom.drawer.classList.remove('rm-open');
    }

    function switchTab(tab) {
        state.tab = tab;
        Array.prototype.forEach.call(dom.drawer.querySelectorAll('.rm-tab'), function (node) {
            node.classList.toggle('rm-active', node.dataset.tab === tab);
        });
        if (tab === 'list') { loadList(); }
        else if (tab === 'create') { renderCreate(); }
        else { renderScan(); }
    }

    /* ---------- 数据加载 ---------- */
    function loadMeta() {
        return request('/meta').then(function (res) {
            if (res && res.code === 0) {
                state.meta = res.data || {};
                updateTriggerCount(state.meta.config || {});
            }
            return state.meta;
        });
    }

    function loadList() {
        dom.body.innerHTML = '<div class="rm-loading">加载中...</div>';
        var query = '?limit=200&status=';
        return request('/list' + query).then(function (res) {
            if (!res || res.code !== 0) {
                dom.body.innerHTML = '<div class="rm-empty">加载失败：' + escapeHtml((res && res.msg) || '未知错误') + '</div>';
                return;
            }
            var data = res.data || {};
            state.items = data.items || [];
            state.stats = data.stats || {};
            state.total = data.total || 0;
            state.items.forEach(function (item) { state.markCache[item.target_value] = item; });
            renderList();
            updateTriggerCount({ total: state.total });
        });
    }

    function refresh() {
        return Promise.all([loadMeta(), loadList()]);
    }

    function updateTriggerCount(config) {
        if (!dom.triggerCount) { return; }
        var total = 0;
        if (config && typeof config.total === 'number') {
            total = config.total;
        } else if (state.items) {
            total = state.items.length;
        }
        dom.triggerCount.textContent = String(total);
        dom.triggerCount.style.display = total > 0 ? '' : 'none';
    }

    /* ---------- 渲染：列表 ---------- */
    function renderStats() {
        var stats = state.stats || {};
        var html = '<div class="rm-stats">';
        html += '<div class="rm-stat"><b style="color:#00d4ff;">' + (state.total || 0) + '</b><span>密标总数</span></div>';
        LEVEL_ORDER.forEach(function (level) {
            var count = Number(stats[level] || 0);
            html += '<div class="rm-stat"><b class="' + levelClass(level) + '" style="color:inherit;">' + count +
                '</b><span>' + levelText(level) + '</span></div>';
        });
        html += '</div>';
        return html;
    }

    function renderCard(item) {
        var level = String(item.level || 'low');
        var metaBits = [];
        if (item.location) { metaBits.push('📍 ' + escapeHtml(item.location)); }
        if (item.source) { metaBits.push('来源 ' + escapeHtml(item.source)); }
        if (item.created_by) { metaBits.push('操作人 ' + escapeHtml(item.created_by)); }
        metaBits.push(escapeHtml(item.updated_at || item.created_at || ''));
        if (item.expires_at) {
            metaBits.push((item.expired ? '已过期 ' : '有效期至 ') + escapeHtml(item.expires_at));
        }
        var code = item.mark_code ? ' <span class="rm-chip">' + escapeHtml(item.mark_code) + '</span>' : '';
        return [
            '<div class="rm-card ' + levelClass(level) + '">',
            '  <div class="rm-card-top">',
            '    <span class="rm-target">' + escapeHtml(item.target_value) + '</span>',
            '    <span class="rm-chip ' + levelClass(level) + '">' + escapeHtml(item.level_label || levelText(level)) + '</span>',
            '  </div>',
            item.reason ? '  <div class="rm-reason">' + escapeHtml(item.reason) + '</div>' : '',
            '  <div class="rm-meta-row"><span>' + metaBits.join('</span><span>') + '</span>' + code + '</div>',
            '  <div class="rm-actions"><button type="button" class="rm-del" data-id="' + escapeHtml(item.id) + '">移除密标</button></div>',
            '</div>'
        ].join('');
    }

    function renderList() {
        var head = renderStats();
        head += '<div class="rm-actions" style="margin-bottom:10px;">' +
            '<button type="button" class="rm-btn rm-ghost" id="rmRefresh">刷新</button>' +
            '<button type="button" class="rm-btn rm-ghost" id="rmClearCache">重新同步标记</button>' +
            '</div>';
        if (!state.items.length) {
            dom.body.innerHTML = head + '<div class="rm-empty">暂无密标。可在"新增密标"页手工标注，或在"风险识别"页扫描近期事件。</div>';
        } else {
            dom.body.innerHTML = head + state.items.map(renderCard).join('');
        }
        var refreshBtn = dom.body.querySelector('#rmRefresh');
        if (refreshBtn) { refreshBtn.addEventListener('click', function () { loadList(); }); }
        var cacheBtn = dom.body.querySelector('#rmClearCache');
        if (cacheBtn) {
            cacheBtn.addEventListener('click', function () {
                state.markCache = {};
                state.items.forEach(function (item) { state.markCache[item.target_value] = item; });
                decorateAll();
                setMessage('已重新同步标记', true);
            });
        }
        Array.prototype.forEach.call(dom.body.querySelectorAll('.rm-del'), function (btn) {
            btn.addEventListener('click', function () { removeMark(btn.dataset.id); });
        });
    }

    function removeMark(id) {
        request('/remove', { method: 'POST', body: { id: id } }).then(function (res) {
            if (res && res.code === 0) {
                delete state.markCache[id];
                loadList();
            } else {
                setMessage((res && res.msg) || '移除失败', false);
            }
        });
    }

    /* ---------- 渲染：新增 ---------- */
    function renderCreate() {
        var meta = state.meta || {};
        var levels = meta.levels || [];
        var targets = meta.target_types || [];
        var levelOptions = levels.map(function (item) {
            return '<option value="' + escapeHtml(item.value) + '">' + escapeHtml(item.label) + '</option>';
        }).join('');
        var targetOptions = targets.map(function (item) {
            return '<option value="' + escapeHtml(item.value) + '">' + escapeHtml(item.label) + '</option>';
        }).join('');

        dom.body.innerHTML = [
            '<div class="rm-tip">密标用于长期锁定关注对象。同一对象重复标注会覆盖旧密标。</div>',
            '<div class="rm-field"><label>对象类型</label><select id="rmType">' + targetOptions + '</select></div>',
            '<div class="rm-field"><label>对象值（如 1.2.3.4 / 会话 ID / 账号）</label><input id="rmValue" type="text" placeholder="必填" autocomplete="off"></div>',
            '<div class="rm-row">',
            '  <div class="rm-field"><label>密级</label><select id="rmLevel">' + levelOptions + '</select></div>',
            '  <div class="rm-field"><label>密标编号（可选）</label><input id="rmCode" type="text" placeholder="如 JB-2026-001" autocomplete="off"></div>',
            '</div>',
            '<div class="rm-row">',
            '  <div class="rm-field"><label>有效期（天，0=长期）</label><input id="rmTtl" type="number" min="0" step="1" value="0"></div>',
            '  <div class="rm-field"><label>操作人（可选）</label><input id="rmBy" type="text" placeholder="默认取当前登录账号" autocomplete="off"></div>',
            '</div>',
            '<div class="rm-field"><label>标注原因</label><textarea id="rmReason" placeholder="例如：持续暴力破解、SQL 注入、敏感文件探测"></textarea></div>',
            '<div class="rm-actions">',
            '  <button type="button" class="rm-btn" id="rmSubmit">保存密标</button>',
            '  <button type="button" class="rm-btn rm-ghost" id="rmReset">清空</button>',
            '</div>',
            '<div class="rm-msg" id="rmMsg"></div>'
        ].join('');

        var msg = dom.body.querySelector('#rmMsg');
        dom.body.querySelector('#rmSubmit').addEventListener('click', function () { submitCreate(msg); });
        dom.body.querySelector('#rmReset').addEventListener('click', function () {
            ['rmValue', 'rmCode', 'rmReason', 'rmBy'].forEach(function (id) {
                var node = dom.body.querySelector('#' + id);
                if (node) { node.value = ''; }
            });
            var ttl = dom.body.querySelector('#rmTtl');
            if (ttl) { ttl.value = '0'; }
        });
    }

    function submitCreate(msgNode) {
        var typeNode = dom.body.querySelector('#rmType');
        var valueNode = dom.body.querySelector('#rmValue');
        var levelNode = dom.body.querySelector('#rmLevel');
        var codeNode = dom.body.querySelector('#rmCode');
        var ttlNode = dom.body.querySelector('#rmTtl');
        var byNode = dom.body.querySelector('#rmBy');
        var reasonNode = dom.body.querySelector('#rmReason');

        var value = valueNode ? valueNode.value.trim() : '';
        if (!value) {
            writeMessage(msgNode, '请填写标注对象', false);
            return;
        }
        var payload = {
            target_type: typeNode ? typeNode.value : 'ip',
            target_value: value,
            level: levelNode ? levelNode.value : 'medium',
            mark_code: codeNode ? codeNode.value.trim() : '',
            reason: reasonNode ? reasonNode.value.trim() : '',
            created_by: byNode ? byNode.value.trim() : '',
            ttl_days: ttlNode ? ttlNode.value : 0
        };
        request('/create', { method: 'POST', body: payload }).then(function (res) {
            if (res && res.code === 0) {
                writeMessage(msgNode, '密标已保存', true);
                state.markCache[value] = res.data || null;
                loadList().then(decorateAll);
            } else {
                writeMessage(msgNode, (res && res.msg) || '保存失败', false);
            }
        });
    }

    /* ---------- 渲染：风险识别 ---------- */
    function renderScan() {
        var detectors = (state.meta && state.meta.detectors) || [];
        var config = (state.meta && state.meta.config) || {};
        var detHtml = detectors.length
            ? detectors.map(function (item) {
                return '<div class="rm-det"><span class="rm-det-name">' + escapeHtml(item.name) + '</span>' +
                    '<span class="rm-det-desc">' + escapeHtml(item.description || '') + '</span></div>';
            }).join('')
            : '<div class="rm-empty">未注册任何识别器</div>';

        dom.body.innerHTML = [
            '<div class="rm-tip">识别器是"风险识别"的扩展点：新增策略只需继承 BaseDetector 并注册，详见 risk_mark/README.md。</div>',
            '<div class="rm-stats">',
            '  <div class="rm-stat"><b style="color:#00d4ff;">' + detectors.length + '</b><span>识别器</span></div>',
            '  <div class="rm-stat"><b style="color:#ffa502;">' + (config.repeat_window_hours || 24) + '</b><span>统计窗口(h)</span></div>',
            '  <div class="rm-stat"><b style="color:#ff6b81;">' + (config.repeat_threshold || 5) + '</b><span>重复阈值</span></div>',
            '</div>',
            '<div class="rm-row">',
            '  <div class="rm-field"><label>扫描时间窗口（小时）</label><input id="rmHours" type="number" min="1" max="720" step="1" value="24"></div>',
            '  <div class="rm-field"><label>结果处理</label><select id="rmApply">',
            '    <option value="0">仅生成建议（不落标）</option>',
            '    <option value="1">直接落标</option>',
            '  </select></div>',
            '</div>',
            '<div class="rm-actions"><button type="button" class="rm-btn" id="rmScanBtn">开始识别</button></div>',
            '<div class="rm-msg" id="rmMsg"></div>',
            '<div style="margin:14px 0 6px;color:#00d4ff;">已注册识别器</div>',
            detHtml,
            '<div id="rmScanResult"></div>'
        ].join('');

        var msg = dom.body.querySelector('#rmMsg');
        dom.body.querySelector('#rmScanBtn').addEventListener('click', function () { runScan(msg); });
    }

    function runScan(msgNode) {
        var hoursNode = dom.body.querySelector('#rmHours');
        var applyNode = dom.body.querySelector('#rmApply');
        var hours = hoursNode ? parseInt(hoursNode.value, 10) || 24 : 24;
        var apply = applyNode ? applyNode.value === '1' : false;
        var button = dom.body.querySelector('#rmScanBtn');
        if (button) { button.disabled = true; }
        writeMessage(msgNode, '识别中...', true);
        request('/scan', { method: 'POST', body: { hours: hours, apply: apply } }).then(function (res) {
            if (button) { button.disabled = false; }
            if (!res || res.code !== 0) {
                writeMessage(msgNode, (res && res.msg) || '识别失败', false);
                return;
            }
            var data = res.data || {};
            state.lastScan = data;
            writeMessage(
                msgNode,
                '已扫描 ' + (data.scanned || 0) + ' 条事件，生成 ' + ((data.proposals || []).length) +
                ' 条建议，落标 ' + ((data.applied || []).length) + ' 条',
                true
            );
            renderScanResult(data);
            if ((data.applied || []).length) {
                state.markCache = {};
                loadList().then(decorateAll);
            }
        });
    }

    function renderScanResult(data) {
        var host = dom.body.querySelector('#rmScanResult');
        if (!host) { return; }
        var rows = (data.proposals || []).map(function (item) {
            return [
                '<div class="rm-card ' + levelClass(item.level) + '">',
                '  <div class="rm-card-top"><span class="rm-target">' + escapeHtml(item.target_value) + '</span>',
                '  <span class="rm-chip ' + levelClass(item.level) + '">' + escapeHtml(item.level_label || levelText(item.level)) + '</span></div>',
                '  <div class="rm-reason">' + escapeHtml(item.reason || '') + '</div>',
                '  <div class="rm-meta-row"><span>识别器 ' + escapeHtml(item.detector || '-') + '</span></div>',
                '</div>'
            ].join('');
        }).join('');
        host.innerHTML = '<div style="margin:14px 0 6px;color:#00d4ff;">识别建议</div>' +
            (rows || '<div class="rm-empty">未命中任何识别规则</div>');
    }

    function writeMessage(node, text, ok) {
        if (!node) { return; }
        node.textContent = text;
        node.className = 'rm-msg ' + (ok ? 'rm-ok' : 'rm-err');
    }

    function setMessage(text, ok) {
        var node = document.createElement('div');
        node.className = 'rm-msg ' + (ok ? 'rm-ok' : 'rm-err');
        node.textContent = text;
        node.style.position = 'fixed';
        node.style.right = '16px';
        node.style.bottom = '16px';
        node.style.zIndex = '1300';
        node.style.background = 'rgba(6,16,32,.95)';
        node.style.border = '1px solid rgba(0,212,255,.4)';
        node.style.padding = '6px 12px';
        node.style.borderRadius = '6px';
        document.body.appendChild(node);
        setTimeout(function () { node.remove(); }, 2200);
    }

    /* ---------- 实时面板打标（非侵入：只读 DOM 文本） ---------- */
    function collectIps(node) {
        var found = {};
        var text = (node && node.textContent) || '';
        var matches = text.match(IP_PATTERN) || [];
        matches.forEach(function (ip) { found[ip] = true; });
        return Object.keys(found);
    }

    function fetchMarks(ips) {
        var pending = ips.filter(function (ip) {
            return !(ip in state.markCache) && !state.pending[ip];
        });
        if (!pending.length) {
            return Promise.resolve(pickMarks(ips));
        }
        pending.forEach(function (ip) { state.pending[ip] = true; });
        var targets = pending.map(function (ip) { return 'ip:' + ip; }).join(',');
        return request('/check?targets=' + encodeURIComponent(targets)).then(function (res) {
            pending.forEach(function (ip) { delete state.pending[ip]; });
            if (res && res.code === 0 && res.data) {
                pending.forEach(function (ip) {
                    state.markCache[ip] = res.data['ip:' + ip] || null;
                });
            }
            return pickMarks(ips);
        }).catch(function () {
            pending.forEach(function (ip) { delete state.pending[ip]; });
            return pickMarks(ips);
        });
    }

    function pickMarks(ips) {
        var out = {};
        ips.forEach(function (ip) {
            if (state.markCache[ip]) { out[ip] = state.markCache[ip]; }
        });
        return out;
    }

    function badgeNode(mark) {
        var span = document.createElement('span');
        span.className = 'rm-badge';
        span.style.color = {
            low: '#2ed573', medium: '#ffa502', high: '#ff6b81', critical: '#ff2e4d'
        }[mark.level] || '#2ed573';
        span.textContent = '密标·' + (mark.level_label || levelText(mark.level));
        return span;
    }

    var debounceTimer = null;

    function scheduleDecorate() {
        if (debounceTimer) { clearTimeout(debounceTimer); }
        debounceTimer = setTimeout(function () { decorateAll(); }, 260);
    }

    function decorateAll() {
        var selectors = ['#logScroll', '#topList', '#suspiciousScroll', '#sessionScroll'];
        var hosts = selectors.map(function (sel) { return document.querySelector(sel); }).filter(Boolean);
        hosts.forEach(function (host) {
            var items = host.querySelectorAll('.log-item, .top-item, .rm-dec-target');
            var chips = [];
            Array.prototype.forEach.call(items, function (item) {
                var text = item.textContent || '';
                (text.match(IP_PATTERN) || []).forEach(function (ip) {
                    if (chips.indexOf(ip) < 0) { chips.push(ip); }
                });
            });
            if (!chips.length) { return; }
            fetchMarks(chips).then(function (marks) {
                if (!Object.keys(marks).length) { return; }
                Array.prototype.forEach.call(items, function (item) {
                    Array.prototype.forEach.call(item.querySelectorAll('.rm-badge'), function (n) { n.remove(); });
                    var text = item.textContent || '';
                    var hit = (text.match(IP_PATTERN) || []).filter(function (ip) { return marks[ip]; });
                    if (!hit.length) { return; }
                    item.appendChild(badgeNode(marks[hit[0]]));
                });
            });
        });
    }

    function watchLivePanels() {
        ['#logScroll', '#topList', '#suspiciousScroll', '#sessionScroll'].forEach(function (sel) {
            var node = document.querySelector(sel);
            if (!node || node.dataset.rmWatched) { return; }
            node.dataset.rmWatched = '1';
            try {
                new MutationObserver(scheduleDecorate).observe(node, { childList: true, subtree: true });
            } catch (e) { /* 环境不支持 MutationObserver 时静默降级 */ }
        });
        scheduleDecorate();
    }

    /* ---------- 初始化 ---------- */
    function init() {
        buildTrigger();
        buildDrawer();
        loadMeta().then(function () {
            return loadList();
        }).then(function () {
            watchLivePanels();
            setInterval(watchLivePanels, 8000);
        });
    }

    window.RiskMark = {
        open: open,
        close: close,
        refresh: refresh,
        isMarked: function (ip) { return state.markCache[ip] || null; },
        fetchMarks: fetchMarks
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
