/**
 * dashboard_data_flow.js
 * 仅负责：数据拉取、失败退避、主刷新流程编排
 */

const _dashboardApiHealth = Object.create(null);
const _dashboardWindowCache = Object.create(null);
let dashboardFetchInFlight = false;
const GEO_DATA_TIMEOUT_MS = 4200;
const GEO_DATA_BOOT_TIMEOUT_MS = 8000;

function notifyDashboardDataState(hasData) {
    try {
        if (typeof window !== 'undefined' && typeof window.__setDashboardDataState === 'function') {
            window.__setDashboardDataState({ hasData: !!hasData });
        }
    } catch (e) {}
}

function notifyDashboardDataStale(isStale) {
    try {
        if (typeof window !== 'undefined' && typeof window.__setDashboardDataStale === 'function') {
            window.__setDashboardDataStale(!!isStale);
        }
    } catch (e) {}
}

function notifyDashboardDataLoading(isLoading) {
    try {
        if (typeof window !== 'undefined' && typeof window.__setDashboardDataLoading === 'function') {
            window.__setDashboardDataLoading(!!isLoading);
        }
    } catch (e) {}
}

function getActiveWindowHours() {
    try {
        if (typeof window !== 'undefined' && typeof window.__getDashboardWindowHours === 'function') {
            const n = Number(window.__getDashboardWindowHours());
            if (Number.isFinite(n) && n > 0) return n;
        }
    } catch (e) {}
    return Number(DASHBOARD_DEFAULT_WINDOW_HOURS) || 24;
}

function getWindowCache(hours) {
    const key = String(Number(hours) || 24);
    return _dashboardWindowCache[key] || null;
}

function setWindowCache(hours, payload) {
    const key = String(Number(hours) || 24);
    _dashboardWindowCache[key] = {
        stats: payload?.stats || null,
        logs: Array.isArray(payload?.logs) ? payload.logs.slice() : [],
        geo: Array.isArray(payload?.geo) ? payload.geo.slice() : [],
        suspicious: Array.isArray(payload?.suspicious) ? payload.suspicious.slice() : [],
        sessions: Array.isArray(payload?.sessions) ? payload.sessions.slice() : [],
        updatedAt: Date.now()
    };
}

function getApiHealthState(key) {
    const k = String(key || 'unknown');
    if (!_dashboardApiHealth[k]) {
        _dashboardApiHealth[k] = {
            failCount: 0,
            backoffUntil: 0,
            lastWarnAt: 0
        };
    }
    return _dashboardApiHealth[k];
}

function fetchJsonWithTimeout(url, key, timeoutMs = DASHBOARD_API_TIMEOUT_MS, options = null) {
    const state = getApiHealthState(key || url);
    const opt = options && typeof options === 'object' ? options : {};
    const enableBackoff = opt.enableBackoff !== false;
    const failThreshold = Number.isFinite(Number(opt.failThreshold))
        ? Math.max(1, Number(opt.failThreshold))
        : Number(DASHBOARD_API_FAIL_THRESHOLD);
    const backoffMs = Number.isFinite(Number(opt.backoffMs))
        ? Math.max(1000, Number(opt.backoffMs))
        : Number(DASHBOARD_API_FAIL_BACKOFF_MS);
    const now = Date.now();
    if (enableBackoff && now < Number(state.backoffUntil || 0)) {
        return Promise.resolve({ code: -2, msg: 'backoff', data: null });
    }

    const controller = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    const timer = setTimeout(function() {
        try {
            if (controller) controller.abort();
        } catch (e) {}
    }, Math.max(200, Number(timeoutMs || DASHBOARD_API_TIMEOUT_MS)));

    return fetch(url, {
        cache: 'no-store',
        signal: controller ? controller.signal : undefined
    })
        .then(function(res) {
            if (!res.ok) throw new Error(`http_${res.status}`);
            return res.json();
        })
        .then(function(data) {
            state.failCount = 0;
            state.backoffUntil = 0;
            return data;
        })
        .catch(function(err) {
            state.failCount = Number(state.failCount || 0) + 1;
            if (enableBackoff && state.failCount >= failThreshold) {
                state.backoffUntil = Date.now() + backoffMs;
            }
            const t = Date.now();
            if ((t - Number(state.lastWarnAt || 0)) >= DASHBOARD_API_WARN_INTERVAL_MS) {
                const tag = (err && err.name === 'AbortError') ? 'timeout' : String(err || 'unknown');
                console.warn(`[dashboard_api] ${String(key || url)} failed:`, tag);
                state.lastWarnAt = t;
            }
            throw err;
        })
        .finally(function() {
            clearTimeout(timer);
        });
}

function fetchDashboardData() {
    if (typeof document !== 'undefined' && document.hidden) return;
    if (dashboardFetchInFlight) return;
    dashboardFetchInFlight = true;
    notifyDashboardDataLoading(true);
    // 数据源优先级：event_stats/event_logs/geo 为主，suspicious/session 为补充面板
    // 回退策略：优先同窗口缓存兜底；
    // 特例：近24小时无数据时，可回退到已有历史缓存（7天/30天）
    const windowHours = getActiveWindowHours();
    const requestWindowHours = Number(windowHours) || 24;
    let shouldRefetchAfterFinish = false;
    const cache = getWindowCache(windowHours);
    const logFetchLimit = Number(DASHBOARD_EVENT_LOG_FETCH_LIMIT) || 500;
    const hasWarmGeoCache =
        (Array.isArray(cache?.geo) && cache.geo.length > 0) ||
        (Array.isArray(lastGeoData) && lastGeoData.length > 0);
    const geoTimeout = hasWarmGeoCache ? GEO_DATA_TIMEOUT_MS : GEO_DATA_BOOT_TIMEOUT_MS;
    // 冷启动时不走退避，持续重试拿首批地理数据，避免地图长时间空白
    const geoBackoffEnabled = hasWarmGeoCache;

    const supplementalPromise = Promise.allSettled([
        fetchJsonWithTimeout(
            `/api/suspicious_requests?hours=${windowHours}`,
            `suspicious_requests_${windowHours}`
        ),
        fetchJsonWithTimeout(
            `/api/session_analysis?hours=${windowHours}`,
            `session_analysis_${windowHours}`
        )
    ]);

    Promise.allSettled([
        fetchJsonWithTimeout(`/api/get_event_stats?hours=${windowHours}`, `event_stats_${windowHours}`),
        fetchJsonWithTimeout(`/api/get_event_logs?limit=${logFetchLimit}&hours=${windowHours}`, `event_logs_${windowHours}`),
        fetchJsonWithTimeout(
            `/api/get_geo_data?hours=${windowHours}`,
            `geo_data_${windowHours}`,
            geoTimeout,
            { enableBackoff: geoBackoffEnabled }
        )
    ])
        .then(async (results) => {
            if (getActiveWindowHours() !== requestWindowHours) {
                shouldRefetchAfterFinish = true;
                return;
            }

            const eventStatsResp = results[0]?.status === 'fulfilled' ? results[0].value : null;
            const eventLogsResp = results[1]?.status === 'fulfilled' ? results[1].value : null;
            const geoResp = results[2]?.status === 'fulfilled' ? results[2].value : null;

            const hasEventStats = !!(eventStatsResp && eventStatsResp.code === 0 && eventStatsResp.data);
            const hasEventLogs = !!(eventLogsResp && eventLogsResp.code === 0 && Array.isArray(eventLogsResp.data));
            const hasGeo = !!(geoResp && geoResp.code === 0 && Array.isArray(geoResp.data));
            const allCoreApisOk = hasEventStats && hasEventLogs && hasGeo;
            let stale = false;
            let usedCoreCache = false;
            let usedHistoryWindowFallback = false;

            setDemoMode(false);

            let normalizedEventLogs = hasEventLogs ? normalizeEventLogs(eventLogsResp.data) : [];
            if (!hasEventLogs && Array.isArray(cache?.logs) && cache.logs.length > 0) {
                normalizedEventLogs = cache.logs.slice();
                usedCoreCache = true;
            }

            let geo = hasGeo ? geoResp.data : [];
            if (!hasGeo && Array.isArray(cache?.geo) && cache.geo.length > 0) {
                geo = cache.geo.slice();
                usedCoreCache = true;
            }

            let stats = null;
            if (hasEventStats) {
                stats = buildStatsFromEventStats(eventStatsResp.data, geo);
            } else if (cache?.stats) {
                stats = cache.stats;
                usedCoreCache = true;
            } else if (normalizedEventLogs.length > 0) {
                stats = buildStatsFromEventLogs(normalizedEventLogs, geo);
            }

            let hasAttackDataWindow = Number(stats?.total || 0) > 0 || normalizedEventLogs.length > 0;
            if ((!Array.isArray(geo) || geo.length === 0) && hasAttackDataWindow && Array.isArray(lastGeoData) && lastGeoData.length > 0) {
                geo = lastGeoData.slice();
            }

            let suspicious = Array.isArray(cache?.suspicious) ? cache.suspicious.slice() : [];
            let sessions = Array.isArray(cache?.sessions) ? cache.sessions.slice() : [];

            // 近24小时查询为空时，允许回退到已有历史缓存（先7天，再30天）
            const hasNoCurrentWindowData =
                Number(stats?.total || 0) <= 0 &&
                normalizedEventLogs.length === 0 &&
                (!Array.isArray(geo) || geo.length === 0);
            if (requestWindowHours === 24 && hasNoCurrentWindowData) {
                const historyCache = [getWindowCache(24 * 7), getWindowCache(24 * 30)].find(function(c) {
                    return !!(
                        Number(c?.stats?.total || 0) > 0 ||
                        (Array.isArray(c?.logs) && c.logs.length > 0) ||
                        (Array.isArray(c?.geo) && c.geo.length > 0)
                    );
                });
                if (historyCache) {
                    if (historyCache.stats) stats = historyCache.stats;
                    normalizedEventLogs = Array.isArray(historyCache.logs) ? historyCache.logs.slice() : [];
                    geo = Array.isArray(historyCache.geo) ? historyCache.geo.slice() : [];
                    suspicious = Array.isArray(historyCache.suspicious) ? historyCache.suspicious.slice() : suspicious;
                    sessions = Array.isArray(historyCache.sessions) ? historyCache.sessions.slice() : sessions;
                    usedCoreCache = true;
                    usedHistoryWindowFallback = true;
                    hasAttackDataWindow = Number(stats?.total || 0) > 0 || normalizedEventLogs.length > 0;
                }
            }

            if (stats) {
                updateStats(stats);
                updatePieChart(stats.by_type || {});
                updateTopList(stats.top_ips || []);
            } else {
                updateStats({ total: 0, by_type: {}, top_ips: [], unique_ips: 0 });
                updatePieChart({});
                updateTopList([]);
            }

            const logs = Array.isArray(normalizedEventLogs) ? normalizedEventLogs : [];
            // 先把当前窗口日志完整交给前端表格层，再由表格层执行“前N条+Web保底”裁剪
            const logsForTable = logs;
            updateLogsTable(logsForTable);
            const latestValue = logsForTable.length > 0 ? getLogOrderValue(logsForTable[0]) : 0;
            if (latestValue > lastLogId) {
                if (lastLogId > 0) triggerAttackFlash();
                lastLogId = latestValue;
            }

            if (Array.isArray(geo) && geo.length > 0) {
                lastGeoData = geo;
            } else if (!hasAttackDataWindow && allCoreApisOk && !usedCoreCache && !usedHistoryWindowFallback) {
                // 仅在“核心接口均成功且确认为空窗”时清空地图，避免接口抖动导致攻击点闪断
                lastGeoData = [];
            }
            updateMapCore(lastGeoData);
            updateSuspiciousRequests(suspicious);
            updateSessionAnalysis(sessions);

            stale = usedHistoryWindowFallback || (usedCoreCache && (!hasEventStats || !hasEventLogs || !hasGeo));
            notifyDashboardDataStale(stale);
            notifyDashboardDataLoading(false);
            const hasDataNow =
                Number(stats?.total || 0) > 0 ||
                logsForTable.length > 0 ||
                (Array.isArray(lastGeoData) && lastGeoData.length > 0) ||
                (Array.isArray(suspicious) && suspicious.length > 0) ||
                (Array.isArray(sessions) && sessions.length > 0);
            notifyDashboardDataState(hasDataNow);

            // 补充面板异步到齐后再增量刷新，不阻塞下一轮拉取
            supplementalPromise
                .then(function(supplementaryResults) {
                    if (getActiveWindowHours() !== requestWindowHours) return;
                    const suspiciousResp = supplementaryResults[0]?.status === 'fulfilled' ? supplementaryResults[0].value : null;
                    const sessionResp = supplementaryResults[1]?.status === 'fulfilled' ? supplementaryResults[1].value : null;
                    const hasSuspicious = !!(suspiciousResp && suspiciousResp.code === 0 && Array.isArray(suspiciousResp.data));
                    const hasSessions = !!(sessionResp && sessionResp.code === 0 && Array.isArray(sessionResp.data));

                    if (hasSuspicious) suspicious = suspiciousResp.data;
                    if (hasSessions) sessions = sessionResp.data;
                    if (!hasSuspicious && Array.isArray(cache?.suspicious) && cache.suspicious.length > 0) stale = true;
                    if (!hasSessions && Array.isArray(cache?.sessions) && cache.sessions.length > 0) stale = true;

                    updateSuspiciousRequests(suspicious);
                    updateSessionAnalysis(sessions);
                    notifyDashboardDataStale(stale);
                    const hasDataAfterSupplement =
                        Number(stats?.total || 0) > 0 ||
                        logsForTable.length > 0 ||
                        (Array.isArray(lastGeoData) && lastGeoData.length > 0) ||
                        (Array.isArray(suspicious) && suspicious.length > 0) ||
                        (Array.isArray(sessions) && sessions.length > 0);
                    notifyDashboardDataState(hasDataAfterSupplement);

                    setWindowCache(windowHours, {
                        stats: stats || null,
                        logs: normalizedEventLogs,
                        geo: lastGeoData,
                        suspicious,
                        sessions
                    });
                })
                .catch(function() {});
        })
        .catch(function(err) {
            console.error(err);
            notifyDashboardDataStale(true);
            notifyDashboardDataLoading(false);
        })
        .finally(() => {
            dashboardFetchInFlight = false;
            if (shouldRefetchAfterFinish) {
                setTimeout(fetchDashboardData, 0);
            }
        });
}

function refreshAllModules() {
    if (typeof document !== 'undefined' && document.hidden) return;
    fetchDashboardData();
}
