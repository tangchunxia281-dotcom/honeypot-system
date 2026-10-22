/**
 * 网络威胁态势感知大屏 - 脚本
 */

// === 安全工具函数（XSS 防护） ===
function escapeHtml(text) {
  if (text == null) return '';
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function clearElement(el) {
    if (!el) return;
    while (el.firstChild) el.removeChild(el.firstChild);
}

function setCenteredMessage(el, text) {
    if (!el) return;
    clearElement(el);
    const msg = document.createElement('div');
    msg.style.display = 'flex';
    msg.style.alignItems = 'center';
    msg.style.justifyContent = 'center';
    msg.style.height = '100%';
    msg.style.color = '#666';
    msg.textContent = text;
    el.appendChild(msg);
}

function setEmptyMessage(el, text, paddingPx) {
    if (!el) return;
    clearElement(el);
    const msg = document.createElement('div');
    msg.style.color = '#6a8caf';
    msg.style.textAlign = 'center';
    msg.style.padding = `${paddingPx || 20}px`;
    msg.textContent = text;
    el.appendChild(msg);
}

function createSvgIcon(pathD) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.style.width = '14px';
    svg.style.height = '14px';
    svg.style.fill = 'currentColor';
    svg.style.verticalAlign = 'text-bottom';
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', pathD);
    svg.appendChild(path);
    return svg;
}

// === 全局变量 ===
let mapChart = null;

// SVG 图标定义 - 确保跨平台一致性 (Windows/Linux/Mac)
function getActivityIcon(type) {
    // SSH / Login -> Key
    if (type === 'SSH')
        return createSvgIcon("M21 10h-8.35A5.99 5.99 0 0 0 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6a5.99 5.99 0 0 0 5.65-4H17v4h4v-4h2v-4zM7 16c-2.21 0-4-1.79-4-4s1.79-4 4-4 4 1.79 4 4-1.79 4-4 4z");

    // Shell Command -> Terminal
    if (type === 'SHELL_CMD')
        return createSvgIcon("M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm-8 12.5v-1.5h7.5v1.5H12zm-3.5-3l-5-5h2.1l3.9 3.9-3.9 3.9H3.5l5-5z");

    // SCP -> Folder
    if (type === 'SCP-Capture')
        return createSvgIcon("M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z");

    // Wget -> Download
    if (type === 'WGET')
        return createSvgIcon("M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z");

    // Default Web -> Globe
    return createSvgIcon("M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z");
}
let pieChart = null;
let lastLogId = 0;
let displayedLogIds = new Set();
let lastGeoData = []; // 缓存地图数据
let logHoverFocusIp = ''; // 当前日志悬停聚焦IP
let mapPinnedFocusIp = ''; // 面板点击锁定聚焦IP
let mapHoverFocusGeoPoint = null; // 悬停补点的临时坐标（仅悬停期间生效）
let mapPinnedFocusGeoPoint = null; // 点击补点的临时坐标（仅锁定期间生效）
let _logHoverDebounceTimer = null;
let _pendingHoverIp = '';
let _pendingHoverSeed = null;
const _mapFocusGeoResolveState = Object.create(null); // ip -> {inFlight, cooldownUntil}
const _suspiciousHeaderHoverState = {
    el: null,
    timer: null,
    sourceItem: null,
    sourceKey: '',
    lastX: 0,
    lastY: 0,
};
let _panelDetailHoverStyleReady = false;
let geoLocationCacheByIp = Object.create(null); // IP -> 位置 文本缓存（抗瞬时接口抖动）

let lastTypeCounts = { SSH: 0, Web: 0 };
let isDemoMode = false;
const DASHBOARD_DEFAULT_WINDOW_HOURS = 24;
const DASHBOARD_WINDOW_OPTIONS = [24, 24 * 7, 24 * 30];
let dashboardWindowHours = DASHBOARD_DEFAULT_WINDOW_HOURS;
let dashboardDataIsStale = false;
let dashboardDataIsLoading = false;
const DASHBOARD_EVENT_LOG_FETCH_LIMIT = 500;
// 实时面板保留条数（滚动窗口）。提高后可减少“夜间日志白天被顶掉”的概率。
const DASHBOARD_LOG_TABLE_LIMIT = 500;
// 时间解析模式：beijing(无时区时间按北京时间原样显示，仅对带时区时间做换算)
const DB_TIME_PARSE_MODE = 'beijing';
// 展示统一为北京时间，避免受浏览器所在时区影响
const DASHBOARD_DISPLAY_TIMEZONE = 'Asia/Shanghai';
const DASHBOARD_POLL_INTERVAL_MS = 4000;
const DASHBOARD_POLL_INTERVAL_IDLE_MS = 12000;
const SYSTEM_POLL_INTERVAL_MS = 4000;
const SYSTEM_STATUS_TIMEOUT_MS = 3000;
const SYSTEM_STATUS_FAIL_BACKOFF_MS = 30000;
const SERVER_INFO_POLL_INTERVAL_MS = 15000;
const SERVER_INFO_TIMEOUT_MS = 3000;
const DASHBOARD_API_TIMEOUT_MS = 1800;
const DASHBOARD_API_FAIL_THRESHOLD = 3;
const DASHBOARD_API_FAIL_BACKOFF_MS = 30000;
const DASHBOARD_API_WARN_INTERVAL_MS = 15000;
const MAP_FOCUS_GEO_TIMEOUT_MS = 2500;
const MAP_RISK_COLORS = {
    high: '#ff4d4f',
    medium: '#ffa940',
    low: '#2ed573'
};
const MAP_HIGHLIGHT_COLOR = '#EAF8FF';
const MAP_HIGHLIGHT_SHADOW = 'rgba(127, 232, 255, 0.95)';
const MAP_TOP_EFFECT_LIMIT = 3;
const MAP_SYMBOL_MIN = 4;
const MAP_SYMBOL_MAX = 12;
const ENABLE_LOG_INSERT_ANIMATION = false;
let _systemStatusFailCount = 0;
let _systemStatusBackoffUntil = 0;
let _systemStatusLastWarnAt = 0;
let _serverInfoFetchInFlight = false;
let _serverInfoLastWarnAt = 0;
let _dashboardPollTimer = null;
let _dashboardCurrentPollMs = DASHBOARD_POLL_INTERVAL_MS;
let _dashboardHasData = true;
let _dashboardWindowSwitchPending = false;

function setDemoMode(enabled) {
    isDemoMode = !!enabled;
    const badge = document.getElementById('demoBadge');
    if (badge) badge.style.display = isDemoMode ? 'inline-block' : 'none';
}

function getDashboardWindowHours() {
    const n = Number(dashboardWindowHours);
    return DASHBOARD_WINDOW_OPTIONS.includes(n) ? n : DASHBOARD_DEFAULT_WINDOW_HOURS;
}

function updateWindowSwitcherUi() {
    const current = getDashboardWindowHours();
    document.querySelectorAll('.window-btn[data-hours]').forEach(btn => {
        const h = Number(btn?.dataset?.hours || 0);
        btn.classList.toggle('active', h === current);
        // 仅在“窗口切换进行中”禁用按钮，避免连续点击导致状态抖动
        btn.disabled = !!(_dashboardWindowSwitchPending && dashboardDataIsLoading);
    });
    const state = document.getElementById('windowState');
    if (state) {
        const label = current === 24 ? '近24小时' : (current === 168 ? '近7天' : '近30天');
        if (dashboardDataIsLoading) {
            state.textContent = '更新';
        } else if (dashboardDataIsStale) {
            state.textContent = '历史';
        } else {
            state.textContent = '实时';
        }
        state.removeAttribute('title');
    }
}

function setDashboardDataStale(isStale) {
    dashboardDataIsStale = !!isStale;
    updateWindowSwitcherUi();
}

function setDashboardDataLoading(isLoading) {
    dashboardDataIsLoading = !!isLoading;
    if (!dashboardDataIsLoading) {
        _dashboardWindowSwitchPending = false;
    }
    updateWindowSwitcherUi();
}

function resetWindowScopedViewState() {
    const scrollIds = ['topList', 'logScroll', 'suspiciousScroll', 'sessionScroll'];
    scrollIds.forEach(function(id) {
        const el = document.getElementById(id);
        if (el) el.scrollTop = 0;
    });
    // 切换时间窗口后重置日志渲染状态，避免旧窗口状态干扰新窗口
    displayedLogIds.clear();
    lastLogId = 0;
    logHoverFocusIp = '';
    mapPinnedFocusIp = '';
    mapHoverFocusGeoPoint = null;
    mapPinnedFocusGeoPoint = null;
    hideSuspiciousHeaderHover();
    Object.keys(_mapFocusGeoResolveState).forEach(function(k) { delete _mapFocusGeoResolveState[k]; });
    updateMapCore(lastGeoData);
}

function setDashboardWindowHours(hours) {
    const next = Number(hours);
    if (!DASHBOARD_WINDOW_OPTIONS.includes(next)) return;
    if (_dashboardWindowSwitchPending && dashboardDataIsLoading) return;
    if (next === getDashboardWindowHours()) return;
    dashboardWindowHours = next;
    _dashboardWindowSwitchPending = true;
    setDashboardDataLoading(true);
    setDashboardDataStale(false);
    updateWindowSwitcherUi();
    resetWindowScopedViewState();
    // 切换窗口后按新窗口策略重建轮询，再立刻拉一次
    applyDashboardPollByDataState(_dashboardHasData);
    refreshAllModules();
}

function initWindowSwitcher() {
    document.querySelectorAll('.window-btn[data-hours]').forEach(btn => {
        btn.addEventListener('click', function() {
            const h = Number(this?.dataset?.hours || 0);
            setDashboardWindowHours(h);
        });
    });
    updateWindowSwitcherUi();
}

function startDashboardPolling(intervalMs) {
    const nextMs = Math.max(1000, Number(intervalMs || DASHBOARD_POLL_INTERVAL_MS));
    _dashboardCurrentPollMs = nextMs;
    if (_dashboardPollTimer) {
        clearInterval(_dashboardPollTimer);
        _dashboardPollTimer = null;
    }
    _dashboardPollTimer = setInterval(refreshAllModules, nextMs);
}

function getWindowPollIntervalMs(hours) {
    const h = Number(hours);
    if (h === 24 * 30) return 12000;
    if (h === 24 * 7) return 8000;
    return 4000;
}

function applyDashboardPollByDataState(hasData) {
    const baseMs = getWindowPollIntervalMs(getDashboardWindowHours());
    const nextMs = hasData ? baseMs : Math.max(baseMs, DASHBOARD_POLL_INTERVAL_IDLE_MS);
    if (nextMs === _dashboardCurrentPollMs) return;
    startDashboardPolling(nextMs);
}

if (typeof window !== 'undefined') {
    window.__setDashboardDataState = function(state) {
        const hasData = !!(state && state.hasData);
        _dashboardHasData = hasData;
        applyDashboardPollByDataState(hasData);
    };
    window.__getDashboardWindowHours = getDashboardWindowHours;
    window.__setDashboardDataStale = setDashboardDataStale;
    window.__setDashboardDataLoading = setDashboardDataLoading;
}


// 国家/地区名称中文映射
const COUNTRY_NAME_MAP = {
    "Afghanistan": "阿富汗",
    "Albania": "阿尔巴尼亚",
    "Algeria": "阿尔及利亚",
    "American Samoa": "美属萨摩亚",
    "Andorra": "安道尔",
    "Angola": "安哥拉",
    "Anguilla": "安圭拉",
    "Antigua and Barbuda": "安提瓜和巴布达",
    "Argentina": "阿根廷",
    "Armenia": "亚美尼亚",
    "Aruba": "阿鲁巴",
    "Ashmore and Cartier Islands": "阿什莫尔和卡捷群岛",
    "Australia": "澳大利亚",
    "Austria": "奥地利",
    "Azerbaijan": "阿塞拜疆",
    "Bahamas": "巴哈马",
    "Bahrain": "巴林",
    "Bangladesh": "孟加拉国",
    "Barbados": "巴巴多斯",
    "Belarus": "白俄罗斯",
    "Belgium": "比利时",
    "Belize": "伯利兹",
    "Benin": "贝宁",
    "Bermuda": "百慕大",
    "Bhutan": "不丹",
    "Bolivia": "玻利维亚",
    "Bosnia and Herzegovina": "波斯尼亚和黑塞哥维那",
    "Botswana": "博茨瓦纳",
    "Brazil": "巴西",
    "British Indian Ocean Territory": "英属印度洋领地",
    "British Virgin Islands": "英属维尔京群岛",
    "Brunei": "文莱",
    "Bulgaria": "保加利亚",
    "Burkina Faso": "布基纳法索",
    "Burundi": "布隆迪",
    "Cambodia": "柬埔寨",
    "Cameroon": "喀麦隆",
    "Canada": "加拿大",
    "Cape Verde": "佛得角",
    "Cayman Islands": "开曼群岛",
    "Central African Republic": "中非共和国",
    "Chad": "乍得",
    "Chile": "智利",
    "China": "中国",
    "Christmas Island": "圣诞岛",
    "Colombia": "哥伦比亚",
    "Comoros": "科摩罗",
    "Cook Islands": "库克群岛",
    "Costa Rica": "哥斯达黎加",
    "Croatia": "克罗地亚",
    "Cuba": "古巴",
    "Curaçao": "库拉索",
    "Cyprus": "塞浦路斯",
    "Czechia": "捷克",
    "Democratic Republic of the Congo": "刚果民主共和国",
    "Denmark": "丹麦",
    "Djibouti": "吉布提",
    "Dominica": "多米尼克",
    "Dominican Republic": "多米尼加共和国",
    "East Timor": "东帝汶",
    "Ecuador": "厄瓜多尔",
    "Egypt": "埃及",
    "El Salvador": "萨尔瓦多",
    "Equatorial Guinea": "赤道几内亚",
    "Eritrea": "厄立特里亚",
    "Estonia": "爱沙尼亚",
    "Eswatini": "斯威士兰",
    "Ethiopia": "埃塞俄比亚",
    "Falkland Islands": "福克兰群岛",
    "Faroe Islands": "法罗群岛",
    "Fiji": "斐济",
    "Finland": "芬兰",
    "France": "法国",
    "French Polynesia": "法属波利尼西亚",
    "French Southern and Antarctic Lands": "法属南部和南极领地",
    "Gabon": "加蓬",
    "Gambia": "冈比亚",
    "Georgia": "格鲁吉亚",
    "Germany": "德国",
    "Ghana": "加纳",
    "Greece": "希腊",
    "Greenland": "格陵兰",
    "Grenada": "格林纳达",
    "Guam": "关岛",
    "Guatemala": "危地马拉",
    "Guernsey": "根西岛",
    "Guinea": "几内亚",
    "Guinea-Bissau": "几内亚比绍",
    "Guyana": "圭亚那",
    "Haiti": "海地",
    "Heard Island and McDonald Islands": "赫德岛和麦克唐纳群岛",
    "Honduras": "洪都拉斯",
    "Hungary": "匈牙利",
    "Iceland": "冰岛",
    "India": "印度",
    "Indonesia": "印度尼西亚",
    "Iran": "伊朗",
    "Iraq": "伊拉克",
    "Ireland": "爱尔兰",
    "Isle of Man": "马恩岛",
    "Israel": "以色列",
    "Italy": "意大利",
    "Ivory Coast": "科特迪瓦",
    "Jamaica": "牙买加",
    "Japan": "日本",
    "Jersey": "泽西岛",
    "Jordan": "约旦",
    "Kazakhstan": "哈萨克斯坦",
    "Kenya": "肯尼亚",
    "Kiribati": "基里巴斯",
    "Kosovo": "科索沃",
    "Kuwait": "科威特",
    "Kyrgyzstan": "吉尔吉斯斯坦",
    "Laos": "老挝",
    "Latvia": "拉脱维亚",
    "Lebanon": "黎巴嫩",
    "Lesotho": "莱索托",
    "Liberia": "利比里亚",
    "Libya": "利比亚",
    "Liechtenstein": "列支敦士登",
    "Lithuania": "立陶宛",
    "Luxembourg": "卢森堡",
    "Madagascar": "马达加斯加",
    "Malawi": "马拉维",
    "Malaysia": "马来西亚",
    "Maldives": "马尔代夫",
    "Mali": "马里",
    "Malta": "马耳他",
    "Marshall Islands": "马绍尔群岛",
    "Mauritania": "毛里塔尼亚",
    "Mauritius": "毛里求斯",
    "Mexico": "墨西哥",
    "Micronesia": "密克罗尼西亚",
    "Moldova": "摩尔多瓦",
    "Monaco": "摩纳哥",
    "Mongolia": "蒙古",
    "Montenegro": "黑山",
    "Montserrat": "蒙特塞拉特",
    "Morocco": "摩洛哥",
    "Mozambique": "莫桑比克",
    "Myanmar": "缅甸",
    "Namibia": "纳米比亚",
    "Nauru": "瑙鲁",
    "Nepal": "尼泊尔",
    "Netherlands": "荷兰",
    "New Caledonia": "新喀里多尼亚",
    "New Zealand": "新西兰",
    "Nicaragua": "尼加拉瓜",
    "Niger": "尼日尔",
    "Nigeria": "尼日利亚",
    "Niue": "纽埃",
    "Norfolk Island": "诺福克岛",
    "North Korea": "朝鲜",
    "North Macedonia": "北马其顿",
    "Northern Cyprus": "北塞浦路斯",
    "Northern Mariana Islands": "北马里亚纳群岛",
    "Norway": "挪威",
    "Oman": "阿曼",
    "Pakistan": "巴基斯坦",
    "Palau": "帕劳",
    "Palestine": "巴勒斯坦",
    "Panama": "巴拿马",
    "Papua New Guinea": "巴布亚新几内亚",
    "Paraguay": "巴拉圭",
    "Peru": "秘鲁",
    "Philippines": "菲律宾",
    "Pitcairn Islands": "皮特凯恩群岛",
    "Poland": "波兰",
    "Portugal": "葡萄牙",
    "Puerto Rico": "波多黎各",
    "Qatar": "卡塔尔",
    "Republic of the Congo": "刚果共和国",
    "Romania": "罗马尼亚",
    "Russia": "俄罗斯",
    "Rwanda": "卢旺达",
    "Saint Barthélemy": "圣巴泰勒米",
    "Saint Helena": "圣赫勒拿",
    "Saint Kitts and Nevis": "圣基茨和尼维斯",
    "Saint Lucia": "圣卢西亚",
    "Saint Martin (French part)": "法属圣马丁",
    "Saint Pierre and Miquelon": "圣皮埃尔和密克隆",
    "Saint Vincent and the Grenadines": "圣文森特和格林纳丁斯",
    "Samoa": "萨摩亚",
    "San Marino": "圣马力诺",
    "Saudi Arabia": "沙特阿拉伯",
    "Senegal": "塞内加尔",
    "Serbia": "塞尔维亚",
    "Seychelles": "塞舌尔",
    "Siachen Glacier": "锡亚琴冰川",
    "Sierra Leone": "塞拉利昂",
    "Singapore": "新加坡",
    "Sint Maarten (Dutch part)": "荷属圣马丁",
    "Slovakia": "斯洛伐克",
    "Slovenia": "斯洛文尼亚",
    "Solomon Islands": "所罗门群岛",
    "Somalia": "索马里",
    "Somaliland": "索马里兰",
    "South Africa": "南非",
    "South Georgia and the South Sandwich Islands": "南乔治亚和南桑威奇群岛",
    "South Korea": "韩国",
    "South Sudan": "南苏丹",
    "Spain": "西班牙",
    "Sri Lanka": "斯里兰卡",
    "Sudan": "苏丹",
    "Suriname": "苏里南",
    "Sweden": "瑞典",
    "Switzerland": "瑞士",
    "Syria": "叙利亚",
    "São Tomé and Príncipe": "圣多美和普林西比",
    "Tajikistan": "塔吉克斯坦",
    "Tanzania": "坦桑尼亚",
    "Thailand": "泰国",
    "Togo": "多哥",
    "Tonga": "汤加",
    "Trinidad and Tobago": "特立尼达和多巴哥",
    "Tunisia": "突尼斯",
    "Turkey": "土耳其",
    "Turkmenistan": "土库曼斯坦",
    "Turks and Caicos Islands": "特克斯和凯科斯群岛",
    "Tuvalu": "图瓦卢",
    "Uganda": "乌干达",
    "Ukraine": "乌克兰",
    "United Arab Emirates": "阿联酋",
    "United Kingdom": "英国",
    "United States": "美国",
    "United States Minor Outlying Islands": "美国本土外小岛屿",
    "United States Virgin Islands": "美属维尔京群岛",
    "Uruguay": "乌拉圭",
    "Uzbekistan": "乌兹别克斯坦",
    "Vanuatu": "瓦努阿图",
    "Vatican City": "梵蒂冈",
    "Venezuela": "委内瑞拉",
    "Vietnam": "越南",
    "Wallis and Futuna": "瓦利斯和富图纳",
    "Western Sahara": "西撒哈拉",
    "Yemen": "也门",
    "Zambia": "赞比亚",
    "Zimbabwe": "津巴布韦",
    "Åland Islands": "奥兰群岛",
    // 兼容别名
    "United States of America": "美国",
    "USA": "美国",
    "UK": "英国",
    "The Netherlands": "荷兰",
    "Taiwan": "中国台湾",
    "Taiwan, Province of China": "中国台湾",
    "Taiwan Province of China": "中国台湾",
    "Republic of China": "中国台湾",
    "ROC": "中国台湾",
    "中華民國": "中国台湾",
    "中华民国": "中国台湾",
    "Great Britain": "英国",
    "Britain": "英国",
    "England": "英国"
};

const LEGACY_GEO_TOKEN_MAP = {
    "People's Republic of China": "中国",
    "People’s Republic of China": "中国",
    "PRC": "中国",
    "Republic of China": "中国台湾",
    "ROC": "中国台湾",
    "中華民國": "中国台湾",
    "中华民国": "中国台湾",
    "Taiwan": "中国台湾",
    "Taiwan, Province of China": "中国台湾",
    "Taiwan Province of China": "中国台湾",
    "Taiwan Province": "台湾",
    "中国台湾省": "中国台湾",
    "台灣": "台湾",
    "台灣省": "台湾",
    "臺灣": "台湾",
    "臺灣省": "台湾",
    "Taipei": "台北",
    "Taipei City": "台北",
    "臺北": "台北",
    "臺北市": "台北",
    "台北市": "台北",
    "United Kingdom": "英国",
    "UK": "英国",
    "Great Britain": "英国",
    "Britain": "英国",
    "England": "英国",
    "London": "伦敦",
};

const TAIWAN_LOCATION_HINTS = new Set([
    '台北', '新北', '桃园', '台中', '台南', '高雄',
    '基隆', '新竹', '嘉义', '宜兰', '苗栗', '彰化',
    '南投', '云林', '屏东', '台东', '花莲', '澎湖',
    '金门', '连江', '台湾', '中国台湾'
]);

function cleanGeoText(value) {
    const text = String(value || '')
        .trim()
        .replace(/（/g, '(')
        .replace(/）/g, ')')
        .replace(/臺/g, '台')
        .replace(/\s+/g, ' ');
    return text.trim();
}

function hasCjkText(value) {
    return /[\u3400-\u9fff]/.test(String(value || ''));
}

function isLatinLocationToken(value) {
    const text = cleanGeoText(value);
    if (!text) return false;
    return /^[A-Za-z0-9 .,'()\-]+$/.test(text);
}

function lookupCaseInsensitiveMap(mapping, value) {
    const text = cleanGeoText(value);
    if (!text) return '';
    if (Object.prototype.hasOwnProperty.call(mapping, text)) return mapping[text];
    const lower = text.toLowerCase();
    for (const [key, alias] of Object.entries(mapping)) {
        if (lower === String(key || '').toLowerCase()) return alias;
    }
    return text;
}

function normalizeLegacyGeoToken(value) {
    let text = lookupCaseInsensitiveMap(LEGACY_GEO_TOKEN_MAP, value);
    if (!text) return '';
    if (text === '内网' || text === '本地' || text === '内网/本地') return '内网/本地';
    text = lookupCaseInsensitiveMap(COUNTRY_NAME_MAP, text);
    if (text.endsWith('省') && text.length <= 4) text = text.slice(0, -1);
    if (text.endsWith('市') && text.length <= 6) text = text.slice(0, -1);
    return text;
}

function buildNormalizedLocation(parts) {
    const tokens = (Array.isArray(parts) ? parts : [])
        .map(normalizeLegacyGeoToken)
        .filter(Boolean);
    if (!tokens.length) return '';
    if (tokens.some(function(part) { return part === '内网/本地' || part === '内网' || part === '本地'; })) {
        return '内网/本地';
    }
    let head = tokens[0];
    let tail = tokens[tokens.length - 1];
    const hasTaiwanHint = tokens.some(function(part) {
        return TAIWAN_LOCATION_HINTS.has(part);
    });
    if (head === '台湾') head = '中国台湾';
    if (head === '中国' && hasTaiwanHint) head = '中国台湾';
    if (tokens.length === 1) {
        if (head === '中国台湾') return head;
        if (hasTaiwanHint) return `中国台湾/${head}`;
        return head || '未知';
    }
    if (tail === '台湾' || tail === '中国台湾') return head || '未知';
    if (!tail || tail === '未知' || tail === head) return head || '未知';
    if (tail === '中国' && head !== '中国') return head;
    if (hasCjkText(head) && !hasCjkText(tail) && isLatinLocationToken(tail)) return head;
    return `${head}/${tail}`;
}

function normalizeLocationText(location) {
    const text = cleanGeoText(location);
    if (!text) return '';
    if (text === '内网' || text === '本地' || text === '内网/本地') return '内网/本地';
    const parts = text.replace(/\s*-\s*/g, '/').split('/').map(cleanGeoText).filter(Boolean);
    if (!parts.length) return '';
    return buildNormalizedLocation(parts) || '未知';
}

function toZhLoc(loc) {
    return normalizeLocationText(loc);
}

function formatServerLocation() {
    const city = cleanGeoText(serverInfo.city || '');
    const country = cleanGeoText(serverInfo.country || '');
    if (!city && !country) return '未知';
    if (city) {
        const normalizedCity = normalizeLocationText(city);
        if (normalizedCity && normalizedCity !== '未知') {
            if (!country || normalizedCity.includes('/')) return normalizedCity;
            return normalizeLocationText(`${country}/${normalizedCity}`);
        }
    }
    return normalizeLocationText(country) || '未知';
}

function getMapZoomLevel() {
    try {
        const opt = mapChart && mapChart.getOption ? mapChart.getOption() : null;
        const zoom = Number(opt?.geo?.[0]?.zoom || 1);
        return Number.isFinite(zoom) && zoom > 0 ? zoom : 1;
    } catch (e) {
        return 1;
    }
}

function classifyMapRiskLevel(eventCount, maxCount) {
    const c = Math.max(0, Number(eventCount) || 0);
    const m = Math.max(1, Number(maxCount) || 1);
    const ratio = c / m;
    if (c >= 30 || ratio >= 0.6) return 'high';
    if (c >= 10 || ratio >= 0.25) return 'medium';
    return 'low';
}

function getMapRiskColor(level) {
    return MAP_RISK_COLORS[level] || MAP_RISK_COLORS.low;
}

function mapRiskLabel(level) {
    if (level === 'high') return '高风险';
    if (level === 'medium') return '中风险';
    return '低风险';
}

function computeAttackSymbolSize(eventCount, topBoost = false) {
    const count = Math.max(1, Number(eventCount) || 1);
    const zoom = Math.max(1, getMapZoomLevel());
    const base = Math.min(MAP_SYMBOL_MAX, Math.max(MAP_SYMBOL_MIN, 3 + Math.log2(count + 1) * 2.2));
    const adjusted = base / Math.sqrt(zoom);
    const sized = adjusted * (topBoost ? 1.15 : 1.0);
    return Math.max(3, Math.min(14, sized));
}

function computeAttackLineWidth(eventCount, maxCount) {
    const c = Math.max(0, Number(eventCount) || 0);
    const m = Math.max(1, Number(maxCount) || 1);
    const ratio = Math.min(1, c / m);
    return 1.6 + ratio * 2.4;
}

// 服务器信息
let serverInfo = {
    ip: '正在检测...',
    latitude: 0,
    longitude: 0,
    city: '定位中...',
    country: '中国'
};
let serverInfoLoaded = false;
let _lastMapBaseRenderKey = '';
let _lastMapHoverRenderKey = '';

// === 初始化 ===
if (typeof document !== 'undefined' && document?.addEventListener) {
    document.addEventListener('DOMContentLoaded', function() {
        if (typeof window !== 'undefined') {
            if (window.__dashboardTimersStarted) return;
            window.__dashboardTimersStarted = true;
        }
        setDemoMode(false);
        initWindowSwitcher();
        initRiskTargets();
        updateTime();
        setInterval(updateTime, 1000);
        initCharts();
        refreshAllModules();
        fetchServerInfo();
        // 定时刷新服务器定位，避免首次请求失败/缓存导致一直不更新
        setInterval(fetchServerInfo, SERVER_INFO_POLL_INTERVAL_MS);
        setInterval(fetchSystemStatus, SYSTEM_POLL_INTERVAL_MS);
        startDashboardPolling(getWindowPollIntervalMs(getDashboardWindowHours()));
        document.addEventListener('visibilitychange', function() {
            if (document.hidden) return;
            fetchServerInfo();
            fetchSystemStatus();
            refreshAllModules();
        });

    });
}

function debounce(fn, wait) {
    let t = null;
    return function() {
        const ctx = this;
        const args = arguments;
        if (t) clearTimeout(t);
        t = setTimeout(function() { fn.apply(ctx, args); }, wait);
    };
}

function initCharts() {
    const mapContainer = document.getElementById('worldMap');
    if (mapContainer) {
        mapChart = echarts.init(mapContainer, null, { renderer: 'canvas' });
        // 加载本地世界地图JSON数据
        fetch('/static/js/world.json')
            .then(response => response.json())
            .then(worldJson => {
                echarts.registerMap('world', worldJson);
                initWorldMap();
            })
            .catch(err => {
                console.error('世界地图加载失败:', err);
                setCenteredMessage(mapContainer, '地图数据加载失败');
            });
    }

    const pieContainer = document.getElementById('pieChart');
    if (pieContainer) {
        pieChart = echarts.init(pieContainer);
        initPieChart();
        setupPieResizeObserver(pieContainer);
    }

    window.addEventListener('resize', debounce(function() {
        mapChart && mapChart.resize();
        pieChart && pieChart.resize();
    }, 150));
}

function setupPieResizeObserver(el) {
    if (!el || !pieChart) return;

    const doResize = function() {
        try { pieChart && pieChart.resize(); } catch (e) {}
    };

    if (typeof ResizeObserver !== 'undefined') {
        try {
            const ro = new ResizeObserver(() => doResize());
            ro.observe(el);
        } catch (e) {}
    }

    // 延迟触发 resize，确保首次布局稳定
    setTimeout(doResize, 0);
    setTimeout(doResize, 120);
    setTimeout(doResize, 600);
}

// === 初始化地图 ===
function initWorldMap() {
    const option = {
        backgroundColor: 'transparent',
        animationDurationUpdate: 0,
        tooltip: {
            trigger: 'item',
            backgroundColor: 'rgba(0, 20, 40, 0.9)',
            borderColor: '#0096ff',
            textStyle: { color: '#fff' },
            formatter: function(params) {
                if (params.componentType === 'geo') {
                    return '';
                }
                if ((params.seriesType === 'scatter' || params.seriesType === 'effectScatter') && params.data) {
                    if (params.seriesName === '蜜罐服务器') {
                        return `本机位置<br/>IP: ${escapeHtml(serverInfo.ip)}<br/>位置: ${escapeHtml(formatServerLocation())}`;
                    }
                    const loc = toZhLoc(params.data.location);
                    const risk = mapRiskLabel(String(params.data.riskLevel || 'low'));
                    return `IP: ${escapeHtml(params.data.ip)}<br/>位置: ${escapeHtml(loc)}<br/>攻击次数: ${params.data.value[2]}<br/>风险: ${risk}`;
                }
                if (params.seriesType === 'lines' && params.data) {
                    const loc = toZhLoc(params.data.sourceLocation);
                    const risk = mapRiskLabel(String(params.data.riskLevel || 'low'));
                    const count = Number(params.data.eventCount || 0);
                    return `攻击线<br/>来源IP: ${escapeHtml(params.data.sourceIp)}<br/>来源位置: ${escapeHtml(loc)}<br/>攻击次数: ${count}<br/>风险: ${risk}`;
                }
                return COUNTRY_NAME_MAP[params.name] || params.name;
            }
        },
        geo: {
            map: 'world',
            nameMap: COUNTRY_NAME_MAP,
            projection: {
                project: function(point) {
                    let lng = point[0];
                    let lat = point[1];
                    if (lat > 85) lat = 85;
                    if (lat < -85) lat = -85;
                    const x = lng;
                    const rad = lat * Math.PI / 180;
                    const y = -(180 / Math.PI) * Math.log(Math.tan((Math.PI / 4) + (rad / 2)));
                    return [x, y];
                },
                unproject: function(point) {
                    const x = point[0];
                    const y = point[1];
                    const lng = x;
                    const lat = (360 / Math.PI) * Math.atan(Math.exp(-y * (Math.PI / 180))) - 90;
                    return [lng, lat];
                }
            },
            layoutCenter: ['50%', '64%'],
            layoutSize: '112%',
            center: [0, 0],
            zoom: 1.10,
            roam: true,
            tooltip: { show: false },
            scaleLimit: { min: 1.10, max: 10 },
            label: { show: false },
            itemStyle: {
                areaColor: '#0a1f3d',
                borderColor: '#0096ff',
                borderWidth: 1,
                shadowColor: 'rgba(0, 150, 255, 0.5)',
                shadowBlur: 10
            },
            emphasis: {
                label: { show: true, color: '#fff', fontSize: 14 },
                itemStyle: { areaColor: '#1a3f6d' }
            }
        },
        series: [
            {
                id: 'map_scatter',
                name: '攻击源',
                type: 'scatter',
                coordinateSystem: 'geo',
                zlevel: 2,
                data: [],
                symbolSize: function(val) { return computeAttackSymbolSize(Number(val?.[2] || 1), false); },
                itemStyle: {
                    color: function(params) { return getMapRiskColor(params?.data?.riskLevel); },
                    opacity: 0.9
                },
                label: { show: false },
                emphasis: {
                    itemStyle: {
                        shadowBlur: 12,
                        shadowColor: 'rgba(255,255,255,0.35)'
                    }
                }
            },
            {
                id: 'map_focus_points',
                name: '重点攻击源',
                type: 'effectScatter',
                coordinateSystem: 'geo',
                zlevel: 3,
                data: [],
                symbolSize: function(val) { return computeAttackSymbolSize(Number(val?.[2] || 1), true); },
                showEffectOn: 'render',
                rippleEffect: { brushType: 'stroke', scale: 3.2, period: 4 },
                itemStyle: {
                    color: function(params) { return getMapRiskColor(params?.data?.riskLevel); },
                    shadowBlur: 16,
                    shadowColor: 'rgba(255, 107, 107, 0.45)'
                },
                label: { show: false }
            },
            {
                id: 'map_lines_low',
                name: '攻击线-低风险',
                type: 'lines',
                coordinateSystem: 'geo',
                zlevel: 2,
                data: [],
                polyline: false,
                lineStyle: { color: MAP_RISK_COLORS.low, width: 1.8, opacity: 0.52, curveness: 0.2 },
                effect: { show: false }
            },
            {
                id: 'map_lines_medium',
                name: '攻击线-中风险',
                type: 'lines',
                coordinateSystem: 'geo',
                zlevel: 2,
                data: [],
                polyline: false,
                lineStyle: { color: MAP_RISK_COLORS.medium, width: 1.8, opacity: 0.55, curveness: 0.2 },
                effect: { show: true, period: 6, trailLength: 0.15, symbol: 'arrow', symbolSize: 6, color: MAP_RISK_COLORS.medium }
            },
            {
                id: 'map_lines_high',
                name: '攻击线-高风险',
                type: 'lines',
                coordinateSystem: 'geo',
                zlevel: 3,
                data: [],
                polyline: false,
                lineStyle: { color: MAP_RISK_COLORS.high, width: 2.2, opacity: 0.8, curveness: 0.22 },
                effect: { show: true, period: 4, trailLength: 0.22, symbol: 'arrow', symbolSize: 8, color: MAP_RISK_COLORS.high }
            },
            {
                id: 'map_server',
                name: '蜜罐服务器',
                type: 'effectScatter',
                coordinateSystem: 'geo',
                zlevel: 10,
                z: 100,
                data: [],
                symbolSize: 16,
                showEffectOn: 'render',
                rippleEffect: { brushType: 'stroke', scale: 4.5, period: 3, color: '#ffd166' },
                itemStyle: { color: '#f8f9fa', shadowBlur: 18, shadowColor: 'rgba(255, 209, 102, 0.75)' },
                label: { show: true, position: 'right', formatter: '本机', color: '#ffd166', fontSize: 12, fontWeight: 'bold' }
            },
            {
                id: 'map_hover_line',
                name: '日志联动线',
                type: 'lines',
                coordinateSystem: 'geo',
                zlevel: 4,
                data: [],
                polyline: false,
                lineStyle: { color: MAP_HIGHLIGHT_COLOR, width: 3, opacity: 0.92, curveness: 0.22 },
                effect: { show: true, period: 3.2, trailLength: 0.28, symbol: 'arrow', symbolSize: 10, color: MAP_HIGHLIGHT_COLOR }
            },
            {
                id: 'map_hover_point',
                name: '日志联动点',
                type: 'effectScatter',
                coordinateSystem: 'geo',
                zlevel: 5,
                data: [],
                symbolSize: function(val) {
                    const count = Math.max(1, Number(val?.[2] || 1));
                    return Math.min(MAP_SYMBOL_MAX + 8, computeAttackSymbolSize(count, true) + 4);
                },
                showEffectOn: 'render',
                rippleEffect: { brushType: 'stroke', scale: 4.2, period: 3 },
                itemStyle: { color: MAP_HIGHLIGHT_COLOR, shadowBlur: 24, shadowColor: MAP_HIGHLIGHT_SHADOW },
                label: { show: false }
            }
        ]
    };

    if (mapChart) {
        mapChart.setOption(option, true);
        mapChart.off('georoam');
        mapChart.on('georoam', debounce(function() {
            updateMapCore(lastGeoData);
        }, 80));
        updateMapCore(lastGeoData);
    }
}

function initPieChart() {
    const option = {
        backgroundColor: 'transparent',
        tooltip: {
            trigger: 'item',
            backgroundColor: 'rgba(0, 20, 40, 0.9)',
            borderColor: '#0096ff',
            textStyle: { color: '#fff' },
            formatter: function(params) {
                const real = (params && params.data && typeof params.data.realValue === 'number') ? params.data.realValue : (params?.value ?? 0);
                return `${params.name}: ${real}`;
            }
        },
        legend: {
            orient: 'horizontal',
            bottom: 2,
            left: 'center',
            itemWidth: 12,
            itemHeight: 8,
            itemGap: 18,
            textStyle: { color: '#6a8caf', fontSize: 12 },
            formatter: function(name) {
                const v = lastTypeCounts[name] ?? 0;
                return `${name} ${v}`;
            }
        },
        series: [{
            name: '攻击类型',
            type: 'pie',
            radius: ['50%', '80%'],
            center: ['50%', '44%'],
            avoidLabelOverlap: true,
            stillShowZeroSum: true,
            minAngle: 8,
            itemStyle: { borderRadius: 5, borderColor: '#0a1428', borderWidth: 2 },
            label: { show: false },
            labelLine: { show: false },
            data: [{ value: 0, name: 'SSH', itemStyle: { color: '#ff6b6b' } }, { value: 0, name: 'Web', itemStyle: { color: '#2ed573' } }]
        }]
    };
    pieChart.setOption(option);
    setPieData(0, 0);
}

function setPieData(ssh, web) {
    if (!pieChart) return;
    const s = Number(ssh || 0);
    const w = Number(web || 0);
    lastTypeCounts = { SSH: s, Web: w };

    const total = s + w;
    const renderSSH = total === 0 ? 1 : s;
    const renderWeb = total === 0 ? 1 : w;

    pieChart.setOption({
        series: [{
            data: [
                { value: renderSSH, realValue: s, name: 'SSH', itemStyle: { color: '#ff6b6b' } },
                { value: renderWeb, realValue: w, name: 'Web', itemStyle: { color: '#2ed573' } }
            ]
        }]
    });
}

function updateTime() {
    const now = new Date();
    document.getElementById('currentTime').textContent = now.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function normalizeDateTimeText(v) {
    const text = String(v || '').trim();
    if (!text) return '';
    const normalized = text.replace('T', ' ');
    const hasTimezone = /([zZ]|[+\-]\d{2}:?\d{2})$/.test(normalized);
    const isoText = normalized.replace(' ', 'T');
    const localDt = new Date(isoText);
    const utcDt = new Date(`${isoText}Z`);
    let dt = null;

    if (DB_TIME_PARSE_MODE === 'beijing') {
        if (hasTimezone) {
            dt = new Date(isoText);
        } else {
            // 直接按北京时间文本使用，不做二次时区换算
            return normalized;
        }
    } else if (hasTimezone) {
        dt = new Date(isoText);
    } else {
        const nowMs = Date.now();
        const candidates = [localDt, utcDt].filter(d => Number.isFinite(d?.getTime?.()));
        if (candidates.length > 0) {
            const scored = candidates.map(d => {
                const ms = d.getTime();
                const inFuture = ms > (nowMs + 5 * 60 * 1000);
                const score = (inFuture ? 1e15 : 0) + Math.abs(nowMs - ms);
                return { d, score };
            }).sort((a, b) => a.score - b.score);
            dt = scored[0].d;
        }
    }
    if (Number.isFinite(dt?.getTime?.())) {
        return formatDateTimeInTimezone(dt, DASHBOARD_DISPLAY_TIMEZONE);
    }
    return normalized.replace('Z', '');
}

function isPrivateOrLoopbackIp(ip) {
    const text = String(ip || '').trim().toLowerCase();
    if (!text) return false;
    if (text === 'localhost' || text === '::1' || text === '0:0:0:0:0:0:0:1') return true;
    const v4 = text.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (!v4) {
        // IPv6 私有网段（fc00::/7、fd00::/8）与链路本地（fe80::/10）
        return text.startsWith('fc') || text.startsWith('fd') || text.startsWith('fe80:');
    }
    const a = Number(v4[1]);
    const b = Number(v4[2]);
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true;
    return false;
}

function normalizeLocation(location, ip) {
    const text = normalizeLocationText(location);
    if (text && text !== '未知') return text;
    return isPrivateOrLoopbackIp(ip) ? '内网/本地' : '未知';
}

function resolveLocation(primaryLocation, fallbackLocation, ip) {
    const primary = normalizeLocation(primaryLocation, ip);
    if (primary && primary !== '未知') return primary;
    return normalizeLocation(fallbackLocation, ip);
}

function mapSeverityToLevel(severity) {
    const s = String(severity || '').trim().toLowerCase();
    if (s === 'critical' || s === 'high' || s === '严重' || s === '高危') return 'high';
    if (s === 'medium' || s === 'med' || s === 'warn' || s === 'warning' || s === '警告') return 'medium';
    if (s === 'low' || s === 'info' || s === '提示') return 'low';
    return '';
}

function mapEventTypeToActivityType(eventType, source) {
    const evt = String(eventType || '').trim().toLowerCase();
    const src = String(source || '').trim().toLowerCase();
    // 先尊重后端来源，避免 Web 事件因命令关键词被误归类为 SSH
    if (src === 'web') return 'Web';
    if (src === 'ssh') return 'SSH';
    if (evt.includes('scp')) return 'SCP-Capture';
    if (evt.includes('shell') || evt.includes('cmd')) return 'SHELL_CMD';
    if (evt.includes('wget') || evt.includes('download')) return 'WGET';
    if (evt.includes('ssh_login')) return 'SSH';
    if (evt.startsWith('ssh_')) return 'SSH';
    if (evt.endsWith('_probe') || evt.endsWith('_attempt') || evt.startsWith('web_')) return 'Web';
    return src === 'ssh' ? 'SSH' : 'Web';
}

function normalizeActivityType(type) {
    const t = String(type || '').trim();
    if (!t) return 'Web';
    const upper = t.toUpperCase();
    if (upper.startsWith('SSH_')) return 'SSH';
    return t;
}

function toDisplayActivityType(type) {
    const normalized = normalizeActivityType(type);
    if (isSshActivityType(normalized)) return 'SSH';
    if (isWebActivityType(normalized)) return 'Web';
    return normalized || 'Web';
}

function isSshActivityType(type) {
    const t = normalizeActivityType(type).toUpperCase();
    return t === 'SSH' || t === 'SHELL_CMD' || t === 'SCP-CAPTURE';
}

function isWebActivityType(type) {
    const t = normalizeActivityType(type).toUpperCase();
    return t === 'WEB' || t === 'WGET';
}

function aggregateSshWebActivityCounts(byType) {
    const raw = (byType && typeof byType === 'object') ? byType : {};
    let sshCount = 0;
    let webCount = 0;
    Object.entries(raw).forEach(([type, count]) => {
        const n = Number(count || 0);
        if (n <= 0) return;
        if (isSshActivityType(type)) {
            sshCount += n;
            return;
        }
        if (isWebActivityType(type)) {
            webCount += n;
        }
    });
    return { sshCount, webCount };
}

function normalizeEventLogs(events) {
    if (!Array.isArray(events)) return [];
    return events.map((row, idx) => {
        const srcIp = row?.src_ip || '-';
        const location = resolveLocation(row?.location, geoLocationCacheByIp[srcIp], srcIp);
        if (location && location !== '未知') {
            geoLocationCacheByIp[srcIp] = location;
        }
        const source = String(row?.source || '').toLowerCase();
        const eventType = String(row?.event_type || '').toLowerCase();
        const activityType = normalizeActivityType(mapEventTypeToActivityType(eventType, source));
        const createTime = normalizeDateTimeText(row?.timestamp || row?.create_time || '');
        const idValue = (row && row.id != null) ? row.id : `${createTime}|${srcIp}|${eventType}|${idx}`;
        const payload = row?.payload ? String(row.payload) : `${eventType || 'unknown'} @ ${srcIp}`;
        return {
            id: idValue,
            src_ip: srcIp,
            activity_type: activityType,
            payload: payload,
            create_time: createTime,
            timestamp: createTime,
            source: source || '',
            severity: String(row?.severity || '').toLowerCase(),
            event_type: eventType,
            tags: row?.tags || '',
            raw_ref: row?.raw_ref || '',
            raw_request_id: row?.raw_request_id ?? null,
            extra: row?.extra ?? null,
            location,
        };
    });
}

function buildLocationByIpMap(geoPoints) {
    const geoList = Array.isArray(geoPoints) ? geoPoints : [];
    const locationByIp = Object.assign({}, geoLocationCacheByIp);
    geoList.forEach(item => {
        const ip = String(item?.src_ip || '').trim();
        if (!ip) return;
        const loc = normalizeLocation(item?.location, ip);
        if (!loc || loc === '未知') return;
        locationByIp[ip] = loc;
        geoLocationCacheByIp[ip] = loc;
    });
    return locationByIp;
}

function buildStatsFromEventStats(eventStats, geoPoints) {
    const data = (eventStats && typeof eventStats === 'object') ? eventStats : {};
    const bySource = (data.by_source && typeof data.by_source === 'object') ? data.by_source : {};
    const topTypes = Array.isArray(data.top_event_types) ? data.top_event_types : [];
    const total = Number(data.total || 0);
    const locationByIp = buildLocationByIpMap(geoPoints);

    let sshTotal = Number(bySource.ssh || 0);
    let webTotal = Number(bySource.web || 0);

    if (sshTotal === 0 && webTotal === 0 && topTypes.length > 0) {
        topTypes.forEach(item => {
            const count = Number(item?.count || 0);
            if (!count) return;
            const mapped = mapEventTypeToActivityType(item?.event_type || '', item?.source || '');
            if (isSshActivityType(mapped)) {
                sshTotal += count;
            } else if (isWebActivityType(mapped)) {
                webTotal += count;
            }
        });
    }

    const topIps = Array.isArray(data.top_ips)
        ? data.top_ips.map(item => ({
            src_ip: item?.src_ip || '-',
            count: Number(item?.count || 0),
            location: resolveLocation(item?.location, locationByIp[item?.src_ip || ''], item?.src_ip || '')
        }))
        : [];

    return {
        total: total,
        by_type: {
            SSH: sshTotal,
            Web: webTotal
        },
        top_ips: topIps,
        unique_ips: Number(data.unique_ips || topIps.length || 0)
    };
}

function buildStatsFromEventLogs(logs, geoPoints) {
    const list = Array.isArray(logs) ? logs : [];
    const locationByIp = buildLocationByIpMap(geoPoints);

    const byType = {};
    const ipCounter = {};
    list.forEach(log => {
        const activityType = normalizeActivityType(log?.activity_type || mapEventTypeToActivityType(log?.event_type, log?.source));
        byType[activityType] = (byType[activityType] || 0) + 1;
        const ip = String(log?.src_ip || '').trim();
        if (!ip) return;
        ipCounter[ip] = (ipCounter[ip] || 0) + 1;
        // 降级口径：优先复用日志记录里的位置，再回落到地图缓存
        const loc = resolveLocation(log?.location, locationByIp[ip], ip);
        if (loc && loc !== '未知') {
            locationByIp[ip] = loc;
            geoLocationCacheByIp[ip] = loc;
        }
    });

    const topIps = Object.keys(ipCounter)
        .map(ip => ({
            src_ip: ip,
            count: ipCounter[ip],
            location: normalizeLocation(locationByIp[ip], ip)
        }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);

    return {
        total: list.length,
        by_type: byType,
        top_ips: topIps,
        unique_ips: Object.keys(ipCounter).length
    };
}

function getLogOrderValue(log) {
    const n = Number(log?.id);
    if (Number.isFinite(n) && n > 0) return n;
    const ts = normalizeDateTimeText(log?.timestamp || log?.create_time || '');
    if (!ts) return 0;
    const ms = Date.parse(ts.replace(' ', 'T'));
    return Number.isFinite(ms) ? ms : 0;
}

function updateStats(stats) {
    animateNumber('totalAttacks', stats.total || 0);

    // 聚合统计：将细分类型归类到 SSH 或 Web
    const raw = stats.by_type || {};
    const agg = aggregateSshWebActivityCounts(raw);
    const sshCount = agg.sshCount;
    const webCount = agg.webCount;

    animateNumber('sshAttacks', sshCount);
    animateNumber('webAttacks', webCount);
    animateNumber('uniqueIPs', Number(stats.unique_ips || stats.top_ips?.length || 0));

    const badge = document.getElementById('demoBadge');
    if (badge) badge.style.display = isDemoMode ? 'inline-block' : 'none';
}

function animateNumber(elementId, targetValue) {
    const element = document.getElementById(elementId);
    if (!element) return;

    if (element.__timer) {
        clearInterval(element.__timer);
        element.__timer = null;
    }
    const currentValue = parseInt(element.textContent) || 0;
    if (targetValue - currentValue === 0) return;
    const steps = 20; const increment = (targetValue - currentValue) / steps;
    let current = currentValue; let step = 0;
    const timer = setInterval(() => { step++; current += increment; element.textContent = Math.round(current); if (step >= steps) { element.textContent = targetValue; clearInterval(timer); element.__timer = null; } }, 30);
    element.__timer = timer;
}

function updatePieChart(byType) {
    if (!byType) return;
    // 使用同样的聚合逻辑
    const agg = aggregateSshWebActivityCounts(byType);
    const sshCount = agg.sshCount;
    const webCount = agg.webCount;
    setPieData(sshCount, webCount);
}

function updateTopList(topIps) {
    const el = document.getElementById('topList');
    if (!el) return;
    const list = Array.isArray(topIps) ? topIps : (topIps?.items || topIps?.data || []);
    if (!list || list.length === 0) {
        if (isDemoMode) {
            const mock = [
                { src_ip: '45.33.32.156', count: 38, location: '美国/洛杉矶' },
                { src_ip: '103.235.46.39', count: 21, location: '中国/上海' },
                { src_ip: '185.199.108.153', count: 12, location: '荷兰/阿姆斯特丹' },
                { src_ip: '91.198.174.192', count: 9, location: '欧洲/未知' },
                { src_ip: '66.249.66.1', count: 7, location: '美国/谷歌(疑似爬虫)' }
            ];
            clearElement(el);
            mock.forEach((item, index) => {
                const rankColor = index === 0 ? '#ff4757' : (index === 1 ? '#ffa502' : (index === 2 ? '#2ed573' : '#6a8caf'));
                const row = document.createElement('div');
                row.className = 'top-item';

                const rank = document.createElement('span');
                rank.style.color = rankColor;
                rank.style.fontWeight = 'bold';
                rank.style.width = '20px';
                rank.textContent = String(index + 1);

                const ip = document.createElement('span');
                ip.className = 'ip';
                ip.style.flex = '1';
                ip.textContent = item.src_ip || '-';

                const loc = document.createElement('span');
                loc.style.color = '#6a8caf';
                loc.style.fontSize = '11px';
                loc.textContent = item.location || '未知';

                const count = document.createElement('span');
                count.className = 'count';
                count.style.marginLeft = '10px';
                count.textContent = `${item.count || 0}次`;

                row.append(rank, ip, loc, count);
                el.appendChild(row);
            });
        } else {
            setEmptyMessage(el, '暂无攻击来源', 12);
        }
        return;
    }
    clearElement(el);
    list.slice(0, 5).forEach((item, index) => {
        const rankColor = index === 0 ? '#ff4757' : (index === 1 ? '#ffa502' : (index === 2 ? '#2ed573' : '#6a8caf'));
        const row = document.createElement('div');
        row.className = 'top-item';

        const rank = document.createElement('span');
        rank.style.color = rankColor;
        rank.style.fontWeight = 'bold';
        rank.style.width = '20px';
        rank.textContent = String(index + 1);

        const ip = document.createElement('span');
        ip.className = 'ip';
        ip.style.flex = '1';
        ip.textContent = item.src_ip || '-';

        const loc = document.createElement('span');
        loc.style.color = '#6a8caf';
        loc.style.fontSize = '11px';
        loc.textContent = resolveLocation(item.location, geoLocationCacheByIp[item.src_ip || ''], item.src_ip);

        const count = document.createElement('span');
        count.className = 'count';
        count.style.marginLeft = '10px';
        count.textContent = `${item.count || 0}次`;

        row.append(rank, ip, loc, count);
        el.appendChild(row);
    });
}

function pad2(n) {
    return String(n).padStart(2, '0');
}

function formatDateTime(d) {
    return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
}

function formatDateTimeInTimezone(d, timezone) {
    try {
        const parts = new Intl.DateTimeFormat('zh-CN', {
            timeZone: timezone,
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        }).formatToParts(d);
        const get = (type) => {
            const value = parts.find(p => p.type === type)?.value || '';
            return type === 'year' ? value : value.padStart(2, '0');
        };
        const y = get('year');
        const m = get('month');
        const day = get('day');
        const h = get('hour');
        const min = get('minute');
        const s = get('second');
        if (y && m && day && h && min && s) {
            return `${y}-${m}-${day} ${h}:${min}:${s}`;
        }
    } catch (_) {}
    return formatDateTime(d);
}

function getMockLogs() {
    const now = new Date();
    const base = [
        { src_ip: '45.33.32.156', activity_type: 'SSH', payload: 'SSH 弱口令尝试: user=root' },
        { src_ip: '103.235.46.39', activity_type: 'Web', payload: '敏感文件探测: GET /.env' },
        { src_ip: '185.199.108.153', activity_type: 'Web', payload: '组件漏洞探测: GET /vendor/phpunit/.../eval-stdin.php' },
        { src_ip: '112.85.120.5', activity_type: 'SSH', payload: 'SSH 命令探测: whoami / uname -a' },
        { src_ip: '66.249.66.1', activity_type: 'WGET', payload: '爬虫/枚举: GET /wp-json/wp/v2/users' },
        { src_ip: '118.38.140.11', activity_type: 'SHELL_CMD', payload: 'SHELL 命令: cat /etc/passwd' },
        { src_ip: '91.198.174.192', activity_type: 'SCP-Capture', payload: 'SCP 捕获: upload tools.sh' }
    ];
    return base.map((item, idx) => ({
        id: 9000 - idx,
        src_ip: item.src_ip,
        activity_type: item.activity_type,
        payload: item.payload,
        create_time: formatDateTime(new Date(now.getTime() - idx * 7000))
    }));
}

function getMockGeoPoints() {
    const coordMap = {
        '45.33.32.156': { latitude: 34.0522, longitude: -118.2437, location: '美国/洛杉矶' },
        '103.235.46.39': { latitude: 31.2304, longitude: 121.4737, location: '中国/上海' },
        '185.199.108.153': { latitude: 52.3676, longitude: 4.9041, location: '荷兰/阿姆斯特丹' },
        '112.85.120.5': { latitude: 22.3193, longitude: 114.1694, location: '中国/香港' },
        '66.249.66.1': { latitude: 37.3861, longitude: -122.0839, location: '美国/山景城' },
        '118.38.140.11': { latitude: 37.5665, longitude: 126.9780, location: '韩国/首尔' },
        '91.198.174.192': { latitude: 52.3676, longitude: 4.9041, location: '荷兰/阿姆斯特丹' }
    };

    const ipCounter = {};
    getMockLogs().forEach(item => {
        const ip = String(item?.src_ip || '').trim();
        if (!ip) return;
        ipCounter[ip] = (ipCounter[ip] || 0) + 1;
    });

    return Object.keys(ipCounter)
        .map(ip => {
            const geo = coordMap[ip];
            if (!geo) return null;
            return {
                src_ip: ip,
                location: geo.location,
                latitude: geo.latitude,
                longitude: geo.longitude,
                event_count: ipCounter[ip]
            };
        })
        .filter(Boolean);
}

function getMockSuspiciousRequests() {
    return [
        { src_ip: '45.33.32.156', method: 'GET', path: '/.env', query_string: '', threat_score: 45 },
        { src_ip: '185.199.108.153', method: 'POST', path: '/graphql', query_string: 'query={__schema}', threat_score: 32 },
        { src_ip: '103.235.46.39', method: 'GET', path: '/actuator/env', query_string: '', threat_score: 28 },
        { src_ip: '66.249.66.1', method: 'GET', path: '/wp-json/wp/v2/users', query_string: 'per_page=100', threat_score: 22 }
    ];
}

function getMockSessionAnalysis() {
    return [
        { src_ip: '45.33.32.156', path_sequence: '/login|/admin|/admin/upload', request_count: 24, threat_level: 'high' },
        { src_ip: '103.235.46.39', path_sequence: '/actuator/health|/actuator/env|/actuator/beans', request_count: 17, threat_level: 'medium' },
        { src_ip: '112.85.120.5', path_sequence: '/login|/admin|/admin/audit/log', request_count: 9, threat_level: 'low' }
    ];
}

function buildLogIdentity(log) {
    if (log && log.id != null) return `id:${String(log.id)}`;
    const normalizedTime = normalizeDateTimeText(log?.timestamp || log?.create_time || '');
    const srcIp = String(log?.src_ip || '').trim();
    const activityType = normalizeActivityType(log?.activity_type || mapEventTypeToActivityType(log?.event_type, log?.source));
    const payload = String(log?.payload || '').trim();
    // 无数据库 id 时，使用稳定字段组合，避免每轮刷新误判为新记录
    return `f:${normalizedTime}|${srcIp}|${activityType}|${payload}`;
}

function parseExtraJsonMaybe(raw) {
    if (!raw) return null;
    if (typeof raw === 'object') return raw;
    const s = String(raw || '').trim();
    if (!s || s[0] !== '{' || s[s.length - 1] !== '}') return null;
    try {
        const parsed = JSON.parse(s);
        return (parsed && typeof parsed === 'object') ? parsed : null;
    } catch (e) {
        return null;
    }
}

function extractAiLogMeta(log) {
    const data = log && typeof log === 'object' ? log : {};
    const extra = parseExtraJsonMaybe(data.extra);
    const ai = extra && typeof extra.ai === 'object' ? extra.ai : null;
    if (!ai) return null;

    const attackType = String(
        ai.attack_type || ai.model_label || ''
    ).trim().toLowerCase();
    const allowedTypes = new Set([
        'xss',
        'sqli',
        'path_traversal',
        'sensitive_path',
        'scanner',
        'normal'
    ]);
    if (!allowedTypes.has(attackType)) return null;

    const confidence = Number(ai.confidence);
    if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
        return null;
    }

    const attackProb = Number(ai.attack_prob);
    if (!Number.isFinite(attackProb) || attackProb < 0 || attackProb > 1) {
        return null;
    }

    const aiPoints = Number(ai.ai_points);
    if (!Number.isFinite(aiPoints) || aiPoints < 0 || aiPoints > 25) {
        return null;
    }

    const isAttack = ai.is_attack === true;
    if (isAttack !== (attackType !== 'normal')) return null;

    const reasons = Array.isArray(ai.reasons)
        ? ai.reasons.map(value => String(value || '').trim()).filter(Boolean)
        : [];
    const signals = Array.isArray(ai.signals) ? ai.signals : [];

    return {
        attackType,
        isAttack,
        attackProb,
        aiPoints,
        confidence,
        reasons,
        signals,
        modelLabel: String(ai.model_label || '').trim(),
        applied: extra.ai_applied === true || aiPoints > 0,
        finalSource: String(extra.final_source || '').trim().toLowerCase(),
        highRisk: ai.high_risk === true
    };
}

function buildRealtimeLogHoverContent(log, displayType, levelText, normalizedTime, payloadFull) {
    const data = log && typeof log === 'object' ? log : {};
    const extra = parseExtraJsonMaybe(data.extra);
    const eventType = String(data.event_type || '').trim().toLowerCase();
    const srcIp = String(data.src_ip || '').trim();
    const locationText = resolveLocation(data.location, geoLocationCacheByIp[srcIp], srcIp);
    const lines = [
        ['时间', normalizedTime || '-'],
        ['来源IP', String(srcIp || '-')],
        ['攻击源位置', locationText || '未知'],
        ['入口类型', String(displayType || '-')],
        ['风险等级', String(levelText || '-')],
    ];

    const method = String(extra?.method || '').trim().toUpperCase();
    const path = String(extra?.path || '').trim();
    if (method || path) {
        lines.push(['请求目标', `${method || ''}${method && path ? ' ' : ''}${path || ''}`.trim()]);
    }

    const signals = Array.isArray(extra?.signals) ? extra.signals : [];
    if (signals.length) {
        const signalText = formatDetailBulletLines(signals);
        if (signalText) lines.push(['命中信号', signalText]);
    }

    const aiMeta = extractAiLogMeta(data);
    if (aiMeta) {
        lines.push([
            'AI判定',
            aiMeta.attackType === 'normal'
                ? '正常'
                : aiMeta.attackType.toUpperCase()
        ]);
        lines.push([
            'AI攻击概率',
            `${(aiMeta.attackProb * 100).toFixed(1)}%`
        ]);
        lines.push(['AI加分', `+${aiMeta.aiPoints}`]);
        lines.push([
            'AI置信度',
            `${(aiMeta.confidence * 100).toFixed(1)}%`
        ]);
        if (aiMeta.reasons.length) {
            lines.push(['AI原因', aiMeta.reasons.join('\n')]);
        }
        if (aiMeta.modelLabel) {
            lines.push(['模型标签', aiMeta.modelLabel]);
        }
        lines.push([
            '最终判定',
            aiMeta.finalSource === 'rule+ai'
                ? '规则 + AI 加分'
                : '原规则结果'
        ]);
    }

    const ua = String(extra?.ua || '').trim();
    if (ua) lines.push(['UA', ua]);

    const isSsh = String(displayType || '').trim().toUpperCase() === 'SSH';
    if (isSsh) {
        const username = String(extra?.username || '').trim();
        if (username) lines.push(['用户名', username]);

        const plainPassword = String(extra?.password || '').trim();
        if (plainPassword && (eventType === 'ssh_login_failed' || eventType === 'ssh_login_success')) {
            lines.push(['口令', plainPassword]);
        }

        const cmd = String(extra?.raw_command || extra?.command || data.command || '').trim();
        if (cmd && cmd !== payloadFull) lines.push(['命令', cmd]);
    }

    const rawRequestId = data.raw_request_id != null ? String(data.raw_request_id) : '';
    if (rawRequestId) lines.push(['原始请求编号', rawRequestId]);
    const rawRef = String(data.raw_ref || '').trim();
    if (rawRef) lines.push(['原始请求引用', rawRef]);

    const summaryText = String(payloadFull || '').trim();
    if (summaryText && summaryText !== '-') {
        const summaryCompare = normalizeDetailValueForCompare(summaryText);
        const duplicated = lines.some(function(pair) {
            return normalizeDetailValueForCompare(pair?.[1] || '') === summaryCompare;
        });
        if (!duplicated) {
            lines.push(['事件摘要', summaryText]);
        }
    }
    return { title: '攻击日志详情', lines };
}

function bindToggleFullText(el, shortText, fullText) {
    if (!el) return;
    const shortVal = String(shortText || '');
    const fullVal = String(fullText || '');
    if (!fullVal || shortVal === fullVal) {
        el.textContent = fullVal || shortVal;
        return;
    }
    let expanded = false;
    const apply = function() {
        el.textContent = expanded ? fullVal : shortVal;
        el.style.whiteSpace = expanded ? 'pre-wrap' : 'normal';
        el.style.maxHeight = expanded ? 'none' : '';
    };
    el.style.cursor = 'pointer';
    el.addEventListener('click', function(evt) {
        evt.preventDefault();
        evt.stopPropagation();
        expanded = !expanded;
        apply();
    });
    apply();
}

function createLogItem(log, logId, isNew) {
    const payloadFull = log.payload ? String(log.payload) : '-';
    const payloadShort = truncateMiddle(payloadFull, 52);
    const activityType = normalizeActivityType(log.activity_type || mapEventTypeToActivityType(log.event_type, log.source));
    const displayType = toDisplayActivityType(activityType);
    const typeIcon = getActivityIcon(displayType);

    const level = detectThreatLevel(activityType, log.payload || '', log.severity || '');
    const levelColor = level === 'high' ? '#ff4757' : (level === 'medium' ? '#ffa502' : '#2ed573');
    const levelText = level === 'high' ? '高风险' : (level === 'medium' ? '中风险' : '低风险');
    const normalizedTime = normalizeDateTimeText(log.timestamp || log.create_time || '');
    const time = normalizedTime ? normalizedTime.split(' ')[1] : '';

    const item = document.createElement('div');
    item.className = 'log-item';
    if (isNew && ENABLE_LOG_INSERT_ANIMATION) item.classList.add('new-item');
    item.style.borderLeft = `3px solid ${levelColor}`;
    item.dataset.logId = logId;
    item.dataset.srcIp = String(log.src_ip || '').trim();
    item.dataset.detailKey = `log:${String(logId || '')}`;
    item.dataset.panelLevel = 'log';

    const header = document.createElement('div');
    header.style.display = 'flex';
    header.style.justifyContent = 'space-between';
    header.style.fontSize = '11px';
    header.style.color = '#6a8caf';

    const timeSpan = document.createElement('span');
    timeSpan.textContent = time;

    const iconSpan = document.createElement('span');
    iconSpan.className = 'icon-span';
    iconSpan.style.display = 'flex';
    iconSpan.style.alignItems = 'center';
    iconSpan.style.gap = '4px';
    if (typeIcon) iconSpan.appendChild(typeIcon);
    const typeText = document.createElement('span');
    typeText.textContent = displayType || 'Web';
    iconSpan.appendChild(typeText);

    header.append(timeSpan, iconSpan);

    const ipDiv = document.createElement('div');
    ipDiv.style.color = '#00d4ff';
    ipDiv.style.fontSize = '12px';
    ipDiv.style.margin = '3px 0';
    ipDiv.textContent = log.src_ip || '-';

    const aiMeta = extractAiLogMeta(log);
    let aiDiv = null;
    if (aiMeta) {
        aiDiv = document.createElement('div');
        aiDiv.style.display = 'inline-flex';
        aiDiv.style.alignItems = 'center';
        aiDiv.style.margin = '0 0 3px 0';
        aiDiv.style.padding = '1px 6px';
        aiDiv.style.borderRadius = '8px';
        aiDiv.style.fontSize = '10px';
        aiDiv.style.fontWeight = '600';
        aiDiv.style.width = 'fit-content';

        const aiDisplayType = aiMeta.attackType === 'normal'
            ? 'Normal'
            : aiMeta.attackType.toUpperCase();

        if (aiMeta.isAttack && aiMeta.applied) {
            aiDiv.textContent =
                `AI ${aiDisplayType} +${aiMeta.aiPoints}`;
            aiDiv.style.color = '#00d4ff';
            aiDiv.style.background = 'rgba(0, 212, 255, 0.12)';
            aiDiv.style.border = '1px solid rgba(0, 212, 255, 0.45)';
        } else if (!aiMeta.isAttack) {
            aiDiv.textContent =
                `AI Normal +${aiMeta.aiPoints}`;
            aiDiv.style.color = '#2ed573';
            aiDiv.style.background = 'rgba(46, 213, 115, 0.10)';
            aiDiv.style.border = '1px solid rgba(46, 213, 115, 0.35)';
        } else {
            aiDiv.textContent =
                `AI ${aiDisplayType} +0`;
            aiDiv.style.color = '#ffa502';
            aiDiv.style.background = 'rgba(255, 165, 2, 0.10)';
            aiDiv.style.border = '1px solid rgba(255, 165, 2, 0.35)';
        }
    }

    const payloadDiv = document.createElement('div');
    payloadDiv.style.color = '#888';
    payloadDiv.style.fontSize = '100%';
    payloadDiv.style.wordBreak = 'break-word';
    payloadDiv.style.overflowWrap = 'anywhere';
    payloadDiv.textContent = payloadShort;

    const hoverContent = buildRealtimeLogHoverContent(log, displayType, levelText, normalizedTime, payloadFull);

    item.append(header, ipDiv);
    if (aiDiv) item.appendChild(aiDiv);
    item.appendChild(payloadDiv);
    bindLogMapHover(item);
    bindPanelDetailHover(item, function() { return hoverContent; });
    return item;
}

function setMapHoverFocusByIpDebounced(ip, delayMs = 120, seedSource = null) {
    const nextIp = String(ip || '').trim();
    _pendingHoverIp = nextIp;
    _pendingHoverSeed = seedSource || null;
    if (_logHoverDebounceTimer) {
        clearTimeout(_logHoverDebounceTimer);
        _logHoverDebounceTimer = null;
    }
    _logHoverDebounceTimer = setTimeout(function() {
        _logHoverDebounceTimer = null;
        if (_pendingHoverIp === logHoverFocusIp) return;
        setMapHoverFocusByIp(_pendingHoverIp, _pendingHoverSeed);
    }, Math.max(0, Number(delayMs) || 0));
}

function buildGeoPointSeed(source) {
    const raw = source && source.dataset ? source.dataset : source;
    const srcIp = String(raw?.srcIp || raw?.src_ip || raw?.ip || '').trim();
    if (!srcIp) return null;
    const lon = Number(raw?.longitude ?? raw?.lon);
    const lat = Number(raw?.latitude ?? raw?.lat);
    if (!Number.isFinite(lon) || !Number.isFinite(lat) || (lon === 0 && lat === 0)) {
        return null;
    }
    const location = resolveLocation(raw?.location, geoLocationCacheByIp[srcIp], srcIp);
    const eventCount = Math.max(
        1,
        Number(raw?.eventCount ?? raw?.event_count ?? raw?.request_count ?? 1) || 1
    );
    return {
        src_ip: srcIp,
        longitude: lon,
        latitude: lat,
        location,
        event_count: eventCount
    };
}

function setMapHoverFocusByIp(ip, seedSource) {
    const nextIp = String(ip || '').trim();
    if (nextIp === logHoverFocusIp) return;
    logHoverFocusIp = nextIp;
    mapHoverFocusGeoPoint = nextIp ? buildGeoPointSeed(seedSource) : null;
    updateMapCore(lastGeoData);
    if (nextIp && !hasGeoPointForIp(nextIp)) ensureFocusedIpGeo(nextIp);
}

function setMapPinnedFocusByIp(ip, seedSource) {
    const nextIp = String(ip || '').trim();
    const current = String(mapPinnedFocusIp || '').trim();
    const resolved = (nextIp && nextIp === current) ? '' : nextIp;
    if (resolved === current) return;
    // 锁定目标变化时清理旧的临时补点；取消时立即消失
    const seedPoint = resolved ? buildGeoPointSeed(seedSource) : null;
    mapPinnedFocusGeoPoint =
        (seedPoint && String(seedPoint?.src_ip || '').trim() === resolved)
            ? seedPoint
            : null;
    mapPinnedFocusIp = resolved;
    updateMapCore(lastGeoData);
    if (resolved && !hasGeoPointForIp(resolved)) ensureFocusedIpGeo(resolved);
}

function getMapFocusIp() {
    return String(logHoverFocusIp || mapPinnedFocusIp || '').trim();
}

function bindLogMapHover(item) {
    if (!item) return;
    item.addEventListener('mouseenter', function() {
        setMapHoverFocusByIpDebounced(item.dataset.srcIp || '', 120, item);
    });
    item.addEventListener('mouseleave', function() {
        setMapHoverFocusByIpDebounced('', 120);
    });
}

function ensureSuspiciousHeaderHoverEl() {
    if (_suspiciousHeaderHoverState.el) return _suspiciousHeaderHoverState.el;
    if (!_panelDetailHoverStyleReady) {
        const style = document.createElement('style');
        style.id = 'panelDetailHoverStyle';
        style.textContent = `
#suspiciousHeaderHover {
  scrollbar-width: thin;
  scrollbar-color: rgba(96, 181, 255, 0.72) rgba(10, 24, 44, 0.88);
}
#suspiciousHeaderHover::-webkit-scrollbar {
  width: 8px;
}
#suspiciousHeaderHover::-webkit-scrollbar-track {
  background: rgba(10, 24, 44, 0.88);
  border-radius: 999px;
}
#suspiciousHeaderHover::-webkit-scrollbar-thumb {
  background: linear-gradient(180deg, rgba(117, 204, 255, 0.9), rgba(49, 129, 255, 0.88));
  border-radius: 999px;
  border: 1px solid rgba(6, 18, 38, 0.95);
}
#suspiciousHeaderHover::-webkit-scrollbar-thumb:hover {
  background: linear-gradient(180deg, rgba(147, 221, 255, 0.95), rgba(75, 156, 255, 0.95));
}
`;
        document.head.appendChild(style);
        _panelDetailHoverStyleReady = true;
    }
    const el = document.createElement('div');
    el.id = 'suspiciousHeaderHover';
    el.style.position = 'fixed';
    el.style.zIndex = '9999';
    el.style.minWidth = '260px';
    el.style.maxWidth = '420px';
    el.style.padding = '10px 12px';
    el.style.border = '1px solid rgba(0, 150, 255, 0.35)';
    el.style.borderRadius = '8px';
    el.style.background = 'rgba(6, 18, 38, 0.95)';
    el.style.color = '#d7e8ff';
    el.style.fontSize = '12px';
    el.style.lineHeight = '1.45';
    el.style.boxShadow = '0 6px 20px rgba(0,0,0,0.35)';
    el.style.maxHeight = '70vh';
    el.style.overflowY = 'auto';
    el.style.overflowX = 'hidden';
    el.style.overscrollBehavior = 'contain';
    el.style.pointerEvents = 'auto';
    el.style.display = 'none';
    document.body.appendChild(el);
    _suspiciousHeaderHoverState.el = el;
    return el;
}

function hideSuspiciousHeaderHover() {
    if (_suspiciousHeaderHoverState.timer) {
        clearTimeout(_suspiciousHeaderHoverState.timer);
        _suspiciousHeaderHoverState.timer = null;
    }
    _suspiciousHeaderHoverState.sourceItem = null;
    _suspiciousHeaderHoverState.sourceKey = '';
    const el = _suspiciousHeaderHoverState.el;
    if (el) el.style.display = 'none';
    if (_logHoverDebounceTimer) {
        clearTimeout(_logHoverDebounceTimer);
        _logHoverDebounceTimer = null;
    }
    _pendingHoverIp = '';
    // 关闭详情时取消点击锁定的地图焦点，避免残留高亮
    if (String(mapPinnedFocusIp || '').trim()) {
        setMapPinnedFocusByIp('');
    }
}

function dismissPanelDetailIfSourceMatches(panelLevel) {
    const targetLevel = String(panelLevel || '').trim();
    if (!targetLevel) return;
    const sourceItem = _suspiciousHeaderHoverState.sourceItem;
    const sourceLevel = String(sourceItem?.dataset?.panelLevel || '').trim();
    if (sourceLevel && sourceLevel === targetLevel) {
        hideSuspiciousHeaderHover();
    }
}

function dismissPanelDetailIfSourceDetached() {
    const sourceItem = _suspiciousHeaderHoverState.sourceItem;
    const sourceKey = String(_suspiciousHeaderHoverState.sourceKey || '').trim();
    if (sourceItem && sourceItem.isConnected === false) {
        if (sourceKey) {
            const matched = Array.from(document.querySelectorAll('.log-item[data-detail-key]')).some(function(node) {
                return String(node?.dataset?.detailKey || '').trim() === sourceKey;
            });
            if (matched) return;
        }
        hideSuspiciousHeaderHover();
    }
}

function normalizeHoverLines(lines) {
    if (!Array.isArray(lines)) return [];
    return lines
        .map(function(pair) {
            const k = String(pair?.[0] || '').trim();
            const v = String(pair?.[1] || '');
            return [k, v];
        })
        .filter(function(pair) {
            return !!(pair[0] && pair[1] != null && String(pair[1]).trim() !== '');
        });
}

function formatAttackChainSteps(steps) {
    if (!Array.isArray(steps)) return '-';
    const safeSteps = steps
        .map(function(step) {
            return String(step || '').replace(/[\r\n\t]+/g, ' ').trim();
        })
        .filter(Boolean);
    if (!safeSteps.length) return '-';
    return safeSteps.map(function(step, idx) {
        return idx === 0 ? step : `→ ${step}`;
    }).join('\n');
}

function selectAttackChainPreviewSteps(steps, chainType) {
    if (!Array.isArray(steps)) return [];
    const safeSteps = steps
        .map(function(step) {
            return String(step || '').replace(/[\r\n\t]+/g, ' ').trim();
        })
        .filter(Boolean);
    if (!safeSteps.length) return [];
    const previewLimit = chainType === 'ssh' ? 7 : 4;
    if (chainType !== 'ssh' || safeSteps.length <= previewLimit) {
        return safeSteps.slice(-previewLimit);
    }
    const selected = [];
    const seen = new Set();
    const authPattern = /(认证失败\(|认证成功\(|触发封禁)/;
    const anchorPattern = /(认证成功\(|高危命令:|可疑命令:|命令:|触发封禁|SCP上传:|SCP拒绝:)/;
    function addIndex(idx) {
        if (selected.length >= previewLimit) return;
        if (idx < 0 || idx >= safeSteps.length || seen.has(idx)) return;
        selected.push(idx);
        seen.add(idx);
    }
    function addWindow(center, before, after) {
        for (let idx = center - before; idx <= center + after; idx += 1) {
            addIndex(idx);
        }
    }
    function addAuthContext(center, maxAuthSteps, lookback) {
        let found = 0;
        for (let idx = center - 1; idx >= 0 && (center - idx) <= lookback; idx -= 1) {
            if (authPattern.test(safeSteps[idx])) {
                addIndex(idx);
                found += 1;
                if (found >= maxAuthSteps) break;
                continue;
            }
            if (found > 0) break;
        }
    }
    const highValueIndexes = [];
    safeSteps.forEach(function(step, idx) {
        if (anchorPattern.test(step)) {
            highValueIndexes.push(idx);
        }
    });
    highValueIndexes.forEach(function(idx) {
        addWindow(idx, 1, 1);
        if (/高危命令:|可疑命令:|命令:|SCP上传:|SCP拒绝:/.test(safeSteps[idx])) {
            addAuthContext(idx, 3, 8);
        }
    });
    const candidates = [0, safeSteps.length - 1].concat(highValueIndexes);
    for (let idx = safeSteps.length - 1; idx >= 0; idx -= 1) {
        candidates.push(idx);
    }
    candidates.forEach(function(idx) {
        addIndex(idx);
    });
    return selected.sort(function(a, b) {
        return a - b;
    }).map(function(idx) {
        return safeSteps[idx];
    });
}

function normalizeSessionPathSteps(sess, useFullSteps = false) {
    const preferredSteps = useFullSteps ? sess?.path_steps_full : sess?.path_steps;
    if (Array.isArray(preferredSteps)) {
        return preferredSteps
            .map(function(step) {
                return String(step || '').replace(/[\r\n\t]+/g, ' ').trim();
            })
            .filter(Boolean);
    }
    if (useFullSteps && Array.isArray(sess?.path_steps)) {
        return sess.path_steps
            .map(function(step) {
                return String(step || '').replace(/[\r\n\t]+/g, ' ').trim();
            })
            .filter(Boolean);
    }
    return String(sess?.path_sequence || '')
        .split('|')
        .map(function(step) {
            return String(step || '').replace(/[\r\n\t]+/g, ' ').trim();
        })
        .filter(Boolean);
}

function buildSessionDetailKey(sess, chainType) {
    const type = String(chainType || 'web').trim().toLowerCase() === 'ssh' ? 'ssh' : 'web';
    const sessionId = String(sess?.session_id || '').trim();
    const srcIp = String(sess?.src_ip || '').trim();
    if (sessionId) {
        return `sess:${type}:${sessionId}`;
    }
    if (srcIp) {
        return `sess:${type}:${srcIp}`;
    }
    return `sess:${type}:unknown`;
}

function normalizeDetailValueForCompare(value) {
    return String(value || '').replace(/\s+/g, ' ').trim();
}

function formatDetailBulletLines(values) {
    if (!Array.isArray(values)) return '';
    const safeValues = values
        .map(function(value) {
            return String(value || '').replace(/[\r\n\t]+/g, ' ').trim();
        })
        .filter(Boolean);
    if (!safeValues.length) return '';
    return safeValues.map(function(value) {
        return `- ${value}`;
    }).join('\n');
}

function parseHeaderJsonMaybe(raw) {
    if (!raw) return null;
    if (typeof raw === 'object') return raw;
    const s = String(raw || '').trim();
    if (!s || s[0] !== '{' || s[s.length - 1] !== '}') return null;
    try {
        const parsed = JSON.parse(s);
        return (parsed && typeof parsed === 'object') ? parsed : null;
    } catch (e) {
        return null;
    }
}

function pickHeaderValue(headerObj, names) {
    const h = headerObj && typeof headerObj === 'object' ? headerObj : null;
    if (!h) return '';
    for (const name of (names || [])) {
        const target = String(name || '').toLowerCase();
        const key = Object.keys(h).find(function(k) {
            return String(k || '').toLowerCase() === target;
        });
        if (key) {
            const v = String(h[key] || '').trim();
            if (v) return v;
        }
    }
    return '';
}

function normalizeHeaderEntries(headerObj) {
    if (!headerObj || typeof headerObj !== 'object') return [];
    return Object.keys(headerObj).map(function(key) {
        return [String(key || ''), String(headerObj[key] || '').trim()];
    }).filter(function(pair) {
        return !!(pair[0] && pair[1]);
    });
}

function buildSuspiciousHeaderLines(req) {
    const data = req && typeof req === 'object' ? req : {};
    const headerObj = parseHeaderJsonMaybe(data.headers);
    const entries = normalizeHeaderEntries(headerObj);
    const lowerMap = Object.create(null);
    entries.forEach(function(pair) {
        const lk = String(pair[0] || '').toLowerCase();
        if (!lk || lowerMap[lk]) return;
        lowerMap[lk] = pair[1];
    });

    const userAgent = String(data.user_agent || pickHeaderValue(headerObj, ['User-Agent']) || '').trim();
    const host = String(pickHeaderValue(headerObj, ['Host']) || '').trim();
    const referer = String(data.referer || pickHeaderValue(headerObj, ['Referer']) || '').trim();
    const accept = String(pickHeaderValue(headerObj, ['Accept']) || '').trim();
    const origin = String(pickHeaderValue(headerObj, ['Origin']) || '').trim();
    const contentType = String(data.content_type || pickHeaderValue(headerObj, ['Content-Type']) || '').trim();
    const xff = String(
        pickHeaderValue(headerObj, ['X-Forwarded-For', 'X-Real-IP', 'Forwarded']) || ''
    ).trim();

    const lines = [];
    if (entries.length > 0) {
        lines.push(['已捕获头', `${entries.length}项`]);
    }
    if (host) lines.push(['Host', truncateMiddle(host, 120)]);
    if (contentType) lines.push(['Content-Type', truncateMiddle(contentType, 120)]);
    if (userAgent) lines.push(['User-Agent', truncateMiddle(userAgent, 160)]);
    if (referer) lines.push(['Referer', truncateMiddle(referer, 160)]);
    if (origin) lines.push(['Origin', truncateMiddle(origin, 120)]);
    if (xff) lines.push(['X-Forwarded-For', truncateMiddle(xff, 120)]);
    if (accept) lines.push(['Accept', truncateMiddle(accept, 120)]);

    // 如果关键头较少，补充其他常见头，避免悬浮框只有 UA 一行
    const preferredExtras = [
        ['accept-language', 'Accept-Language'],
        ['accept-encoding', 'Accept-Encoding'],
        ['connection', 'Connection'],
        ['x-requested-with', 'X-Requested-With'],
        ['sec-fetch-site', 'Sec-Fetch-Site'],
        ['sec-fetch-mode', 'Sec-Fetch-Mode'],
        ['sec-fetch-dest', 'Sec-Fetch-Dest'],
        ['cache-control', 'Cache-Control']
    ];
    const shownKeys = new Set(lines.map(function(pair) {
        return String(pair?.[0] || '').toLowerCase();
    }));
    preferredExtras.forEach(function(item) {
        const key = item[0];
        const label = item[1];
        const val = String(lowerMap[key] || '').trim();
        if (!val) return;
        if (shownKeys.has(label.toLowerCase())) return;
        if (lines.length >= 8) return;
        lines.push([label, truncateMiddle(val, 120)]);
        shownKeys.add(label.toLowerCase());
    });

    // 再兜底补充“其他头”最多 2 条
    if (lines.length < 8) {
        entries.forEach(function(pair) {
            const key = String(pair[0] || '').trim();
            const val = String(pair[1] || '').trim();
            const lk = key.toLowerCase();
            if (!key || !val) return;
            if (lk === 'cookie' || lk === 'authorization') return;
            if (shownKeys.has(lk)) return;
            if (lines.length >= 8) return;
            lines.push([key, truncateMiddle(val, 120)]);
            shownKeys.add(lk);
        });
    }
    return lines;
}

function isSshSuspiciousItem(req) {
    const data = req && typeof req === 'object' ? req : {};
    const method = String(data.method || '').trim().toUpperCase();
    if (method === 'SSH') return true;
    const path = String(data.path || '').trim();
    return path.indexOf('疑似命令') >= 0 || path.indexOf('可疑命令') >= 0;
}

function decodeUrlTextMaybe(text) {
    const raw = String(text || '');
    if (!raw) return '';
    try {
        return decodeURIComponent(raw.replace(/\+/g, '%20'));
    } catch (e) {
        return raw;
    }
}

function isSensitiveRequestFieldName(name) {
    const key = String(name || '').trim().toLowerCase();
    if (!key) return false;
    return /(pass(word|wd)?|pwd|secret|token|authorization|cookie|session(?:id)?|access[_-]?token|refresh[_-]?token|bearer|jwt|api[_-]?token)/i.test(key);
}

function redactSensitiveJsonValue(value, depth = 0) {
    if (depth >= 5) return '[已折叠]';
    if (Array.isArray(value)) {
        return value.slice(0, 50).map(function(item) {
            return redactSensitiveJsonValue(item, depth + 1);
        });
    }
    if (value && typeof value === 'object') {
        const out = {};
        Object.keys(value).slice(0, 50).forEach(function(key) {
            out[key] = isSensitiveRequestFieldName(key) ? '[已脱敏]' : redactSensitiveJsonValue(value[key], depth + 1);
        });
        return out;
    }
    return value;
}

function redactUrlEncodedBody(text) {
    return String(text || '').split('&').map(function(part) {
        const raw = String(part || '');
        if (!raw) return raw;
        const idx = raw.indexOf('=');
        if (idx < 0) return raw;
        const key = raw.slice(0, idx);
        const value = raw.slice(idx + 1);
        const keyDecoded = decodeUrlTextMaybe(key).trim();
        if (!isSensitiveRequestFieldName(keyDecoded)) return `${key}=${value}`;
        return `${key}=[已脱敏]`;
    }).join('&');
}

function redactSensitiveBodyText(text) {
    const body = String(text || '');
    const maskedKv = body.replace(
        /((?:^|[?&;,\s\r\n])(?:pass(?:word|wd)?|pwd|secret|token|authorization|cookie|session(?:id)?|access[_-]?token|refresh[_-]?token|bearer|jwt|api[_-]?token)\s*=)\s*([^&;\s\r\n]+)/gi,
        function(_, prefix) {
            return `${prefix}[已脱敏]`;
        }
    );
    return maskedKv.replace(
        /((?:"|')?(?:pass(?:word|wd)?|pwd|secret|token|authorization|cookie|session(?:id)?|access[_-]?token|refresh[_-]?token|bearer|jwt|api[_-]?token)(?:"|')?\s*[:=]\s*)("[^"]*"|'[^']*'|[^,\s\r\n}\]]+)/gi,
        '$1"[已脱敏]"'
    );
}

function isLikelyBinaryRequestBody(text, contentType) {
    const ct = String(contentType || '').toLowerCase();
    if (
        ct.includes('multipart/form-data') ||
        ct.includes('application/octet-stream') ||
        ct.includes('application/pdf') ||
        ct.includes('application/zip') ||
        ct.startsWith('image/') ||
        ct.startsWith('audio/') ||
        ct.startsWith('video/') ||
        ct.startsWith('font/')
    ) {
        return true;
    }
    const sample = String(text || '').slice(0, 256);
    let controlCount = 0;
    for (let i = 0; i < sample.length; i++) {
        const code = sample.charCodeAt(i);
        if (code === 0) return true;
        if ((code < 9 || (code > 13 && code < 32)) && code !== 27) {
            controlCount += 1;
            if (controlCount >= 4) return true;
        }
    }
    return false;
}

function summarizeSuspiciousRequestBody(req) {
    const data = req && typeof req === 'object' ? req : {};
    const bodyRaw = data.body;
    if (bodyRaw == null) return '';
    let bodyText = '';
    if (typeof bodyRaw === 'string') {
        bodyText = bodyRaw;
    } else if (typeof bodyRaw === 'object') {
        try {
            bodyText = JSON.stringify(bodyRaw, null, 2);
        } catch (e) {
            bodyText = String(bodyRaw || '');
        }
    } else {
        bodyText = String(bodyRaw || '');
    }
    bodyText = bodyText.replace(/\r\n/g, '\n').trim();
    if (!bodyText) return '';

    const headerObj = parseHeaderJsonMaybe(data.headers);
    const contentType = String(data.content_type || pickHeaderValue(headerObj, ['Content-Type']) || '').trim();
    const contentTypeLower = contentType.toLowerCase();
    if (contentTypeLower.includes('multipart/form-data')) {
        return '[multipart/form-data 或文件上传内容，已省略]';
    }
    if (isLikelyBinaryRequestBody(bodyText, contentTypeLower)) {
        return '[二进制或非文本请求体，已省略]';
    }

    let summary = bodyText;
    if (contentTypeLower.includes('application/x-www-form-urlencoded')) {
        summary = redactUrlEncodedBody(bodyText);
    } else if (contentTypeLower.includes('application/json') || /^[\[{]/.test(bodyText)) {
        try {
            const parsed = JSON.parse(bodyText);
            summary = JSON.stringify(redactSensitiveJsonValue(parsed), null, 2);
        } catch (e) {
            summary = redactSensitiveBodyText(bodyText);
        }
    } else {
        summary = redactSensitiveBodyText(bodyText);
    }

    summary = summary.replace(/\r\n/g, '\n').trim();
    if (!summary) return '';
    if (summary.length > 420) {
        summary = `${summary.slice(0, 420).trimEnd()}\n...[请求体已截断]`;
    }
    return summary;
}

function buildSuspiciousHoverContent(req) {
    const data = req && typeof req === 'object' ? req : {};
    const srcIp = String(data.src_ip || '-').trim() || '-';
    const srcLoc = resolveLocation(data.location, geoLocationCacheByIp[srcIp], srcIp);
    const sourceLines = [
        ['攻击源IP', srcIp],
        ['攻击源位置', srcLoc || '未知'],
    ];
    if (isSshSuspiciousItem(data)) {
        const cmdRaw = String(
            data.command || data.query_string || data.payload || ''
        );
        const cmd = cmdRaw.trim();
        const lines = sourceLines.slice();
        const behavior = String(data.path || '可疑命令行为').trim();
        if (behavior) lines.push(['行为类型', behavior]);
        if (cmd) lines.push(['命令', cmd]); // SSH 保留整条命令
        return { title: 'SSH 命令详情', lines };
    }
    const method = String(data.method || 'GET').trim().toUpperCase() || 'GET';
    const pathRaw = String(data.path || '/').trim() || '/';
    const qsRaw = String(data.query_string || '').trim();
    const qsClean = qsRaw.replace(/^\?+/, '');
    const urlRaw = `${pathRaw}${qsClean ? (pathRaw.includes('?') ? '&' : '?') + qsClean : ''}`;

    const pathDecoded = decodeUrlTextMaybe(pathRaw);
    const qsDecoded = decodeUrlTextMaybe(qsClean);
    const urlDecoded = `${pathDecoded}${qsDecoded ? (pathDecoded.includes('?') ? '&' : '?') + qsDecoded : ''}`;

    const baseLines = sourceLines.slice();
    const signals = Array.isArray(data.signals) ? data.signals : [];
    if (signals.length) {
        const signalText = formatDetailBulletLines(signals);
        if (signalText) baseLines.push(['判定依据', signalText]);
    }
    baseLines.push(['方法', method]);
    baseLines.push(['URL', urlRaw]);
    if (urlDecoded && urlDecoded !== urlRaw) {
        baseLines.push(['URL(解码)', urlDecoded]);
    }
    const bodySummary = summarizeSuspiciousRequestBody(data);
    const detailLines = baseLines.concat(buildSuspiciousHeaderLines(data));
    if (bodySummary && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
        detailLines.push(['请求体', bodySummary]);
    }
    return {
        title: '可疑请求详情',
        lines: detailLines
    };
}

function renderSuspiciousHeaderHover(lines, titleText) {
    const safeLines = normalizeHoverLines(lines);
    if (!safeLines.length) return;
    const el = ensureSuspiciousHeaderHoverEl();
    clearElement(el);
    const title = document.createElement('div');
    title.textContent = String(titleText || '详情');
    title.style.color = '#7fc4ff';
    title.style.fontWeight = '700';
    title.style.marginBottom = '6px';
    el.appendChild(title);
    safeLines.forEach(function(pair) {
        const fieldName = String(pair?.[0] || '');
        const isTrajectoryField = fieldName === '轨迹' || fieldName === '行为轨迹';
        const isPreformattedField =
            isTrajectoryField ||
            fieldName === '命令' ||
            fieldName === '内容' ||
            fieldName === '命中信号' ||
            fieldName === '判定依据' ||
            fieldName === '请求体' ||
            fieldName === '路径' ||
            fieldName === 'URL' ||
            fieldName === 'URL(解码)';
        const row = document.createElement('div');
        row.style.display = 'flex';
        row.style.gap = '6px';
        row.style.marginBottom = '2px';

        const k = document.createElement('span');
        k.textContent = `${fieldName}:`;
        k.style.flex = '0 0 102px';
        k.style.color = '#8fb7de';

        const v = document.createElement('span');
        v.textContent = String(pair?.[1] || '');
        v.style.color = '#e6f2ff';
        v.style.wordBreak = 'break-word';
        v.style.overflowWrap = 'anywhere';
        if (isPreformattedField) {
            v.style.whiteSpace = 'pre-wrap';
            if (!isTrajectoryField) {
                v.style.fontFamily = 'Consolas, Menlo, Monaco, monospace';
            }
        }
        if (isTrajectoryField) {
            row.style.display = 'block';
            row.style.marginBottom = '6px';
            k.style.display = 'block';
            k.style.flex = 'none';
            k.style.marginBottom = '4px';
            v.style.display = 'block';
            v.style.lineHeight = '1.55';
            v.style.paddingLeft = '2px';
        }

        row.append(k, v);
        el.appendChild(row);
    });
}

function moveSuspiciousHeaderHover(clientX, clientY) {
    const el = ensureSuspiciousHeaderHoverEl();
    const pad = 14;
    const vw = window.innerWidth || document.documentElement.clientWidth || 0;
    const vh = window.innerHeight || document.documentElement.clientHeight || 0;
    const rect = el.getBoundingClientRect();
    let left = Number(clientX || 0) + pad;
    let top = Number(clientY || 0) + pad;
    if (left + rect.width + 8 > vw) left = Math.max(8, (Number(clientX || 0) - rect.width - pad));
    if (top + rect.height + 8 > vh) top = Math.max(8, (Number(clientY || 0) - rect.height - pad));
    el.style.left = `${left}px`;
    el.style.top = `${top}px`;
}

let _panelDetailDismissBound = false;
function ensurePanelDetailDismissBinding() {
    if (_panelDetailDismissBound) return;
    _panelDetailDismissBound = true;
    document.addEventListener('click', function(evt) {
        const target = evt?.target;
        if (target && typeof target.closest === 'function' && target.closest('.log-item')) return;
        if (target && typeof target.closest === 'function' && target.closest('#suspiciousHeaderHover')) return;
        hideSuspiciousHeaderHover();
    }, true);
}

function bindPanelDetailHover(item, contentProvider) {
    if (!item || typeof contentProvider !== 'function') return;
    ensurePanelDetailDismissBinding();
    item.style.cursor = 'pointer';
    const detailKey = String(
        item?.dataset?.detailKey ||
        item?.dataset?.logId ||
        item?.dataset?.srcIp ||
        ''
    ).trim();

    item.addEventListener('click', function(evt) {
        evt.preventDefault();
        evt.stopPropagation();
        const el = ensureSuspiciousHeaderHoverEl();
        const isSameVisible =
            String(_suspiciousHeaderHoverState.sourceKey || '') === detailKey &&
            (el.style.display !== 'none');
        if (isSameVisible) {
            hideSuspiciousHeaderHover();
            return;
        }
        hideSuspiciousHeaderHover();

        const content = contentProvider() || {};
        const title = String(content?.title || '详情');
        const lines = normalizeHoverLines(content?.lines || []);
        if (!lines.length) return;

        _suspiciousHeaderHoverState.sourceItem = item;
        _suspiciousHeaderHoverState.sourceKey = detailKey;
        // 点击详情时锁定该 IP 的地图焦点，便于阅读联动线与攻击点
        setMapPinnedFocusByIp(String(item?.dataset?.srcIp || '').trim(), item);
        renderSuspiciousHeaderHover(lines, title);
        el.style.display = 'block';
        const cx = Number(evt?.clientX || 0);
        const cy = Number(evt?.clientY || 0);
        if (cx > 0 || cy > 0) {
            _suspiciousHeaderHoverState.lastX = cx;
            _suspiciousHeaderHoverState.lastY = cy;
            moveSuspiciousHeaderHover(cx, cy);
        } else {
            const rect = item.getBoundingClientRect();
            const rx = rect.left + rect.width / 2;
            const ry = rect.top + rect.height / 2;
            _suspiciousHeaderHoverState.lastX = rx;
            _suspiciousHeaderHoverState.lastY = ry;
            moveSuspiciousHeaderHover(rx, ry);
        }
    });

    // 刷新后若同一条目仍在，保持详情展示并更新内容
    const hoverEl = _suspiciousHeaderHoverState.el;
    const isVisible = !!(hoverEl && hoverEl.style.display !== 'none');
    if (isVisible && String(_suspiciousHeaderHoverState.sourceKey || '') === detailKey) {
        _suspiciousHeaderHoverState.sourceItem = item;
        hoverEl.style.display = 'block';
    }
}

function bindSuspiciousHeaderHover(item, req) {
    bindPanelDetailHover(item, function() {
        return buildSuspiciousHoverContent(req);
    });
}

function hasGeoPointForIp(ip) {
    const target = String(ip || '').trim();
    if (!target) return false;
    const existsInMain = (Array.isArray(lastGeoData) ? lastGeoData : []).some(function(p) {
        const v = String(p?.src_ip || '').trim();
        const lon = Number(p?.longitude);
        const lat = Number(p?.latitude);
        return v === target && Number.isFinite(lon) && Number.isFinite(lat) && !(lon === 0 && lat === 0);
    });
    if (existsInMain) return true;
    const extras = [mapHoverFocusGeoPoint, mapPinnedFocusGeoPoint];
    return extras.some(function(extra) {
        if (!extra) return false;
        const ev = String(extra?.src_ip || '').trim();
        const elon = Number(extra?.longitude);
        const elat = Number(extra?.latitude);
        return ev === target && Number.isFinite(elon) && Number.isFinite(elat) && !(elon === 0 && elat === 0);
    });
}

function ensureFocusedIpGeo(ip) {
    const target = String(ip || '').trim();
    if (!target) return;
    if (hasGeoPointForIp(target)) return;

    const state = _mapFocusGeoResolveState[target] || { inFlight: false, cooldownUntil: 0, requestId: 0 };
    const now = Date.now();
    if (state.inFlight || now < Number(state.cooldownUntil || 0)) return;
    const requestId = now;
    state.inFlight = true;
    state.requestId = requestId;
    _mapFocusGeoResolveState[target] = state;

    let hours = 24;
    try {
        if (typeof window !== 'undefined' && typeof window.__getDashboardWindowHours === 'function') {
            const n = Number(window.__getDashboardWindowHours());
            if (Number.isFinite(n) && n > 0) hours = n;
        }
    } catch (e) {}

    const controller = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    const timer = setTimeout(function() {
        try {
            if (controller) controller.abort();
        } catch (e) {}
    }, MAP_FOCUS_GEO_TIMEOUT_MS);

    fetch(`/api/get_geo_data?hours=${hours}&focus_ip=${encodeURIComponent(target)}`, {
        cache: 'no-store',
        signal: controller ? controller.signal : undefined
    })
        .then(function(res) {
            if (!res.ok) throw new Error(`http_${res.status}`);
            return res.json();
        })
        .then(function(data) {
            const list = Array.isArray(data?.data) ? data.data : [];
            if (!list.length) {
                state.cooldownUntil = Date.now() + 15000;
                return;
            }
            const targetPoint = list.find(function(p) {
                const ipv = String(p?.src_ip || '').trim();
                const lon = Number(p?.longitude);
                const lat = Number(p?.latitude);
                return ipv === target && Number.isFinite(lon) && Number.isFinite(lat) && !(lon === 0 && lat === 0);
            });
            if (!targetPoint) {
                state.cooldownUntil = Date.now() + 15000;
                return;
            }
            // 只做临时补点，不污染主缓存；仅在当前焦点仍是该 IP 时生效
            if (String(getMapFocusIp() || '').trim() === target) {
                if (String(logHoverFocusIp || '').trim() === target) {
                    mapHoverFocusGeoPoint = targetPoint;
                }
                if (String(mapPinnedFocusIp || '').trim() === target) {
                    mapPinnedFocusGeoPoint = targetPoint;
                }
            }
            updateMapCore(lastGeoData);
        })
        .catch(function() {
            state.cooldownUntil = Date.now() + 15000;
        })
        .finally(function() {
            clearTimeout(timer);
            const activeState = _mapFocusGeoResolveState[target];
            if (!activeState || Number(activeState.requestId || 0) !== requestId) return;
            state.inFlight = false;
            state.requestId = 0;
            _mapFocusGeoResolveState[target] = state;
        });
}

function updateLogsTable(logs) {
    const container = document.getElementById('logScroll');
    if (!container) return;
    const list = Array.isArray(logs) ? logs.slice() : [];
    if (!list.length) {
        setEmptyMessage(container, '暂无攻击记录', 20);
        dismissPanelDetailIfSourceDetached();
        displayedLogIds.clear();
        setMapHoverFocusByIp('');
        return;
    }
    const sortedAll = list
        .sort((a, b) => getLogOrderValue(b) - getLogOrderValue(a));
    const sorted = sortedAll.slice(0, DASHBOARD_LOG_TABLE_LIMIT);

    const existingNodeMap = new Map();
    Array.from(container.children).forEach(node => {
        const id = node?.dataset?.logId;
        if (id) existingNodeMap.set(id, node);
    });

    const desiredNodes = [];
    const nextDisplayed = new Set();
    sorted.forEach(log => {
        const logId = buildLogIdentity(log);
        nextDisplayed.add(logId);

        let node = existingNodeMap.get(logId);
        if (!node) {
            node = createLogItem(log, logId, !displayedLogIds.has(logId));
        }
        desiredNodes.push(node);
    });

    for (let i = desiredNodes.length - 1; i >= 0; i--) {
        container.prepend(desiredNodes[i]);
    }

    Array.from(container.children).forEach(node => {
        const id = node?.dataset?.logId;
        if (!id || !nextDisplayed.has(id)) {
            container.removeChild(node);
        }
    });
    dismissPanelDetailIfSourceDetached();

    if (logHoverFocusIp) {
        const visibleIpSet = new Set(
            sorted
                .map(function(log) { return String(log?.src_ip || '').trim(); })
                .filter(Boolean)
        );
        if (!visibleIpSet.has(logHoverFocusIp)) {
            setMapHoverFocusByIp('');
        }
    }

    displayedLogIds = nextDisplayed;
}
function detectThreatLevel(type, p, severity) {
    const mapped = mapSeverityToLevel(severity);
    if (mapped) return mapped;
    if (type === 'SCP-Capture') return 'high'; // 捕获到文件绝对是高危
    if (!p) return 'low';
    p = String(p).toLowerCase();
    if ([/rm\s*-rf/i, /wget/i, /curl/i, /union\s+select/i, /reboot/i].some(r => r.test(p))) return 'high';
    if ([/ls\b/i, /whoami/i, /scan/i, /cat\b/i, /cd\b/i].some(r => r.test(p))) return 'medium';
    return (type === 'SSH' || type === 'SHELL_CMD') ? 'medium' : 'low';
}

// 地图绘制核心逻辑
function updateMapCore(geoPoints) {
    if (!mapChart) return;

    const focusIpForBuild = getMapFocusIp();
    const points = (Array.isArray(geoPoints) ? geoPoints : []).filter(function(p) {
        const lon = Number(p?.longitude);
        const lat = Number(p?.latitude);
        return Number.isFinite(lon) && Number.isFinite(lat) && !(lon === 0 && lat === 0);
    });
    if (
        focusIpForBuild &&
        mapHoverFocusGeoPoint &&
        String(mapHoverFocusGeoPoint?.src_ip || '').trim() === focusIpForBuild
    ) {
        const existsInMain = points.some(function(p) {
            return String(p?.src_ip || '').trim() === focusIpForBuild;
        });
        if (!existsInMain) {
            points.push(mapHoverFocusGeoPoint);
        }
    }
    if (
        focusIpForBuild &&
        mapPinnedFocusGeoPoint &&
        String(mapPinnedFocusGeoPoint?.src_ip || '').trim() === focusIpForBuild
    ) {
        const existsInMain = points.some(function(p) {
            return String(p?.src_ip || '').trim() === focusIpForBuild;
        });
        if (!existsInMain) {
            points.push(mapPinnedFocusGeoPoint);
        }
    }

    const isReady = (Number(serverInfo.latitude) !== 0 || Number(serverInfo.longitude) !== 0);
    const serverPos = [Number(serverInfo.longitude) || 0, Number(serverInfo.latitude) || 0];
    const maxCount = points.reduce(function(m, p) {
        return Math.max(m, Math.max(1, Number(p?.event_count) || 1));
    }, 1);

    const scatter = points.map(function(p) {
        const count = Math.max(1, Number(p?.event_count) || 1);
        const riskLevel = classifyMapRiskLevel(count, maxCount);
        return {
            name: p.src_ip,
            value: [Number(p.longitude), Number(p.latitude), count],
            ip: p.src_ip,
            location: p.location || '未知',
            riskLevel,
            riskColor: getMapRiskColor(riskLevel),
            lineWidth: computeAttackLineWidth(count, maxCount)
        };
    });

    const focusPoints = scatter
        .slice()
        .sort(function(a, b) { return Number(b?.value?.[2] || 0) - Number(a?.value?.[2] || 0); })
        .slice(0, MAP_TOP_EFFECT_LIMIT);

    let linesLow = [];
    let linesMedium = [];
    let linesHigh = [];
    let server = [];
    let hoverLine = [];
    let hoverPoint = [];

    if (isReady) {
        const focusIp = getMapFocusIp();
        scatter.forEach(function(p) {
            const lineData = {
                coords: [[p.value[0], p.value[1]], serverPos],
                sourceIp: p.ip,
                sourceLocation: p.location,
                riskLevel: p.riskLevel,
                eventCount: p.value[2],
                lineStyle: {
                    width: p.lineWidth
                }
            };
            if (p.riskLevel === 'high') {
                linesHigh.push(lineData);
            } else if (p.riskLevel === 'medium') {
                linesMedium.push(lineData);
            } else {
                linesLow.push(lineData);
            }
        });

        server = [{
            name: '本机位置',
            value: [serverPos[0], serverPos[1], 1],
            ip: serverInfo.ip,
            location: formatServerLocation()
        }];

        if (focusIp) {
            const hoverTarget = scatter.find(function(p) {
                return String(p?.ip || '').trim() === focusIp;
            });
            if (hoverTarget) {
                const hoverCurveness = (hoverTarget?.riskLevel === 'high') ? 0.22 : 0.2;
                hoverLine = [{
                    coords: [[hoverTarget.value[0], hoverTarget.value[1]], serverPos],
                    sourceIp: hoverTarget.ip,
                    sourceLocation: hoverTarget.location,
                    riskLevel: hoverTarget.riskLevel,
                    eventCount: hoverTarget.value[2],
                    lineStyle: {
                        // 与底层风险线保持同曲率，避免出现“平行双线”视觉错位
                        curveness: hoverCurveness
                    }
                }];
                hoverPoint = [{
                    name: hoverTarget.ip,
                    value: hoverTarget.value,
                    ip: hoverTarget.ip,
                    location: hoverTarget.location,
                    riskLevel: hoverTarget.riskLevel,
                    riskColor: MAP_HIGHLIGHT_COLOR
                }];
            }
        }
    }

    const zoomTag = Math.round(getMapZoomLevel() * 100) / 100;
    const baseRenderKey = [
        zoomTag,
        Number(serverInfo.longitude) || 0,
        Number(serverInfo.latitude) || 0,
        String(serverInfo.ip || ''),
        scatter.map(function(p) {
            return [
                String(p.ip || ''),
                Number(p.value?.[0]) || 0,
                Number(p.value?.[1]) || 0,
                Number(p.value?.[2]) || 0,
                String(p.riskLevel || 'low')
            ].join('|');
        }).join(';')
    ].join('#');
    const hoverRenderKey = [
        String(getMapFocusIp() || ''),
        hoverLine.map(function(h) {
            const c0 = h?.coords?.[0] || [];
            const c1 = h?.coords?.[1] || [];
            return [
                String(h?.sourceIp || ''),
                Number(h?.eventCount || 0),
                Number(c0[0] || 0),
                Number(c0[1] || 0),
                Number(c1[0] || 0),
                Number(c1[1] || 0),
            ].join('|');
        }).join(';'),
        hoverPoint.map(function(h) {
            const v = h?.value || [];
            return [
                String(h?.ip || ''),
                Number(v[0] || 0),
                Number(v[1] || 0),
                Number(v[2] || 0),
            ].join('|');
        }).join(';')
    ].join('#');

    const baseChanged = (baseRenderKey !== _lastMapBaseRenderKey);
    const hoverChanged = (hoverRenderKey !== _lastMapHoverRenderKey);
    if (!baseChanged && !hoverChanged) return;

    if (baseChanged) {
        _lastMapBaseRenderKey = baseRenderKey;
        mapChart.setOption({
            series: [
                { id: 'map_scatter', data: scatter },
                { id: 'map_focus_points', data: focusPoints },
                { id: 'map_lines_low', data: linesLow },
                { id: 'map_lines_medium', data: linesMedium },
                { id: 'map_lines_high', data: linesHigh },
                { id: 'map_server', data: server },
            ]
        });
    }

    if (hoverChanged) {
        _lastMapHoverRenderKey = hoverRenderKey;
        mapChart.setOption({
            series: [
                { id: 'map_hover_line', data: hoverLine },
                { id: 'map_hover_point', data: hoverPoint }
            ]
        });
    }

    const _getSeriesIndexById = function(seriesId) {
        try {
            const optionNow = mapChart.getOption() || {};
            const list = Array.isArray(optionNow.series) ? optionNow.series : [];
            for (let i = 0; i < list.length; i++) {
                if (String(list[i]?.id || '') === String(seriesId || '')) return i;
            }
        } catch (e) {}
        return -1;
    };

    try {
        if (hoverLine.length > 0) {
            const idx = _getSeriesIndexById('map_hover_line');
            if (idx < 0) return;
            mapChart.dispatchAction({
                type: 'showTip',
                seriesIndex: idx,
                dataIndex: 0
            });
        } else if (hoverPoint.length > 0) {
            const idx = _getSeriesIndexById('map_hover_point');
            if (idx < 0) return;
            mapChart.dispatchAction({
                type: 'showTip',
                seriesIndex: idx,
                dataIndex: 0
            });
        } else {
            mapChart.dispatchAction({ type: 'hideTip' });
        }
    } catch (e) {}
}

function triggerAttackFlash() {
    const f = document.getElementById('attackFlash'); f.classList.add('active'); setTimeout(() => f.classList.remove('active'), 300);
}
function truncateMiddle(s, maxLen) {
    s = String(s ?? '');
    const n = Number(maxLen || 0);
    if (!n || s.length <= n) return s;
    if (n <= 3) return s.slice(0, n);
    const head = Math.max(1, Math.ceil((n - 1) * 0.65));
    const tail = Math.max(1, (n - 1) - head);
    return s.slice(0, head) + '…' + s.slice(-tail);
}

async function fetchServerInfo() {
    if (typeof document !== 'undefined' && document.hidden) return;
    if (_serverInfoFetchInFlight) return;
    _serverInfoFetchInFlight = true;
    const controller = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    const timer = setTimeout(function() {
        try {
            if (controller) controller.abort();
        } catch (e) {}
    }, SERVER_INFO_TIMEOUT_MS);
    try {
        const res = await fetch('/api/server_info?include_system=0', {
            cache: 'no-store',
            signal: controller ? controller.signal : undefined
        });
        if (!res.ok) throw new Error(`http_${res.status}`);
        const data = await res.json();
        if (data.code === 0 && data.data) {
            const info = data.data;
            const prevIp = String(serverInfo.ip || '').trim();
            const nextIp = String(info.server?.public_ip || prevIp).trim();
            const ipChanged = !!nextIp && nextIp !== prevIp;
            serverInfo.ip = nextIp || prevIp;

            const lat = Number(info.location?.latitude);
            const lon = Number(info.location?.longitude);
            const hasValidGeo = Number.isFinite(lat) && Number.isFinite(lon) && (lat !== 0 || lon !== 0);
            const hasCachedGeo = (Number(serverInfo.latitude) !== 0 || Number(serverInfo.longitude) !== 0);
            // 坐标缓存策略：
            // 1) 不因一次失败/缺失定位把已有坐标清空
            // 2) 仅在 IP 变化时替换坐标；首次无缓存时允许填充
            if (hasValidGeo && (ipChanged || !hasCachedGeo)) {
                serverInfo.latitude = lat;
                serverInfo.longitude = lon;
                serverInfo.city = info.location?.city || serverInfo.city || '未知';
                serverInfo.country = COUNTRY_NAME_MAP[info.location?.country] || info.location?.country || serverInfo.country || '未知';
            } else if (!hasCachedGeo) {
                // 无有效坐标且无缓存时，仅更新文本信息
                serverInfo.city = info.location?.city || '未知';
                serverInfo.country = COUNTRY_NAME_MAP[info.location?.country] || info.location?.country || '未知';
            }
            if (serverInfo.city && serverInfo.country) {
                const cityCompact = serverInfo.city.replace(/\s+/g, '');
                const countryCompact = serverInfo.country.replace(/\s+/g, '');
                if (cityCompact.includes(countryCompact) || serverInfo.city.includes('/')) {
                    serverInfo.country = '';
                }
            }

            serverInfoLoaded = true;
            const locEl = document.getElementById('serverLocation'); const ipEl = document.getElementById('serverIP');
            if (locEl) locEl.textContent = formatServerLocation();
            if(ipEl) ipEl.textContent = `IP: ${escapeHtml(serverInfo.ip)}`;

            // 定位成功后统一刷新地图，攻击线和本机点会自动出现
            updateMapCore(lastGeoData);
        }
        serverInfoLoaded = true;
    } catch (e) {
        serverInfoLoaded = true;
        const t = Date.now();
        if ((t - _serverInfoLastWarnAt) >= 15000) {
            const tag = (e && e.name === 'AbortError') ? 'timeout' : String(e || 'unknown');
            console.warn('[server_info] poll failed:', tag);
            _serverInfoLastWarnAt = t;
        }
    } finally {
        clearTimeout(timer);
        _serverInfoFetchInFlight = false;
    }
}
function fetchSystemStatus() {
    if (typeof document !== 'undefined' && document.hidden) return;
    const now = Date.now();
    if (now < _systemStatusBackoffUntil) return;

    const controller = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    const timer = setTimeout(function() {
        try {
            if (controller) controller.abort();
        } catch (e) {}
    }, SYSTEM_STATUS_TIMEOUT_MS);

    fetch('/api/system_status', {
        cache: 'no-store',
        signal: controller ? controller.signal : undefined
    })
        .then(function(r) {
            if (!r.ok) throw new Error(`http_${r.status}`);
            return r.json();
        })
        .then(function(d) {
            if (d && d.code === 0) {
                _systemStatusFailCount = 0;
                _systemStatusBackoffUntil = 0;
                updateSystemStatus(d.data || {});
                return;
            }
            throw new Error(`code_${d && d.code}`);
        })
        .catch(function(err) {
            _systemStatusFailCount += 1;
            if (_systemStatusFailCount >= 3) {
                _systemStatusBackoffUntil = Date.now() + SYSTEM_STATUS_FAIL_BACKOFF_MS;
            }
            const t = Date.now();
            if ((t - _systemStatusLastWarnAt) >= 15000) {
                const tag = (err && err.name === 'AbortError') ? 'timeout' : String(err || 'unknown');
                console.warn('[system_status] poll failed:', tag);
                _systemStatusLastWarnAt = t;
            }
        })
        .finally(function() {
            clearTimeout(timer);
        });
}
function updateSystemStatus(s) {
    const c = s.cpu_percent||0; const m = s.memory_percent||0;
    const ce = document.getElementById('cpuUsage'); if(ce) animateNumber('cpuUsage', Math.round(c));
    const me = document.getElementById('memoryUsage'); if(me) animateNumber('memoryUsage', Math.round(m));
    const de = document.getElementById('memoryDetail'); if(de && s.memory_used_gb) de.textContent = `${escapeHtml(s.memory_used_gb)}GB / ${escapeHtml(s.memory_total_gb)}GB`;
    const cp = document.getElementById('cpuProgress'); if(cp) { cp.style.width=`${c}%`; updateProgressColor(cp, c); }
    const mp = document.getElementById('memoryProgress'); if(mp) { mp.style.width=`${m}%`; updateProgressColor(mp, m); }
}
function updateProgressColor(el, p) { el.classList.remove('warning','danger'); if(p>=80) el.classList.add('danger'); else if(p>=60) el.classList.add('warning'); }

// === 行为分析模块（可疑请求/会话分析） ===

function updateSuspiciousRequests(requests) {
    const container = document.getElementById('suspiciousScroll');
    if (!container) return;
    let list = Array.isArray(requests) ? requests : (requests?.items || requests?.data || []);
    if (!list || list.length === 0) {
        dismissPanelDetailIfSourceMatches('suspicious');
        if (isDemoMode) {
            list = getMockSuspiciousRequests();
        } else {
            setEmptyMessage(container, '暂无可疑行为', 6);
            return;
        }
    }

    const getSortKey = function(req) {
        return String(req?.create_time || req?.timestamp || '');
    };
    const sortByTimeThenScoreDesc = function(a, b) {
        const ta = getSortKey(a);
        const tb = getSortKey(b);
        if (tb !== ta) return tb.localeCompare(ta);
        return Number(b?.threat_score || 0) - Number(a?.threat_score || 0);
    };
    const dedupKey = function(req) {
        return [
            String(req?.src_ip || '').trim(),
            String(req?.method || '').trim().toUpperCase(),
            String(req?.path || '').trim(),
            String(req?.query_string || '').trim(),
            String(req?.create_time || req?.timestamp || '').trim(),
            String(Number(req?.threat_score || 0)),
        ].join('|');
    };
    const dedupedList = [];
    const seen = new Set();
    (Array.isArray(list) ? list : []).sort(sortByTimeThenScoreDesc).forEach(function(req) {
        const key = dedupKey(req);
        if (seen.has(key)) return;
        seen.add(key);
        dedupedList.push(req);
    });
    dedupedList.sort(sortByTimeThenScoreDesc);

    clearElement(container);
    const renderReqItem = function(req) {
        const srcIp = String(req.src_ip || '').trim();
        const resolvedLocation = resolveLocation(req.location, geoLocationCacheByIp[srcIp], srcIp);
        if (resolvedLocation && resolvedLocation !== '未知' && srcIp) {
            geoLocationCacheByIp[srcIp] = resolvedLocation;
        }
        const score = Number(req.threat_score || 0);
        const riskLevel = mapSeverityToLevel(req.risk_level || req.severity) || (score >= 40 ? 'high' : (score >= 20 ? 'medium' : 'low'));
        const level = riskLevel === 'high' ? '高风险' : (riskLevel === 'medium' ? '中风险' : '低风险');
        const scoreColor = riskLevel === 'high' ? '#ff4757' : (riskLevel === 'medium' ? '#ffa502' : '#2ed573');

        const method = String(req.method || 'GET').trim().toUpperCase() || 'GET';
        const path = String(req.path || '');
        const qs = String(req.query_string || '');
        const isSshItem = method === 'SSH';
        const shortUrl = truncateMiddle(path + (qs ? ('?' + qs) : ''), 34);
        const sshCommand = truncateMiddle(String(req.command || req.query_string || '').trim(), 36);
        const shortPath = isSshItem
            ? (sshCommand ? `SSH 命令 · ${sshCommand}` : 'SSH 可疑命令')
            : `${method} ${shortUrl}`;
        const signals = Array.isArray(req.signals) ? req.signals.map(function(sig) {
            return String(sig || '').trim();
        }).filter(Boolean) : [];
        const primaryReason = signals.length ? truncateMiddle(signals[0], 30) : '';
        const reasonText = primaryReason
            ? `${primaryReason}${signals.length > 1 ? ` 等${signals.length}项` : ''}`
            : '';

        const item = document.createElement('div');
        item.className = 'log-item';
        item.style.borderLeft = `3px solid ${scoreColor}`;
        item.dataset.srcIp = srcIp;
        item.dataset.location = resolvedLocation;
        item.dataset.latitude = String(req.latitude || '');
        item.dataset.longitude = String(req.longitude || '');
        item.dataset.eventCount = '1';
        const reqId = String(req.id || req.raw_request_id || '').trim();
        const detailFallbackKey = [
            String(req.src_ip || '').trim(),
            String(req.method || '').trim().toUpperCase(),
            String(req.path || '').trim(),
            String(req.query_string || '').trim(),
            String(req.create_time || req.timestamp || '').trim(),
            String(req.threat_score || '').trim()
        ].join('|');
        // 优先使用请求唯一 ID，避免刷新时同 IP/同 URL 的不同请求互相覆盖详情
        item.dataset.detailKey = `susp:${reqId || detailFallbackKey}`;
        item.dataset.panelLevel = 'suspicious';

        const header = document.createElement('div');
        header.style.display = 'flex';
        header.style.justifyContent = 'space-between';
        header.style.fontSize = '11px';

        const ip = document.createElement('span');
        ip.style.color = '#00d4ff';
        ip.textContent = srcIp || '-';

        const levelSpan = document.createElement('span');
        levelSpan.style.color = scoreColor;
        levelSpan.textContent = level;

        header.append(ip, levelSpan);

        const pathDiv = document.createElement('div');
        pathDiv.style.color = '#888';
        pathDiv.style.fontSize = '10px';
        pathDiv.style.marginTop = '2px';
        pathDiv.textContent = shortPath;

        const ts = normalizeDateTimeText(req.create_time || req.timestamp || '');
        const timeDiv = document.createElement('div');
        timeDiv.style.color = '#5f7896';
        timeDiv.style.fontSize = '10px';
        timeDiv.style.marginTop = '1px';
        timeDiv.textContent = ts || '-';

        item.append(header, pathDiv);
        if (reasonText) {
            const reasonDiv = document.createElement('div');
            reasonDiv.style.color = '#7c98b6';
            reasonDiv.style.fontSize = '10px';
            reasonDiv.style.marginTop = '1px';
            reasonDiv.style.wordBreak = 'break-word';
            reasonDiv.style.overflowWrap = 'anywhere';
            reasonDiv.textContent = `判定: ${reasonText}`;
            item.appendChild(reasonDiv);
        }
        item.appendChild(timeDiv);
        bindLogMapHover(item);
        bindSuspiciousHeaderHover(item, req);
        container.appendChild(item);
    };

    if (dedupedList.length === 0) {
        setEmptyMessage(container, '暂无可疑行为', 6);
        return;
    }
    dedupedList.forEach(function(req) {
        renderReqItem(req);
    });
    dismissPanelDetailIfSourceDetached();
}

function updateSessionAnalysis(sessions) {
    const container = document.getElementById('sessionScroll');
    if (!container) return;
    let list = Array.isArray(sessions) ? sessions : (sessions?.items || sessions?.data || []);
    if (!list || list.length === 0) {
        dismissPanelDetailIfSourceMatches('session');
        if (isDemoMode) {
            list = getMockSessionAnalysis();
        } else {
            setEmptyMessage(container, '暂无会话分析', 6);
            return;
        }
    }
    list = Array.isArray(list) ? list.slice() : [];
    clearElement(container);
    list.forEach(sess => {
        const srcIp = String(sess.src_ip || '').trim();
        const chainType = String(sess.chain_type || 'web').trim().toLowerCase() === 'ssh' ? 'ssh' : 'web';
        const chainTypeText = chainType === 'ssh' ? 'SSH' : 'Web';
        const resolvedLocation = resolveLocation(sess.location, geoLocationCacheByIp[srcIp], srcIp);
        if (resolvedLocation && resolvedLocation !== '未知' && srcIp) {
            geoLocationCacheByIp[srcIp] = resolvedLocation;
        }
        const level = sess.threat_level || 'unknown';
        const levelText = level === 'high' ? '高风险' : (level === 'medium' ? '中风险' : (level === 'low' ? '低风险' : '未知'));
        const levelColor = level === 'high' ? '#ff4757' : (level === 'medium' ? '#ffa502' : '#2ed573');
        const rawPaths = normalizeSessionPathSteps(sess, false);
        const detailPaths = normalizeSessionPathSteps(sess, chainType === 'ssh' ? false : true);
        const paths = rawPaths
            .filter(p => {
                const s = String(p || '').toLowerCase();
                if (!s) return false;
                if (s.includes('favicon')) return false;
                if (s.startsWith('/static/')) return false;
                if (s.startsWith('/robots.txt')) return false;
                if (s.startsWith('/sitemap.xml')) return false;
                return true;
            });
        const previewPaths = selectAttackChainPreviewSteps(paths.length ? paths : rawPaths, chainType);

        const item = document.createElement('div');
        item.className = 'log-item';
        item.style.borderLeft = `3px solid ${levelColor}`;
        item.dataset.srcIp = srcIp;
        item.dataset.location = resolvedLocation;
        item.dataset.latitude = String(sess.latitude || '');
        item.dataset.longitude = String(sess.longitude || '');
        item.dataset.eventCount = String(Math.max(1, Number(sess.request_count || 0) || 1));
        item.dataset.detailKey = buildSessionDetailKey(sess, chainType);
        item.dataset.panelLevel = 'session';

        const header = document.createElement('div');
        header.style.display = 'flex';
        header.style.justifyContent = 'space-between';
        header.style.fontSize = '12px';

        const left = document.createElement('div');
        left.style.display = 'flex';
        left.style.alignItems = 'center';
        left.style.gap = '6px';

        const ip = document.createElement('span');
        ip.style.color = '#00d4ff';
        ip.textContent = srcIp || '-';

        const typeBadge = document.createElement('span');
        typeBadge.style.padding = '1px 6px';
        typeBadge.style.borderRadius = '10px';
        typeBadge.style.fontSize = '10px';
        typeBadge.style.letterSpacing = '0.5px';
        typeBadge.style.color = chainType === 'ssh' ? '#8fd3ff' : '#7bed9f';
        typeBadge.style.background = chainType === 'ssh' ? 'rgba(0, 212, 255, 0.14)' : 'rgba(46, 213, 115, 0.14)';
        typeBadge.textContent = chainTypeText;

        left.append(ip, typeBadge);

        const count = document.createElement('span');
        count.style.color = levelColor;
        count.textContent = `${sess.request_count || 0}次`;

        header.append(left, count);

        const pathDiv = document.createElement('div');
        pathDiv.style.color = '#666';
        pathDiv.style.fontSize = '11px';
        pathDiv.style.marginTop = '2px';
        pathDiv.style.lineHeight = '1.45';
        pathDiv.style.wordBreak = 'break-word';
        pathDiv.style.overflowWrap = 'anywhere';
        const displayPaths = previewPaths.join(' → ');
        const fullPaths = detailPaths.join(' → ');
        const formattedPaths = formatAttackChainSteps(detailPaths);
        pathDiv.textContent = displayPaths || '-';

        item.append(header, pathDiv);
        bindLogMapHover(item);
        bindPanelDetailHover(item, function() {
            const srcIp = String(sess.src_ip || '-').trim() || '-';
            const srcLoc = resolveLocation(sess.location, geoLocationCacheByIp[srcIp], srcIp);
            return {
                title: '攻击链详情',
                lines: [
                    ['攻击源IP', srcIp],
                    ['入口类型', chainTypeText],
                    ['攻击源位置', srcLoc || '未知'],
                    ['行为次数', `${Number(sess.request_count || 0)}次`],
                    ['威胁等级', levelText],
                    ['行为轨迹', formattedPaths !== '-' ? formattedPaths : (fullPaths || displayPaths || '-')],
                ]
            };
        });
        container.appendChild(item);
    });
    dismissPanelDetailIfSourceDetached();
}

// 行为分析随主刷新周期自动更新


// ==================== 风险目标标注 ====================
const RISK_TARGET_POLL_INTERVAL_MS = 20000;
const RISK_TARGET_RISK_COLORS = {
    critical: '#ff2d55',
    high: '#ff4757',
    medium: '#ffa502',
    low: '#2ed573',
    unknown: '#6a8caf'
};
const RISK_TARGET_RISK_LABELS = {
    critical: '严重',
    high: '高',
    medium: '中',
    low: '低',
    unknown: '未知'
};
const RISK_TARGET_STATUS_LABELS = {
    watching: '观察中',
    banned: '已封禁',
    handled: '已处置'
};
let _riskTargetsCache = [];
let _riskTargetFetchInFlight = false;

function getDashboardCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (meta && meta.getAttribute('content')) return meta.getAttribute('content');
    const input = document.querySelector('input[name="csrf_token"]');
    if (input && input.value) return input.value;
    return '';
}

function riskTargetFetchJson(url, options) {
    const opts = options || {};
    return fetch(url, opts).then(function(res) {
        if (!res.ok) throw new Error('http_' + res.status);
        return res.json();
    });
}

function fetchRiskTargets() {
    if (typeof document !== 'undefined' && document.hidden) return;
    if (_riskTargetFetchInFlight) return;
    _riskTargetFetchInFlight = true;
    const searchEl = document.getElementById('riskTargetSearch');
    const kw = encodeURIComponent((searchEl && searchEl.value || '').trim());
    riskTargetFetchJson('/api/risk_targets?limit=200&q=' + kw, { cache: 'no-store' })
        .then(function(resp) {
            const list = resp && resp.code === 0 && Array.isArray(resp.data) ? resp.data : [];
            _riskTargetsCache = list.slice();
            updateRiskTargets(list);
        })
        .catch(function() {
            updateRiskTargets(_riskTargetsCache);
        })
        .finally(function() { _riskTargetFetchInFlight = false; });
}

function updateRiskTargets(list) {
    const container = document.getElementById('riskTargetList');
    if (!container) return;
    const items = Array.isArray(list) ? list : [];
    if (!items.length) {
        setEmptyMessage(container, '暂无风险目标，点击「识别目标」自动生成', 8);
        return;
    }
    clearElement(container);
    items.forEach(function(item) {
        container.appendChild(buildRiskTargetRow(item));
    });
}

function buildRiskTargetRow(item) {
    const id = item.id;
    const ip = String(item.target_value || '').trim();
    const risk = String(item.risk_level || 'medium').toLowerCase();
    const status = String(item.status || 'watching').toLowerCase();
    const color = RISK_TARGET_RISK_COLORS[risk] || RISK_TARGET_RISK_COLORS.medium;
    const riskLabel = RISK_TARGET_RISK_LABELS[risk] || risk;
    const statusLabel = RISK_TARGET_STATUS_LABELS[status] || status;
    const source = String(item.source || 'auto').toLowerCase();
    const tags = Array.isArray(item.tags) ? item.tags : [];
    const note = String(item.note || '').trim();
    const location = String(item.location || '未知');

    const row = document.createElement('div');
    row.className = 'log-item';
    row.style.borderLeft = '3px solid ' + color;
    row.dataset.riskTargetId = String(id || '');

    const header = document.createElement('div');
    header.style.display = 'flex';
    header.style.justifyContent = 'space-between';
    header.style.alignItems = 'center';
    header.style.fontSize = '12px';

    const left = document.createElement('div');
    left.style.display = 'flex';
    left.style.alignItems = 'center';
    left.style.gap = '6px';

    const ipSpan = document.createElement('span');
    ipSpan.style.color = '#00d4ff';
    ipSpan.textContent = ip || '-';

    const riskBadge = document.createElement('span');
    riskBadge.style.padding = '1px 6px';
    riskBadge.style.borderRadius = '10px';
    riskBadge.style.fontSize = '10px';
    riskBadge.style.color = color;
    riskBadge.style.background = 'rgba(255,255,255,0.06)';
    riskBadge.textContent = riskLabel;

    const statusBadge = document.createElement('span');
    statusBadge.style.padding = '1px 6px';
    statusBadge.style.borderRadius = '10px';
    statusBadge.style.fontSize = '10px';
    statusBadge.style.color = status === 'banned' ? '#ffa502' : (status === 'handled' ? '#7bed9f' : '#9fc6e7');
    statusBadge.style.background = 'rgba(255,255,255,0.06)';
    statusBadge.textContent = statusLabel;

    left.append(ipSpan, riskBadge, statusBadge);

    const actions = document.createElement('div');
    actions.style.display = 'flex';
    actions.style.gap = '6px';

    const editBtn = document.createElement('button');
    editBtn.type = 'button';
    editBtn.textContent = '编辑';
    editBtn.style.cssText = 'border:1px solid rgba(0,150,255,0.4);background:rgba(0,150,255,0.12);color:#9fc6e7;border-radius:3px;font-size:10px;padding:1px 6px;cursor:pointer;';
    editBtn.addEventListener('click', function() { openRiskTargetModal(item); });

    const delBtn = document.createElement('button');
    delBtn.type = 'button';
    delBtn.textContent = '删除';
    delBtn.style.cssText = 'border:1px solid rgba(255,77,79,0.4);background:rgba(255,77,79,0.12);color:#ff6b6b;border-radius:3px;font-size:10px;padding:1px 6px;cursor:pointer;';
    delBtn.addEventListener('click', function() { deleteRiskTargetById(id, ip); });

    actions.append(editBtn, delBtn);
    header.append(left, actions);

    const meta = document.createElement('div');
    meta.style.color = '#6a8caf';
    meta.style.fontSize = '10px';
    meta.style.marginTop = '3px';
    meta.textContent = [
        location !== '未知' ? location : '',
        `${item.event_count || 0} 事件`,
        source === 'manual' ? '人工标注' : '自动识别'
    ].filter(Boolean).join(' · ') || '-';

    row.append(header, meta);

    if (tags.length) {
        const tagRow = document.createElement('div');
        tagRow.style.display = 'flex';
        tagRow.style.flexWrap = 'wrap';
        tagRow.style.gap = '3px';
        tagRow.style.marginTop = '3px';
        tags.slice(0, 5).forEach(function(t) {
            const tSpan = document.createElement('span');
            tSpan.style.padding = '0 5px';
            tSpan.style.borderRadius = '3px';
            tSpan.style.fontSize = '9px';
            tSpan.style.color = '#8fd3ff';
            tSpan.style.background = 'rgba(0,212,255,0.12)';
            tSpan.textContent = String(t || '').trim();
            tagRow.appendChild(tSpan);
        });
        row.appendChild(tagRow);
    }

    if (note) {
        const noteDiv = document.createElement('div');
        noteDiv.style.color = '#7c98b6';
        noteDiv.style.fontSize = '10px';
        noteDiv.style.marginTop = '3px';
        noteDiv.style.wordBreak = 'break-word';
        noteDiv.style.overflowWrap = 'anywhere';
        noteDiv.textContent = note;
        row.appendChild(noteDiv);
    }

    return row;
}

function openRiskTargetModal(item) {
    const modal = document.getElementById('riskTargetModal');
    const title = document.getElementById('riskTargetModalTitle');
    const idEl = document.getElementById('riskTargetId');
    const valEl = document.getElementById('riskTargetValue');
    const levelEl = document.getElementById('riskTargetLevel');
    const statusEl = document.getElementById('riskTargetStatus');
    const tagsEl = document.getElementById('riskTargetTags');
    const noteEl = document.getElementById('riskTargetNote');
    if (!modal) return;
    const editing = !!(item && item.id != null);
    title.textContent = editing ? '编辑风险目标' : '新增风险目标';
    idEl.value = editing ? String(item.id) : '';
    valEl.value = editing ? String(item.target_value || '') : '';
    levelEl.value = editing ? String(item.risk_level || 'medium').toLowerCase() : 'medium';
    statusEl.value = editing ? String(item.status || 'watching').toLowerCase() : 'watching';
    tagsEl.value = editing ? (Array.isArray(item.tags) ? item.tags.join(',') : String(item.tags || '')) : '';
    noteEl.value = editing ? String(item.note || '') : '';
    modal.style.display = 'flex';
}

function closeRiskTargetModal() {
    const modal = document.getElementById('riskTargetModal');
    if (modal) modal.style.display = 'none';
}

function submitRiskTarget() {
    const id = String(document.getElementById('riskTargetId').value || '').trim();
    const target_value = String(document.getElementById('riskTargetValue').value || '').trim();
    if (!target_value) {
        alert('请填写目标 IP');
        return;
    }
    const payload = {
        target_value: target_value,
        risk_level: document.getElementById('riskTargetLevel').value,
        status: document.getElementById('riskTargetStatus').value,
        tags: String(document.getElementById('riskTargetTags').value || '').split(',').map(function(s) { return s.trim(); }).filter(Boolean),
        note: String(document.getElementById('riskTargetNote').value || '')
    };
    const token = getDashboardCsrfToken();
    const isEdit = id !== '';
    const url = isEdit ? ('/api/risk_targets/' + encodeURIComponent(id)) : '/api/risk_targets';
    riskTargetFetchJson(url, {
        method: 'POST',
        cache: 'no-store',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
        body: JSON.stringify(payload)
    }).then(function(resp) {
        if (resp && resp.code === 0) {
            closeRiskTargetModal();
            fetchRiskTargets();
        } else {
            alert((resp && resp.msg) || '保存失败');
        }
    }).catch(function() {
        alert('请求失败，请重试');
    });
}

function deleteRiskTargetById(id, ip) {
    if (id == null || id === '') return;
    if (!confirm('确定删除风险目标 ' + (ip || '') + ' 吗？')) return;
    const token = getDashboardCsrfToken();
    riskTargetFetchJson('/api/risk_targets/' + encodeURIComponent(String(id)) + '/delete', {
        method: 'POST',
        cache: 'no-store',
        headers: { 'X-CSRF-Token': token }
    }).then(function(resp) {
        if (resp && resp.code === 0) {
            fetchRiskTargets();
        } else {
            alert((resp && resp.msg) || '删除失败');
        }
    }).catch(function() {
        alert('请求失败，请重试');
    });
}

function deriveRiskTargets() {
    const btn = document.getElementById('riskTargetDeriveBtn');
    if (btn) { btn.disabled = true; btn.textContent = '识别中…'; }
    const token = getDashboardCsrfToken();
    riskTargetFetchJson('/api/risk_targets/derive', {
        method: 'POST',
        cache: 'no-store',
        headers: { 'X-CSRF-Token': token }
    }).then(function() {
        fetchRiskTargets();
    }).catch(function() {
        alert('识别失败，请重试');
    }).finally(function() {
        if (btn) { btn.disabled = false; btn.textContent = '识别目标'; }
    });
}

function initRiskTargets() {
    const addBtn = document.getElementById('riskTargetAddBtn');
    const deriveBtn = document.getElementById('riskTargetDeriveBtn');
    const searchInput = document.getElementById('riskTargetSearch');
    const saveBtn = document.getElementById('riskTargetSave');
    const cancelBtn = document.getElementById('riskTargetCancel');
    const modal = document.getElementById('riskTargetModal');

    if (addBtn) addBtn.addEventListener('click', function() { openRiskTargetModal(null); });
    if (deriveBtn) deriveBtn.addEventListener('click', deriveRiskTargets);
    if (searchInput) {
        searchInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') fetchRiskTargets();
        });
        searchInput.addEventListener('input', debounce(fetchRiskTargets, 500));
    }
    if (saveBtn) saveBtn.addEventListener('click', submitRiskTarget);
    if (cancelBtn) cancelBtn.addEventListener('click', closeRiskTargetModal);
    if (modal) {
        modal.addEventListener('click', function(e) {
            if (e.target === modal) closeRiskTargetModal();
        });
    }
    fetchRiskTargets();
    setInterval(fetchRiskTargets, RISK_TARGET_POLL_INTERVAL_MS);
}



