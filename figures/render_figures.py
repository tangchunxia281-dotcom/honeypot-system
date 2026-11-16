from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

W, H = 1920, 1080
S = 2
OUT = Path(__file__).resolve().parent

FONT_DIR = Path("C:/Windows/Fonts")
REG = FONT_DIR / "msyh.ttc"
BOLD = FONT_DIR / "msyhbd.ttc"
MONO = FONT_DIR / "consola.ttf"
MONO_B = FONT_DIR / "consolab.ttf"

# frontend palette (dashboard/static/css/ai.css + ai_shell.css)
BG = (8, 19, 34)
TEXT = (223, 235, 247)
HEAD = (228, 242, 255)
MUTED = (166, 186, 208)
DIM = (128, 155, 183)
FAINT = (95, 122, 147)
LINE = (41, 65, 92)
LINE2 = (47, 77, 104)
PANEL = (16, 34, 57)
PANEL2 = (12, 27, 46)
CODEBG = (9, 23, 39)
CODE = (165, 214, 255)
CYAN = (115, 216, 220)
BLUE = (142, 216, 255)
GREEN = (119, 224, 180)
AMBER = (255, 208, 133)
ORANGE = (255, 178, 124)
RED = (255, 133, 140)

_font_cache = {}


def u(v):
    return int(round(v * S))


def F(size, bold=False, mono=False):
    key = (size, bold, mono)
    if key not in _font_cache:
        path = (MONO_B if bold else MONO) if mono else (BOLD if bold else REG)
        _font_cache[key] = ImageFont.truetype(str(path), u(size), index=0)
    return _font_cache[key]


def T(d, x, y, text, size, color, bold=False, mono=False, anchor="la"):
    d.text((u(x), u(y)), str(text), font=F(size, bold, mono), fill=color, anchor=anchor)


def tw(d, text, size, bold=False, mono=False):
    return d.textlength(str(text), font=F(size, bold, mono)) / S


def wrap(d, text, size, maxw, bold=False, mono=False):
    font = F(size, bold, mono)
    limit = maxw * S
    lines, cur = [], ""
    for ch in str(text):
        if ch == "\n":
            lines.append(cur)
            cur = ""
            continue
        if d.textlength(cur + ch, font=font) <= limit:
            cur += ch
        else:
            if cur:
                lines.append(cur)
            cur = ch
    if cur:
        lines.append(cur)
    return lines


def para(d, x, y, w, text, size=15, color=MUTED, leading=1.55, bold=False, mono=False):
    lines = wrap(d, text, size, w, bold, mono)
    lh = size * leading
    for i, line in enumerate(lines):
        T(d, x, y + i * lh, line, size, color, bold, mono)
    return y + len(lines) * lh


def dot(d, x, y, r, color):
    d.ellipse([u(x - r), u(y - r), u(x + r), u(y + r)], fill=color)


def hline(d, x1, x2, y, color, width=1):
    d.line([u(x1), u(y), u(x2), u(y)], fill=color, width=u(width))


def vline(d, x, y1, y2, color, width=1):
    d.line([u(x), u(y1), u(x), u(y2)], fill=color, width=u(width))


def card(d, x, y, w, h, accent=LINE, glow=False):
    d.rounded_rectangle(
        [u(x), u(y), u(x + w), u(y + h)],
        radius=u(16),
        fill=PANEL,
        outline=(61, 127, 147) if glow else LINE,
        width=u(1),
    )
    d.line([u(x + 16), u(y + 2), u(x + w * 0.64), u(y + 2)], fill=accent, width=u(2))


def card_head(d, x, y, num, title):
    d.ellipse([u(x), u(y), u(x + 34), u(y + 34)], fill=(11, 28, 47), outline=(54, 134, 171), width=u(1))
    T(d, x + 17, y + 17, num, 13, BLUE, bold=True, mono=True, anchor="mm")
    T(d, x + 46, y + 17, title, 23, HEAD, bold=True, anchor="lm")


def pill(d, x, y, text, size=13, color=TEXT, border=LINE2, bg=PANEL2, padx=13, ph=32):
    w = tw(d, text, size) + 2 * padx
    d.rounded_rectangle([u(x), u(y), u(x + w), u(y + ph)], radius=u(ph / 2), fill=bg, outline=border, width=u(1))
    T(d, x + w / 2, y + ph / 2, text, size, color, anchor="mm")
    return w


def right_pill(d, right, y, text, size=13):
    w = tw(d, text, size) + 26
    pill(d, right - w, y, text, size)
    return w


def chip(d, x, y, text, size=12, fg=MUTED, bg=PANEL2, border=LINE2, padx=9, ph=24):
    w = tw(d, text, size) + 2 * padx
    d.rounded_rectangle([u(x), u(y), u(x + w), u(y + ph)], radius=u(ph / 2), fill=bg, outline=border, width=u(1))
    T(d, x + w / 2, y + ph / 2, text, size, fg, anchor="mm")
    return w


def mono_chip(d, x, y, text, size=11.5, fg=CODE, bg=CODEBG, border=LINE2, padx=10, ph=27):
    w = tw(d, text, size, mono=True) + 2 * padx
    d.rounded_rectangle([u(x), u(y), u(x + w), u(y + ph)], radius=u(ph / 2), fill=bg, outline=border, width=u(1))
    T(d, x + w / 2, y + ph / 2, text, size, fg, mono=True, anchor="mm")
    return w


def badge(d, x, y, text, fg, bg, border, w=92, h=30):
    d.rounded_rectangle([u(x), u(y), u(x + w), u(y + h)], radius=u(h / 2), fill=bg, outline=border, width=u(1))
    T(d, x + w / 2, y + h / 2, text, 13, fg, bold=True, anchor="mm")


def row(d, x, y, w, label, value, accent):
    T(d, x, y, label, 13.5, accent, bold=True)
    para(d, x + 96, y - 2, w - 96, value, 16.5, TEXT, 1.45)
    hline(d, x, y + 50, x + w, LINE, 1)


def mono_box(d, x, y, w, h, text, size=13.5):
    d.rounded_rectangle([u(x), u(y), u(x + w), u(y + h)], radius=u(8), fill=CODEBG, outline=LINE, width=u(1))
    para(d, x + 14, y + 13, w - 28, text, size, CODE, 1.55, mono=True)


def footer_item(d, x, y, text, dot_color=None, size=12.5):
    if dot_color:
        dot(d, x + 3, y + 8, 3, dot_color)
        x += 14
    T(d, x, y, text, size, DIM)
    return x + tw(d, text, size)


def background():
    yy, xx = np.mgrid[0:H, 0:W].astype(np.float32)
    base = np.empty((H, W, 3), dtype=np.float32)
    base[:] = BG

    d1 = np.sqrt(((xx - 0.82 * W) / (0.52 * W)) ** 2 + ((yy + 0.08 * H) / (0.62 * H)) ** 2)
    a1 = np.clip(1 - d1, 0, 1) ** 2 * 0.55
    base = base * (1 - a1[..., None]) + np.array([18, 58, 92], dtype=np.float32) * a1[..., None]

    d2 = np.sqrt(((xx + 0.08 * W) / (0.45 * W)) ** 2 + ((yy - 1.12 * H) / (0.50 * H)) ** 2)
    a2 = np.clip(1 - d2, 0, 1) ** 2 * 0.22
    base = base * (1 - a2[..., None]) + np.array([20, 44, 46], dtype=np.float32) * a2[..., None]

    img = Image.fromarray(np.clip(base, 0, 255).astype(np.uint8), "RGB").convert("RGBA")
    img = img.resize((W * S, H * S), Image.LANCZOS)

    dots = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
    dd = ImageDraw.Draw(dots)
    step = u(30)
    for y in range(0, H * S, step):
        for x in range(0, W * S, step):
            dd.ellipse([x, y, x + u(1.6), y + u(1.6)], fill=(112, 154, 190, 30))
    return Image.alpha_composite(img, dots)


def shadow_layer(boxes):
    layer = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
    sd = ImageDraw.Draw(layer)
    for x, y, w, h in boxes:
        sd.rounded_rectangle([u(x), u(y), u(x + w), u(y + h)], radius=u(16), fill=(0, 0, 0, 120))
    return layer.filter(ImageFilter.GaussianBlur(u(14)))


def save(img, name):
    img = img.convert("RGB").resize((W, H), Image.LANCZOS)
    path = OUT / name
    img.save(path, "PNG")
    print(path)


def kpi(d, x, y, label, value, note, accent, value_color):
    w, h = 287, 146
    d.rounded_rectangle([u(x), u(y), u(x + w), u(y + h)], radius=u(12), fill=PANEL, outline=LINE, width=u(1))
    d.line([u(x + 2), u(y + 14), u(x + 2), u(y + h - 14)], fill=accent, width=u(3))
    T(d, x + 18, y + 18, label, 13, MUTED)
    T(d, x + 18, y + 42, value, 38, value_color, bold=True, mono=True)
    T(d, x + 18, y + 104, note, 11.5, DIM)


def draw_model_layer():
    img = background()

    cards = [(64, 264, 320, 510), (410, 264, 610, 510), (1046, 264, 424, 510), (1496, 264, 360, 510)]
    kpis = [(64 + i * 301, 796, 287, 146) for i in range(6)]
    img = Image.alpha_composite(img, shadow_layer(cards + kpis))
    d = ImageDraw.Draw(img)

    # header
    T(d, 64, 46, "AI · 第一层｜请求级攻击识别", 15, CYAN, bold=True)
    T(d, 64, 72, "自研攻击识别模型", 58, HEAD, bold=True)
    T(d, 64, 158, "规则 + 模型，两条证据一起判；不是调用现成的大模型接口", 21, MUTED)
    hline(d, 64, 1856, 206, LINE)

    right_pill(d, 1856, 56, "model v2 · 2026-10-22", 13)
    right_pill(d, 1856, 98, "5 类 + 扫描器规则兜底", 13)

    # pipeline heading
    T(d, 64, 226, "一条 HTTP 请求的判定路径", 14, DIM)
    hline(d, 300, 1600, 238, (39, 71, 100), 1)
    T(d, 1610, 226, "先规则，再模型；两路都留证据", 13, FAINT)

    # card 1
    card(d, 64, 264, 320, 510, accent=(54, 134, 171))
    card_head(d, 86, 286, "01", "请求进入")
    mono_box(d, 86, 336, 276, 66, "GET /search\n?q=<script>alert(1)</script>", 12.5)
    T(d, 86, 420, "字段", 14, HEAD, bold=True)
    T(d, 126, 420, "method · path · query · body · UA", 13, MUTED)
    T(d, 86, 456, "先落", 14, HEAD, bold=True)
    T(d, 126, 456, "raw_request", 14, CODE, mono=True)
    T(d, 86, 488, "原始证据不丢", 13.5, MUTED)
    x = 86
    x += chip(d, x, 530, "规则与模型", 12, (188, 209, 228)) + 8
    chip(d, x, 530, "同一份请求", 12, (188, 209, 228))
    d.line([u(224), u(570), u(224), u(604)], fill=(54, 134, 171), width=u(2))
    d.polygon([u(217), u(600), u(231), u(600), u(224), u(612)], fill=(54, 134, 171))
    d.rounded_rectangle([u(86), u(616), u(362), u(696)], radius=u(8), fill=PANEL2, outline=LINE, width=u(1))
    d.rectangle([u(88), u(628), u(91), u(672)], fill=(54, 134, 171))
    para(d, 102, 628, 244, "页面返回 200 还是 404，\n请求都已经留痕。", 13.5, (143, 169, 193), 1.6)

    # card 2
    card(d, 410, 264, 610, 510, accent=CYAN, glow=True)
    card_head(d, 432, 286, "02", "双通道并行")

    # rule lane
    d.rounded_rectangle([u(432), u(332), u(998), u(482)], radius=u(10), fill=(11, 27, 45), outline=LINE, width=u(1))
    T(d, 448, 346, "规则层", 16, HEAD, bold=True)
    m = "rule_score 0–100"
    T(d, 982 - tw(d, m, 12.5, mono=True), 349, m, 12.5, CYAN, mono=True)
    rx, ry = 448, 378
    for t in ["SQL 注入", "XSS", "路径遍历", "命令执行"]:
        rx += chip(d, rx, ry, t, 12, (188, 209, 228), (16, 34, 57), (47, 77, 104)) + 7
    rx, ry = 448, 409
    for t in ["SSTI", "XXE", "SSRF", "扫描器指纹"]:
        rx += chip(d, rx, ry, t, 12, (188, 209, 228), (16, 34, 57), (47, 77, 104)) + 7
    T(d, 448, 446, "确定性特征，速度快；扫描器 UA 也在这一层。", 12, (127, 153, 179))

    # model lane
    d.rounded_rectangle([u(432), u(494), u(998), u(750)], radius=u(10), fill=(11, 27, 45), outline=(58, 104, 126), width=u(1))
    T(d, 448, 508, "自研模型", 16, HEAD, bold=True)
    m = "ai_points 0–25"
    T(d, 982 - tw(d, m, 12.5, mono=True), 511, m, 12.5, CYAN, mono=True)

    boxes = [("字符级 TF-IDF", 448), ("逻辑回归", 630), ("5 类概率", 812)]
    for text, bx in boxes:
        d.rounded_rectangle([u(bx), u(538), u(bx + 168), u(578)], radius=u(6), fill=(16, 34, 57), outline=(47, 77, 104), width=u(1))
        T(d, bx + 84, 558, text, 12.5, (207, 230, 245), anchor="mm")
    for ax in (620, 802):
        T(d, ax, 558, "→", 14, CYAN, anchor="mm")

    cx = 448
    for t, fg, bg, bd in [
        ("XSS", RED, (42, 22, 29), (109, 53, 64)),
        ("SQL 注入", ORANGE, (42, 29, 20), (109, 74, 53)),
        ("路径遍历", AMBER, (42, 36, 20), (109, 90, 53)),
        ("敏感路径", BLUE, (16, 38, 53), (47, 90, 115)),
        ("正常", GREEN, (16, 42, 35), (47, 106, 85)),
    ]:
        cx += chip(d, cx, 598, t, 11.5, fg, bg, bd, 8, 23) + 6
    T(d, 448, 634, "扫描器不训练，交给规则；概率映射为加分。", 12, (127, 153, 179))
    hline(d, 448, 982, 664, (36, 59, 82), 1)
    T(d, 448, 680, "输出 attack_type · attack_prob · ai_points", 12, CODE)
    T(d, 448, 710, "五分类，不含 scanner；类别证据和分值一起返回。", 12, (127, 153, 179))

    # card 3
    card(d, 1046, 264, 424, 510, accent=(54, 134, 171))
    card_head(d, 1068, 286, "03", "融合判定")
    d.rounded_rectangle([u(1068), u(332), u(1448), u(382)], radius=u(8), fill=CODEBG, outline=LINE, width=u(1))
    T(d, 1082, 357, "final = min(100, rule + ai)", 14.5, CODE, mono=True, anchor="lm")

    for yy, dc, text in [
        (404, GREEN, "规则分不被覆盖"),
        (436, AMBER, "normal 最终 +0，仍记 rule+ai"),
        (468, CYAN, "AI 只加分，不单独定罪"),
    ]:
        dot(d, 1074, yy + 7, 3.5, dc)
        T(d, 1088, yy, text, 14, (184, 204, 223))

    d.rounded_rectangle([u(1068), u(510), u(1448), u(660)], radius=u(10), fill=(11, 27, 45), outline=LINE, width=u(1))
    T(d, 1082, 524, "示例：XSS", 12.5, (157, 185, 210))
    ex = "rule 22 + AI 25 = 47"
    T(d, 1434 - tw(d, ex, 12.5, mono=True), 524, ex, 12.5, AMBER, mono=True)
    gx, gy, gw = 1082, 556, 352
    d.rounded_rectangle([u(gx), u(gy), u(gx + gw), u(gy + 11)], radius=u(5), fill=(8, 19, 34), outline=LINE, width=u(1))
    d.rounded_rectangle([u(gx), u(gy), u(gx + gw * 0.47), u(gy + 11)], radius=u(5), fill=(64, 150, 178))
    for frac in (0.20, 0.40):
        tx = gx + gw * frac
        d.line([u(tx), u(gy - 5), u(tx), u(gy + 16)], fill=AMBER, width=u(2))
    T(d, gx, 578, "0", 11, FAINT)
    T(d, gx + gw * 0.20, 578, "可疑 20", 11, AMBER, anchor="ma")
    T(d, gx + gw * 0.40, 578, "高危 40", 11, AMBER, anchor="ma")
    T(d, gx + gw, 578, "100", 11, FAINT, anchor="ra")
    T(d, 1082, 606, "47 → 高危；规则分仍保留在事件里。", 12, (127, 153, 179))

    T(d, 1068, 686, "normal 的原始概率仍保留在", 12, DIM)
    T(d, 1068, 708, "extra.ai，便于追溯，不回写规则。", 12, DIM)

    # card 4
    card(d, 1496, 264, 360, 510, accent=(54, 134, 171))
    card_head(d, 1518, 286, "04", "落库与呈现")
    mono_box(d, 1518, 330, 316, 44, "final_source = rule / rule+ai", 12.5)
    mono_box(d, 1518, 384, 316, 44, "raw_request → event_log", 12.5)
    chip(d, 1518, 452, "AI XSS +25", 12.5, GREEN, (16, 42, 35), (47, 106, 85), 10, 28)
    T(d, 1518, 500, "大屏实时日志", 13, MUTED)
    T(d, 1518, 524, "调查工作台 · AI 报告", 13, MUTED)

    for i, t in enumerate(["实时日志", "调查工作台", "AI 报告"]):
        chip(d, 1518, 574 + i * 38, t, 12, (188, 209, 228), PANEL2, LINE2, 10, 26)

    T(d, 1518, 708, "证据可回跳原始请求", 12, DIM)

    # KPI row
    kpi(d, 64, 796, "训练样本", "104,327", "增强训练集", (54, 134, 171), HEAD)
    kpi(d, 365, 796, "测试准确率", "99.36%", "独立测试集 4,083 条", GREEN, GREEN)
    kpi(d, 666, 796, "宏平均 F1", "98.98%", "五分类", CYAN, BLUE)
    kpi(d, 967, 796, "线上检出", "27/34", "端到端攻击载荷", AMBER, AMBER)
    kpi(d, 1268, 796, "正常误报", "0/6", "小样本对照", GREEN, GREEN)
    kpi(d, 1569, 796, "平均延迟", "39ms", "P95 63ms", BLUE, BLUE)

    # footer
    x = footer_item(d, 64, 972, "模型只做分类与加分，不执行命令", GREEN, 12.5)
    vline(d, x + 16, 973, 987, LINE, 1)
    x = footer_item(d, x + 32, 972, "服务不可达 → 自动熔断，回退纯规则", AMBER, 12.5)
    vline(d, x + 16, 973, 987, LINE, 1)
    footer_item(d, x + 32, 972, "误报、漏报由人工复核兜底", CYAN, 12.5)

    src_label = "数据："
    src_files = "model_meta.json / ai_model_live.json"
    lw = tw(d, src_label, 11.5)
    fw = tw(d, src_files, 11.5, mono=True)
    sx = 1856 - lw - 6 - fw
    T(d, sx, 972, src_label, 11.5, FAINT)
    T(d, sx + lw + 6, 972, src_files, 11.5, FAINT, mono=True)

    save(img, "ai_model_layer.png")


def draw_two_layers():
    img = background()
    cards = [(64, 250, 840, 620), (1016, 250, 840, 620)]
    img = Image.alpha_composite(img, shadow_layer(cards))
    d = ImageDraw.Draw(img)

    # header
    T(d, 64, 46, "AI · 两层分工｜请求级 + 研判级", 15, CYAN, bold=True)
    T(d, 64, 72, "两层 AI，各干各的事", 58, HEAD, bold=True)
    T(d, 64, 158, "不是一个大模型包打天下；一条请求、一次研判，各自留下证据", 21, MUTED)
    hline(d, 64, 1856, 206, LINE)
    right_pill(d, 1856, 56, "第一层 · 请求级", 13)
    right_pill(d, 1856, 98, "第二层 · 研判级", 13)
    right_pill(d, 1856, 140, "互不覆盖结论", 13)

    # card 1
    card(d, 64, 250, 840, 620, accent=CYAN, glow=True)
    badge(d, 88, 276, "第一层", CYAN, (13, 40, 44), (47, 106, 110))
    T(d, 192, 291, "请求级", 13, DIM, anchor="lm")
    T(d, 88, 326, "自研攻击识别模型", 36, HEAD, bold=True)
    T(d, 88, 378, "请求进来，先判一次", 18, MUTED)
    row(d, 88, 426, 792, "输入", "HTTP 请求的 path / query / body / UA", CYAN)
    row(d, 88, 490, 792, "方法", "字符级 TF-IDF → 逻辑回归 → 5 类", CYAN)
    row(d, 88, 554, 792, "输出", "ai_points 0–25，与规则分相加", CYAN)
    row(d, 88, 618, 792, "边界", "快、可熔断；normal 最终 +0", CYAN)
    mono_box(d, 88, 694, 792, 54, "final_source = rule / rule+ai", 13.5)
    dot(d, 92, 772, 3.5, GREEN)
    T(d, 104, 766, "只做分类与加分，不碰主机；服务不可达自动熔断。", 13.5, (143, 169, 193))
    cx = 88
    cx += mono_chip(d, cx, 804, "final_source=rule+ai", 11.5) + 10
    chip(d, cx, 804, "AI XSS +25", 11.5, GREEN, (16, 42, 35), (47, 106, 85), 9, 27)

    # card 2
    card(d, 1016, 250, 840, 620, accent=BLUE)
    badge(d, 1040, 276, "第二层", BLUE, (13, 31, 47), (47, 90, 115))
    T(d, 1144, 291, "研判级", 13, DIM, anchor="lm")
    T(d, 1040, 326, "通用大模型", 36, HEAD, bold=True)
    T(d, 1040, 378, "日志出去，再读一遍", 18, MUTED)
    row(d, 1040, 426, 792, "输入", "事件日志 / 原始请求 / 交互记录", BLUE)
    row(d, 1040, 490, 792, "任务", "分析 · 问答 · 互动 · 复核", BLUE)
    row(d, 1040, 554, 792, "方法", "JSON Schema + 证据引用 + 封闭策略", BLUE)
    row(d, 1040, 618, 792, "边界", "慢、可降级；不执行命令", BLUE)
    mono_box(d, 1040, 694, 792, 54, "refs -> exact quote", 13.5)
    dot(d, 1044, 772, 3.5, AMBER)
    T(d, 1056, 766, "引用必须命中原文；只读证据，不改写规则。", 13.5, (143, 169, 193))
    cx = 1040
    for t in ["分析报告", "证据问答", "封闭策略"]:
        cx += chip(d, cx, 804, t, 11.5, BLUE, (13, 31, 47), (47, 90, 115), 9, 27) + 10

    # center divider
    for yy in range(270, 850, 18):
        d.line([u(960), u(yy), u(960), u(yy + 9)], fill=LINE, width=u(1))
    d.rounded_rectangle([u(918), u(300), u(1002), u(328)], radius=u(14), fill=PANEL2, outline=LINE2, width=u(1))
    T(d, 960, 314, "两条链路", 11.5, MUTED, anchor="mm")
    d.ellipse([u(931), u(491), u(989), u(549)], fill=PANEL2, outline=AMBER, width=u(1))
    T(d, 960, 520, "≠", 26, AMBER, bold=True, anchor="mm")
    d.rounded_rectangle([u(918), u(770), u(1002), u(798)], radius=u(14), fill=PANEL2, outline=LINE2, width=u(1))
    T(d, 960, 784, "互不覆盖", 11.5, MUTED, anchor="mm")

    # bottom principles
    d.rounded_rectangle([u(64), u(900), u(1856), u(1000)], radius=u(14), fill=PANEL, outline=LINE, width=u(1))
    items = [("规则分不被 AI 覆盖", GREEN), ("AI 结论 ≠ 攻击成功", AMBER), ("模型不可用只降级，不阻断", CYAN)]
    xs = [92, 690, 1286]
    for (text, color), x in zip(items, xs):
        dot(d, x, 930, 3.5, color)
        T(d, x + 14, 922, text, 15, TEXT)
    vline(d, 656, 920, 948, LINE, 1)
    vline(d, 1252, 920, 948, LINE, 1)
    T(d, 92, 960, "共同边界：不执行命令 · 不碰主机 · 不改写原结论 · 全程审计", 12.5, DIM)

    T(d, 64, 1032, "状态与执行由程序控制；模型只做分类、研判与策略选择。", 12, DIM)
    T(d, 1856, 1032, "配图对应演讲稿「两层 AI」段", 11.5, FAINT, anchor="ra")

    save(img, "ai_two_layers.png")


if __name__ == "__main__":
    draw_model_layer()
    draw_two_layers()
