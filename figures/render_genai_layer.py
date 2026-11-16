"""Render the second-layer (judging-level) general LLM principle diagram.

Reuses palette + draw helpers from render_figures.py so the output matches
ai_model_layer.png / ai_two_layers.png exactly in style.
"""
from pathlib import Path
import sys
import math

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render_figures as R
from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent


def U(v):
    return R.u(v)


def arrow(d, x1, y1, x2, y2, color, width=2):
    d.line([U(x1), U(y1), U(x2), U(y2)], fill=color, width=U(width))
    ang = math.atan2(y2 - y1, x2 - x1)
    L = 10
    for da in (math.radians(150), math.radians(210)):
        ex = x2 + L * math.cos(ang + da)
        ey = y2 + L * math.sin(ang + da)
        d.line([U(x2), U(y2), U(ex), U(ey)], fill=color, width=U(width))


def right_chips(d, x_right, y, specs, size=12, padx=10, ph=28, gap=8):
    specs = list(reversed(specs))
    x = x_right
    for (text, fg, bg, border) in specs:
        w = R.tw(d, text, size) + 2 * padx
        x = x - w
        R.chip(d, x, y, text, size, fg, bg, border, padx, ph)
        x = x - gap
    return x


def fn_card(d, cx, cy, cw, ch, num, title, summary, rows, footer, chips):
    R.card(d, cx, cy, cw, ch, accent=R.CYAN, glow=True)
    R.card_head(d, cx + 22, cy + 20, num, title)
    if chips:
        right_chips(d, cx + cw - 18, cy + 16, chips)
    R.para(d, cx + 24, cy + 70, cw - 48, summary, 15, R.MUTED)
    y = cy + 112
    for label, value, accent in rows:
        R.row(d, cx + 24, y, cw - 48, label, value, accent)
        y += 60
    if footer:
        R.dot(d, cx + 26, y + 6, 3.5, R.GREEN)
        R.T(d, cx + 38, y, footer, 12.5, R.MUTED)


def draw_genai_layer():
    img = R.background()
    cards = [
        (64, 250, 360, 316),    # evidence input
        (64, 578, 360, 316),    # general LLM node
        (448, 250, 696, 316),   # 分析
        (1160, 250, 696, 316),  # 问答
        (448, 578, 696, 316),   # 互动
        (1160, 578, 696, 316),  # 复核
    ]
    img = Image.alpha_composite(img, R.shadow_layer(cards))
    d = ImageDraw.Draw(img)

    # ---- header ----
    R.T(d, 64, 46, "AI · 第二层｜研判级 · 通用大模型", 15, R.CYAN, bold=True)
    R.T(d, 64, 72, "通用大模型，四件事各管一段", 58, R.HEAD, bold=True)
    R.T(d, 64, 158, "日志只当数据，不当指令；输出必须过格式与证据校验，不合格就重试或降级", 21, R.MUTED)
    R.hline(d, 64, 1856, 206, R.LINE)
    R.right_pill(d, 1856, 56, "第二层 · 研判级", 13)
    R.right_pill(d, 1856, 98, "通用大模型", 13)
    R.right_pill(d, 1856, 140, "分析 · 问答 · 互动 · 复核", 13)

    # ---- arrows: model node -> four functions ----
    mx, my = 424, 736
    targets = [(448, 408), (1160, 408), (448, 736), (1160, 736)]
    for (tx, ty) in targets:
        arrow(d, mx + 4, my, tx - 4, ty, (54, 134, 171), 2)

    # ---- left: evidence input ----
    ix, iy, iw, ih = 64, 250, 360, 316
    R.card(d, ix, iy, iw, ih, accent=(54, 134, 171))
    R.card_head(d, ix + 22, iy + 20, "IN", "证据输入")
    R.T(d, ix + 24, iy + 72, "三类证据，统一喂给模型", 14, R.HEAD, bold=True)
    yy = iy + 104
    for t in ["事件日志", "原始请求", "交互记录"]:
        R.chip(d, ix + 24, yy, t, 12.5, (188, 209, 228), R.PANEL2, R.LINE2, 10, 28)
        yy += 38
    R.mono_box(d, ix + 24, yy + 6, iw - 48, 44, "refs -> 原文引用", 12.5)
    R.T(d, ix + 24, yy + 64, "同源 / 同会话 / 跨协议", 12.5, R.DIM)

    # ---- left: general LLM node ----
    gx, gy, gw, gh = 64, 578, 360, 316
    R.card(d, gx, gy, gw, gh, accent=R.BLUE, glow=True)
    R.card_head(d, gx + 22, gy + 20, "M", "通用大模型")
    R.T(d, gx + 24, gy + 70, "三种后端，可切换", 14, R.HEAD, bold=True)
    yy = gy + 102
    for t in ["DeepSeek", "本地 Ollama", "共享网关"]:
        R.chip(d, gx + 24, yy, t, 12, R.BLUE, (13, 31, 47), (47, 90, 115), 9, 27)
        yy += 36
    R.mono_box(d, gx + 24, yy + 4, gw - 48, 44, "JSON Schema + 证据引用", 12)
    R.dot(d, gx + 26, gy + gh - 30, 3.5, R.AMBER)
    R.T(d, gx + 38, gy + gh - 36, "不可用 → 自动降级，不阻断", 12.5, R.MUTED)

    # ---- four function cards ----
    fn_card(
        d, 448, 250, 696, 316, "01", "分析 · Analysis",
        "把零散日志读成一次攻击过程",
        [
            ("机制", "增量索引 · 每批 ≤24 条 · 最多 6 条代表证据", R.CYAN),
            ("报告", "攻击目的 / 行为推进 / 风险理由 / 复核建议 / 局限", R.CYAN),
            ("约束", "关键判断带原文引用，须逐字出现于原始记录", R.CYAN),
        ],
        "引用必须逐字出现；验证器拦掉无证据的『已被攻破』",
        [("81/81 报告", R.GREEN, (16, 42, 35), (47, 106, 85)),
         ("调用 108/110", R.AMBER, (42, 36, 20), (109, 90, 53))],
    )

    fn_card(
        d, 1160, 250, 696, 316, "02", "问答 · Q&A",
        "围绕日志追问，不脱离证据",
        [
            ("检索", "按 IP / 关键词；≤250 候选 · 24 相关 · 6 证据", R.CYAN),
            ("输出", "回答带引用；明确『只看到这些片段』", R.CYAN),
            ("边界", "无工具 · 无联网 · 无主机执行权限", R.CYAN),
        ],
        "没有工具、没有联网、没有主机执行权限",
        [("≤250 候选", R.BLUE, (13, 31, 47), (47, 90, 115)),
         ("6 证据", R.BLUE, (13, 31, 47), (47, 90, 115))],
    )

    fn_card(
        d, 448, 578, 696, 316, "03", "互动 · Interaction",
        "让蜜罐『会说话』，但模型只做选择题",
        [
            ("SSH", "未知命令 → 命令不存在 / 服务不可用 / 拒绝访问", R.CYAN),
            ("Web", "预览请求 → 排队 / 格式错误 / 服务繁忙", R.CYAN),
            ("边界", "正文模板渲染，状态程序维护；不能生成命令", R.CYAN),
        ],
        "每次交互留痕，回放按会话看输入 / 回应 / 策略",
        [("封闭策略", R.AMBER, (42, 36, 20), (109, 90, 53)),
         ("模板渲染", R.AMBER, (42, 36, 20), (109, 90, 53))],
    )

    fn_card(
        d, 1160, 578, 696, 316, "04", "复核 · Review",
        "异步抽样 HTTP 请求，二次研判",
        [
            ("三档", "可疑 / 未见明确攻击 / 不确定（须引用原文）", R.CYAN),
            ("机制", "按来源限流、排队；失败不影响规则与响应", R.CYAN),
            ("对照", "规则与 AI 并排，互不覆盖结论", R.CYAN),
        ],
        "监控页看状态、真实调用、失败原因与备用处理",
        [("三档结论", R.GREEN, (16, 42, 35), (47, 106, 85)),
         ("可降级", R.GREEN, (16, 42, 35), (47, 106, 85))],
    )

    # label near dispatch
    R.pill(d, 432, 700, "四件事", 12, R.TEXT, R.PANEL2, R.LINE2, 12, 26)

    # ---- bottom boundary bar ----
    d.rounded_rectangle([U(64), U(906), U(1856), U(1006)], radius=U(14), fill=R.PANEL, outline=R.LINE, width=U(1))
    items = [
        ("日志只当数据", R.CYAN),
        ("过格式+证据校验", R.AMBER),
        ("只读证据不改写规则", R.GREEN),
        ("不执行命令", R.ORANGE),
        ("不可用自动降级", R.BLUE),
    ]
    xs = [92, 458, 824, 1190, 1556]
    for (text, color), x in zip(items, xs):
        R.dot(d, x, 936, 3.5, color)
        R.T(d, x + 14, 928, text, 15, R.TEXT)
    for sx in (424, 790, 1156, 1522):
        R.vline(d, sx, 924, 952, R.LINE, 1)
    R.T(d, 92, 964, "共同边界：日志当数据 · 不执行命令 · 不碰主机 · 不改写原结论 · 全程审计", 12.5, R.DIM)

    # ---- footer ----
    R.T(d, 64, 1036, "模型只做研判与策略选择，不执行命令", 12, R.DIM)
    R.T(d, 1856, 1036, "配图对应演讲稿『AI 是助手，不是裁判』段", 11.5, R.FAINT, anchor="ra")

    R.save(img, "ai_genai_layer.png")


if __name__ == "__main__":
    draw_genai_layer()
