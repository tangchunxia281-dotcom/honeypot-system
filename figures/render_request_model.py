from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

# ---------------------------------------------------------------------------
# Request-level detector / concept board
# 2560 x 1522 (same aspect as the supplied reference board)
# ---------------------------------------------------------------------------

W, H = 2560, 1522
S = 2
OUT = Path(__file__).resolve().parent

FONT_DIR = Path("C:/Windows/Fonts")
SANS = FONT_DIR / "NotoSansSC-VF.ttf"
MONO = FONT_DIR / "CascadiaMono.ttf"
MONO_B = FONT_DIR / "CascadiaMono.ttf"

BG_TOP = (5, 13, 23)
BG_BOT = (6, 19, 31)
TEXT = (232, 242, 252)
HEAD = (241, 248, 255)
MUTED = (160, 181, 201)
DIM = (112, 137, 158)
FAINT = (76, 101, 123)
LINE = (26, 47, 64)
LINE2 = (39, 68, 88)
PANEL = (8, 22, 35)
PANEL2 = (10, 27, 42)
CODEBG = (5, 15, 24)

AMBER = (255, 190, 92)
TEAL = (67, 224, 190)
BLUE = (106, 157, 255)
PURPLE = (186, 126, 255)
GREEN = (103, 224, 169)
RED = (255, 126, 137)
ORANGE = (255, 163, 102)
CYAN = (94, 220, 218)
WHITE = (255, 255, 255)

ACCENTS = [AMBER, TEAL, BLUE, PURPLE]

_font_cache = {}
_text_glow_cache = {}


def u(v):
    return int(round(v * S))


def mix(c1, c2, t):
    return tuple(int(round(c1[i] * (1 - t) + c2[i] * t)) for i in range(3))


def rgba(c, a):
    return (c[0], c[1], c[2], a)


def F(size, weight="Regular", mono=False):
    key = (round(size, 2), weight, mono)
    if key not in _font_cache:
        path = MONO if mono else SANS
        f = ImageFont.truetype(str(path), u(size))
        if not mono:
            try:
                f.set_variation_by_name(weight)
            except Exception:
                pass
        _font_cache[key] = f
    return _font_cache[key]


def T(d, x, y, text, size, color, weight="Regular", mono=False, anchor="la"):
    d.text((u(x), u(y)), str(text), font=F(size, weight, mono), fill=color, anchor=anchor)


def tw(d, text, size, weight="Regular", mono=False):
    return d.textlength(str(text), font=F(size, weight, mono)) / S


def tracked(d, x, y, text, size, color, weight="Regular", mono=False, tracking=1.6):
    cx = x
    for ch in text:
        T(d, cx, y, ch, size, color, weight, mono)
        cx += tw(d, ch, size, weight, mono) + tracking
    return cx - tracking


def rich(d, x, y, parts, size, default_weight="Regular", mono=False):
    """parts: [(text, color, weight_optional), ...]"""
    cx = x
    for part in parts:
        s = part[0]
        color = part[1]
        weight = part[2] if len(part) > 2 else default_weight
        T(d, cx, y, s, size, color, weight, mono)
        cx += tw(d, s, size, weight, mono)
    return cx


def dot(d, x, y, r, color):
    d.ellipse([u(x - r), u(y - r), u(x + r), u(y + r)], fill=color)


def hline(d, x1, x2, y, color, width=1.0):
    d.line([u(x1), u(y), u(x2), u(y)], fill=color, width=max(1, u(width)))


def vline(d, x, y1, y2, color, width=1.0):
    d.line([u(x), u(y1), u(x), u(y2)], fill=color, width=max(1, u(width)))


def dashed_line(d, x1, x2, y, color, width=1.0, dash=8, gap=7):
    x = x1
    while x < x2:
        d.line([u(x), u(y), u(min(x + dash, x2)), u(y)], fill=color, width=max(1, u(width)))
        x += dash + gap


def arrow(d, x1, y, x2, color, width=1.2):
    d.line([u(x1), u(y), u(x2 - 3), u(y)], fill=color, width=max(1, u(width)))
    d.line([u(x2 - 9), u(y - 5), u(x2 - 3), u(y)], fill=color, width=max(1, u(width)))
    d.line([u(x2 - 9), u(y + 5), u(x2 - 3), u(y)], fill=color, width=max(1, u(width)))


def rrect(d, x, y, w, h, r, fill=None, outline=None, width=1):
    d.rounded_rectangle(
        [u(x), u(y), u(x + w), u(y + h)],
        radius=u(r),
        fill=fill,
        outline=outline,
        width=max(1, u(width)),
    )


def chip(d, x, y, text, size=12.5, fg=TEXT, bg=None, border=None, padx=10, h=27, mono=False, weight="Regular"):
    bg = bg or mix(PANEL2, LINE, 0.13)
    border = border or mix(LINE, bg, 0.30)
    w = tw(d, text, size, weight, mono) + 2 * padx
    rrect(d, x, y, w, h, h / 2, fill=bg, outline=border, width=1)
    T(d, x + w / 2, y + h / 2 + 0.5, text, size, fg, weight, mono, anchor="mm")
    return w


def pill(d, x, y, w, h, text, size, fg, border, bg, mono=False, weight="Regular"):
    rrect(d, x, y, w, h, h / 2, fill=bg, outline=border, width=1)
    T(d, x + w / 2, y + h / 2 + 0.5, text, size, fg, weight, mono, anchor="mm")


def vertical_gradient_rrect(img, x, y, w, h, r, c1, c2, outline=None, outline_w=1.0):
    uw, uh = u(w), u(h)
    t = np.linspace(0.0, 1.0, uh, dtype=np.float32)[:, None]
    arr = np.empty((uh, uw, 3), dtype=np.uint8)
    for i in range(3):
        arr[:, :, i] = np.clip(c1[i] * (1 - t) + c2[i] * t, 0, 255).astype(np.uint8)
    grad = Image.fromarray(arr, "RGB").convert("RGBA")
    mask = Image.new("L", (uw, uh), 0)
    md = ImageDraw.Draw(mask)
    md.rounded_rectangle([0, 0, uw - 1, uh - 1], radius=u(r), fill=255)
    grad.putalpha(mask)
    img.alpha_composite(grad, (u(x), u(y)))
    if outline:
        d = ImageDraw.Draw(img)
        d.rounded_rectangle(
            [u(x), u(y), u(x + w), u(y + h)],
            radius=u(r),
            outline=outline,
            width=max(1, u(outline_w)),
        )


def text_width_in(d, text, size, weight="Regular", mono=False):
    return tw(d, text, size, weight, mono)


# ---------------------------------------------------------------------------
# Background
# ---------------------------------------------------------------------------


def background():
    yy, xx = np.mgrid[0:H, 0:W].astype(np.float32)
    ty = yy / (H - 1)
    base = np.empty((H, W, 3), dtype=np.float32)
    for i in range(3):
        base[:, :, i] = BG_TOP[i] * (1 - ty) + BG_BOT[i] * ty

    def radial(cx, cy, rx, ry, color, strength, power=2.0):
        nonlocal base
        dist = np.sqrt(((xx - cx) / rx) ** 2 + ((yy - cy) / ry) ** 2)
        a = np.clip(1 - dist, 0, 1) ** power * strength
        for i in range(3):
            base[:, :, i] = base[:, :, i] * (1 - a) + color[i] * a

    radial(0.78 * W, -0.02 * H, 0.55 * W, 0.48 * H, (16, 52, 76), 0.38, 1.8)
    radial(0.06 * W, 0.12 * H, 0.46 * W, 0.48 * H, (18, 38, 59), 0.22, 2.0)
    radial(0.17 * W, 1.02 * H, 0.42 * W, 0.55 * H, (12, 48, 49), 0.16, 2.0)
    radial(0.96 * W, 0.72 * H, 0.42 * W, 0.70 * H, (23, 31, 52), 0.14, 2.0)
    radial(0.48 * W, 0.05 * H, 0.35 * W, 0.22 * H, (8, 24, 40), 0.18, 1.8)

    # fine grain in the atmosphere
    rng = np.random.default_rng(21)
    noise = rng.normal(0, 2.3, (H, W, 1)).astype(np.float32)
    base = np.clip(base + noise, 0, 255)

    img = Image.fromarray(base.astype(np.uint8), "RGB").resize((W * S, H * S), Image.LANCZOS).convert("RGBA")

    # technical grid
    grid = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
    gd = ImageDraw.Draw(grid)
    step = u(62)
    for x in range(0, W * S, step):
        gd.line([x, 0, x, H * S], fill=(100, 142, 166, 14), width=1)
    for y in range(0, H * S, step):
        gd.line([0, y, W * S, y], fill=(100, 142, 166, 14), width=1)
    for x in range(0, W * S, step * 4):
        gd.line([x, 0, x, H * S], fill=(104, 145, 168, 10), width=1)
    for y in range(0, H * S, step * 4):
        gd.line([0, y, W * S, y], fill=(104, 145, 168, 10), width=1)
    img = Image.alpha_composite(img, grid)

    # thin keyboard-line at the very top
    top = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
    td = ImageDraw.Draw(top)
    for i, x in enumerate(range(0, u(1280), 4)):
        fade = max(0.0, 1 - x / u(1280))
        td.rectangle([x, 0, x + 4, u(1.4)], fill=(70, 198, 194, int(34 * fade)))
    img = Image.alpha_composite(img, top)
    return img


# ---------------------------------------------------------------------------
# Shared decorative components
# ---------------------------------------------------------------------------


def glow_layer(cards, flow_box):
    layer = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)

    # card top-edge bloom
    for (x, y, w, h), accent in zip(cards, ACCENTS):
        d.rounded_rectangle(
            [u(x + 18), u(y + 2), u(x + w - 90), u(y + 8)],
            radius=u(4),
            fill=rgba(accent, 62),
        )
        # icon-tile bloom
        d.rounded_rectangle(
            [u(x + 28), u(y + 88), u(x + 136), u(y + 196)],
            radius=u(24),
            fill=rgba(accent, 38),
        )

    # flow chips bloom
    fx, fy, fw, fh = flow_box
    for i, accent in enumerate(ACCENTS):
        cx = fx + 38 + i * (fw - 76) / 3
        d.rounded_rectangle(
            [u(cx - 48), u(fy + 26), u(cx + 48), u(fy + 122)],
            radius=u(20),
            fill=rgba(accent, 30),
        )

    layer = layer.filter(ImageFilter.GaussianBlur(u(18)))
    return layer


def shadow_layer(cards, flow_box):
    layer = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    for x, y, w, h in cards:
        d.rounded_rectangle(
            [u(x), u(y + 18), u(x + w), u(y + h + 22)],
            radius=u(24),
            fill=(0, 0, 0, 145),
        )
    fx, fy, fw, fh = flow_box
    d.rounded_rectangle(
        [u(fx), u(fy + 12), u(fx + fw), u(fy + fh + 18)],
        radius=u(22),
        fill=(0, 0, 0, 120),
    )
    return layer.filter(ImageFilter.GaussianBlur(u(30)))


def small_icon(d, kind, cx, cy, color):
    """Simple line icons for the card corner buttons."""
    lw = max(1, u(1.3))
    if kind == "request":
        d.line([u(cx - 8), u(cy - 9), u(cx - 8), u(cy + 6)], fill=color, width=lw)
        d.line([u(cx + 8), u(cy - 9), u(cx + 8), u(cy + 6)], fill=color, width=lw)
        d.line([u(cx - 8), u(cy + 6), u(cx - 3), u(cy + 10)], fill=color, width=lw)
        d.line([u(cx + 8), u(cy + 6), u(cx + 3), u(cy + 10)], fill=color, width=lw)
        d.line([u(cx - 3), u(cy + 10), u(cx + 3), u(cy + 10)], fill=color, width=lw)
        d.line([u(cx), u(cy - 11), u(cx), u(cy + 1)], fill=color, width=lw)
        d.line([u(cx - 4), u(cy - 3), u(cx), u(cy + 1)], fill=color, width=lw)
        d.line([u(cx + 4), u(cy - 3), u(cx), u(cy + 1)], fill=color, width=lw)
    elif kind == "rule":
        pts = [(cx, cy - 11), (cx + 9, cy - 7), (cx + 8, cy + 4), (cx, cy + 11), (cx - 8, cy + 4), (cx - 9, cy - 7)]
        d.polygon([(u(px), u(py)) for px, py in pts], outline=color, width=lw)
        d.line([u(cx - 4), u(cy), u(cx - 1), u(cy + 3)], fill=color, width=lw)
        d.line([u(cx - 1), u(cy + 3), u(cx + 5), u(cy - 4)], fill=color, width=lw)
    elif kind == "model":
        d.rounded_rectangle([u(cx - 6), u(cy - 6), u(cx + 6), u(cy + 6)], radius=u(2), outline=color, width=lw)
        d.rounded_rectangle([u(cx - 2), u(cy - 2), u(cx + 2), u(cy + 2)], radius=u(0.5), outline=color, width=lw)
        for dx in (-11, 11):
            d.line([u(cx + dx), u(cy - 3), u(cx + dx), u(cy + 3)], fill=color, width=lw)
            d.line([u(cx - 3), u(cy + dx / 2), u(cx + 3), u(cy + dx / 2)], fill=color, width=lw)
    else:  # verdict
        d.ellipse([u(cx - 10), u(cy - 10), u(cx + 10), u(cy + 10)], outline=color, width=lw)
        d.line([u(cx - 5), u(cy), u(cx - 1), u(cy + 4)], fill=color, width=lw)
        d.line([u(cx - 1), u(cy + 4), u(cx + 6), u(cy - 5)], fill=color, width=lw)


def panel_head(d, x, y, w, label, right, accent):
    dot(d, x, y + 6, 2.6, accent)
    T(d, x + 10, y - 1, label, 13.0, TEXT, "Medium", mono=True)
    T(d, x + w, y, right, 10.0, mix(FAINT, MUTED, 0.25), mono=True, anchor="ra")
    hline(d, x, x + w, y + 27, mix(LINE, PANEL, 0.15), 0.9)


def tiny_dot_row(d, x, y, color, text, size=10.5, mono=False, color_text=FAINT):
    dot(d, x, y + 4.5, 2.0, color)
    T(d, x + 9, y, text, size, color_text, mono=mono)


def fill_bar(d, x, y, w, h, frac, color, bg=None):
    bg = bg or mix(CODEBG, LINE, 0.28)
    rrect(d, x, y, w, h, h / 2, fill=bg)
    if frac > 0:
        rrect(d, x, y, max(h, w * frac), h, h / 2, fill=color)


# ---------------------------------------------------------------------------
# Cards
# ---------------------------------------------------------------------------


def draw_flow_panel(img, box):
    fx, fy, fw, fh = box
    vertical_gradient_rrect(
        img, fx, fy, fw, fh, 22,
        (10, 26, 41), (6, 17, 29),
        outline=mix(LINE2, (66, 116, 148), 0.28), outline_w=1.2,
    )
    d = ImageDraw.Draw(img)
    hline(d, fx + 20, fx + fw - 20, fy + fh - 49, mix(LINE, (5, 17, 29), 0.15), 0.9)

    # four action nodes
    n = 4
    left = fx + 38
    right = fx + fw - 38
    tile = 84
    gap = (right - left - n * tile) / (n - 1)
    labels = ["请求", "规则", "模型", "结论"]
    chars = ["收", "规", "模", "判"]
    centers = []
    for i, (ch, label, accent) in enumerate(zip(chars, labels, ACCENTS)):
        tx = left + i * (tile + gap)
        cy = fy + 27
        centers.append((tx + tile / 2, cy + tile / 2))
        vertical_gradient_rrect(
            img, tx, cy, tile, tile, 16,
            mix((9, 22, 35), accent, 0.18),
            mix((6, 16, 27), accent, 0.05),
            outline=mix(accent, LINE2, 0.35), outline_w=1.3,
        )
        # crisp inner hairline
        rrect(d, tx + 5, cy + 5, tile - 10, tile - 10, 12, outline=mix(accent, (12, 30, 46), 0.72), width=0.7)
        T(d, tx + tile / 2, cy + tile / 2 - 2, ch, 51, mix(accent, WHITE, 0.18), "Black", anchor="mm")
        T(d, tx + tile / 2, cy + tile + 18, label, 15.0, mix(TEXT, accent, 0.10), "Medium", anchor="ma")

        if i:
            prev_tx = left + (i - 1) * (tile + gap) + tile
            arrow(d, prev_tx + 19, cy + tile / 2, tx - 18, mix(accent, LINE2, 0.42), 1.2)

    # panel footer
    T(d, left, fy + fh - 34, "REQUEST IN", 10.4, mix(DIM, MUTED, 0.22), mono=True)
    center = fx + fw / 2
    T(d, center, fy + fh - 36, "一条请求  ·  一条可追溯的结论", 12.0, mix(DIM, MUTED, 0.25), anchor="ma")
    T(d, right, fy + fh - 34, "VERDICT OUT", 10.4, mix(DIM, MUTED, 0.22), mono=True, anchor="ra")


def draw_card_frame(img, x, y, w, h, idx, accent):
    vertical_gradient_rrect(
        img, x, y, w, h, 24,
        mix((11, 28, 44), accent, 0.040), (6, 17, 28),
        outline=mix(accent, LINE2, 0.30), outline_w=1.2,
    )
    d = ImageDraw.Draw(img)
    # top rule
    d.line([u(x + 30), u(y + 2), u(x + w - 92), u(y + 2)], fill=mix(accent, (12, 30, 45), 0.28), width=u(2.6))
    d.line([u(x + 30), u(y + 2), u(x + 180), u(y + 2)], fill=mix(accent, WHITE, 0.10), width=u(2.6))
    # inner hairline
    rrect(d, x + 5, y + 5, w - 10, h - 10, 20, outline=mix(LINE, (5, 14, 23), 0.45), width=0.6)

    step = f"STEP 0{idx+1} / " + ["REQUEST", "RULE", "CLASSIFY", "VERDICT"][idx]
    tracked(d, x + 31, y + 32, step, 12.0, mix(accent, MUTED, 0.22), mono=True, tracking=1.2)
    # corner button
    bx, by = x + w - 57, y + 28
    d.ellipse([u(bx), u(by), u(bx + 40), u(by + 40)], fill=mix(PANEL2, accent, 0.04), outline=mix(accent, LINE, 0.28), width=u(1))
    small_icon(d, ["request", "rule", "model", "verdict"][idx], bx + 20, by + 20, mix(accent, TEXT, 0.12))


def draw_card_head(img, x, y, accent, char, title, subtitle, icon_kind):
    d = ImageDraw.Draw(img)
    # large action tile
    tx, ty, ts = x + 31, y + 112, 112
    vertical_gradient_rrect(
        img, tx, ty, ts, ts, 21,
        mix((12, 29, 43), accent, 0.19),
        mix((7, 18, 29), accent, 0.04),
        outline=mix(accent, LINE2, 0.38), outline_w=1.4,
    )
    rrect(d, tx + 5, ty + 5, ts - 10, ts - 10, 15, outline=mix(accent, (24, 43, 57), 0.58), width=0.7)
    T(d, tx + ts / 2, ty + ts / 2 - 3, char, 76, mix(accent, WHITE, 0.18), "Black", anchor="mm")

    T(d, x + 164, y + 122, title, 40, HEAD, "Bold")
    T(d, x + 164, y + 179, subtitle, 14.0, mix(accent, MUTED, 0.30), "Medium", mono=False)


def draw_card_copy(d, x, y, w, accent, lines):
    yy = y
    for parts in lines:
        rich(d, x, yy, parts, 20.0, "Regular")
        yy += 31


def draw_quote(d, x, y, w, accent, text):
    hline(d, x, x + w, y - 25, mix(LINE, (5, 14, 23), 0.15), 0.9)
    d.rectangle([u(x), u(y + 2), u(x + 3), u(y + 42)], fill=mix(accent, (12, 28, 42), 0.15))
    T(d, x + 18, y - 2, text, 21.0, mix(TEXT, MUTED, 0.18), "Medium")


# ---------------------------------------------------------------------------
# Card body content
# ---------------------------------------------------------------------------


def body_request(img, d, x, y, w, h, accent):
    panel_head(d, x + 18, y + 16, w - 36, "raw_request", "HTTP / 1.1", accent)

    bx, by, bw, bh = x + 16, y + 56, w - 32, 112
    rrect(d, bx, by, bw, bh, 9, fill=CODEBG, outline=mix(LINE, accent, 0.13), width=1)
    T(d, bx + 13, by + 10, "INCOMING REQUEST", 9.8, DIM, mono=True)
    # request line
    T(d, bx + 13, by + 32, "GET", 15.0, mix(accent, WHITE, 0.12), "Medium", mono=True)
    T(d, bx + 55, by + 32, "/download?file=../../etc/passwd", 15.0, (197, 216, 233), mono=True)
    # headers
    T(d, bx + 13, by + 62, "Host:", 11.3, FAINT, mono=True)
    T(d, bx + 58, by + 62, "honeypot.local", 11.3, DIM, mono=True)
    T(d, bx + 13, by + 86, "User-Agent:", 11.3, FAINT, mono=True)
    T(d, bx + 110, by + 86, "curl/8.7.1", 11.3, DIM, mono=True)

    # field rows
    rows = [
        ("METHOD", "GET", "PATH", "/download"),
        ("QUERY", "file=../../etc/passwd", None, None),
        ("UA", "curl/8.7.1", None, None),
        ("BODY", "—", None, None),
    ]
    ry = y + 190
    for r in rows:
        label, val, label2, val2 = r
        T(d, x + 24, ry + 10, label, 10.3, mix(DIM, FAINT, 0.25), mono=True)
        if label2:
            T(d, x + 114, ry + 8, val, 13.6, (214, 229, 243), mono=True)
            T(d, x + 286, ry + 10, label2, 10.3, mix(DIM, FAINT, 0.25), mono=True)
            T(d, x + 348, ry + 8, val2, 13.6, (214, 229, 243), mono=True)
        else:
            color = mix(AMBER, WHITE, 0.20) if label == "QUERY" else (214, 229, 243)
            T(d, x + 114, ry + 8, val, 13.6, color, mono=True)
        hline(d, x + 20, x + w - 20, ry + 36, mix(LINE, CODEBG, 0.18), 0.8)
        ry += 44

    # footer note
    tiny_dot_row(d, x + 22, y + h - 30, accent, "原始请求先留档 · 不改写", 11.0)
    T(d, x + w - 22, y + h - 30, "RAW", 10.0, FAINT, mono=True, anchor="ra")


def body_rules(img, d, x, y, w, h, accent):
    panel_head(d, x + 18, y + 16, w - 36, "rule_layer", "FAST PASS", accent)

    T(d, x + 20, y + 52, "扫描器指纹", 15.0, HEAD, "Bold")
    T(d, x + w - 20, y + 55, "UA / 路径 / 已知特征", 10.3, mix(FAINT, MUTED, 0.30), anchor="ra")

    # scanner chips, 4 + 4
    names = [["sqlmap", "nikto", "nmap", "masscan"], ["nuclei", "awvs", "gobuster", "wpscan"]]
    for row, arr in enumerate(names):
        cx = x + 20
        for name in arr:
            cw = chip(
                d, cx, y + 79 + row * 31, name, 11.0,
                fg=mix(TEXT, accent, 0.10), bg=mix(PANEL2, accent, 0.07),
                border=mix(LINE, accent, 0.18), padx=8, h=24, mono=True,
            )
            cx += cw + 6

    # observed UA / miss
    ux, uy, uw = x + 20, y + 151, w - 40
    rrect(d, ux, uy, uw, 52, 8, fill=mix(CODEBG, accent, 0.025), outline=mix(LINE, accent, 0.12), width=1)
    T(d, ux + 11, uy + 9, "THIS REQUEST  ·  UA", 9.5, FAINT, mono=True)
    T(d, ux + 11, uy + 26, "curl/8.7.1", 12.8, (202, 220, 237), mono=True)
    chip(d, ux + uw - 92, uy + 13, "未命中", 10.5, mix(TEXT, accent, 0.15), mix(PANEL2, accent, 0.05), mix(accent, LINE, 0.28), 8, 24)

    # outcomes
    box_y = y + 224
    bw = (w - 40 - 12) / 2
    # hit
    rrect(d, x + 20, box_y, bw, 138, 10, fill=mix(PANEL2, accent, 0.035), outline=mix(LINE, accent, 0.13), width=1)
    T(d, x + 34, box_y + 18, "HIT", 9.5, FAINT, mono=True)
    T(d, x + 34, box_y + 39, "指纹命中", 15.5, mix(TEXT, MUTED, 0.18), "Medium")
    d.line([u(x + 34), u(box_y + 78), u(x + 76), u(box_y + 78)], fill=mix(accent, (18, 38, 53), 0.52), width=u(1.4))
    T(d, x + 34, box_y + 94, "规则直接定性", 11.5, DIM)

    # miss highlighted
    mx = x + 20 + bw + 12
    rrect(d, mx, box_y, bw, 138, 10, fill=mix(PANEL2, BLUE, 0.10), outline=mix(BLUE, LINE, 0.30), width=1.2)
    T(d, mx + 14, box_y + 18, "MISS", 9.5, mix(BLUE, MUTED, 0.22), mono=True)
    T(d, mx + 14, box_y + 39, "指纹未命中", 15.5, HEAD, "Medium")
    d.line([u(mx + 14), u(box_y + 78), u(mx + 56), u(box_y + 78)], fill=mix(BLUE, (18, 38, 53), 0.45), width=u(1.4))
    T(d, mx + 14, box_y + 94, "交给模型判断", 11.5, mix(TEXT, BLUE, 0.16))
    # small next arrow
    arrow(d, mx + bw - 40, box_y + 102, mx + bw - 16, mix(BLUE, MUTED, 0.25), 1.1)

    tiny_dot_row(d, x + 22, y + h - 30, accent, "扫描器只走规则，不进入模型训练", 11.0)
    T(d, x + w - 22, y + h - 30, "SCANNER → RULE", 9.5, FAINT, mono=True, anchor="ra")


def body_model(img, d, x, y, w, h, accent):
    panel_head(d, x + 18, y + 16, w - 36, "self_trained_model", "5-CLASS", accent)

    T(d, x + 20, y + 50, "字符级切分", 10.4, mix(FAINT, MUTED, 0.30))
    T(d, x + 88, y + 50, "· CHAR", 9.6, mix(FAINT, MUTED, 0.25), mono=True)
    T(d, x + w - 20, y + 50, "LOGISTIC REGRESSION", 9.2, mix(FAINT, MUTED, 0.22), mono=True, anchor="ra")

    # payload sample
    sample = "file=../../etc/passwd"
    T(d, x + 20, y + 67, sample, 15.0, mix(accent, WHITE, 0.18), "Medium", mono=True)

    # char n-grams
    grams = ["..", "./", "/e", "et", "tc", "c/", "/p", "pa", "…"]
    gx = x + 20
    for g in grams:
        gw = 40 if g != "…" else 30
        rrect(d, gx, y + 98, gw, 28, 5, fill=mix(PANEL2, accent, 0.065), outline=mix(LINE, accent, 0.18), width=0.8)
        T(d, gx + gw / 2, y + 112, g, 10.5, mix(TEXT, accent, 0.12), mono=True, anchor="mm")
        gx += gw + 4

    # pipeline
    py = y + 141
    boxes = [
        ("TF-IDF", "字符级向量"),
        ("逻辑回归", "线性分类"),
        ("5 类概率", "softmax"),
    ]
    bw = (w - 40 - 30) / 3
    for i, (t1, t2) in enumerate(boxes):
        bx = x + 20 + i * (bw + 15)
        rrect(d, bx, py, bw, 46, 7, fill=mix(CODEBG, accent, 0.04), outline=mix(LINE, accent, 0.15), width=0.9)
        T(d, bx + 9, py + 7, t1, 11.2, mix(TEXT, accent, 0.04), "Medium")
        T(d, bx + 9, py + 26, t2, 9.2, FAINT)
        if i < 2:
            T(d, bx + bw + 3.5, py + 17, "›", 15, mix(accent, FAINT, 0.25), "Bold", anchor="ma")

    # probabilities
    T(d, x + 20, y + 206, "五类概率", 10.2, mix(FAINT, MUTED, 0.30))
    T(d, x + 98, y + 205, "示意值", 9.0, mix(FAINT, accent, 0.2))
    classes = [
        ("XSS", 0.01, RED),
        ("SQL 注入", 0.01, ORANGE),
        ("路径遍历", 0.96, BLUE),
        ("敏感路径", 0.01, PURPLE),
        ("正常", 0.01, GREEN),
    ]
    ry = y + 227
    for i, (name, p, color) in enumerate(classes):
        highlight = name == "路径遍历"
        if highlight:
            rrect(d, x + 17, ry - 5, w - 34, 31, 6, fill=mix(PANEL2, BLUE, 0.12), outline=mix(BLUE, LINE, 0.25), width=0.7)
        dot(d, x + 26, ry + 8, 2.8, color if highlight else mix(color, FAINT, 0.28))
        T(d, x + 36, ry + 1, name, 12.4, HEAD if highlight else MUTED, "Medium" if highlight else "Regular")
        bx, barw = x + 126, 278
        fill_bar(d, bx, ry + 4, barw, 7, p, color if highlight else mix(color, PANEL2, 0.42), mix(CODEBG, LINE, 0.25))
        T(d, x + w - 26, ry + 1, f"{p:.2f}", 11.2, HEAD if highlight else DIM, "Medium", mono=True, anchor="ra")
        ry += 34

    T(d, x + 20, y + h - 29, "扫描器不属于这五类，由规则处理。", 10.3, mix(DIM, FAINT, 0.30))


def body_verdict(img, d, x, y, w, h, accent):
    panel_head(d, x + 18, y + 16, w - 36, "verdict", "REQUEST LEVEL", accent)

    # final verdict block
    bx, by, bw, bh = x + 18, y + 52, w - 36, 150
    vertical_gradient_rrect(
        img, bx, by, bw, bh, 10,
        mix(PANEL2, accent, 0.17), mix(PANEL2, accent, 0.035),
        outline=mix(accent, LINE, 0.32), outline_w=1.1,
    )
    T(d, bx + 15, by + 14, "FINAL LABEL", 9.4, mix(accent, MUTED, 0.2), mono=True)
    T(d, bx + bw - 15, by + 13, "conf  0.96", 10.0, HEAD, "Medium", mono=True, anchor="ra")
    T(d, bx + 15, by + 37, "路径遍历", 30, HEAD, "Bold")
    # attack badge
    pill(d, bx + bw - 74, by + 40, 58, 24, "攻击", 10.5, mix(TEXT, accent, 0.12), mix(accent, LINE, 0.38), mix(PANEL2, accent, 0.12), weight="Medium")
    T(d, bx + 15, by + 82, "来源  ·  自研五类模型", 10.8, DIM)
    # evidence line
    rrect(d, bx + 13, by + 104, bw - 26, 33, 6, fill=CODEBG, outline=mix(LINE, accent, 0.12), width=0.8)
    T(d, bx + 22, by + 113, "q = ", 10.6, FAINT, mono=True)
    T(d, bx + 49, by + 113, "../../etc/passwd", 10.6, mix(accent, WHITE, 0.14), mono=True)

    # trace rows
    T(d, x + 20, y + 220, "证据链", 10.2, mix(FAINT, MUTED, 0.30))
    T(d, x + 68, y + 220, "· TRACE", 9.4, mix(FAINT, MUTED, 0.25), mono=True)
    rows = [
        ("规则", "未命中", "进入模型", TEAL),
        ("模型", "路径遍历", "0.96", BLUE),
        ("原文", "raw_request", "已留档", PURPLE),
    ]
    ry = y + 244
    for label, v1, v2, color in rows:
        dot(d, x + 25, ry + 7, 2.4, color)
        T(d, x + 35, ry, label, 11.3, MUTED, "Medium")
        T(d, x + 93, ry, v1, 11.3, mix(TEXT, color, 0.10))
        T(d, x + w - 25, ry, v2, 10.6, DIM, anchor="ra")
        hline(d, x + 18, x + w - 18, ry + 26, mix(LINE, CODEBG, 0.2), 0.75)
        ry += 36

    # output
    oy = y + h - 60
    rrect(d, x + 18, oy, w - 36, 42, 7, fill=CODEBG, outline=mix(LINE, accent, 0.12), width=0.8)
    T(d, x + 28, oy + 10, "verdict", 10.6, accent, "Medium", mono=True)
    T(d, x + 93, oy + 10, "(label, prob, evidence)  →  event_log", 10.0, mix(TEXT, DIM, 0.2), mono=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    img = background()

    cards = [(104, 360, 570, 960), (698, 360, 570, 960), (1292, 360, 570, 960), (1886, 360, 570, 960)]
    flow_box = (1530, 72, 900, 204)

    img = Image.alpha_composite(img, shadow_layer(cards, flow_box))
    img = Image.alpha_composite(img, glow_layer(cards, flow_box))
    d = ImageDraw.Draw(img)

    # header ---------------------------------------------------------------
    # eyebrow pill (width follows its content)
    pill_x, pill_y, pill_h = 104, 62, 42
    en_size, zh_size = 12.6, 14.4
    en_text, zh_text = "SELF-TRAINED MODEL", "请求级判定"
    en_w = tw(d, en_text, en_size, "Medium", True)
    zh_w = tw(d, zh_text, zh_size, "Medium")
    pill_w = 31 + en_w + 19 + 9 + 15 + zh_w + 18
    rrect(d, pill_x, pill_y, pill_w, pill_h, 21, fill=mix((7, 24, 35), TEAL, 0.08), outline=mix(TEAL, LINE, 0.35), width=1.1)
    dot(d, pill_x + 19, pill_y + 21, 3.2, TEAL)
    T(d, pill_x + 31, pill_y + 11, en_text, en_size, mix(TEAL, TEXT, 0.15), "Medium", mono=True)
    sep_x = pill_x + 31 + en_w + 19
    T(d, sep_x, pill_y + 11, "·", 13, FAINT)
    T(d, sep_x + 17, pill_y + 10, zh_text, zh_size, mix(TEXT, TEAL, 0.08), "Medium")

    T(d, 104, 112, "请求判定工作原理", 98, HEAD, "Black")
    # subtitle with four colored actions
    rich(
        d, 104, 231,
        [
            ("不是调用现成的大模型接口；自己训练、自己评测，把一条请求拆成 ", MUTED, "Regular"),
            ("收", AMBER, "Bold"),
            (" · ", DIM),
            ("规", TEAL, "Bold"),
            (" · ", DIM),
            ("模", BLUE, "Bold"),
            (" · ", DIM),
            ("判", PURPLE, "Bold"),
            (" 四个动作。", MUTED, "Regular"),
        ],
        25.0,
    )

    # slim path divider
    T(d, 104, 300, "一条 HTTP 请求的判定路径", 13.0, mix(DIM, MUTED, 0.18))
    T(d, 2456, 300, "先规则 · 再模型 · 全程留证", 12.2, mix(FAINT, DIM, 0.30), anchor="ra")
    hline(d, 330, 2456, 314, mix(LINE, (5, 14, 24), 0.18), 0.9)

    draw_flow_panel(img, flow_box)

    # cards ----------------------------------------------------------------
    meta = [
        ("收", "接收原始请求", "输入层 · REQUEST CAPTURE", "request"),
        ("规", "规则先行过滤", "确定性层 · RULE GATE", "rule"),
        ("模", "模型五类判定", "分类层 · SELF-TRAINED CLASSIFIER", "model"),
        ("判", "合成请求结论", "决策层 · VERDICT", "verdict"),
    ]
    body_fns = [body_request, body_rules, body_model, body_verdict]
    copy_lines = [
        [
            [("方法、路径、参数、Body、UA 一起收下；", MUTED)],
            [("原始请求先留档，后续判断都基于它。", MUTED)],
        ],
        [
            [("扫描器指纹交给规则：UA、路径、已知特征命中，", MUTED)],
            [("规则直接定性，不占用模型。", MUTED)],
        ],
        [
            [("字符级 TF-IDF 向量化，逻辑回归给出五类概率。", MUTED)],
            [("自己训练、自己评测，不调用现成的大模型接口。", MUTED)],
        ],
        [
            [("规则命中先定性；未命中，取模型最高概率类。", MUTED)],
            [("结论、类别概率与原始请求，一起留档。", MUTED)],
        ],
    ]
    quotes = [
        "先有完整请求，才有可靠判断。",
        "扫描器不训练，交给规则。",
        "不是一个 API，是一个分类器。",
        "每条结论，都能回到那条请求。",
    ]

    for i, (x, y, w, h) in enumerate(cards):
        accent = ACCENTS[i]
        draw_card_frame(img, x, y, w, h, i, accent)
        draw_card_head(img, x, y, accent, meta[i][0], meta[i][1], meta[i][2], meta[i][3])

        bx, by, bw, bh = x + 30, y + 285, w - 60, 430
        vertical_gradient_rrect(
            img, bx, by, bw, bh, 14,
            (6, 18, 30), (5, 15, 24),
            outline=mix(accent, LINE, 0.17), outline_w=1.0,
        )
        # panel faint left accent
        d.rectangle([u(bx), u(by + 12), u(bx + 1.5), u(by + bh - 12)], fill=mix(accent, (9, 24, 37), 0.55))
        body_fns[i](img, d, bx, by, bw, bh, accent)

        draw_card_copy(d, x + 30, y + 745, w - 60, accent, copy_lines[i])
        draw_quote(d, x + 30, y + 865, w - 60, accent, quotes[i])

    # footer ---------------------------------------------------------------
    fy = 1390
    hline(d, 104, 2456, fy - 24, mix(LINE, (4, 12, 20), 0.18), 0.9)
    x = 104
    for label, value, color in [
        ("输入", "一条 HTTP 请求", AMBER),
        ("输出", "请求级结论", BLUE),
        ("证据", "原文与类别概率", PURPLE),
    ]:
        dot(d, x + 3, fy + 8, 3.0, color)
        T(d, x + 14, fy, label, 10.8, mix(FAINT, DIM, 0.25))
        T(d, x + 53, fy - 1, value, 13.0, MUTED)
        x += 53 + text_width_in(d, value, 13.0, "Regular") + 34
        if label != "证据":
            vline(d, x - 18, fy + 1, fy + 17, mix(LINE, (5, 14, 24), 0.2), 0.8)

    # right concept mark
    line_right = 2456
    prefix = "CONCEPT DIAGRAM"
    suffix = "  ·  原理示意 · 概率为演示值"
    prefix_w = tw(d, prefix, 9.8, "Regular", True)
    suffix_w = tw(d, suffix, 10.2, "Regular")
    concept_x = line_right - prefix_w - suffix_w
    dash_x2 = concept_x - 20
    dashed_line(d, dash_x2 - 72, dash_x2, fy + 8, mix(BLUE, (6, 18, 30), 0.45), 1.0, 12, 7)
    T(d, concept_x, fy - 1, prefix, 9.8, mix(FAINT, DIM, 0.25), mono=True)
    T(d, concept_x + prefix_w, fy - 1.5, suffix, 10.2, mix(FAINT, DIM, 0.18))

    # final subtle top-left corner mark
    T(d, 104, 1466, "REQUEST-LEVEL  /  RULE + MODEL  /  SELF-TRAINED", 9.2, (49, 73, 91), mono=True)

    # downsample, add a whisper of grain, save
    out = img.convert("RGB").resize((W, H), Image.LANCZOS)
    arr = np.array(out).astype(np.int16)
    rng = np.random.default_rng(7)
    grain = rng.normal(0, 1.35, (H, W, 1)).astype(np.int16)
    arr = np.clip(arr + grain, 0, 255).astype(np.uint8)
    out = Image.fromarray(arr, "RGB")
    path = OUT / "request_model_principle.png"
    out.save(path, "PNG")
    print(path)


if __name__ == "__main__":
    main()
