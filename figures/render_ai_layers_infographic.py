from pathlib import Path

import numpy as np
from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont

# ---------------------------------------------------------------------------
# Canvas
# ---------------------------------------------------------------------------
W, H = 1920, 1080
S = 2
OUT = Path(__file__).resolve().parent
FONT_NOTO = Path("C:/Windows/Fonts/NotoSansSC-VF.ttf")
FONT_MONO = Path("C:/Windows/Fonts/CascadiaMono.ttf")

# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------
BG = (5, 11, 19)
HEAD = (245, 250, 255)
TEXT = (225, 237, 247)
MUTED = (160, 180, 197)
DIM = (119, 142, 161)
FAINT = (78, 102, 121)
LINE = (28, 47, 64)
LINE2 = (42, 68, 89)
PANEL = (10, 21, 34)
PANEL_2 = (8, 18, 29)
INNER = (7, 17, 28)
AMBER = (232, 172, 84)
AMBER_HI = (255, 209, 138)
AMBER_DARK = (86, 60, 31)
BLUE = (112, 174, 247)
BLUE_HI = (157, 205, 255)
BLUE_DARK = (40, 75, 108)
CYAN = (86, 209, 202)
GREEN = (104, 221, 177)
PURPLE = (171, 146, 245)
RED = (255, 137, 145)

_font_cache = {}


def u(v):
    return int(round(v * S))


def F(size, weight=400, mono=False):
    key = (round(size, 2), weight, mono)
    if key not in _font_cache:
        path = FONT_MONO if mono else FONT_NOTO
        font = ImageFont.truetype(str(path), u(size))
        if mono:
            weight = max(200, min(700, weight))
        else:
            weight = max(100, min(900, weight))
        font.set_variation_by_axes([weight])
        _font_cache[key] = font
    return _font_cache[key]


def tw(text, size, weight=400, mono=False, tracking=0.0):
    font = F(size, weight, mono)
    value = font.getlength(str(text)) / S
    if tracking:
        value += tracking * max(len(str(text)) - 1, 0)
    return value


def T(d, x, y, text, size, color, weight=400, mono=False, tracking=0.0, anchor="la"):
    font = F(size, weight, mono)
    text = str(text)
    if tracking and anchor == "la":
        cx = x
        for ch in text:
            d.text((u(cx), u(y)), ch, font=font, fill=color, anchor="la")
            cx += font.getlength(ch) / S + tracking
        return cx - tracking
    if tracking and anchor in ("ra", "ma", "mm", "rm"):
        total = tw(text, size, weight, mono, tracking)
        if anchor in ("ra", "rm"):
            x -= total
        elif anchor in ("ma", "mm"):
            x -= total / 2
        return T(d, x, y, text, size, color, weight, mono, tracking, "la")
    d.text((u(x), u(y)), text, font=font, fill=color, anchor=anchor)
    return x + tw(text, size, weight, mono)


def R(d, x, y, parts, size=20, tracking=0.0):
    """Draw a line made of differently coloured segments."""
    cx = x
    for part in parts:
        text, color = part[0], part[1]
        weight = part[2] if len(part) > 2 else 400
        mono = part[3] if len(part) > 3 else False
        T(d, cx, y, text, size, color, weight, mono)
        cx += tw(text, size, weight, mono) + tracking
    return cx - tracking


def rr(d, box, radius, fill=None, outline=None, width=1.0):
    d.rounded_rectangle(
        [u(box[0]), u(box[1]), u(box[2]), u(box[3])],
        radius=u(radius),
        fill=fill,
        outline=outline,
        width=max(1, u(width)),
    )


def line(d, x1, y1, x2, y2, color, width=1.0):
    d.line([u(x1), u(y1), u(x2), u(y2)], fill=color, width=max(1, u(width)))


def dot(d, x, y, r, color):
    d.ellipse([u(x - r), u(y - r), u(x + r), u(y + r)], fill=color)


def arrow_head(d, x, y, color, direction="right", size=4.5):
    if direction == "right":
        d.polygon(
            [(u(x), u(y)), (u(x - size), u(y - size * 0.72)), (u(x - size), u(y + size * 0.72))],
            fill=color,
        )
    elif direction == "down":
        d.polygon(
            [(u(x), u(y)), (u(x - size * 0.72), u(y - size)), (u(x + size * 0.72), u(y - size))],
            fill=color,
        )


def lerp(a, b, t):
    return tuple(int(round(a[i] + (b[i] - a[i]) * t)) for i in range(3))


def alpha(color, a):
    return (color[0], color[1], color[2], a)


def gradient_round_rect(img, box, radius, top, bottom, border=None, border_width=1.0):
    x, y, w, h = box
    gw, gh = u(w), u(h)
    if gw <= 0 or gh <= 0:
        return
    grad = Image.new("RGB", (gw, gh))
    gd = ImageDraw.Draw(grad)
    for yy in range(gh):
        gd.line([(0, yy), (gw, yy)], fill=lerp(top, bottom, yy / max(gh - 1, 1)))
    mask = Image.new("L", (gw, gh), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, gw - 1, gh - 1], radius=u(radius), fill=255)
    img.paste(grad, (u(x), u(y)), mask)
    if border:
        rr(ImageDraw.Draw(img), (x, y, x + w, y + h), radius, outline=border, width=border_width)


def gradient_hline(d, x1, x2, y, c1, c2, width=1.0, steps=120):
    for i in range(steps):
        xa = x1 + (x2 - x1) * i / steps
        xb = x1 + (x2 - x1) * (i + 1) / steps + 0.4
        d.line([u(xa), u(y), u(xb), u(y)], fill=lerp(c1, c2, i / max(steps - 1, 1)), width=u(width))


def soft_glow(img, box, radius, color, strength=80, blur=18, grow=0, y_offset=0):
    x, y, w, h = box
    pad = blur * 3 + 8
    lw, lh = u(w + pad * 2), u(h + pad * 2)
    layer = Image.new("RGBA", (lw, lh), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    ld.rounded_rectangle(
        [u(pad - grow), u(pad - grow + y_offset), u(pad + w + grow), u(pad + h + grow + y_offset)],
        radius=u(radius + grow),
        fill=alpha(color, strength),
    )
    layer = layer.filter(ImageFilter.GaussianBlur(u(blur)))
    img.alpha_composite(layer, (u(x - pad), u(y - pad)))


def soft_shadow(img, box, radius, strength=150, blur=24, y_offset=9):
    soft_glow(img, box, radius, (0, 0, 0), strength=strength, blur=blur, y_offset=y_offset, grow=1)


def pill(d, x, y, text, fg, bg, border, size=9.0, h=21, padx=9, weight=500, mono=True, tracking=0.5):
    w = tw(text, size, weight, mono, tracking) + padx * 2
    rr(d, (x, y, x + w, y + h), h / 2, fill=bg, outline=border, width=1)
    T(d, x + padx, y + h / 2 + 0.5, text, size, fg, weight, mono, tracking, anchor="lm")
    return w


def pill_right(d, right, y, text, fg, bg, border, size=9.0, h=21, padx=9, weight=500, mono=True, tracking=0.5):
    w = tw(text, size, weight, mono, tracking) + padx * 2
    return pill(d, right - w, y, text, fg, bg, border, size, h, padx, weight, mono, tracking)


def rich_pill(d, x, y, parts, bg, border, h=22, padx=10, tracking=0.4):
    total = 0
    for p in parts:
        total += tw(p[0], p[3] if len(p) > 3 else 9.0, p[2] if len(p) > 2 else 500, False)
    w = total + padx * 2
    rr(d, (x, y, x + w, y + h), h / 2, fill=bg, outline=border, width=1)
    cx = x + padx
    for p in parts:
        s, c = p[0], p[1]
        weight = p[2] if len(p) > 2 else 500
        size = p[3] if len(p) > 3 else 9.0
        T(d, cx, y + h / 2 + 0.5, s, size, c, weight, False, 0.3, anchor="lm")
        cx += tw(s, size, weight, False) + tracking
    return w


# ---------------------------------------------------------------------------
# Background
# ---------------------------------------------------------------------------
def make_background():
    yy, xx = np.mgrid[0:H, 0:W].astype(np.float32)
    base = np.empty((H, W, 3), dtype=np.float32)
    base[:] = (5, 12, 20)

    # a soft, cool light coming in from the upper right
    d1 = np.sqrt(((xx - 0.88 * W) / (0.55 * W)) ** 2 + ((yy + 0.06 * H) / (0.62 * H)) ** 2)
    a1 = np.clip(1 - d1, 0, 1) ** 2.1 * 0.80
    base = base * (1 - a1[..., None]) + np.array([18, 47, 75], dtype=np.float32) * a1[..., None]

    # teal glow at upper left
    d2 = np.sqrt(((xx - 0.04 * W) / (0.50 * W)) ** 2 + ((yy - 0.02 * H) / (0.56 * H)) ** 2)
    a2 = np.clip(1 - d2, 0, 1) ** 2.2 * 0.52
    base = base * (1 - a2[..., None]) + np.array([12, 42, 43], dtype=np.float32) * a2[..., None]

    # low amber / violet atmosphere at the edges
    d3 = np.sqrt(((xx - 0.03 * W) / (0.45 * W)) ** 2 + ((yy - 1.05 * H) / (0.44 * H)) ** 2)
    a3 = np.clip(1 - d3, 0, 1) ** 2.5 * 0.22
    base = base * (1 - a3[..., None]) + np.array([46, 33, 22], dtype=np.float32) * a3[..., None]

    d4 = np.sqrt(((xx - 1.03 * W) / (0.42 * W)) ** 2 + ((yy - 0.96 * H) / (0.48 * H)) ** 2)
    a4 = np.clip(1 - d4, 0, 1) ** 2.5 * 0.28
    base = base * (1 - a4[..., None]) + np.array([37, 29, 52], dtype=np.float32) * a4[..., None]

    # vertical falloff / vignette
    vy = np.clip((yy / H - 0.02) / 0.98, 0, 1)
    base *= (1 - 0.10 * vy[..., None])
    edge = np.minimum(np.minimum(xx / W, 1 - xx / W), np.minimum(yy / H, 1 - yy / H))
    base *= (0.72 + 0.28 * np.clip(edge / 0.18, 0, 1))[..., None]

    # fine noise for a matte technical surface
    rng = np.random.default_rng(17)
    base += rng.normal(0, 1.05, (H, W, 1))

    img = Image.fromarray(np.clip(base, 0, 255).astype(np.uint8), "RGB")
    img = img.resize((W * S, H * S), Image.LANCZOS).convert("RGBA")

    # large technical grid
    grid = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
    gd = ImageDraw.Draw(grid)
    for x in range(32, W, 48):
        gd.line([u(x), 0, u(x), H * S], fill=(113, 150, 180, 18), width=u(0.8))
    for y in range(28, H, 48):
        gd.line([0, u(y), W * S, u(y)], fill=(113, 150, 180, 18), width=u(0.8))
    for x in range(80, W, 96):
        for y in range(76, H, 96):
            gd.ellipse([u(x - 0.8), u(y - 0.8), u(x + 0.8), u(y + 0.8)], fill=(128, 168, 194, 34))
    img = Image.alpha_composite(img, grid)

    # very subtle circuit-like nodes behind the top diagram
    net = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
    nd = ImageDraw.Draw(net)
    nodes = [(1220, 80), (1290, 128), (1370, 90), (1480, 145), (1590, 80), (1700, 128), (1800, 88)]
    for i, (x, y) in enumerate(nodes[:-1]):
        x2, y2 = nodes[i + 1]
        nd.line([u(x), u(y), u(x2), u(y2)], fill=(95, 153, 177, 12), width=u(0.8))
    for x, y in nodes:
        nd.ellipse([u(x - 1.6), u(y - 1.6), u(x + 1.6), u(y + 1.6)], fill=(126, 201, 202, 24))
    img = Image.alpha_composite(img, net)

    d = ImageDraw.Draw(img)
    # top / bottom frame rules
    gradient_hline(d, 32, 1888, 28, (29, 67, 77), (32, 62, 99), 0.8)
    gradient_hline(d, 32, 1888, 1074, (57, 44, 76), (27, 57, 66), 0.8)
    # short luminous tick at each end
    line(d, 32, 28, 136, 28, (92, 202, 188), 0.8)
    line(d, 1784, 28, 1888, 28, (71, 130, 179), 0.8)
    return img


# ---------------------------------------------------------------------------
# Small icons
# ---------------------------------------------------------------------------
def crosshair_icon(d, cx, cy, color, r=8):
    d.ellipse([u(cx - r), u(cy - r), u(cx + r), u(cy + r)], outline=color, width=u(1))
    line(d, cx - r - 5, cy, cx - 3, cy, color, 1)
    line(d, cx + 3, cy, cx + r + 5, cy, color, 1)
    line(d, cx, cy - r - 5, cx, cy - 3, color, 1)
    line(d, cx, cy + 3, cx, cy + r + 5, color, 1)
    dot(d, cx, cy, 1.5, color)


def chat_icon(d, cx, cy, color):
    rr(d, (cx - 10, cy - 8, cx + 10, cy + 6), 3, outline=color, width=1)
    d.polygon([(u(cx - 4), u(cy + 6)), (u(cx - 7), u(cy + 11)), (u(cx + 1), u(cy + 6))], fill=color)
    for dx in (-4.5, 0, 4.5):
        dot(d, cx + dx, cy - 1, 1.2, color)


def bracket_icon(d, cx, cy, color):
    line(d, cx - 7, cy - 8, cx - 11, cy - 8, color, 1)
    line(d, cx - 11, cy - 8, cx - 11, cy + 8, color, 1)
    line(d, cx - 11, cy + 8, cx - 7, cy + 8, color, 1)
    line(d, cx + 7, cy - 8, cx + 11, cy - 8, color, 1)
    line(d, cx + 11, cy - 8, cx + 11, cy + 8, color, 1)
    line(d, cx + 11, cy + 8, cx + 7, cy + 8, color, 1)
    dot(d, cx, cy, 1.8, color)


def glyph_tile(d, x, y, size, glyph, color, tint, border):
    rr(d, (x, y, x + size, y + size), 12, fill=tint, outline=border, width=1)
    T(d, x + size / 2, y + size / 2 + 1.5, glyph, size * 0.48, color, 800, False, 0, anchor="mm")


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
def draw_header(img):
    d = ImageDraw.Draw(img)

    # badge
    bx, by, bh = 80, 57, 29
    bw = 249
    rr(d, (bx, by, bx + bw, by + bh), 14.5, fill=(10, 24, 25), outline=(33, 67, 59), width=1)
    dot(d, bx + 15, by + bh / 2, 3.2, (86, 215, 177))
    T(d, bx + 27, by + bh / 2 + 0.5, "THE AI PART", 9.4, (140, 196, 182), 500, True, 1.7, anchor="lm")
    T(d, bx + 124, by + bh / 2 + 0.5, "·", 9.4, (66, 104, 98), 400, False, 0, anchor="lm")
    T(d, bx + 136, by + bh / 2 + 0.5, "两层架构图", 11.0, (168, 191, 182), 500, False, 0, anchor="lm")

    # title
    T(d, 80, 94, "两层 AI，各干各的事", 72, HEAD, 900, False, -1.5)
    # subtitle
    R(
        d,
        82,
        188,
        [
            ("一层，", (166, 185, 202), 400),
            ("自己训练的攻击识别模型", AMBER_HI, 500),
            ("；一层，", (166, 185, 202), 400),
            ("通用大模型", BLUE_HI, 500),
            ("。", (166, 185, 202), 400),
        ],
        size=21.2,
    )
    T(
        d,
        82,
        226,
        "ONE SCENE  ·  TWO MODELS  ·  SEPARATE OUTPUTS",
        8.7,
        (66, 90, 108),
        500,
        True,
        1.8,
    )


def draw_flow_panel(img):
    d = ImageDraw.Draw(img)
    x, y, w, h = 1116, 52, 724, 184
    soft_glow(img, (x, y, w, h), 18, (43, 119, 130), strength=42, blur=28, grow=2)
    gradient_round_rect(img, (x, y, w, h), 17, (10, 24, 37), (7, 16, 27), border=(31, 56, 74), border_width=1)
    d = ImageDraw.Draw(img)
    gradient_hline(d, x + 28, x + 196, y + 1, (176, 128, 58), (49, 82, 110), 1.4, 70)

    T(d, x + 24, y + 16, "SAME SCENE", 9.0, (119, 145, 163), 500, True, 1.7)
    T(d, x + w - 24, y + 16, "TWO TRACKS  ·  NO OVERRIDE", 8.9, (102, 166, 154), 500, True, 1.4, anchor="ra")

    # input card
    ix, iy, iw, ih = x + 22, y + 48, 126, 104
    rr(d, (ix, iy, ix + iw, iy + ih), 10, fill=(9, 23, 35), outline=(37, 62, 81), width=1)
    T(d, ix + 12, iy + 10, "INPUT", 8.0, (82, 110, 130), 500, True, 1.4)
    T(d, ix + 12, iy + 28, "现场", 17.4, HEAD, 600)
    T(d, ix + 12, iy + 58, "请求 · 日志", 9.3, (137, 159, 177), 400)
    T(d, ix + 12, iy + 74, "行为记录", 9.3, (137, 159, 177), 400)
    dot(d, ix + iw - 15, iy + 17, 2.4, (92, 205, 194))

    # branching connector
    sx = ix + iw + 5
    mid_y = iy + ih / 2
    lane_x = ix + iw + 48
    lane1_cy, lane2_cy = iy + 22, iy + 74
    line(d, sx, mid_y, sx + 15, mid_y, (53, 80, 100), 0.9)
    dot(d, sx + 15, mid_y, 1.8, (88, 124, 145))
    line(d, sx + 15, lane1_cy, sx + 15, lane2_cy, (53, 80, 100), 0.9)
    line(d, sx + 15, lane1_cy, lane_x - 4, lane1_cy, (53, 80, 100), 0.9)
    line(d, sx + 15, lane2_cy, lane_x - 4, lane2_cy, (53, 80, 100), 0.9)
    arrow_head(d, lane_x - 1, lane1_cy, (83, 111, 131), "right", 3.9)
    arrow_head(d, lane_x - 1, lane2_cy, (83, 111, 131), "right", 3.9)

    # two lanes
    lane_w = 384
    lane1_y, lane2_y = y + 48, y + 100
    lane_h = 44
    rr(d, (lane_x, lane1_y, lane_x + lane_w, lane1_y + lane_h), 9, fill=(24, 19, 12), outline=(81, 58, 30), width=1)
    rr(d, (lane_x, lane2_y, lane_x + lane_w, lane2_y + lane_h), 9, fill=(11, 22, 36), outline=(37, 65, 92), width=1)
    # lane accents
    line(d, lane_x + 1, lane1_y + 10, lane_x + 1, lane1_y + lane_h - 10, AMBER, 1.4)
    line(d, lane_x + 1, lane2_y + 10, lane_x + 1, lane2_y + lane_h - 10, BLUE, 1.4)

    glyph_tile(d, lane_x + 10, lane1_y + 9, 26, "识", AMBER, (37, 28, 16), (91, 66, 34))
    T(d, lane_x + 46, lane1_y + 10, "攻击识别模型", 13.2, HEAD, 600)
    T(d, lane_x + lane_w - 12, lane1_y + 13, "标签 · 置信度", 9.0, (214, 163, 91), 500, False, 0, anchor="ra")
    glyph_tile(d, lane_x + 10, lane2_y + 9, 26, "解", BLUE, (15, 28, 44), (43, 75, 107))
    T(d, lane_x + 46, lane2_y + 10, "通用大模型", 13.2, HEAD, 600)
    T(d, lane_x + lane_w - 12, lane2_y + 13, "语义 · 解释", 9.0, (136, 190, 245), 500, False, 0, anchor="ra")

    # output block
    ox = lane_x + lane_w + 20
    oy, ow, oh = y + 48, 106, 96
    rr(d, (ox, oy, ox + ow, oy + oh), 10, fill=(9, 25, 24), outline=(38, 81, 69), width=1)
    T(d, ox + ow / 2, oy + 16, "并列", 12.2, (228, 245, 238), 600, False, 0, anchor="ma")
    T(d, ox + ow / 2, oy + 35, "输出", 12.2, (228, 245, 238), 600, False, 0, anchor="ma")
    T(d, ox + ow / 2, oy + 64, "互不覆盖", 8.9, GREEN, 500, False, 0, anchor="ma")
    T(d, ox + ow / 2, oy + 79, "SEPARATE", 7.2, (82, 128, 115), 500, True, 1.2, anchor="ma")

    # connectors into output
    line(d, lane_x + lane_w + 4, lane1_cy, ox - 5, lane1_cy, (49, 77, 93), 0.9)
    line(d, lane_x + lane_w + 4, lane2_cy, ox - 5, lane2_cy, (49, 77, 93), 0.9)
    arrow_head(d, ox - 2, lane1_cy, (77, 106, 120), "right", 3.6)
    arrow_head(d, ox - 2, lane2_cy, (77, 106, 120), "right", 3.6)

    # footer microcopy
    fy = y + h - 24
    dot(d, x + 25, fy + 4, 2.3, AMBER)
    T(d, x + 33, fy, "第一层：攻击标签", 9.1, (132, 151, 167), 400)
    dot(d, x + 165, fy + 4, 2.3, BLUE)
    T(d, x + 173, fy, "第二层：语义解释", 9.1, (132, 151, 167), 400)
    T(d, x + w - 24, fy, "同一份现场进入，各自的证据出来", 9.1, (92, 116, 133), 400, False, 0, anchor="ra")


# ---------------------------------------------------------------------------
# Cards
# ---------------------------------------------------------------------------
def draw_card_base(img, box, accent):
    x, y, w, h = box
    soft_shadow(img, (x, y, w, h), 18, strength=180, blur=26, y_offset=10)
    gradient_round_rect(img, (x, y, w, h), 18, (13, 28, 44), (8, 18, 30), border=(44, 70, 91), border_width=1)
    d = ImageDraw.Draw(img)
    # faint inner top light
    wash = Image.new("RGBA", (u(w), u(h)), (0, 0, 0, 0))
    wd = ImageDraw.Draw(wash)
    for yy in range(u(115)):
        a = int(19 * (1 - yy / max(u(115), 1)))
        if a > 0:
            wd.line([(0, yy), (u(w), yy)], fill=alpha(accent, a))
    mask = Image.new("L", (u(w), u(h)), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, u(w) - 1, u(h) - 1], radius=u(18), fill=255)
    wash.putalpha(ImageChops.multiply(wash.getchannel("A"), mask))
    img.alpha_composite(wash, (u(x), u(y)))
    d = ImageDraw.Draw(img)
    # accent rule at the very top
    soft_glow(img, (x + 1, y, w * 0.54, 3.0), 1.2, accent, strength=92, blur=11, grow=0)
    d = ImageDraw.Draw(img)
    gradient_hline(d, x + 2, x + w * 0.54, y + 1.2, accent, (10, 21, 34), 2.0, 90)
    # thin corner marks
    line(d, x + 1, y + 30, x + 1, y + 78, accent, 0.8)
    line(d, x + w - 1, y + h - 78, x + w - 1, y + h - 30, accent, 0.8)


def draw_card_header(img, box, accent, step, title, subtitle, icon, icon_fn):
    d = ImageDraw.Draw(img)
    x, y, w, h = box
    # step
    dot(d, x + 31, y + 35, 2.8, accent)
    T(d, x + 41, y + 26, step, 10.0, accent, 500, True, 1.45)
    # right icon tile
    ix, iy, isz = x + w - 68, y + 18, 38
    rr(d, (ix, iy, ix + isz, iy + isz), 9, fill=(11, 24, 37), outline=(43, 68, 88), width=1)
    icon_fn(d, ix + isz / 2, iy + isz / 2, accent)

    # glyph tile with a soft halo
    gx, gy, gsz = x + 30, y + 62, 82
    soft_glow(img, (gx, gy, gsz, gsz), 12, accent, strength=58, blur=20, grow=1)
    d = ImageDraw.Draw(img)
    rr(d, (gx, gy, gx + gsz, gy + gsz), 13, fill=(31, 25, 15) if accent == AMBER else (13, 26, 42), outline=(88, 66, 37) if accent == AMBER else (45, 78, 110), width=1)
    # inner top glint
    line(d, gx + 12, gy + 1, gx + gsz - 12, gy + 1, accent, 1)
    T(d, gx + gsz / 2, gy + gsz / 2 + 1, icon, 41, accent, 800, False, 0, anchor="mm")

    # title
    T(d, x + 132, y + 64, title, 33, HEAD, 700, False, -0.5)
    T(d, x + 133, y + 113, subtitle, 10.2, (124, 149, 168), 500, False, 1.05)


def draw_card1(img):
    box = (80, 280, 850, 596)
    x, y, w, h = box
    draw_card_base(img, box, AMBER)
    d = ImageDraw.Draw(img)
    draw_card_header(
        img, box, AMBER,
        "LAYER 01 / SPECIALIZED MODEL",
        "攻击识别模型",
        "自己训练  /  SELF-TRAINED",
        "识",
        crosshair_icon,
    )

    # inner console
    px, py, pw, ph = x + 30, y + 172, w - 60, 244
    rr(d, (px, py, px + pw, py + ph), 11, fill=(6, 16, 26), outline=(31, 51, 67), width=1)
    line(d, px + 14, py + 1, px + pw - 14, py + 1, (71, 55, 35), 0.8)
    # header
    dot(d, px + 17, py + 20, 2.6, AMBER)
    T(d, px + 26, py + 12, "attack-classifier", 11.2, (205, 222, 235), 500, True, 0.2)
    pill_right(d, px + pw - 12, py + 10, "SELF-TRAINED", (222, 175, 101), (30, 23, 13), (87, 64, 34), 7.8, 21, 8, 500, True, 0.9)
    line(d, px + 14, py + 39, px + pw - 14, py + 39, (29, 48, 63), 0.8)

    # left: training loop
    T(d, px + 18, py + 51, "TRAINING LOOP", 8.5, (119, 141, 157), 500, True, 1.4)
    t_nodes = [
        ("自有数据", "请求 / 载荷 / 行为"),
        ("训练", "学我们自己的样本"),
        ("专用分类器", "只判断是不是攻击"),
    ]
    nx = px + 28
    top = py + 76
    line(d, nx, top + 4, nx, top + 108, (63, 69, 50), 0.9)
    for i, (head, sub) in enumerate(t_nodes):
        ny = top + i * 45
        d.ellipse([u(nx - 7), u(ny - 4), u(nx + 7), u(ny + 10)], fill=(22, 25, 17), outline=(121, 89, 43), width=u(0.9))
        T(d, nx, ny + 3, f"0{i+1}", 5.6, (222, 171, 94), 500, True, 0, anchor="mm")
        T(d, px + 45, ny - 4, head, 13.3, (231, 240, 247), 600)
        T(d, px + 45, ny + 16, sub, 9.4, (119, 139, 155), 400)

    # feature-signal strip: a tiny visual fingerprint under the training loop
    T(d, px + 18, py + 198, "FEATURE SIGNALS", 7.4, (101, 123, 140), 500, True, 1.3)
    heights = [8, 13, 17, 10, 19, 23, 14, 20, 9, 16, 24, 18, 12, 17, 21, 11, 16, 23, 13, 19, 10, 21, 15, 22, 8, 18, 12, 20, 14, 22]
    baseline = py + 236
    line(d, px + 18, baseline + 1, px + 300, baseline + 1, (48, 55, 39), 0.8)
    for i, hgt in enumerate(heights):
        bx = px + 20 + i * 9.25
        col = AMBER if i % 4 == 0 else (167, 125, 68)
        line(d, bx, baseline - hgt, bx, baseline, col, 2.0)

    # divider
    line(d, px + 307, py + 52, px + 307, py + 196, (28, 46, 60), 0.8)

    # right: classifier outputs
    T(d, px + 326, py + 51, "识别输出", 8.6, (119, 141, 157), 500, False, 0)
    T(d, px + pw - 18, py + 51, "CONFIDENCE", 7.8, (85, 108, 126), 500, True, 1.1, anchor="ra")
    rows = [("路径遍历", 0.94, 188), ("SQL 注入", 0.89, 178), ("扫描探测", 0.86, 172)]
    for i, (name, conf, barw) in enumerate(rows):
        ry = py + 79 + i * 42
        T(d, px + 326, ry - 1, name, 13.2, (229, 239, 246), 500)
        # track
        rr(d, (px + 420, ry + 7, px + 420 + 218, ry + 12), 2.5, fill=(24, 39, 51))
        rr(d, (px + 420, ry + 7, px + 420 + barw, ry + 12), 2.5, fill=AMBER if i == 0 else (197, 147, 76))
        T(d, px + pw - 18, ry - 2, f"{conf:.2f}", 11.1, AMBER_HI if i == 0 else (207, 163, 96), 500, True, 0, anchor="ra")
    # illustrative labels
    T(d, px + 326, py + 199, "attack_type", 7.6, (104, 163, 191), 500, True, 0.5)
    T(d, px + 405, py + 199, "·", 7.6, (65, 88, 105), 400)
    T(d, px + 416, py + 199, "confidence", 7.6, (104, 163, 191), 500, True, 0.5)
    T(d, px + 498, py + 199, "·", 7.6, (65, 88, 105), 400)
    T(d, px + 509, py + 199, "evidence", 7.6, (104, 163, 191), 500, True, 0.5)
    T(d, px + pw - 18, py + 199, "ILLUSTRATIVE", 7.2, (78, 100, 116), 500, True, 1.0, anchor="ra")

    # description
    desc = [
        "用我们自己的数据训练，专攻一件事：从请求、载荷、行为里认出攻击，",
        "并给出攻击类型、置信度与判断依据。",
    ]
    for i, ln in enumerate(desc):
        T(d, x + 30, y + 438 + i * 28.5, ln, 16.2, (165, 184, 201), 400)

    # bottom purpose
    line(d, x + 30, y + 522, x + 30, y + 561, AMBER, 1.4)
    T(d, x + 44, y + 514, "TASK 01", 8.2, (147, 106, 53), 500, True, 1.4)
    T(d, x + 44, y + 532, "把「像攻击」认出来。", 17.0, (215, 229, 239), 500)


def draw_card2(img):
    box = (990, 280, 850, 596)
    x, y, w, h = box
    draw_card_base(img, box, BLUE)
    d = ImageDraw.Draw(img)
    draw_card_header(
        img, box, BLUE,
        "LAYER 02 / GENERAL MODEL",
        "通用大模型",
        "通用模型  /  GENERAL LLM",
        "解",
        chat_icon,
    )

    px, py, pw, ph = x + 30, y + 172, w - 60, 244
    rr(d, (px, py, px + pw, py + ph), 11, fill=(6, 16, 26), outline=(31, 51, 67), width=1)
    line(d, px + 14, py + 1, px + pw - 14, py + 1, (43, 72, 105), 0.8)
    dot(d, px + 17, py + 20, 2.6, BLUE)
    T(d, px + 26, py + 12, "analyst.console", 11.2, (205, 222, 235), 500, True, 0.2)
    pill_right(d, px + pw - 12, py + 10, "READ ONLY", (152, 198, 252), (15, 30, 47), (49, 84, 119), 7.8, 21, 8, 500, True, 0.9)
    line(d, px + 14, py + 39, px + pw - 14, py + 39, (29, 48, 63), 0.8)

    # prompt bubble
    rr(d, (px + 12, py + 44, px + 304, py + 70), 7, fill=(10, 23, 38), outline=(34, 58, 82), width=0.9)
    R(
        d,
        px + 20,
        py + 50,
        [
            ("> ", (106, 171, 230), 600, True),
            ("这段请求在做什么？", (166, 201, 233), 500, False),
        ],
        size=10.6,
    )

    # response with a quiet evidence rule
    line(d, px + 15, py + 78, px + 15, py + 137, (49, 88, 126), 1.6)
    T(d, px + 26, py + 77, "目录探测之后，它尝试读取", 12.7, (206, 221, 234), 400)
    # line with inline code highlight
    cx = px + 26
    code = "/etc/passwd"
    T(d, cx, py + 100, code, 11.2, (132, 195, 251), 500, True, 0.1)
    T(d, cx + tw(code, 11.2, 500, True) + 2, py + 100, "；结合来源 IP 的连续扫描，", 12.7, (206, 221, 234), 400)
    T(d, px + 26, py + 123, "更像是在寻找可读取的敏感文件。", 12.7, (206, 221, 234), 400)

    # citations
    T(d, px + 26, py + 162, "依据", 8.6, (116, 139, 157), 500, False, 0)
    cw = pill(d, px + 58, py + 153, "[req #1842]", (148, 194, 242), (13, 27, 42), (44, 73, 100), 7.8, 20, 7, 500, True, 0.2)
    pill(d, px + 66 + cw, py + 153, "[ip 203.0.113.7]", (148, 194, 242), (13, 27, 42), (44, 73, 100), 7.8, 20, 7, 500, True, 0.2)

    # tiny provenance row
    dot(d, px + 27, py + 190, 1.8, (71, 109, 147))
    T(d, px + 34, py + 185, "refs", 7.2, (80, 104, 124), 500, True, 1.0)
    T(d, px + 64, py + 185, "event_log  /  raw_request  /  session", 7.3, (92, 116, 136), 500, True, 0.5)

    # divider
    line(d, px + 371, py + 52, px + 371, py + 196, (28, 46, 60), 0.8)

    # right capabilities
    T(d, px + 390, py + 51, "WHAT IT ADDS", 8.5, (119, 141, 157), 500, True, 1.4)
    caps = [
        ("语义理解", "读懂行为在做什么", 0),
        ("上下文", "把孤立动作串起来", 1),
        ("解释", "给出可核对的一段话", 2),
    ]
    for i, (head, sub, kind) in enumerate(caps):
        cy = py + 82 + i * 43
        soft_glow(img, (px + 389, cy - 3, 17, 17), 5, (79, 137, 196), strength=32, blur=8, grow=0)
        d = ImageDraw.Draw(img)
        rr(d, (px + 389, cy - 3, px + 406, cy + 14), 5, fill=(15, 31, 48), outline=(46, 81, 114), width=0.9)
        icx, icy = px + 397.5, cy + 5.5
        if kind == 0:
            line(d, icx - 3.5, icy - 2, icx + 3.5, icy - 2, (145, 192, 242), 0.8)
            line(d, icx - 3.5, icy + 2, icx + 1.5, icy + 2, (145, 192, 242), 0.8)
        elif kind == 1:
            d.ellipse([u(icx - 4.5), u(icy - 2.5), u(icx - 0.5), u(icy + 1.5)], outline=(145, 192, 242), width=u(0.8))
            d.ellipse([u(icx + 0.5), u(icy - 2.5), u(icx + 4.5), u(icy + 1.5)], outline=(145, 192, 242), width=u(0.8))
            line(d, icx - 0.5, icy - 0.5, icx + 0.5, icy - 0.5, (145, 192, 242), 0.8)
        else:
            rr(d, (icx - 3, icy - 4, icx + 3, icy + 4), 1, outline=(145, 192, 242), width=0.8)
            line(d, icx - 1.5, icy - 1.5, icx + 1.5, icy - 1.5, (145, 192, 242), 0.7)
            line(d, icx - 1.5, icy + 1.2, icx + 0.8, icy + 1.2, (145, 192, 242), 0.7)
        T(d, px + 416, cy - 5, head, 12.6, (225, 237, 246), 500)
        T(d, px + 416, cy + 14, sub, 9.4, (119, 141, 157), 400)

    # inner footer boundary
    line(d, px + 18, py + 210, px + pw - 18, py + 210, (28, 47, 61), 0.8)
    dot(d, px + 24, py + 225, 2.5, GREEN)
    T(d, px + 32, py + 217, "只解释现场，不替识别模型下结论", 9.6, (137, 168, 158), 400)
    T(d, px + pw - 18, py + 217, "NO CROSS-CONCLUSION", 7.1, (70, 106, 100), 500, True, 0.9, anchor="ra")

    # description
    desc = [
        "不抢识别模型的活。它读请求、日志和上下文，把「这串行为在说什么」",
        "讲清楚，并标明每一句的依据。",
    ]
    for i, ln in enumerate(desc):
        T(d, x + 30, y + 438 + i * 28.5, ln, 16.2, (165, 184, 201), 400)

    # bottom purpose
    line(d, x + 30, y + 522, x + 30, y + 561, BLUE, 1.4)
    T(d, x + 44, y + 514, "TASK 02", 8.2, (88, 135, 188), 500, True, 1.4)
    T(d, x + 44, y + 532, "把「看不懂的」讲明白。", 17.0, (215, 229, 239), 500)


# ---------------------------------------------------------------------------
# Boundary band + footer
# ---------------------------------------------------------------------------
def draw_boundary(img):
    x, y, w, h = 80, 900, 1760, 126
    soft_shadow(img, (x, y, w, h), 15, strength=150, blur=24, y_offset=8)
    gradient_round_rect(img, (x, y, w, h), 15, (11, 25, 33), (8, 18, 26), border=(35, 68, 63), border_width=1)
    d = ImageDraw.Draw(img)
    gradient_hline(d, x + 1, x + w * 0.62, y + 1, (80, 162, 130), (41, 78, 100), 1.4, 100)
    gradient_hline(d, x + w * 0.62, x + w - 1, y + 1, (41, 78, 100), (57, 50, 81), 1.4, 90)

    # boundary glyph tile
    gx, gy, gsz = x + 28, y + 34, 58
    soft_glow(img, (gx, gy, gsz, gsz), 12, (69, 175, 137), strength=38, blur=18, grow=1)
    d = ImageDraw.Draw(img)
    rr(d, (gx, gy, gx + gsz, gy + gsz), 13, fill=(11, 28, 25), outline=(42, 84, 70), width=1)
    line(d, gx + 13, gy + 1, gx + gsz - 13, gy + 1, GREEN, 1)
    T(d, gx + gsz / 2, gy + gsz / 2 + 1, "界", 28, GREEN, 700, False, 0, anchor="mm")

    tx = x + 110
    T(d, tx, y + 21, "THE BOUNDARY", 9.0, (99, 165, 145), 500, True, 1.7)
    T(d, tx + 101, y + 21, "/ 协同边界", 9.4, (101, 141, 128), 400, False, 0)

    R(
        d,
        tx,
        y + 41,
        [
            ("两层各干各的事，", (237, 245, 250), 700),
            ("谁也不替谁下结论。", (116, 229, 187), 700),
        ],
        size=26.0,
    )
    T(
        d,
        tx,
        y + 83,
        "攻击标签归第一层，语义解释归第二层；两套输出并列保留，互不覆盖。",
        12.4,
        (119, 144, 160),
        400,
    )

    # three principles
    line(d, 1005, y + 22, 1005, y + h - 22, (29, 55, 52), 0.9)
    cols = [
        ("01", "独立读取", "同一份现场，各自取证", GREEN),
        ("02", "独立输出", "攻击标签 + 语义解释", BLUE),
        ("03", "不做代判", "不替对方下结论", PURPLE),
    ]
    starts = [1032, 1296, 1560]
    for i, (num, head, sub, col) in enumerate(cols):
        cx = starts[i]
        line(d, cx - 15, y + 24, cx - 15, y + h - 24, (28, 50, 55), 0.8) if i else None
        dot(d, cx + 2, y + 28, 2.3, col)
        T(d, cx + 11, y + 22, num, 8.8, col, 500, True, 1.1)
        T(d, cx + 36, y + 20, head, 13.2, (221, 236, 243), 600)
        T(d, cx + 24, y + 43, sub, 10.2, (108, 133, 147), 400)
        # tiny micro rule
        line(d, cx, y + 70, cx + 32, y + 70, col, 1.0)


def draw_footer(img):
    d = ImageDraw.Draw(img)
    fy = 1048
    items = [
        ((232, 172, 84), "第一层：攻击标签"),
        ((112, 174, 247), "第二层：语义解释"),
        ((104, 221, 177), "共同边界：互不代判"),
    ]
    x = 80
    for col, text in items:
        dot(d, x, fy + 6.5, 2.6, col)
        T(d, x + 9, fy, text, 9.5, (108, 132, 149), 400)
        x += 164
    parts = [
        ("CONCEPT DIAGRAM", (75, 99, 117), 500, True),
        ("   ·   示意内容，非真实数据", (75, 99, 117), 400, False),
    ]
    total = sum(tw(p[0], 7.9, p[2], p[3]) for p in parts)
    R(d, 1840 - total, fy - 1, parts, size=7.9)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    img = make_background()
    draw_header(img)
    draw_flow_panel(img)
    draw_card1(img)
    draw_card2(img)
    draw_boundary(img)
    draw_footer(img)
    result = img.convert("RGB").resize((W, H), Image.LANCZOS)
    out = OUT / "ai_two_layers_infographic.png"
    result.save(out, "PNG")
    print(out)


if __name__ == "__main__":
    main()
