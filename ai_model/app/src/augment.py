# src/augment.py
"""
多类别数据增强。
- xss：大小写、URL 编码、HTML 实体、注释混淆、空白替换、Unicode 转义等
- sqli：大小写、注释替换、空白替换、URL 编码、常见变形等
- path_traversal：URL 编码、反斜杠、双重编码、大小写等
- normal：不做增强，原样保留
"""
import urllib.parse
import random


# ============================================================
# XSS 增强
# ============================================================
def augment_xss(payload: str):
    variants = set()
    variants.add(payload)
    variants.add(payload.upper())
    variants.add(payload.lower())

    variants.add(urllib.parse.quote(payload))
    variants.add(urllib.parse.quote_plus(payload))
    variants.add(urllib.parse.quote(urllib.parse.quote(payload)))

    variants.add(
        payload.replace("<", "&#x3C;")
               .replace(">", "&#x3E;")
               .replace("(", "&#x28;")
               .replace(")", "&#x29;")
    )
    variants.add(
        payload.replace("<", "&lt;")
               .replace(">", "&gt;")
    )

    mixed = "".join(
        c.upper() if random.random() > 0.5 else c.lower()
        for c in payload
    )
    variants.add(mixed)

    variants.add(payload.replace("script", "scr<!-- -->ipt"))
    variants.add(payload.replace("script", "scr\nipt"))

    variants.add(payload.replace(" ", "\t"))
    variants.add(payload.replace(" ", "\n"))
    variants.add(payload.replace(" ", "/**/"))

    variants.add(payload.replace("a", "\\u0061"))
    variants.add(payload.replace("e", "\\u0065"))

    variants.add(payload.replace('"', "").replace("'", ""))

    return list(variants)


# ============================================================
# SQLi 增强
# ============================================================
def augment_sqli(payload: str):
    variants = set()
    variants.add(payload)
    variants.add(payload.upper())
    variants.add(payload.lower())

    # 空白变注释
    variants.add(payload.replace(" ", "/**/"))
    variants.add(payload.replace(" ", "%20"))
    variants.add(payload.replace(" ", "+"))
    variants.add(payload.replace(" ", "\t"))
    variants.add(payload.replace(" ", "\n"))

    # URL 编码（仅对特殊字符编码，避免整条变成编码串）
    variants.add(urllib.parse.quote(payload, safe=""))
    variants.add(urllib.parse.quote(payload, safe="=<>'\" "))

    # 关键字混淆
    variants.add(payload.replace("union", "uni/**/on"))
    variants.add(payload.replace("select", "sel/**/ect"))
    variants.add(payload.replace("or", "O/**/R"))
    variants.add(payload.replace("and", "A/**/ND"))

    # 大小写混合（SQL 关键字）
    mixed = "".join(
        c.upper() if random.random() > 0.5 else c.lower()
        for c in payload
    )
    variants.add(mixed)

    # 注释后缀变体
    if "--" in payload:
        variants.add(payload.replace("--", "#"))
        variants.add(payload.replace("--", "-- -"))
    if "#" in payload:
        variants.add(payload.replace("#", "--"))

    return list(variants)


# ============================================================
# 路径遍历 / 敏感路径 增强
# ============================================================
def augment_path_traversal(payload: str):
    variants = set()
    variants.add(payload)
    variants.add(payload.upper())
    variants.add(payload.lower())

    # ../ 变 ..\
    if "../" in payload:
        variants.add(payload.replace("../", "..\\"))
        variants.add(payload.replace("../", "..%2f"))
        variants.add(payload.replace("../", "..%5c"))
        variants.add(payload.replace("../", "%2e%2e%2f"))
        variants.add(payload.replace("../", "%2e%2e/"))
        variants.add(payload.replace("../", "....//"))
        variants.add(payload.replace("../", "..;/"))

    # 反斜杠变正斜杠
    if "..\\" in payload:
        variants.add(payload.replace("..\\", "../"))
        variants.add(payload.replace("..\\", "..%5c"))

    # 整体 URL 编码
    variants.add(urllib.parse.quote(payload))
    variants.add(urllib.parse.quote(urllib.parse.quote(payload)))

    # 双斜杠
    variants.add(payload.replace("/", "//"))

    return list(variants)


# ============================================================
# 敏感文件/目录探测 增强
# ============================================================
def augment_sensitive_path(payload: str):
    """
    敏感路径探测的变体：大小写、双斜杠、点号编码、查询参数。

    注意：**不要**拼接 "/index.php" 或裸 "?"。
    早期版本会为每条敏感路径生成 "xxx/index.php"，这对字符级 n-gram 模型是
    强烈的噪声信号——它会让模型把普通路径 "/index.php" 也学成敏感路径。
    实测该增强导致 "/index.php" 被判定为 sensitive_path(prob=1.0)。
    """
    variants = set()
    variants.add(payload)
    variants.add(payload.upper())
    variants.add(payload.lower())

    # 双斜杠 / 前置点斜杠 绕过
    variants.add(payload.replace("/", "//"))
    if payload.startswith("/"):
        variants.add("./" + payload.lstrip("/"))
        variants.add("/." + payload)

    # URL 编码（保留 / 便于语义识别）
    variants.add(urllib.parse.quote(payload, safe="/"))
    # 仅编码点号，绕过 . 过滤
    variants.add(payload.replace(".", "%2e"))

    # 目录探测常见的"加尾斜杠"形式（这是真实存在的扫描行为）
    if not payload.endswith("/"):
        variants.add(payload + "/")

    # 带真实参数的探测
    variants.add(payload + "?id=1")

    return list(variants)


# ============================================================
# 统一入口
# ============================================================
AUGMENTORS = {
    "xss": augment_xss,
    "sqli": augment_sqli,
    "path_traversal": augment_path_traversal,
    "sensitive_path": augment_sensitive_path,
}


def build_augmented_dataset(df, text_col="text", label_col="label"):
    """
    对所有攻击类别做增强，normal 样本保留原样。
    """
    import pandas as pd

    rows = []
    for _, row in df.iterrows():
        text = str(row[text_col])
        label = row[label_col]
        source = row.get("source", "unknown")

        if label in AUGMENTORS:
            variants = AUGMENTORS[label](text)
            for v in variants:
                rows.append({text_col: v, label_col: label, "source": source})
        else:
            rows.append({text_col: text, label_col: label, "source": source})

    result = pd.DataFrame(rows)
    result = result.drop_duplicates(subset=[text_col])
    return result