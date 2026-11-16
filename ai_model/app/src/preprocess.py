# src/preprocess.py
import urllib.parse
import html
import re


def url_decode(text: str) -> str:
    """反复 URL 解码，处理多重编码"""
    prev = None
    cur = text
    for _ in range(5):
        if prev == cur:
            break
        prev = cur
        cur = urllib.parse.unquote(cur)
    return cur


def html_decode(text: str) -> str:
    """HTML 实体解码，最多 5 次"""
    prev = None
    cur = text
    for _ in range(5):
        if prev == cur:
            break
        prev = cur
        cur = html.unescape(cur)
    return cur


def unicode_decode(text: str) -> str:
    """处理 \\u0061 这种 Unicode 转义"""
    def replace_unicode(m):
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)

    return re.sub(r"\\u([0-9a-fA-F]{4})", replace_unicode, text)


def remove_null_bytes(text: str) -> str:
    return text.replace("\x00", "")


def normalize_text(text: str) -> str:
    """
    统一预处理入口。
    未来加新攻击类型时，这里可以继续加规则。
    """
    if text is None:
        return ""
    text = str(text)
    text = remove_null_bytes(text)
    text = url_decode(text)
    text = html_decode(text)
    text = unicode_decode(text)
    return text


def normalize_for_model(text: str) -> str:
    """
    给模型用的版本。
    保留特殊字符，只做归一化，不做词干化。
    """
    return normalize_text(text)