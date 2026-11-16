# src/utils.py
"""
通用工具函数：
- read_csv_safe: 自动尝试多种编码读取 CSV，跳过坏行
- write_csv_safe: 统一用 utf-8-sig 写入
- 附带一些调试用的小工具
"""

import os
from pathlib import Path

import pandas as pd


# ---------------------------------------------------------
# 支持的编码列表，按优先级尝试
# ---------------------------------------------------------
ENCODINGS = [
    "utf-8-sig",   # 带 BOM 的 UTF-8，Excel 常用
    "utf-8",       # 标准 UTF-8
    "gbk",         # 中文 Windows 常见
    "gb18030",     # GBK 超集
    "big5",        # 繁体中文
    "latin1",      # 万能解码，最后兜底
]


# ---------------------------------------------------------
# 读取 CSV
# ---------------------------------------------------------
def read_csv_safe(path, **kwargs):
    """
    安全读取 CSV：
    1. 依次尝试多种编码
    2. 遇到格式错误行自动跳过
    3. 失败时抛出带详细信息的异常

    参数:
        path: CSV 文件路径
        **kwargs: 传给 pandas.read_csv 的其他参数

    返回:
        pandas.DataFrame
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"文件不存在: {path}")

    if path.stat().st_size == 0:
        raise ValueError(f"文件为空: {path}")

    last_err = None

    for enc in ENCODINGS:
        # 第一次尝试：正常读
        try:
            df = pd.read_csv(path, encoding=enc, **kwargs)
            print(f"[read_csv_safe] 读取成功，编码: {enc}, 行数: {len(df)}")
            return df
        except UnicodeDecodeError as e:
            # 编码不对，换下一个
            last_err = e
            continue
        except pd.errors.ParserError as e:
            # 编码对了，但某些行列数不对，跳过坏行再读
            print(f"[read_csv_safe] 编码 {enc} 正确，但存在格式错误的行，尝试跳过坏行...")
            try:
                df = pd.read_csv(
                    path,
                    encoding=enc,
                    on_bad_lines="skip",
                    **kwargs,
                )
                print(f"[read_csv_safe] 读取成功（已跳过坏行），编码: {enc}, 行数: {len(df)}")
                return df
            except UnicodeDecodeError as e2:
                last_err = e2
                continue
            except Exception as e2:
                last_err = e2
                continue
        except Exception as e:
            # 其他异常，记录后继续尝试
            last_err = e
            continue

    # 全部失败
    raise ValueError(
        f"无法读取 {path}\n"
        f"尝试过的编码: {ENCODINGS}\n"
        f"最后一次错误: {last_err}"
    ) from last_err


# ---------------------------------------------------------
# 写入 CSV
# ---------------------------------------------------------
def write_csv_safe(df, path, **kwargs):
    """
    安全写入 CSV：
    - 统一用 utf-8-sig，Excel 打开不乱码
    - 自动创建父目录

    参数:
        df: pandas.DataFrame
        path: 输出路径
        **kwargs: 传给 df.to_csv 的其他参数
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # 默认不写索引，除非用户显式指定
    kwargs.setdefault("index", False)
    kwargs.setdefault("encoding", "utf-8-sig")

    df.to_csv(path, **kwargs)
    print(f"[write_csv_safe] 已保存: {path}, 行数: {len(df)}")


# ---------------------------------------------------------
# 调试用：打印 CSV 前几行 + 编码信息
# ---------------------------------------------------------
def inspect_csv(path, n=5):
    """
    打印 CSV 的编码、列名、前 n 行，便于调试。
    """
    path = Path(path)
    if not path.exists():
        print(f"文件不存在: {path}")
        return

    print(f"文件: {path}")
    print(f"大小: {path.stat().st_size} 字节")

    df = read_csv_safe(path)
    print(f"列名: {list(df.columns)}")
    print(f"行数: {len(df)}")
    print(f"前 {n} 行:")
    print(df.head(n))


# ---------------------------------------------------------
# 调试用：检测文件编码
# ---------------------------------------------------------
def detect_encoding(path, sample_size=100000):
    """
    尝试检测文件最可能的编码。
    返回第一个能成功解码的编码名。
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"文件不存在: {path}")

    with open(path, "rb") as f:
        raw = f.read(sample_size)

    for enc in ENCODINGS:
        try:
            raw.decode(enc)
            return enc
        except UnicodeDecodeError:
            continue

    return None


# ---------------------------------------------------------
# 调试用：统计每行列数
# ---------------------------------------------------------
def check_csv_shape(path, encoding=None):
    """
    检查 CSV 每行的字段数，找出列数不一致的行。
    适合在 ParserError 之后定位问题行。
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"文件不存在: {path}")

    if encoding is None:
        encoding = detect_encoding(path) or "utf-8-sig"

    print(f"使用编码: {encoding}")

    bad_lines = []
    counts = {}

    with open(path, "r", encoding=encoding, errors="replace") as f:
        for i, line in enumerate(f, start=1):
            # 简单按逗号切分，不处理引号
            n = len(line.rstrip("\n").split(","))
            counts[n] = counts.get(n, 0) + 1
            if i == 1:
                expected = n
            elif n != expected:
                bad_lines.append((i, n, line.rstrip("\n")[:120]))

    print(f"字段数统计: {counts}")
    if bad_lines:
        print(f"发现 {len(bad_lines)} 行列数异常，前 10 行:")
        for lineno, n, content in bad_lines[:10]:
            print(f"  行 {lineno} (字段数 {n}): {content}")
    else:
        print("所有行列数一致。")

    return bad_lines


# ---------------------------------------------------------
# 直接运行时的调试入口
# ---------------------------------------------------------
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("用法:")
        print("  python -m src.utils <csv路径>              # 检测编码 + 预览")
        print("  python -m src.utils <csv路径> check        # 检查每行列数")
        sys.exit(0)

    csv_path = sys.argv[1]

    if len(sys.argv) >= 3 and sys.argv[2] == "check":
        check_csv_shape(csv_path)
    else:
        inspect_csv(csv_path)