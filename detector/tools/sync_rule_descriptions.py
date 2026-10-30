# tools/sync_rule_descriptions.py
"""自动同步 RULE_DESCRIPTIONS：为缺少中文描述的规则补上条目。

背景：rules.py 里的规则(pattern)与描述(RULE_DESCRIPTIONS)是两份数据，
手工维护必然出现"加了规则忘了加描述"，导致 reason 字段回退成原始正则。

本脚本读取 RULES 与 RULE_DESCRIPTIONS，找出缺失项，
按类别生成默认中文描述并写回 rules.py（插在 `# Sensitive Path 补充描述` 之前）。

用法:
    python -m tools.sync_rule_descriptions          # 试运行，只报告
    python -m tools.sync_rule_descriptions --write  # 写回文件
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.rules import RULES, RULE_DESCRIPTIONS

LABEL_CN = {
    "xss": "XSS 注入",
    "sqli": "SQL 注入",
    "path_traversal": "目录穿越",
    "sensitive_path": "敏感路径探测",
}

ANCHOR = "    # Sensitive Path 补充描述"


def default_desc(label, pattern):
    """为缺失描述的规则生成一个可读的默认描述。"""
    if pattern in MANUAL_DESC:
        return MANUAL_DESC[pattern]
    # 把正则里的转义与分组去掉，得到更接近人类可读的片段
    s = pattern
    s = re.sub(r"\(\?:[^)]*\)", "", s)      # 去掉 (?:^|/) 这类非捕获组
    s = re.sub(r"\(\?[^)]*\)", "", s)       # 去掉其它 (?...) 结构
    s = s.replace("\\\\", "\\").replace("\\b", "").replace("\\s*", " ")
    s = re.sub(r"\\s\+", " ", s)
    s = re.sub(r"[\\^$]", "", s)
    s = s.strip("|() ")
    if len(s) > 40:
        s = s[:40] + "…"
    return f"命中{LABEL_CN.get(label, label)}特征: {s}"


# 少数规则需要人工措辞，避免自动生成的描述过于生硬
MANUAL_DESC = {
    r"\band\s+\d+\s*=\s*\d+\s*(?:--|#|/\*|;|$)": "检测到 SQL 恒真条件 and N=N",
    r"\bor\s+\d+\s*=\s*\d+\s*(?:--|#|/\*|;|$)": "检测到 SQL 恒真条件 or N=N",
    r"['\"`)]\s*and\s+\d+\s*=\s*\d+": "检测到带引号的 SQL 盲注 and 条件",
    r"['\"`)]\s*or\s+\d+\s*=\s*\d+": "检测到带引号的 SQL 布尔注入 or 条件",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="写回 rules.py")
    ap.add_argument("--fix-generated", action="store_true",
                    help="把此前自动生成的粗糙描述（含 '命中...特征:' 字样）改为改进版")
    args = ap.parse_args()

    missing = [(lab, p) for lab, pats in RULES.items()
               for p in pats if p not in RULE_DESCRIPTIONS]

    # 需要重写的：之前自动生成、措辞生硬的描述
    rewrite = []
    if args.fix_generated:
        for lab, pats in RULES.items():
            for p in pats:
                d = RULE_DESCRIPTIONS.get(p, "")
                if "命中" in d and "特征:" in d:
                    new = default_desc(lab, p)
                    if new != d:
                        rewrite.append((lab, p, d, new))

    print(f"规则总数: {sum(len(v) for v in RULES.values())}")
    print(f"已有描述: {len(RULE_DESCRIPTIONS)}")
    print(f"缺失描述: {len(missing)}")
    for lab, p in missing:
        print(f"  [{lab}] {p!r}  ->  {default_desc(lab, p)}")
    if rewrite:
        print(f"\n可改进的自动描述: {len(rewrite)} 条")
        for lab, p, old, new in rewrite[:10]:
            print(f"  {old}  ->  {new}")

    if not missing and not rewrite:
        print("\n无需修改。")
        return

    if not args.write:
        print("\n(试运行，未写文件。加 --write 才会写回)")
        return

    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "src", "rules.py")
    src = open(path, encoding="utf-8").read()

    # 先替换需要重写的旧描述
    for lab, p, old, new in rewrite:
        old_line = f'    {p!r}: {old!r},'
        new_line = f'    {p!r}: {new!r},'
        if old_line in src:
            src = src.replace(old_line, new_line, 1)

    # 再补充缺失描述
    if missing:
        if ANCHOR not in src:
            print(f"[错误] 找不到插入锚点: {ANCHOR}")
            sys.exit(1)
        lines = "".join(f'    {p!r}: {default_desc(lab, p)!r},\n'
                        for lab, p in missing)
        src = src.replace(ANCHOR, lines + ANCHOR, 1)

    open(path, "w", encoding="utf-8").write(src)
    print(f"\n[已写回] {path}  补充 {len(missing)} 条, 重写 {len(rewrite)} 条")


if __name__ == "__main__":
    main()
