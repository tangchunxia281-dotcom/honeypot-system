# tools/augment_extra.py
import pandas as pd
import urllib.parse

df = pd.read_csv("data/train_extra.csv", encoding="utf-8-sig")
augmented = []

for _, row in df.iterrows():
    text = str(row["text"])
    label = row["label"]
    source = row["source"]
    augmented.append({"text": text, "label": label, "source": source})

    # 只对攻击类别做增强
    if label in ("sqli", "path_traversal"):
        # 1. URL 编码
        encoded = urllib.parse.quote(text, safe="/")
        if encoded != text:
            augmented.append({"text": encoded, "label": label, "source": source + "_urlencode"})

        # 2. 大写
        upper = text.upper()
        if upper != text:
            augmented.append({"text": upper, "label": label, "source": source + "_upper"})

        # 3. 空格替换为注释（对 SQLi 有效）
        if label == "sqli" and " " in text:
            augmented.append({"text": text.replace(" ", "/**/"), "label": label, "source": source + "_comment"})

        # 4. 路径遍历专属：反斜杠变体
        if label == "path_traversal" and "../" in text:
            augmented.append({"text": text.replace("../", "..\\"), "label": label, "source": source + "_backslash"})
            augmented.append({"text": text.replace("../", "..%2f"), "label": label, "source": source + "_urlenc"})

df_aug = pd.DataFrame(augmented).drop_duplicates(subset=["text"]).reset_index(drop=True)
df_aug.to_csv("data/train_extra_aug.csv", index=False, encoding="utf-8-sig")
print(f"增强后总样本数: {len(df_aug)}")
print(f"标签分布:\n{df_aug['label'].value_counts()}")