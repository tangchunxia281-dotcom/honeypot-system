# 数据质量体检报告

自动生成，用于定位标签噪声、标签冲突与样本分布缺口。

---

文件: `data\raw\train_raw_backup_v3.csv`

## 原始备份 v3
- 总行数: **8570**
- 标签分布: `xss`=470, `sqli`=969, `path_traversal`=117, `normal`=7013
- normal 占比: **81.8%**
- 空值列: 无
- 完全重复的 text 行数: **6**
- **标签冲突（同一文本对应多个标签）: 0 组**
- 疑似误标统计（攻击标签但文本不含该类任何特征）:
    - `xss`: **1/470 (0.2%)** 不含特征
    - `sqli`: **101/969 (10.4%)** 不含特征
    - `path_traversal`: **69/117 (59.0%)** 不含特征
- 攻击类里的碎片样本（长度<=6 或纯 alnum 短串）:
    - `sqli`: 68 条，样例 ['/1', '/0', 'extractvalue', 'length', 'ord', 'ascii', 'char', 'count', 'left', 'right', 'a', '@']
    - `path_traversal`: 7 条，样例 ['/admin/', '/admin/login', '/console', '/phpmyadmin/', '/pma/', '/mysql/', '/phpinfo']
- 各来源的标签纯度（来源里出现非预期标签说明转换有误）:
    - `final` (n=3531): normal=3531
    - `generated` (n=456): xss=456
    - `manual` (n=138): normal=118, path_traversal=20
    - `payload` (n=131): normal=117, xss=14
    - `source` (n=1): label=1
    - `sqldata.csv` (n=33): sqli=33
    - `sqli.csv` (n=3935): normal=2999, sqli=936
    - `web_cn` (n=226): normal=226
    - `敏感文件路径.csv` (n=119): path_traversal=97, normal=22

---

文件: `data\processed\train_raw.csv`

## 训练集 train_raw
- 总行数: **6867**
- 标签分布: `xss`=376, `sqli`=707, `path_traversal`=15, `normal`=5695
- normal 占比: **82.9%**
- 空值列: 无
- 完全重复的 text 行数: **0**
- **标签冲突（同一文本对应多个标签）: 0 组**
- 疑似误标统计（攻击标签但文本不含该类任何特征）:
    - `xss`: **1/376 (0.3%)** 不含特征
    - `sqli`: **37/707 (5.2%)** 不含特征
    - `path_traversal`: **0/15 (0.0%)** 不含特征
- 攻击类里的碎片样本（长度<=6 或纯 alnum 短串）:
    - `sqli`: 11 条，样例 ['handler', '+sqlvuln', '%2A%7C', '%7C', 'procedure', 'bfilename', 'sqlvuln', 'truncate', 'replace', 'distinct', 'limit']
- 各来源的标签纯度（来源里出现非预期标签说明转换有误）:
    - `benign_path` (n=82): normal=82
    - `final` (n=2818): normal=2818
    - `generated` (n=363): xss=363
    - `manual` (n=111): normal=100, path_traversal=11
    - `payload` (n=108): normal=95, xss=13
    - `sqldata.csv` (n=14): sqli=14
    - `sqli.csv` (n=3082): normal=2389, sqli=693
    - `web_cn` (n=193): normal=193
    - `敏感文件路径.csv` (n=96): sensitive_path=74, normal=18, path_traversal=4

---

文件: `data\processed\test_raw.csv`

## 独立测试集 test_raw
- 总行数: **1717**
- 标签分布: `xss`=94, `sqli`=177, `path_traversal`=3, `normal`=1424
- normal 占比: **82.9%**
- 空值列: 无
- 完全重复的 text 行数: **0**
- **标签冲突（同一文本对应多个标签）: 0 组**
- 疑似误标统计（攻击标签但文本不含该类任何特征）:
    - `xss`: **0/94 (0.0%)** 不含特征
    - `sqli`: **7/177 (4.0%)** 不含特征
    - `path_traversal`: **0/3 (0.0%)** 不含特征
- 攻击类里的碎片样本（长度<=6 或纯 alnum 短串）:
    - `sqli`: 1 条，样例 ['PRINT']
- 各来源的标签纯度（来源里出现非预期标签说明转换有误）:
    - `benign_path` (n=24): normal=24
    - `final` (n=713): normal=713
    - `generated` (n=93): xss=93
    - `manual` (n=21): normal=18, path_traversal=3
    - `payload` (n=23): normal=22, xss=1
    - `sqldata.csv` (n=2): sqli=2
    - `sqli.csv` (n=785): normal=610, sqli=175
    - `web_cn` (n=33): normal=33
    - `敏感文件路径.csv` (n=23): sensitive_path=19, normal=4

---

文件: `data\augmented\augmented.csv`

## 增强集 augmented
- 总行数: **20511**
- 标签分布: `xss`=5241, `sqli`=8865, `path_traversal`=145, `normal`=5695
- normal 占比: **27.8%**
- 空值列: 无
- 完全重复的 text 行数: **0**
- **标签冲突（同一文本对应多个标签）: 0 组**
- 疑似误标统计（攻击标签但文本不含该类任何特征）:
    - `xss`: **58/5241 (1.1%)** 不含特征
    - `sqli`: **359/8865 (4.0%)** 不含特征
    - `path_traversal`: **2/145 (1.4%)** 不含特征
- 攻击类里的碎片样本（长度<=6 或纯 alnum 短串）:
    - `sqli`: 46 条，样例 ['haNDleR', 'HANDLER', 'handler', '+SQLVULN', '+sqlvuln', '+sqlvuLn', '%2A%7C', '%2a%7c', '%2a%7C', '%7C', '%7c', '%257C']
- 各来源的标签纯度（来源里出现非预期标签说明转换有误）:
    - `benign_path` (n=82): normal=82
    - `final` (n=2818): normal=2818
    - `generated` (n=5069): xss=5069
    - `manual` (n=197): normal=100, path_traversal=97
    - `payload` (n=267): xss=172, normal=95
    - `sqldata.csv` (n=110): sqli=110
    - `sqli.csv` (n=11144): sqli=8755, normal=2389
    - `web_cn` (n=193): normal=193
    - `敏感文件路径.csv` (n=631): sensitive_path=565, path_traversal=48, normal=18

---

## 跨文件一致性检查
- 训练集与测试集文本重叠: **0** 条 （>0 说明测试集被污染，指标虚高）
- 增强集与测试集文本重叠: **7** 条
- 增强集标签分布: sqli=8865, normal=5695, xss=5241, sensitive_path=565, path_traversal=145

## 模型元数据 vs 当前数据
- meta 记录: 训练样本 16203, 测试样本 1717, 训练时间 2026-10-15 19:00:49
- augmented 实际行数: 20511 -> **不一致，模型已过期**