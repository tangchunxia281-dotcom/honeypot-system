# 蜜罐系统全功能测试 · 截图说明

测试时间：2026-11-07 22:52 — 23:12（Asia/Shanghai）
运行实例：D:\honeypot（本机回环，所有攻击流量仅发往 127.0.0.1）

## 基础功能
- 01_web_home.png：Web 蜜罐企业站点首页
- 02_web_admin_login.png：诱饵后台 /admin 登录页
- 03_web_admin_dashboard.png：使用诱饵凭证 admin/System123 登录后的后台工作台
- 04_dashboard_login.png：真实 Dashboard 登录页 /super/login
- 05_dashboard.png：态势大屏（总攻击 255、SSH 92、Web 132、攻击源 9）
- 06_dashboard_full.png：大屏完整页面

## AI 工作区
- 07_ai_monitor.png：本地 AI 运行监控（真实调用成功 219、备用处理 23、连接验收成功）
- 08_ai_analysis_list.png：AI 攻击日志分析中心（已生成 103+ 份报告）
- 09_ai_analysis_detail.png：高危报告详情（SSH 探测后下载外部脚本）
- 09b_ai_analysis_detail_full.png：报告详情完整页（含证据引用）
- 10_ai_detection.png：规则与 AI 攻击研判对照（来源 203.0.113.45，8 条已完成）
- 10b_ai_detection_full.png：研判对照完整页
- 10c_ai_detection_detail.png：XXE 研判证据（原文引用 + 规则分 24）
- 11_ai_interactions.png：会话交互回放（AI 选择策略 15 / 预设逻辑 21）
- 11b_ai_interactions_full.png：交互回放完整页
- 12_ai_investigations.png：调查工作台（1 条调查，关联 AI 报告与审计历史）
- 13_ai_team.png：团队研判工作台（云端 DeepSeek API 实际调用验收成功）

## 模型与汇总
- 14_model_validation.png：请求级 AI 模型运行验证（v2、27/34 召回、0/6 误报、39ms）
- 16_test_summary.png：测试汇总报告（305 事件、181 原始请求、171/171 回归、29/29 API）

## 文字与数据
- reports/test_summary.html：可交互的测试汇总报告
- reports/model_validation.html：模型验证卡片
- reports/attack_eval_*.json：34 条 Web 攻击 + SSH 全流程的落库明细
- reports/ai_model_live.json：模型真实载荷直测指标
- reports/ai_model_eval.json：项目 fixtures 压力测试指标
- reports/api_smoke.json：29 个 Dashboard 接口冒烟结果
- reports/verify_project.log：171 项项目回归测试日志

说明：截图中的 203.0.113.x / 198.51.100.x / 192.0.2.x 为 RFC 5737 文档保留地址，
仅通过 X-Forwarded-For 模拟攻击来源，不对应任何真实主机。
