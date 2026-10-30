# src/api.py
import json
import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.config import (
    MODEL_PATH,
    MODEL_META_PATH,
    ALL_LABELS,
    HONEYPOT_LOG_PATH,
)
from src.predict import predict_xss, predict_signal, detect_request, get_model

app = FastAPI(
    title="Attack Detector AI Service",
    description=(
        "面向蜜罐的 Web 攻击检测服务。\n\n"
        "## 对接方式（只需看这一个接口）\n"
        "**`POST /api/v1/detect`** —— 提交采集到的 HTTP 请求，返回攻击判定与分值。\n\n"
        "## 其余接口\n"
        "标注为 **【内部调试】** 的接口供本模块自测使用，"
        "蜜罐侧无需了解其内部字段。\n\n"
        "## 最小可用请求\n"
        "```json\n"
        '{"path": "/search", "query": "id=1 and 1=1"}\n'
        "```"
    ),
    version="2.0.0",
    contact={"name": "AI 检测模块"},
)

# 配置日志轮转（单文件 5MB，保留 5 个备份）
# 注意：日志文件不可写时不能让服务启动失败，降级为控制台输出即可。
logger = logging.getLogger("honeypot_logger")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    _log_handler = None
    try:
        os.makedirs(os.path.dirname(str(HONEYPOT_LOG_PATH)) or ".", exist_ok=True)
        _log_handler = RotatingFileHandler(
            HONEYPOT_LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
    except Exception as _e:  # 权限不足/磁盘只读/路径异常等
        print(f"[WARN] 蜜罐日志文件不可写({_e})，降级为控制台输出")
        _log_handler = logging.StreamHandler()
    logger.addHandler(_log_handler)


class PredictRequest(BaseModel):
    text: str = Field(..., description="要检测的文本", max_length=100000)
    source: Optional[str] = Field("unknown", description="来源: web / ssh / http / api")
    ip: Optional[str] = Field("", description="来源 IP")
    extra: Optional[dict] = Field(default_factory=dict, description="额外元信息")


class PredictResponse(BaseModel):
    label: str
    is_attack: bool
    confidence: float
    reason: str


class BatchPredictRequest(BaseModel):
    texts: List[str] = Field(..., description="批量文本列表", max_length=1000)
    source: Optional[str] = Field("unknown", description="来源")
    ip: Optional[str] = Field("", description="来源 IP")


class BatchPredictResponse(BaseModel):
    results: List[PredictResponse]
    total: int
    attack_count: int


class SignalResponse(BaseModel):
    """信号接口返回：供蜜罐"多特征加权 + 双阈值分层"使用。"""
    attack_type: str
    is_attack: bool
    attack_prob: float
    ai_points: int = Field(..., description="AI 建议累加分值 (0~25)")
    rule_points: int
    effective_rule_points: int
    fusion_score: int = Field(..., description="累加总分 = 生效规则分 + AI 分")
    suspicious: bool = Field(..., description=">=20 可疑事件")
    high_risk: bool = Field(..., description=">=40 高危告警")
    confidence: float
    reason: str
    rule_hits: List[dict]
    model_label: str


class DetectRequest(BaseModel):
    """请求级检测入参：蜜罐把采集到的 HTTP 请求各部分传过来。

    最简单用法：只传 url（完整 URL，含查询串）。
    更准确用法：分别传 path / query / body，检测器会分段判定。
    """
    url: Optional[str] = Field(None, description="完整 URL（含查询串），如 /search?id=1")
    path: Optional[str] = Field(None, description="请求路径，如 /download")
    query: Optional[str] = Field(None, description="查询串，如 id=1&name=x（可带 ? 前缀）")
    body: Optional[str] = Field(None, description="请求体原文")
    method: Optional[str] = Field(None, description="HTTP 方法，如 GET/POST")
    headers: Optional[dict] = Field(default_factory=dict, description="请求头字典")
    user_agent: Optional[str] = Field(None, description="User-Agent")
    # 溯源信息（可选，用于蜜罐侧日志关联）
    source: Optional[str] = Field("web", description="来源: web / ssh / http / api")
    ip: Optional[str] = Field("", description="来源 IP")
    session_id: Optional[str] = Field("", description="会话标识")
    timestamp: Optional[str] = Field(None, description="事件时间（ISO8601，可选）")
    extra: Optional[dict] = Field(default_factory=dict, description="额外元信息")


class DetectSignalItem(BaseModel):
    field: str = Field(..., description="命中位置: path / query.参数名 / body / user_agent")
    value: str = Field(..., description="该位置的实际内容")
    attack_type: str
    attack_prob: float = Field(
        ..., description="★ 该位置属于攻击的概率 0~1（做阈值门控请用这个字段）")
    ai_points: int = Field(
        ..., description="该位置的建议累加分值 = round(attack_prob × 25)")
    confidence: float = Field(
        ..., description="模型对判定类别的置信度。这是「判定确定性」，"
                         "不代表「攻击可能性」，不要用它做攻击阈值门控")
    fusion_score: int = Field(..., description="该位置的累加分（含规则与白名单修正）")
    high_risk: bool
    reason: str


class DetectResponse(BaseModel):
    attack_type: str = Field(..., description="判定类型: xss/sqli/path_traversal/sensitive_path/normal")
    is_attack: bool
    attack_prob: float = Field(
        ..., description="★ 属于攻击的概率 0~1（做阈值门控请用这个字段）")
    ai_points: int = Field(..., description="★ AI 建议累加分值 0~25，直接累加进风险分")
    confidence: float = Field(
        ..., description="模型对判定类别的置信度。这是「判定确定性」，"
                         "不代表「攻击可能性」。例如样本含 <script> 标签被规则命中时"
                         "该值为 0.99，但若模型认为正常，is_attack 仍为 false")
    high_risk: bool = Field(..., description="是否达到高危阈值(>=40)")
    reasons: List[str] = Field(default_factory=list, description="可读的中文判定理由")
    signals: List[DetectSignalItem] = Field(default_factory=list,
                                            description="命中明细，含位置与证据")
    model_label: str
    # 回显溯源信息，便于蜜罐侧对账
    source: str = ""
    ip: str = ""
    session_id: str = ""


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_path: str


class ModelInfoResponse(BaseModel):
    version: str
    trained_at: str
    labels: List[str]
    model_path: str


def _mask_ip(ip: str) -> str:
    """对 IP 进行脱敏处理（如 1.2.3.4 -> 1.2.3.*）"""
    if not ip:
        return ""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.*"
    return ip


def _log_event(text: str, result: dict, source: str = "unknown", ip: str = "", extra: Optional[dict] = None):
    """把预测事件追加写入日志，已做脱敏和轮转"""
    try:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": source or "unknown",
            "ip": _mask_ip(ip),
            "text": text,
            "extra": extra or {},
            "label": result.get("label"),
            "is_attack": result.get("is_attack"),
            "confidence": result.get("confidence"),
            "reason": result.get("reason"),
        }
        logger.info(json.dumps(record, ensure_ascii=False))
    except Exception as e:
        print(f"[WARN] 写入蜜罐日志失败: {e}")


@app.get("/health", response_model=HealthResponse, tags=["蜜罐对接"],
         summary="健康检查")
def health():
    """健康检查：真正尝试加载模型"""
    try:
        get_model()
        return {"status": "ok", "model_loaded": True, "model_path": str(MODEL_PATH)}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"模型未就绪: {e}")


@app.get("/model/info", response_model=ModelInfoResponse, tags=["蜜罐对接"],
         summary="模型版本信息")
def model_info():
    """返回模型真实元数据"""
    if os.path.exists(MODEL_META_PATH):
        with open(MODEL_META_PATH, "r", encoding="utf-8") as f:
            meta = json.load(f)
        return {
            "version": meta.get("version", "unknown"),
            "trained_at": meta.get("trained_at", "unknown"),
            "labels": meta.get("labels", ALL_LABELS),
            "model_path": str(MODEL_PATH),
        }
    return {
        "version": "v1",
        "trained_at": "unknown",
        "labels": ALL_LABELS,
        "model_path": str(MODEL_PATH),
    }


@app.post("/predict", response_model=PredictResponse, tags=["【内部调试】"],
          summary="单条文本检测（内部调试）")
def predict(req: PredictRequest):
    """
    ⚠️ **内部调试接口，蜜罐侧请勿使用。**

    这是早期的级联接口：规则命中即短路返回，`confidence` 固定为 0.99，
    不适合作为蜜罐的加权特征。请改用 `POST /api/v1/detect`。
    """
    try:
        result = predict_xss(req.text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"预测失败: {e}")

    _log_event(req.text, result, req.source or "unknown", req.ip or "", req.extra)
    return PredictResponse(**result)


@app.post("/predict/signal", response_model=SignalResponse, tags=["【内部调试】"],
          summary="单条文本信号明细（内部调试）", deprecated=True)
def predict_signal_api(req: PredictRequest):
    """
    ⚠️ **内部调试接口，蜜罐侧请勿使用。**（已标记为 deprecated）

    返回 `rule_points` / `effective_rule_points` / `fusion_score` 等本模块内部
    的加权累加细节。这些字段会随内部实现调整而变化，不属于对外契约。

    蜜罐对接请统一使用 `POST /api/v1/detect`，它只暴露稳定的对外字段。
    """
    try:
        result = predict_signal(req.text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"信号计算失败: {e}")

    _log_event(req.text, {
        "label": result["attack_type"],
        "is_attack": result["is_attack"],
        "confidence": result["confidence"],
        "reason": result["reason"],
    }, req.source or "unknown", req.ip or "", {
        **(req.extra or {}),
        "ai_points": result["ai_points"],
        "fusion_score": result["fusion_score"],
        "high_risk": result["high_risk"],
    })
    return SignalResponse(**result)


@app.post("/predict/batch", response_model=BatchPredictResponse,
          tags=["【内部调试】"], summary="批量文本检测（内部调试）", deprecated=True)
def predict_batch(req: BatchPredictRequest):
    """
    ⚠️ **内部调试接口，蜜罐侧请勿使用。**

    用于离线批量跑样本（如评估数据集）。蜜罐实时对接请用
    `POST /api/v1/detect`——它接受完整的 HTTP 请求结构，判定更准确。
    """
    if not req.texts:
        raise HTTPException(status_code=400, detail="texts 不能为空")
    if len(req.texts) > 1000:
        raise HTTPException(status_code=400, detail="单次最多 1000 条")

    results = []
    attack_count = 0

    for text in req.texts:
        try:
            r = predict_xss(text)
            results.append(PredictResponse(**r))
            if r["is_attack"]:
                attack_count += 1
        except Exception as e:
            r = {
                "label": "error",
                "is_attack": False,
                "confidence": 0.0,
                "reason": f"处理失败: {e}",
            }
            results.append(PredictResponse(**r))

        _log_event(text, r, req.source or "unknown", req.ip or "")

    return BatchPredictResponse(results=results, total=len(results), attack_count=attack_count)


@app.post("/api/v1/detect", response_model=DetectResponse,
          tags=["蜜罐对接"], summary="★ 请求级检测（蜜罐对接主接口）")
def detect(req: DetectRequest):
    """
    **蜜罐对接只需使用本接口。**

    提交采集到的 HTTP 请求各部分，返回攻击类型判定、建议分值（`ai_points`）
    与可读的中文理由（`reasons`）。蜜罐侧把 `ai_points` 累加进自己的风险分即可。

    **最少只需传 `path`（或 `url`）**：
    ```json
    {"path": "/search", "query": "id=1 and 1=1"}
    ```

    **推荐分别传 `path` / `query` / `body`**：本接口会按字段分段检测，
    并在 `signals[].field` 中指出命中位置（如 `query.id`），
    比把整条 URL 当一团文本检测更准确。
    """
    # 归一出入参：只给 url 时自动拆分 path 与 query
    path = req.path or ""
    query = req.query or ""
    url = req.url or ""
    if url and not path:
        path, _, qs = url.partition("?")
        if not query:
            query = qs
    if not path and not query and not req.body:
        raise HTTPException(status_code=400,
                            detail="至少需要提供 url、path 或 body 之一")

    try:
        result = detect_request(
            path=path,
            query=query,
            body=req.body or "",
            headers=req.headers or {},
            user_agent=req.user_agent or "",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"检测失败: {e}")

    # 记录事件（脱敏）
    _log_event(
        f"{path}?{query}" if query else path or (req.body or ""),
        {
            "label": result["attack_type"],
            "is_attack": result["is_attack"],
            "confidence": result["confidence"],
            "reason": " | ".join(result["reasons"]) or "未命中",
        },
        req.source or "web", req.ip or "",
        {**(req.extra or {}), "session_id": req.session_id,
         "method": req.method, "ai_points": result["ai_points"],
         "high_risk": result["high_risk"]},
    )

    return DetectResponse(
        attack_type=result["attack_type"],
        is_attack=result["is_attack"],
        attack_prob=result["attack_prob"],
        ai_points=result["ai_points"],
        confidence=result["confidence"],
        high_risk=result["high_risk"],
        reasons=result["reasons"],
        signals=[DetectSignalItem(**s) for s in result["signals"]],
        model_label=result["model_label"],
        source=req.source or "",
        ip=_mask_ip(req.ip or ""),
        session_id=req.session_id or "",
    )


@app.get("/")
def root():
    return {
        "service": "Attack Detector AI Service",
        "version": "2.0.0",
        "docs": "/docs",
        # ★ 对蜜罐组而言，只需要关心这一个接口
        "main_endpoint": {
            "path": "/api/v1/detect",
            "method": "POST",
            "note": "蜜罐对接只用这个接口",
            "minimal_request": {"path": "/search", "query": "id=1 and 1=1"},
        },
        "auxiliary": {
            "/health": "健康检查（建议启动前探活）",
            "/model/info": "查看模型版本与支持的类别",
        },
        "internal_debug_only": {
            "note": "以下接口为【内部调试】，蜜罐侧无需了解其内部字段",
            "endpoints": ["/predict", "/predict/signal", "/predict/batch"],
        },
    }