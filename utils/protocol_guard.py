# -*- coding: utf-8 -*-
"""
多协议蜜罐公共防护组件
======================

为 MySQL / Redis / FTP / Telnet 等新增协议蜜罐提供与 SSH 蜜罐一致的治理能力：
1. 连接限流（全局并发 / 单 IP 并发 / worker 信号量）
2. 认证爆破检测与指数封禁（60s 窗口 12 次失败 -> 600s 起指数退避，上限 7200s）
3. 预认证端口扫描检测（10s 窗口 18 连接）
4. 统一事件上报（2.5s 去重 -> log_event -> 双阈值告警 alert_event）

各协议接入层只负责协议仿真与特征评分，不直接操作数据库/告警细节，
对应方案中的“接入层独立、治理层复用”。
"""
import hashlib
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Tuple

from db.event_logs import log_event
from utils.alerting import (
    alert_event,
    ALERT_RISK_THRESHOLD,
    ALERT_HIGH_THRESHOLD,
    ALERT_CRITICAL_THRESHOLD,
)

# 双阈值分层（复用 utils.alerting 配置，与 Web/SSH 端保持一致）
# >= 风险线：可疑事件写入统一事件表并触发告警；>= 高危/严重线：级别上调
SCORE_SUSPICIOUS = ALERT_RISK_THRESHOLD   # 默认 40：medium + 告警线
SCORE_HIGH_RISK = ALERT_HIGH_THRESHOLD    # 默认 60：high
SCORE_CRITICAL = ALERT_CRITICAL_THRESHOLD # 默认 80：critical
# 事件分级映射（按威胁分）
SEVERITY_LOW = 'low'
SEVERITY_MEDIUM = 'medium'
SEVERITY_HIGH = 'high'
SEVERITY_CRITICAL = 'critical'

# 会话 ID 采用 1 小时时间窗（与 Web 端 generate_session_id 口径一致）
_SESSION_WINDOW_SECONDS = 3600
_EVENT_DEDUP_WINDOW = 2.5


def severity_from_score(score: int) -> str:
    """威胁分 -> 严重级别：<40 low / 40-59 medium / 60-79 high / >=80 critical（阈值跟随 honeypot.ini）。"""
    if score >= SCORE_CRITICAL:
        return SEVERITY_CRITICAL
    if score >= SCORE_HIGH_RISK:
        return SEVERITY_HIGH
    if score >= SCORE_SUSPICIOUS:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def make_protocol_session_id(protocol: str, ip: str) -> str:
    """
    生成 {protocol}-{16位md5} 格式会话标识。
    md5 内容为 IP + 1 小时时间窗，同一来源一小时内聚合为同一会话，供攻击链关联。
    """
    window = int(time.time()) // _SESSION_WINDOW_SECONDS
    raw = f"{protocol}:{ip}:{window}".encode('utf-8')
    return f"{protocol}-{hashlib.md5(raw).hexdigest()[:16]}"


class ConnectionGuard:
    """
    单协议实例的内存态防护状态机（每协议一个实例，互不影响）。

    状态表：
      _active_total            : 全局活跃连接数
      _active_per_ip[ip]       : 单 IP 活跃连接数
      _fails[ip]               : 认证失败时间戳队列
      _ban_until[ip]           : 封禁到期时间戳
      _ban_level[ip]           : 封禁等级（指数退避）
      _preauth[ip]             : 预认证连接时间戳队列（扫描检测）
      _scan_cooldown[ip]       : 扫描事件告警冷却
    """

    def __init__(self,
                 protocol: str,
                 max_workers: int = 80,
                 max_active_total: int = 60,
                 max_active_per_ip: int = 10,
                 fail_window_seconds: int = 60,
                 fail_threshold: int = 12,
                 ban_base_seconds: int = 600,
                 ban_max_seconds: int = 7200,
                 scan_window_seconds: int = 10,
                 scan_threshold: int = 18,
                 scan_cooldown_seconds: int = 120):
        self.protocol = protocol
        self.max_workers = max(1, int(max_workers))
        self.max_active_total = max(1, int(max_active_total))
        self.max_active_per_ip = max(1, int(max_active_per_ip))
        self.fail_window_seconds = fail_window_seconds
        self.fail_threshold = fail_threshold
        self.ban_base_seconds = ban_base_seconds
        self.ban_max_seconds = ban_max_seconds
        self.scan_window_seconds = scan_window_seconds
        self.scan_threshold = scan_threshold
        self.scan_cooldown_seconds = scan_cooldown_seconds

        self._sem = threading.BoundedSemaphore(self.max_workers)
        self._lock = threading.RLock()
        self._active_total = 0
        self._active_per_ip: Dict[str, int] = defaultdict(int)
        self._fails: Dict[str, Deque[float]] = defaultdict(deque)
        self._ban_until: Dict[str, float] = {}
        self._ban_level: Dict[str, int] = defaultdict(int)
        self._preauth: Dict[str, Deque[float]] = defaultdict(deque)
        self._scan_cooldown: Dict[str, float] = {}

    # ---------------- worker 信号量 ----------------
    def acquire_worker(self, timeout: float = 1.0) -> bool:
        try:
            return self._sem.acquire(blocking=True, timeout=timeout)
        except Exception:
            return False

    def release_worker(self) -> None:
        try:
            self._sem.release()
        except ValueError:
            pass

    # ---------------- 封禁状态 ----------------
    def ban_remaining(self, ip: str) -> int:
        with self._lock:
            until = self._ban_until.get(ip, 0.0)
            return max(0, int(until - time.time())) if until else 0

    def record_auth_success(self, ip: str) -> None:
        """登录成功：清失败队列，封禁等级衰减一级。"""
        with self._lock:
            self._fails.pop(ip, None)
            if self._ban_level.get(ip, 0) > 0:
                self._ban_level[ip] -= 1

    def record_auth_failure(self, ip: str) -> int:
        """
        记录一次认证失败。
        60s 滑窗内累计 >=12 次 -> 封禁 600 * 2^(level-1)，上限 7200s。
        返回本次封禁秒数（0 表示未触发封禁）。
        """
        now = time.time()
        with self._lock:
            q = self._fails[ip]
            q.append(now)
            while q and now - q[0] > self.fail_window_seconds:
                q.popleft()
            if len(q) < self.fail_threshold:
                return 0
            level = self._ban_level[ip] + 1
            self._ban_level[ip] = level
            ban_seconds = min(self.ban_base_seconds * (2 ** (level - 1)), self.ban_max_seconds)
            self._ban_until[ip] = now + ban_seconds
            q.clear()  # 进入封禁后清空计数，避免刚解封立刻二次封禁
            return ban_seconds

    # ---------------- 连接准入 ----------------
    def admit(self, ip: str) -> Tuple[bool, str]:
        """
        连接准入检查。
        返回 (是否放行, 原因)。原因取值：ok / banned / global_full / ip_full。
        注意：即便拒绝，协议层仍可先发送真实 banner 再断开（反识别），由调用方决定。
        """
        with self._lock:
            if self.ban_remaining(ip) > 0:
                return False, 'banned'
            if self._active_total >= self.max_active_total:
                return False, 'global_full'
            if self._active_per_ip[ip] >= self.max_active_per_ip:
                return False, 'ip_full'
            self._active_total += 1
            self._active_per_ip[ip] += 1
            return True, 'ok'

    def release(self, ip: str) -> None:
        with self._lock:
            if self._active_total > 0:
                self._active_total -= 1
            if self._active_per_ip.get(ip, 0) > 0:
                self._active_per_ip[ip] -= 1
                if self._active_per_ip[ip] <= 0:
                    self._active_per_ip.pop(ip, None)
            if self._active_per_ip.get(ip, 0) == 0 and ip not in self._fails and ip not in self._ban_until:
                self._preauth.pop(ip, None)
                self._scan_cooldown.pop(ip, None)

    # ---------------- 扫描检测 ----------------
    def record_preauth_connection(self, ip: str) -> Optional[dict]:
        """
        每个新 TCP 连接（认证前）记一个时间戳。
        10s 内达到 18 连接判定为端口扫描，120s 冷却避免刷屏。
        返回 None 或事件描述字典。
        """
        now = time.time()
        with self._lock:
            q = self._preauth[ip]
            q.append(now)
            while q and now - q[0] > self.scan_window_seconds:
                q.popleft()
            if len(q) < self.scan_threshold:
                return None
            last_alert = self._scan_cooldown.get(ip, 0.0)
            if now - last_alert < self.scan_cooldown_seconds:
                return None
            self._scan_cooldown[ip] = now
            return {
                'count': len(q),
                'window_seconds': self.scan_window_seconds,
                'threshold': self.scan_threshold,
            }


class ProtocolReporter:
    """
    统一事件上报器：去重 -> log_event -> 双阈值企业微信告警。

    用法：
        reporter.event('db_query', ip, score=45, payload='SELECT ...',
                       tags=['mysql','sql_injection'])
    """

    def __init__(self, protocol: str, logger=None):
        self.protocol = protocol
        self.session_id = __import__("uuid").uuid4().hex
        self.logger = logger
        self._lock = threading.Lock()
        self._last_sent: Dict[str, float] = {}

    @staticmethod
    def _dedup_key(event_type: str, ip: str, payload: str) -> str:
        norm = ' '.join(str(payload or '').lower().split())[:160]
        return f"{event_type}|{ip}|{norm}"

    def _is_duplicate(self, key: str, window: float) -> bool:
        now = time.time()
        with self._lock:
            last = self._last_sent.get(key, 0.0)
            if now - last < window:
                return True
            self._last_sent[key] = now
            # 顺带清理过期项，防止内存膨胀
            if len(self._last_sent) > 2000:
                expired = [k for k, ts in self._last_sent.items() if now - ts > 3600]
                for k in expired:
                    self._last_sent.pop(k, None)
            return False

    def event(self,
              event_type: str,
              src_ip: str,
              score: int = 0,
              severity: str = '',
              payload: str = '',
              tags=None,
              extra: Optional[dict] = None,
              session_id: str = '',
              force_alert: bool = False,
              dedup_window: float = _EVENT_DEDUP_WINDOW) -> None:
        """
        记录一个协议事件。

        :param event_type: 事件类型，如 db_auth_success / redis_unauthorized
        :param src_ip: 来源 IP
        :param score: 威胁分（决定 severity 与是否告警）
        :param severity: 显式指定级别（留空则按分数映射）
        :param force_alert: 强制告警（用于 LOAD DATA LOCAL 等单项即高危的命令）
        """
        tags = list(tags or [])
        if self.protocol not in tags:
            tags.insert(0, self.protocol)
        key = self._dedup_key(event_type, src_ip, payload)
        if not force_alert and self._is_duplicate(key, dedup_window):
            return
        sev = severity or severity_from_score(score)
        sid = session_id or self.session_id
        safe_extra = dict(extra or {})
        safe_extra.setdefault('threat_score', int(score))
        safe_extra.setdefault('protocol', self.protocol)
        try:
            log_event(
                source=self.protocol,
                severity=sev,
                event_type=event_type,
                src_ip=src_ip,
                session_id=sid,
                tags=tags,
                payload=payload,
                extra=safe_extra,
            )
        except Exception as exc:
            if self.logger:
                self.logger.error(f"[{self.protocol}] 事件写入失败: {exc}")
        # 告警线：分数达到风险线（默认 40）或显式强制；级别由 alert_event 按分数自行映射
        if force_alert or score >= SCORE_SUSPICIOUS:
            try:
                alert_event(
                    title=f"[{self.protocol.upper()}蜜罐] {event_type}",
                    src_ip=src_ip,
                    summary=payload[:500],
                    score=score,
                    event_type=event_type,
                    tags=tags,
                )
            except Exception as exc:
                if self.logger:
                    self.logger.error(f"[{self.protocol}] 告警发送失败: {exc}")
