# -*- coding: utf-8 -*-
"""
工业级日志系统
支持控制台输出、文件输出、按大小轮转
"""
import os
import sys
import logging
import subprocess
import getpass
from logging.handlers import RotatingFileHandler
from typing import Optional

# 导入配置
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app_config import Config

# 日志器缓存，避免重复创建
_loggers = {}


def _harden_permissions(path: str, is_dir: bool) -> None:
    """POSIX limits modes; Windows preserves inherited service-account access.

    Do not remove inherited ACLs based on USERNAME: a scheduled task or restricted
    process may run with a different identity and lose access to its own files.
    Windows deployment privacy is inherited from the user's private project folder.
    """
    if not path:
        return
    try:
        if os.name == 'posix':
            os.chmod(path, 0o700 if is_dir else 0o600)
            return
        if os.name == 'nt':
            result = subprocess.run(['whoami','/user','/fo','csv','/nh'],capture_output=True,text=True,check=False)
            import re
            match = re.search(r'S-1-5-[0-9-]+', result.stdout or '')
            if not match:
                return
            user = '*'+match.group(0)
            if is_dir:
                cmd = ['icacls', path, '/inheritance:e', '/grant:r', f'{user}:(OI)(CI)F']
            else:
                cmd = ['icacls', path, '/inheritance:e', '/grant:r', f'{user}:(F)']
            subprocess.run(cmd, capture_output=True, check=False)
    except Exception:
        # 权限收敛失败不应阻塞主业务
        pass


class SecureRotatingFileHandler(RotatingFileHandler):
    """轮转日志文件并在创建/轮转后收敛文件权限。"""
    def __init__(self, filename, maxBytes, backupCount, encoding='utf-8'):
        super().__init__(filename=filename, maxBytes=maxBytes, backupCount=backupCount, encoding=encoding)
        self._secure_files()

    def doRollover(self):
        super().doRollover()
        self._secure_files()

    def _secure_files(self):
        _harden_permissions(self.baseFilename, is_dir=False)
        for i in range(1, int(self.backupCount or 0) + 1):
            backup = f"{self.baseFilename}.{i}"
            if os.path.exists(backup):
                _harden_permissions(backup, is_dir=False)


def ensure_log_dir():
    """确保日志目录存在"""
    if not os.path.exists(Config.LOG_DIR):
        os.makedirs(Config.LOG_DIR, exist_ok=True)
        print(f"[Logger] 日志目录已创建: {Config.LOG_DIR}")
    _harden_permissions(Config.LOG_DIR, is_dir=True)


def setup_logger(
    name: str,
    log_file: str,
    level: Optional[str] = None,
    console_output: bool = True
) -> logging.Logger:
    """
    配置并返回日志器

    Args:
        name: 日志器名称（模块标识）
        log_file: 日志文件名（相对于 logs 目录）
        level: 日志级别（DEBUG/INFO/WARNING/ERROR/CRITICAL）
        console_output: 是否同时输出到控制台

    Returns:
        配置好的 Logger 实例

    Example:
        logger = setup_logger('ssh', 'ssh.log')
        logger.info('SSH 蜜罐已启动')
    """
    # 如果已创建过，直接返回
    if name in _loggers:
        return _loggers[name]

    # 确保日志目录存在
    ensure_log_dir()

    # 创建日志器
    logger = logging.getLogger(name)

    # 设置日志级别
    log_level = getattr(logging, (level or Config.LOG_LEVEL).upper(), logging.INFO)
    logger.setLevel(log_level)

    # 防止日志重复
    if logger.handlers:
        return logger

    # 日志格式器
    formatter = logging.Formatter(
        fmt=Config.LOG_FORMAT,
        datefmt=Config.LOG_DATE_FORMAT
    )

    # 文件处理器（按大小轮转）
    # 某些环境下日志目录/文件可能被占用或权限受限，避免因此导致服务启动失败。
    log_path = os.path.join(Config.LOG_DIR, log_file)
    try:
        file_handler = SecureRotatingFileHandler(
            filename=log_path,
            maxBytes=Config.LOG_MAX_BYTES,
            backupCount=Config.LOG_BACKUP_COUNT,
            encoding='utf-8'
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except (PermissionError, OSError) as e:
        # 仅降级文件输出，保留控制台输出，不影响主流程可用性。
        try:
            print(f"[Logger] 文件日志不可用，已降级为仅控制台输出: {log_path} ({e})")
        except Exception:
            pass

    # 控制台处理器
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # 禁止向上传播，避免重复输出
    logger.propagate = False

    # 缓存日志器
    _loggers[name] = logger

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    获取已存在的日志器，如不存在则创建默认配置

    Args:
        name: 日志器名称

    Returns:
        Logger 实例
    """
    if name in _loggers:
        return _loggers[name]

    # 默认日志文件为 {name}.log
    return setup_logger(name, f'{name}.log')


# ============================================
# 预配置的模块日志器
# ============================================

def get_ssh_logger() -> logging.Logger:
    """获取 SSH 蜜罐日志器"""
    return setup_logger('ssh', Config.LOG_FILE_SSH)


def get_web_logger() -> logging.Logger:
    """获取 Web 蜜罐日志器"""
    return setup_logger('web', Config.LOG_FILE_WEB)


def get_dashboard_logger() -> logging.Logger:
    """获取管理端日志器（仅控制台输出，不写文件）"""
    logger = logging.getLogger('dashboard')
    logger.setLevel(logging.ERROR)  # 只记录错误级别

    # 只添加控制台处理器，不写文件
    if not logger.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.ERROR)
        formatter = logging.Formatter(
            fmt=Config.LOG_FORMAT,
            datefmt=Config.LOG_DATE_FORMAT
        )
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        logger.propagate = False

    return logger


def get_db_logger() -> logging.Logger:
    """获取数据库模块日志器（仅控制台输出，不写文件）"""
    logger = logging.getLogger('database')
    logger.setLevel(logging.CRITICAL)  # 只记录严重错误

    # 只添加控制台处理器，不写文件
    if not logger.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.CRITICAL)
        formatter = logging.Formatter(
            fmt=Config.LOG_FORMAT,
            datefmt=Config.LOG_DATE_FORMAT
        )
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        logger.propagate = False

    return logger
