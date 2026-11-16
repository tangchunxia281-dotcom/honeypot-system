# -*- coding: utf-8 -*-
"""
系统信息获取模块
"""
import psutil
import socket
import logging
import os

from utils.ip_location import get_server_location
from utils.ai_client import get_ai_metrics

logger = logging.getLogger(__name__)

def get_system_status():
    """获取系统负载"""
    try:
        # Use a slightly longer sampling window to reduce jitter in dashboard display.
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk_path = os.path.abspath(os.sep)
        disk = psutil.disk_usage(disk_path)
        return {
            'cpu_percent': cpu,
            'memory_percent': mem.percent,
            'memory_used_gb': round(mem.used / (1024**3), 1),
            'memory_total_gb': round(mem.total / (1024**3), 1),
            'disk_percent': disk.percent,
            'ai': get_ai_metrics()
        }
    except Exception as e:
        logger.debug(f"获取系统状态失败: {e}")
        return {
            'cpu_percent': 0,
            'memory_percent': 0,
            'memory_used_gb': 0,
            'memory_total_gb': 0,
            'disk_percent': 0,
            'ai': get_ai_metrics()
        }

def get_server_info(include_system: bool = True):
    """API 聚合"""
    loc = get_server_location()
    data = {
        'server': {
            'public_ip': loc.get('public_ip'),
            'hostname': socket.gethostname()
        },
        'location': loc
    }
    if include_system:
        data['system'] = get_system_status()
    return data
