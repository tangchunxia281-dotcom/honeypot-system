# -*- coding: utf-8 -*-
"""
环境/根配置读取工具
统一整数/浮点/布尔/字符串读取与边界收敛逻辑，减少重复实现。

实际配置读取集中在 app_config.py：环境变量 > 根目录 honeypot.ini > 默认值。
"""
from app_config import env_bool, env_csv, env_float, env_int, env_path, env_str

__all__ = ['env_bool', 'env_csv', 'env_float', 'env_int', 'env_path', 'env_str']
