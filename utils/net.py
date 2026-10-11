# -*- coding: utf-8 -*-
"""
网络相关工具
"""
import ipaddress


def is_private_ip(ip: str) -> bool:
    if not ip:
        return True
    try:
        obj = ipaddress.ip_address(ip.strip())
    except ValueError:
        return True
    return (
        obj.is_private
        or obj.is_loopback
        or obj.is_reserved
        or obj.is_multicast
        or obj.is_unspecified
    )
