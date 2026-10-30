# -*- coding: utf-8 -*-
"""
GeoIP 在线解析（统一出口）
本机点：bilibili
攻击点：ip-api
"""
import json
import logging
import os
import socket
import time
import ipaddress
import requests
from threading import Lock
from env_utils import env_int as _env_int, env_float as _env_float, env_str as _env_str

logger = logging.getLogger(__name__)

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_STATE_DIR = os.path.join(_BASE_DIR, 'dashboard', 'state')
_PUBLIC_IP_CACHE_PATH = os.path.join(_STATE_DIR, 'server_public_ip.json')

_GEOIP_TIMEOUT = _env_float('GEOIP_TIMEOUT', 2.5, 0.1, 30.0)
_SERVER_LOCATION_CACHE_TTL = _env_int('SERVER_LOCATION_CACHE_TTL', 300, 10, 86400)
# 落盘缓存的最大有效期（秒），超时后会主动刷新
_SERVER_PUBLIC_IP_CACHE_MAX_AGE = _env_int('SERVER_PUBLIC_IP_CACHE_MAX_AGE', 86400, 60, 31536000)
_SERVER_PUBLIC_IP = _env_str('SERVER_PUBLIC_IP', '')

_server_location_lock = Lock()
_server_location_cache = {'ts': 0.0, 'data': None}

_COUNTRY_ALIASES = {
    'China': '中国',
    'People\'s Republic of China': '中国',
    'People’s Republic of China': '中国',
    '中华人民共和国': '中国',
    'PRC': '中国',
    'Republic of China': '中国',
    'ROC': '中国',
    '中華民國': '中国',
    '中华民国': '中国',
    'Taiwan': '中国',
    'Taiwan, Province of China': '中国',
    'Taiwan Province of China': '中国',
    '中国台湾': '中国',
    '中国台湾省': '中国',
    'United Kingdom': '英国',
    'UK': '英国',
    'Great Britain': '英国',
    'Britain': '英国',
    'England': '英国',
    'United States': '美国',
    'United States of America': '美国',
    'USA': '美国',
}

_REGION_ALIASES = {
    'Taiwan': '台湾',
    'Taiwan Province': '台湾',
    'Taiwan Province of China': '台湾',
    '中國台灣省': '台湾',
    '中国台湾省': '台湾',
    '臺灣省': '台湾',
}

_CITY_ALIASES = {
    'Taipei': '台北',
    'Taipei City': '台北',
    '臺北': '台北',
    '臺北市': '台北',
    '台北市': '台北',
    'London': '伦敦',
}

_TAIWAN_CITY_SET = {
    '台北', '新北', '桃园', '台中', '台南', '高雄',
    '基隆', '新竹', '嘉义', '宜兰', '苗栗', '彰化',
    '南投', '云林', '屏东', '台东', '花莲', '澎湖',
    '金门', '连江'
}


def _normalize_public_ip(ip: str):
    if not ip:
        return None
    try:
        obj = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    if (obj.is_private or obj.is_loopback or obj.is_reserved
            or obj.is_multicast or obj.is_unspecified):
        return None
    return str(obj)


def _clean_geo_text(value) -> str:
    text = str(value or '').strip()
    if not text:
        return ''
    text = text.replace('（', '(').replace('）', ')')
    text = text.replace('臺', '台').replace('　', ' ')
    text = ' '.join(text.split())
    return text.strip()


def _lookup_geo_alias(text: str, mapping: dict) -> str:
    value = _clean_geo_text(text)
    if not value:
        return ''
    if value in mapping:
        return mapping[value]
    lower = value.lower()
    for key, alias in mapping.items():
        if value == key or lower == str(key).lower():
            return alias
    return value


def normalize_country_name(country) -> str:
    value = _lookup_geo_alias(country, _COUNTRY_ALIASES)
    if not value:
        return ''
    if value in ('内网', '本地'):
        return '内网'
    return value


def normalize_region_name(region) -> str:
    value = _lookup_geo_alias(region, _REGION_ALIASES)
    if not value:
        return ''
    if value.endswith('省') and len(value) <= 4:
        value = value[:-1]
    return value


def normalize_city_name(city) -> str:
    value = _lookup_geo_alias(city, _CITY_ALIASES)
    if not value:
        return ''
    if value.endswith('市') and len(value) <= 6:
        value = value[:-1]
    return value


def normalize_geo_fields(country='', region='', city=''):
    raw_country = _clean_geo_text(country)
    raw_region = _clean_geo_text(region)
    raw_city = _clean_geo_text(city)
    country_v = normalize_country_name(country)
    region_v = normalize_region_name(region)
    city_v = normalize_city_name(city)
    if country_v == '内网' or city_v == '本地':
        return ('内网', '本地', '本地')
    raw_country_lower = raw_country.lower()
    raw_region_lower = raw_region.lower()
    taiwan_context = (
        raw_country in ('中国台湾', '中国台湾省', '中华民国', '中華民國')
        or raw_region in ('台湾', '台湾省', '臺灣', '臺灣省')
        or raw_country_lower in (
            'taiwan', 'taiwan, province of china', 'taiwan province of china',
            'republic of china', 'roc'
        )
        or raw_region_lower in ('taiwan', 'taiwan province', 'taiwan province of china')
        or city_v in _TAIWAN_CITY_SET
    )
    if country_v == '中国':
        if region_v in ('中国', '中国台湾'):
            region_v = ''
        if city_v in ('中国', '中国台湾'):
            city_v = ''
        if taiwan_context and not region_v:
            region_v = '台湾'
    if city_v and city_v == country_v:
        city_v = ''
    if city_v and region_v and city_v == region_v:
        city_v = ''
    return (country_v, region_v, city_v)


def build_geo_location(country='', region='', city='') -> str:
    country_v, region_v, city_v = normalize_geo_fields(country, region, city)
    if country_v == '内网':
        return '内网/本地'
    country_label = country_v
    if country_v == '中国' and (region_v == '台湾' or city_v in _TAIWAN_CITY_SET):
        country_label = '中国台湾'
    if country_label and city_v and city_v not in ('未知', country_label, country_v, region_v):
        return f"{country_label}/{city_v}"
    if country_label and region_v and region_v not in ('未知', country_label, country_v):
        return f"{country_label}/{region_v}"
    return country_label or region_v or city_v or '未知'


def _load_cached_server_location():
    if not _PUBLIC_IP_CACHE_PATH:
        return None
    try:
        if os.path.exists(_PUBLIC_IP_CACHE_PATH):
            with open(_PUBLIC_IP_CACHE_PATH, 'r', encoding='utf-8') as f:
                data = json.load(f) or {}
            ip = _normalize_public_ip((data.get('ip') or '').strip())
            loc = data.get('location') or {}
            return {
                'ip': ip,
                'ts': int(data.get('ts') or 0),
                'country': loc.get('country'),
                'region': loc.get('region'),
                'city': loc.get('city'),
                'latitude': loc.get('latitude'),
                'longitude': loc.get('longitude'),
                'isp': loc.get('isp')
            }
    except Exception as e:
        logger.debug(f"读取公网位置缓存失败: {e}")
    return None


def _is_cached_server_location_fresh(info: dict) -> bool:
    if not info:
        return False
    ts = int(info.get('ts') or 0)
    if ts <= 0:
        return False
    return (time.time() - ts) <= _SERVER_PUBLIC_IP_CACHE_MAX_AGE


def _save_cached_server_location(info: dict):
    if not info:
        return
    ip = _normalize_public_ip(info.get('ip') or '')
    if not ip:
        return
    try:
        os.makedirs(os.path.dirname(_PUBLIC_IP_CACHE_PATH), exist_ok=True)
        payload = {
            'ip': ip,
            'ts': int(time.time()),
            'location': {
                'country': info.get('country') or '',
                'region': info.get('region') or '',
                'city': info.get('city') or '',
                'latitude': info.get('latitude'),
                'longitude': info.get('longitude'),
                'isp': info.get('isp') or ''
            }
        }
        with open(_PUBLIC_IP_CACHE_PATH, 'w', encoding='utf-8') as f:
            json.dump(payload, f, ensure_ascii=False)
    except Exception as e:
        logger.debug(f"写入公网位置缓存失败: {e}")


_cached_server_location = _load_cached_server_location()
if _cached_server_location and _is_cached_server_location_fresh(_cached_server_location) and not _SERVER_PUBLIC_IP:
    _SERVER_PUBLIC_IP = _cached_server_location.get('ip') or ''


def _fetch_public_ip_and_city_bilibili():
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'application/json'
        }
        res = requests.get('https://api.bilibili.com/x/web-interface/zone', timeout=_GEOIP_TIMEOUT, headers=headers)
        if res.status_code != 200:
            return (None, {})
        try:
            body = res.json()
        except Exception as e:
            logger.debug(f"bilibili 响应解析失败: {e}")
            return (None, {})
        if body.get('code') not in (0, '0', None):
            logger.debug(f"bilibili 返回异常 code: {body.get('code')}")
            return (None, {})
        payload = body.get('data', {}) or {}
        ip = (payload.get('addr') or '').strip()
        city = (payload.get('city') or '').replace('市', '').strip()
        try:
            lat = float(payload.get('latitude')) if payload.get('latitude') is not None else None
        except Exception:
            lat = None
        try:
            lon = float(payload.get('longitude')) if payload.get('longitude') is not None else None
        except Exception:
            lon = None
        info = {
            'ip': _normalize_public_ip(ip),
            'country': payload.get('country') or '',
            'region': payload.get('province') or '',
            'city': city,
            'latitude': lat,
            'longitude': lon,
            'isp': payload.get('isp') or '',
            'timezone': ''
        }
        return (info.get('ip'), info)
    except Exception as e:
        logger.debug(f"bilibili 获取公网位置失败: {e}")
        return (None, {})


def _build_location_str(country, province, city):
    return build_geo_location(country, province, city)


def get_server_location():
    """本机点：仅使用 bilibili"""
    now = time.monotonic()
    with _server_location_lock:
        cached = _server_location_cache.get('data')
        ts = _server_location_cache.get('ts', 0.0)
        if cached and (now - ts) < _SERVER_LOCATION_CACHE_TTL:
            return cached

    env_public_ip = _normalize_public_ip(_SERVER_PUBLIC_IP)
    public_ip = env_public_ip
    cache_file_exists = os.path.exists(_PUBLIC_IP_CACHE_PATH)
    cached_location = _load_cached_server_location() if cache_file_exists else None
    if cached_location and cached_location.get('ip'):
        # 如果显式配置了 SERVER_PUBLIC_IP，且与缓存不一致，则忽略文件缓存
        if env_public_ip and cached_location.get('ip') != env_public_ip:
            cached_location = None
        # 文件缓存超期后也不直接使用，避免公网 IP 变更后长期错误
        elif not _is_cached_server_location_fresh(cached_location):
            cached_location = None

    if cached_location and cached_location.get('ip'):
        public_ip = cached_location.get('ip')
        country_name = cached_location.get('country') or '未知'
        region_name = cached_location.get('region') or ''
        city_name = (cached_location.get('city') or '').replace('市', '')
        location_str = _build_location_str(country_name, region_name, city_name)
        lat = cached_location.get('latitude')
        lon = cached_location.get('longitude')
        if lat is None or lon is None:
            lat, lon = 0.0, 0.0
            location_str = location_str or '未知'
        result = {
            'public_ip': public_ip,
            'country': country_name,
            'city': location_str,
            'isp': cached_location.get('isp') or '',
            'latitude': lat,
            'longitude': lon,
            'source': 'cache'
        }
        with _server_location_lock:
            _server_location_cache['data'] = result
            _server_location_cache['ts'] = now
        return result

    bilibili_info = None
    _, bilibili_info = _fetch_public_ip_and_city_bilibili()
    if bilibili_info and bilibili_info.get('ip'):
        public_ip = bilibili_info.get('ip')
        _save_cached_server_location(bilibili_info)

    if bilibili_info:
        country_name = bilibili_info.get('country') or '未知'
        region_name = bilibili_info.get('region') or ''
        city_name = (bilibili_info.get('city') or '').replace('市', '')
        location_str = _build_location_str(country_name, region_name, city_name)
        lat = bilibili_info.get('latitude')
        lon = bilibili_info.get('longitude')
        if lat is None or lon is None:
            lat, lon = 0.0, 0.0
            location_str = location_str or '未知'
        result = {
            'public_ip': public_ip or bilibili_info.get('ip') or '',
            'country': country_name,
            'city': location_str,
            'isp': bilibili_info.get('isp') or '',
            'latitude': lat,
            'longitude': lon,
            'source': 'bilibili'
        }
        with _server_location_lock:
            _server_location_cache['data'] = result
            _server_location_cache['ts'] = now
        return result

    # bilibili 失败时，若显式配置了 SERVER_PUBLIC_IP，则基于该 IP 走一次 ip-api 定位
    if env_public_ip:
        ip_info = _fetch_geo_from_ip_api(env_public_ip) or {}
        country_name = ip_info.get('country') or '未知'
        region_name = ip_info.get('region') or ''
        city_name = (ip_info.get('city') or '').replace('市', '')
        result = {
            'public_ip': env_public_ip,
            'country': country_name,
            'city': _build_location_str(country_name, region_name, city_name),
            'isp': ip_info.get('isp') or '',
            'latitude': ip_info.get('latitude') or 0,
            'longitude': ip_info.get('longitude') or 0,
            'source': 'env'
        }
        with _server_location_lock:
            _server_location_cache['data'] = result
            _server_location_cache['ts'] = now
        return result

    local_ip = _get_local_ip()
    result = {
        'public_ip': local_ip,
        'country': '内网',
        'city': '内网',
        'isp': '内网',
        'latitude': 0,
        'longitude': 0,
        'source': 'local'
    }
    return result


def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('223.5.5.5', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        logger.debug(f"获取本机IP失败: {e}")
        return '127.0.0.1'


def get_ip_location(ip=None):
    """IP 地理定位：使用 ip-api"""
    return _fetch_geo_from_ip_api(ip)


def _fetch_geo_from_ip_api(ip=None):
    base = 'http://ip-api.com/json'
    path = f'/{ip}' if ip else ''
    fields = 'status,message,query,country,regionName,city,lat,lon,isp,timezone'
    url = f"{base}{path}?fields={fields}&lang=zh-CN"
    try:
        res = requests.get(url, timeout=_GEOIP_TIMEOUT)
        if res.status_code != 200:
            return None
        data = res.json()
        if data.get('status') != 'success':
            return None
        return {
            'ip': data.get('query'),
            'country': data.get('country'),
            'region': data.get('regionName'),
            'city': data.get('city'),
            'latitude': data.get('lat'),
            'longitude': data.get('lon'),
            'isp': data.get('isp'),
            'timezone': data.get('timezone')
        }
    except Exception:
        return None


def _fetch_geo_from_ipwhois(ip=None):
    """
    HTTPS 备选源（ipwho.is）
    返回结构与 _fetch_geo_from_ip_api 一致。
    """
    if not ip:
        return None
    url = f"https://ipwho.is/{ip}"
    try:
        res = requests.get(url, timeout=_GEOIP_TIMEOUT)
        if res.status_code != 200:
            return None
        data = res.json()
        # ipwho.is: success=true/false
        if not bool(data.get('success')):
            return None
        return {
            'ip': data.get('ip'),
            'country': data.get('country'),
            'region': data.get('region'),
            'city': data.get('city'),
            'latitude': data.get('latitude'),
            'longitude': data.get('longitude'),
            'isp': data.get('connection', {}).get('isp') if isinstance(data.get('connection'), dict) else None,
            'timezone': (data.get('timezone') or {}).get('id') if isinstance(data.get('timezone'), dict) else None,
        }
    except Exception:
        return None


def _fetch_geo_from_ipapi_co(ip=None):
    """
    HTTPS 备选源（ipapi.co）
    返回结构与 _fetch_geo_from_ip_api 一致。
    """
    if not ip:
        return None
    url = f"https://ipapi.co/{ip}/json/"
    try:
        res = requests.get(url, timeout=_GEOIP_TIMEOUT)
        if res.status_code != 200:
            return None
        data = res.json()
        # ipapi.co 在异常时包含 error/reason
        if data.get('error'):
            return None
        return {
            'ip': data.get('ip'),
            'country': data.get('country_name') or data.get('country'),
            'region': data.get('region'),
            'city': data.get('city'),
            'latitude': data.get('latitude'),
            'longitude': data.get('longitude'),
            'isp': data.get('org'),
            'timezone': data.get('timezone'),
        }
    except Exception:
        return None


def fetch_geoip_external(ip=None):
    """外部 GeoIP 查询入口（多源回退）"""
    if not ip:
        return None
    # 优先保留既有 ip-api 结果；失败后回退到 HTTPS 源
    return (
        _fetch_geo_from_ip_api(ip)
        or _fetch_geo_from_ipwhois(ip)
        or _fetch_geo_from_ipapi_co(ip)
    )
