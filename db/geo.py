# -*- coding: utf-8 -*-
"""
GeoIP 缓存与在线解析
"""
from utils.ip_location import fetch_geoip_external, normalize_geo_fields
from utils.net import is_private_ip
from .demo_data import DEMO_IP_MAP
from .connection import get_connection, USE_MYSQL, logger


def has_geo_cache(ip: str) -> bool:
    key = str(ip or '').strip()
    if not key:
        return False
    conn = get_connection()
    try:
        cursor = conn.cursor()
        placeholder = '%s' if USE_MYSQL else '?'
        cursor.execute(f"SELECT 1 FROM geo_ip WHERE ip = {placeholder} LIMIT 1", (key,))
        row = cursor.fetchone()
        return bool(row)
    except Exception:
        return False
    finally:
        conn.close()


def get_geo_info(ip: str, allow_online: bool = True) -> dict:
    if is_private_ip(ip):
        return {'country': '内网', 'province': '本地', 'city': '本地', 'latitude': 0, 'longitude': 0, 'isp': '内网'}
    if ip in DEMO_IP_MAP:
        d = DEMO_IP_MAP[ip]
        return {'country': d['country'], 'province': d['province'], 'city': d['city'], 'latitude': d['lat'], 'longitude': d['long'], 'isp': d['isp']}

    conn = get_connection()
    try:
        cursor = conn.cursor()
        placeholder = '%s' if USE_MYSQL else '?'
        cursor.execute(f"SELECT * FROM geo_ip WHERE ip = {placeholder}", (ip,))
        row = cursor.fetchone()
        if row:
            if USE_MYSQL:
                row_info = dict(row or {})
            else:
                cols = [d[0] for d in cursor.description]
                row_info = dict(zip(cols, row))
            country_v, region_v, city_v = normalize_geo_fields(
                row_info.get('country'),
                row_info.get('province'),
                row_info.get('city'),
            )
            row_info['country'] = country_v or '未知'
            row_info['province'] = region_v or '未知'
            row_info['city'] = city_v or '未知'
            # 历史缓存若为无效坐标(0,0)，尝试在线刷新，避免地图长期无点
            try:
                lat0 = float(row_info.get('latitude') or 0)
                lon0 = float(row_info.get('longitude') or 0)
            except Exception:
                lat0, lon0 = 0.0, 0.0
            if not (lat0 == 0 and lon0 == 0):
                return row_info
            logger.debug(f"geo_ip 存在无效坐标，触发刷新: {ip}")
            if not allow_online:
                return row_info

        default = {'country': '未知', 'province': '未知', 'city': '未知', 'latitude': 0, 'longitude': 0, 'isp': '未知'}
        if not allow_online:
            return default.copy()
        info = default.copy()

        online = fetch_geoip_external(ip)
        if online and online.get('ip'):
            country_v, region_v, city_v = normalize_geo_fields(
                online.get('country'),
                online.get('region'),
                online.get('city'),
            )
            info = {
                'country': country_v or '未知',
                'province': region_v or '未知',
                'city': city_v or '未知',
                'latitude': float(online.get('latitude') or 0),
                'longitude': float(online.get('longitude') or 0),
                'isp': online.get('isp') or '未知'
            }

        cols_sql = "ip, country, province, city, latitude, longitude, isp"
        vals_sql = f"{placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}"
        if USE_MYSQL:
            cursor.execute(
                f"""INSERT INTO geo_ip ({cols_sql})
                    VALUES ({vals_sql})
                    ON DUPLICATE KEY UPDATE
                        country=VALUES(country),
                        province=VALUES(province),
                        city=VALUES(city),
                        latitude=VALUES(latitude),
                        longitude=VALUES(longitude),
                        isp=VALUES(isp),
                        update_time=CURRENT_TIMESTAMP""",
                (ip, info['country'], info['province'], info['city'], info['latitude'], info['longitude'], info['isp'])
            )
        else:
            cursor.execute(
                f"INSERT OR REPLACE INTO geo_ip ({cols_sql}) VALUES ({vals_sql})",
                (ip, info['country'], info['province'], info['city'], info['latitude'], info['longitude'], info['isp'])
            )
        conn.commit()
        return info
    except Exception as e:
        logger.debug(f"get_geo_info 失败({ip}): {e}")
        return {'country': '未知', 'province': '未知', 'city': '未知', 'latitude': 0, 'longitude': 0, 'isp': '未知'}
    finally:
        conn.close()


__all__ = ['get_geo_info', 'has_geo_cache']
