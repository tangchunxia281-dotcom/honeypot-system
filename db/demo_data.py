# -*- coding: utf-8 -*-
"""
模拟数据与演示用 IP 位置库
"""
from datetime import datetime, timedelta

DEMO_IP_MAP = {
    '220.181.38.148': {'country': '中国', 'province': '北京', 'city': '北京', 'lat': 39.9042, 'long': 116.4074, 'isp': 'China Telecom'},
    '112.85.120.5':    {'country': '中国', 'province': '香港', 'city': '香港', 'lat': 22.3193, 'long': 114.1694, 'isp': 'HK Telecom'},
    '27.112.124.155': {'country': '日本', 'province': '东京都', 'city': '东京', 'lat': 35.6895, 'long': 139.6917, 'isp': 'Softbank'},
    '118.38.140.11':   {'country': '韩国', 'province': '首尔', 'city': '首尔', 'lat': 37.5665, 'long': 126.9780, 'isp': 'Korea Telecom'},
    '45.83.123.88':    {'country': '美国', 'province': '加利福尼亚', 'city': '洛杉矶', 'lat': 34.0522, 'long': -118.2437, 'isp': 'Cloud Host'},
    '45.33.32.156':    {'country': '美国', 'province': '加利福尼亚', 'city': '洛杉矶', 'lat': 34.0522, 'long': -118.2437, 'isp': 'Linode'},
    '103.235.46.39':   {'country': '中国', 'province': '上海', 'city': '上海', 'lat': 31.2304, 'long': 121.4737, 'isp': 'China Telecom'},
    '185.199.108.153': {'country': '荷兰', 'province': '北荷兰省', 'city': '阿姆斯特丹', 'lat': 52.3676, 'long': 4.9041, 'isp': 'CDN/Edge'},
    '91.198.174.192':  {'country': '荷兰', 'province': '北荷兰省', 'city': '阿姆斯特丹', 'lat': 52.3676, 'long': 4.9041, 'isp': 'Wikimedia'},
    '66.249.66.1':     {'country': '美国', 'province': '加利福尼亚', 'city': '山景城', 'lat': 37.3861, 'long': -122.0839, 'isp': 'Googlebot'},
    '144.76.25.11':    {'country': '德国', 'province': '柏林', 'city': '柏林', 'lat': 52.5200, 'long': 13.4050, 'isp': 'Hetzner'},
    '185.193.92.12':   {'country': '法国', 'province': '巴黎', 'city': '巴黎', 'lat': 48.8566, 'long': 2.3522, 'isp': 'OVH'},
    '82.1.1.1':        {'country': '英国', 'province': '伦敦', 'city': '伦敦', 'lat': 51.5074, 'long': -0.1278, 'isp': 'Virgin Media'},
    '203.117.132.1':   {'country': '新加坡', 'province': '新加坡', 'city': '新加坡', 'lat': 1.3521, 'long': 103.8198, 'isp': 'Singtel'},
    '1.1.1.1':         {'country': '澳大利亚', 'province': '维多利亚', 'city': '墨尔本', 'lat': -37.8136, 'long': 144.9631, 'isp': 'Cloudflare'},
    '5.9.158.0':       {'country': '俄罗斯', 'province': '莫斯科', 'city': '莫斯科', 'lat': 55.7558, 'long': 37.6173, 'isp': 'Yandex'},
    '192.168.1.100':   {'country': '内网', 'province': '本地', 'city': '本地', 'lat': 0, 'long': 0, 'isp': 'Intranet'},
    '10.0.0.50':       {'country': '内网', 'province': '本地', 'city': '本地', 'lat': 0, 'long': 0, 'isp': 'Intranet'}
}


def get_consistent_mock_data():
    now = datetime.now()
    mock_logs = []

    event_samples = [
        ('45.33.32.156', 'Web', '敏感文件探测: GET /.env / .git/config', 38),
        ('103.235.46.39', 'Web', '服务探测: GET /actuator/health /actuator/env', 21),
        ('185.199.108.153', 'Web', 'GraphQL 探测: POST /graphql (introspection)', 12),
        ('91.198.174.192', 'Web', '组件漏洞探测: GET /vendor/phpunit/.../eval-stdin.php', 9),
        ('66.249.66.1', 'Web', '爬虫/枚举: GET /wp-json/wp/v2/users?per_page=100', 7),
        ('220.181.38.148', 'Web', "SQLi 探测: GET /search?q=' or 1=1--", 6),
        ('112.85.120.5', 'SSH', 'SSH 弱口令尝试: user=root', 6),
        ('118.38.140.11', 'SSH', 'SSH 命令探测: whoami / uname -a', 5)
    ]

    for i, item in enumerate(event_samples):
        ip, type_, payload = item[0], item[1], item[2]
        count = int(item[3]) if len(item) > 3 else max(5, 50 - i * 5)
        info = DEMO_IP_MAP.get(ip, {})

        mock_logs.append({
            'id': 10 - i,
            'src_ip': ip,
            'activity_type': type_,
            'payload': payload,
            'location': f"{info.get('country','未知')}/{info.get('city','未知')}",
            'latitude': info.get('lat', 0),
            'longitude': info.get('long', 0),
            'create_time': (now - timedelta(seconds=i * 5)).strftime('%Y-%m-%d %H:%M:%S'),
            'count': count
        })
    return mock_logs


def build_mock_event_activity_logs(limit: int = 50):
    now = datetime.now()
    base = get_consistent_mock_data()
    logs = []
    for i, item in enumerate(base):
        if i >= limit:
            break
        logs.append({
            'id': 1000 - i,
            'src_ip': item.get('src_ip'),
            'activity_type': item.get('activity_type'),
            'payload': item.get('payload'),
            'location': item.get('location'),
            'latitude': item.get('latitude', 0),
            'longitude': item.get('longitude', 0),
            'create_time': (now - timedelta(seconds=i * 6)).strftime('%Y-%m-%d %H:%M:%S')
        })
    return logs


def build_mock_suspicious_requests():
    return [
        {'src_ip': '45.33.32.156', 'method': 'GET', 'path': '/.env', 'query_string': '', 'threat_score': 45},
        {'src_ip': '185.199.108.153', 'method': 'POST', 'path': '/graphql', 'query_string': 'query={__schema}', 'threat_score': 32},
        {'src_ip': '103.235.46.39', 'method': 'GET', 'path': '/actuator/env', 'query_string': '', 'threat_score': 28},
        {'src_ip': '66.249.66.1', 'method': 'GET', 'path': '/wp-json/wp/v2/users', 'query_string': 'per_page=100', 'threat_score': 22},
    ]


def build_mock_session_analysis():
    return [
        {'src_ip': '45.33.32.156', 'path_sequence': '/login|/admin|/admin/upload', 'path_steps': ['/login', '/admin', '/admin/upload'], 'path_steps_full': ['/login', '/admin', '/admin/upload'], 'request_count': 24, 'threat_level': 'high'},
        {'src_ip': '103.235.46.39', 'path_sequence': '/actuator/health|/actuator/env|/actuator/beans', 'path_steps': ['/actuator/health', '/actuator/env', '/actuator/beans'], 'path_steps_full': ['/actuator/health', '/actuator/env', '/actuator/beans'], 'request_count': 17, 'threat_level': 'medium'},
        {'src_ip': '112.85.120.5', 'path_sequence': '/login|/admin|/admin/audit/log', 'path_steps': ['/login', '/admin', '/admin/audit/log'], 'path_steps_full': ['/login', '/admin', '/admin/audit/log'], 'request_count': 9, 'threat_level': 'low'},
    ]

