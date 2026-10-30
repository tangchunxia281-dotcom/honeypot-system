# -*- coding: utf-8 -*-
"""
MySQL 协议仿真处理器（纯 Python，无第三方依赖）
=================================================

伪装 MySQL 8.0.36 服务端，实现：
1. HandshakeV10 握手与 mysql_native_password（SHA1 scramble）认证
2. COM_QUERY 语义评分：
   LOAD DATA LOCAL +30 / INTO OUTFILE +25 / UNION +22 / 时间盲注 +20
   mysql.user +18 / 布尔注入与报错注入 +15~18
3. 伪造结果集（show databases / information_schema / mysql.user / version() 等）
4. 所有事件经 utils.protocol_guard 统一上报，不直接操作数据库

仅用于合法授权的教学、演示和防御研究。
"""
import hashlib
import os
import socket
import struct

# ------------------------------------------------------------
# 协议常量
# ------------------------------------------------------------
SERVER_VERSION = '8.0.36'
SERVER_STATUS_AUTOCOMMIT = 0x0002

# Capability flags
CLIENT_LONG_PASSWORD = 0x00000001
CLIENT_LONG_FLAG = 0x00000004
CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_TRANSACTIONS = 0x00002000
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_MULTI_STATEMENTS = 0x00010000
CLIENT_MULTI_RESULTS = 0x00020000
CLIENT_PLUGIN_AUTH = 0x00080000
CLIENT_CONNECT_ATTRS = 0x00100000
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
CLIENT_DEPRECATE_EOF = 0x01000000
CLIENT_SESSION_TRACK = 0x00800000

SERVER_CAPABILITIES = (
    CLIENT_LONG_PASSWORD | CLIENT_LONG_FLAG | CLIENT_CONNECT_WITH_DB
    | CLIENT_PROTOCOL_41 | CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION
    | CLIENT_MULTI_STATEMENTS | CLIENT_MULTI_RESULTS | CLIENT_PLUGIN_AUTH
    | CLIENT_CONNECT_ATTRS | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
    | CLIENT_DEPRECATE_EOF | CLIENT_SESSION_TRACK
)

# 列类型
MYSQL_TYPE_LONG = 0x03
MYSQL_TYPE_VAR_STRING = 0xfd

# COM_*
COM_QUIT = 0x01
COM_INIT_DB = 0x02
COM_QUERY = 0x03
COM_PING = 0x0e
COM_CHANGE_USER = 0x11

# 诱饵弱口令（启动时输出 CRED 行）；同一用户可配置多个弱口令
DECOY_ACCOUNTS = [
    ('root', '123456'),
    ('root', 'root'),
    ('admin', 'admin'),
    ('test', 'test'),
]
_PASSWORD_MAP = {}
for _u, _p in DECOY_ACCOUNTS:
    _PASSWORD_MAP.setdefault(_u, []).append(_p)

_FAKE_DATABASES = ['information_schema', 'mysql', 'performance_schema', 'sys', 'honeypot_db']
_FAKE_TABLES = ['users', 'member_account', 'admin_log', 'order_info', 'payment_record']
_BAIT_VARIABLES = {
    'version': '8.0.36',
    'version_comment': 'MySQL Community Server - GPL',
    'version_compile_os': 'Linux',
    'version_compile_machine': 'x86_64',
    'hostname': 'db-server-01',
    'datadir': '/var/lib/mysql/',
    'basedir': '/usr/',
    'max_allowed_packet': '67108864',
}


# ------------------------------------------------------------
# 基础编解码
# ------------------------------------------------------------
def _lenenc_int(n: int) -> bytes:
    if n < 0xFB:
        return bytes([n])
    if n <= 0xFFFF:
        return b'\xfc' + struct.pack('<H', n)
    if n <= 0xFFFFFF:
        return b'\xfd' + struct.pack('<I', n)[:3]
    return b'\xfe' + struct.pack('<Q', n)


def _read_lenenc_int(buf: bytes, pos: int):
    first = buf[pos]
    if first < 0xFB:
        return first, pos + 1
    if first == 0xFC:
        return struct.unpack_from('<H', buf, pos + 1)[0], pos + 3
    if first == 0xFD:
        return struct.unpack_from('<I', buf[pos + 1:pos + 4] + b'\x00')[0], pos + 4
    return struct.unpack_from('<Q', buf, pos + 1)[0], pos + 9


def _lenenc_str(s: bytes) -> bytes:
    return _lenenc_int(len(s)) + s


def _nul_str(s: str) -> bytes:
    return s.encode('utf-8') + b'\x00'


def _packet(payload: bytes, seq: int) -> bytes:
    return struct.pack('<I', len(payload))[:3] + bytes([seq & 0xFF]) + payload


def _read_packet(sock: socket.socket, max_size: int = 32 * 1024 * 1024):
    """读取一个 MySQL 包，返回 (seq, payload)；连接关闭返回 (None, None)。"""
    header = _recvn(sock, 4)
    if not header or len(header) < 4:
        return None, None
    length = header[0] | (header[1] << 8) | (header[2] << 16)
    seq = header[3]
    if length > max_size:
        return None, None
    payload = _recvn(sock, length)
    if payload is None or len(payload) < length:
        return None, None
    return seq, payload


def _recvn(sock: socket.socket, n: int):
    chunks = []
    remaining = n
    while remaining > 0:
        try:
            chunk = sock.recv(remaining)
        except OSError:
            return None
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


# ------------------------------------------------------------
# 服务端报文构造
# ------------------------------------------------------------
def _ok_packet(seq: int = 2, info: bytes = b'') -> bytes:
    payload = b'\x00' + _lenenc_int(0) + _lenenc_int(0)
    payload += struct.pack('<H', SERVER_STATUS_AUTOCOMMIT)
    payload += struct.pack('<H', 0)  # warnings
    if info:
        payload += info
    return _packet(payload, seq)


def _err_packet(message: str, code: int = 1064, sqlstate: str = '42000', seq: int = 2) -> bytes:
    payload = b'\xff' + struct.pack('<H', code)
    payload += b'#' + sqlstate.encode('ascii')
    payload += message.encode('utf-8', errors='replace')
    return _packet(payload, seq)


def _access_denied(seq: int = 2) -> bytes:
    return _err_packet(
        "Access denied for user (using password: YES)",
        code=1045, sqlstate='28000', seq=seq,
    )


def _column_def(name: str, col_type: int = MYSQL_TYPE_VAR_STRING,
                col_len: int = 255, seq: int = 0) -> bytes:
    payload = b''
    payload += _lenenc_str(b'def')          # catalog
    payload += _lenenc_str(b'')             # schema
    payload += _lenenc_str(b'')             # table
    payload += _lenenc_str(b'')             # org_table
    payload += _lenenc_str(name.encode('utf-8'))
    payload += _lenenc_str(b'')             # org_name
    payload += b'\x0c'                      # 后续固定字段长度
    payload += struct.pack('<H', 33)        # charset utf8_general_ci
    payload += struct.pack('<I', col_len)
    payload += bytes([col_type])
    payload += struct.pack('<H', 0)         # flags
    payload += bytes([0])                   # decimals
    payload += b'\x00\x00'                  # filler
    return _packet(payload, seq)


def _eof_packet(seq: int) -> bytes:
    """经典 EOF_Packet：0xfe + warning_count(2) + server_status(2)。"""
    return _packet(b'\xfe' + struct.pack('<H', 0)
                   + struct.pack('<H', SERVER_STATUS_AUTOCOMMIT), seq)


def _resultset(columns, rows, seq_start: int = 1) -> bytes:
    """
    构造一个完整文本结果集（经典 EOF 形态，pymysql/mysql-connector 均兼容）。
    columns: [(列名, 类型)]；rows: [[str, ...], ...]
    报文序号必须连续，客户端（pymysql）会严格校验，错乱即按断连处理。
    """
    out = _packet(_lenenc_int(len(columns)), seq_start)
    seq = seq_start + 1
    for name, col_type in columns:
        out += _column_def(name, col_type, seq=seq)
        seq += 1
    out += _eof_packet(seq)   # 列定义结束 EOF
    seq += 1
    for row in rows:
        payload = b''
        for cell in row:
            text = '' if cell is None else str(cell)
            payload += _lenenc_str(text.encode('utf-8', errors='replace'))
        out += _packet(payload, seq)
        seq += 1
    out += _eof_packet(seq)   # 结果集结束 EOF
    return out


def _build_handshake(connection_id: int, scramble: bytes) -> bytes:
    payload = b'\x0a'
    payload += _nul_str(SERVER_VERSION)
    payload += struct.pack('<I', connection_id)
    payload += scramble[:8] + b'\x00'
    payload += struct.pack('<H', SERVER_CAPABILITIES & 0xFFFF)
    payload += bytes([33])                                      # charset
    payload += struct.pack('<H', SERVER_STATUS_AUTOCOMMIT)     # status
    payload += struct.pack('<H', SERVER_CAPABILITIES >> 16)
    payload += bytes([21])                                      # auth plugin data 总长度
    payload += b'\x00' * 10                                    # reserved
    payload += scramble[8:] + b'\x00'                          # 12 + NUL
    payload += _nul_str('mysql_native_password')
    return _packet(payload, 0)


# ------------------------------------------------------------
# HandshakeResponse41 解析
# ------------------------------------------------------------
def _parse_handshake_response(data: bytes):
    try:
        cap = struct.unpack_from('<I', data, 0)[0]
        pos = 4 + 4 + 1 + 23
        end = data.index(b'\x00', pos)
        user = data[pos:end].decode('utf-8', errors='replace')
        pos = end + 1

        if cap & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
            auth_len, pos = _read_lenenc_int(data, pos)
        elif cap & CLIENT_SECURE_CONNECTION:
            auth_len = data[pos]
            pos += 1
        else:
            end = data.index(b'\x00', pos)
            auth_len = end - pos
        auth_response = data[pos:pos + auth_len]
        pos += auth_len

        database = ''
        if cap & CLIENT_CONNECT_WITH_DB and pos < len(data):
            end = data.find(b'\x00', pos)
            if end >= 0:
                database = data[pos:end].decode('utf-8', errors='replace')
        return {'capabilities': cap, 'user': user, 'auth': auth_response, 'database': database}
    except Exception:
        return None


def _native_password_valid(password: str, scramble: bytes, token: bytes) -> bool:
    """
    mysql_native_password 校验：
        token = SHA1(password) XOR SHA1(scramble + SHA1(SHA1(password)))
    """
    if not password or len(token) != 20:
        return False
    stage1 = hashlib.sha1(password.encode('utf-8')).digest()
    stage2 = hashlib.sha1(stage1).digest()
    digest = hashlib.sha1(scramble + stage2).digest()
    expected = bytes(a ^ b for a, b in zip(stage1, digest))
    return expected == token


# ------------------------------------------------------------
# SQL 评分
# ------------------------------------------------------------
def score_query(sql: str):
    """返回 (score, tags, 命中说明列表)。"""
    s = ' '.join(sql.lower().split())
    score = 0
    tags = ['mysql']
    hits = []

    def add(points, label, *extra_tags):
        nonlocal score
        if label not in hits:
            score += points
            hits.append(label)
            tags.extend(t for t in extra_tags if t)

    if 'load data local' in s:
        add(30, 'load_data_local', 'load_data_local', 'file_read', 'attack_technique:T1539')
    if 'into outfile' in s or 'into dumpfile' in s:
        add(25, 'into_outfile', 'into_outfile', 'webshell_write', 'attack_technique:T1505')
    if 'union select' in s or 'union distinct' in s or 'union all select' in s:
        add(22, 'union_select', 'sql_injection', 'union_select', 'attack_technique:T1190')
    if 'sleep(' in s or 'benchmark(' in s or 'waitfor delay' in s or 'pg_sleep(' in s:
        add(20, 'time_based_blind', 'sql_injection', 'time_based_blind', 'attack_technique:T1190')
    if 'mysql.user' in s:
        add(18, 'mysql_user', 'sensitive_table', 'attack_technique:T1213')
    if 'or 1=1' in s or "or '1'='1" in s or 'or "1"="1' in s or 'or 1 = 1' in s:
        add(18, 'boolean_or', 'sql_injection', 'boolean_based', 'attack_technique:T1190')
    if 'information_schema' in s:
        add(15, 'information_schema', 'sensitive_table', 'attack_technique:T1213')
    if 'extractvalue' in s or 'updatexml' in s:
        add(15, 'error_based', 'sql_injection', 'error_based', 'attack_technique:T1190')
    if 'concat(' in s and ('0x' in s or 'char(' in s or 'ascii(' in s):
        add(12, 'concat_encoding', 'sql_injection')
    if re_match_stacked(s):
        add(10, 'stacked_query', 'stacked_query')
    return min(score, 100), dedup_tags(tags), hits


def re_match_stacked(s: str) -> bool:
    # 粗粒度：语句中出现分号后再接写操作关键字
    for kw in (';select', ';insert', ';update', ';delete', ';drop', ';alter', ';create'):
        if kw in s:
            return True
    return False


def dedup_tags(tags):
    out = []
    for t in tags:
        if t and t not in out:
            out.append(t)
    return out


# ------------------------------------------------------------
# 伪造查询响应
# ------------------------------------------------------------
def _query_response(sql: str, database: str) -> bytes:
    s = sql.strip().rstrip(';').strip()
    low = s.lower()

    # LOAD DATA LOCAL：服务端可主动索取客户端文件
    if low.startswith('load data local'):
        return _err_packet(code=1148, message='LOCAL INFILE disabled in virtual honeypot', seq=1)

    if low.startswith(('insert', 'update', 'delete', 'create', 'drop', 'alter',
                       'grant', 'revoke', 'rename', 'truncate', 'replace')):
        return _ok_packet(seq=1)
    if low.startswith(('set ', 'use ', 'lock ', 'unlock', 'commit', 'rollback', 'begin', 'start transaction')):
        return _ok_packet(seq=1)
    if low.startswith('kill '):
        return _ok_packet(seq=1)

    if low.startswith('show databases'):
        return _resultset([('Database', MYSQL_TYPE_VAR_STRING)],
                          [[db] for db in _FAKE_DATABASES])
    if low.startswith(('show tables', 'show full tables')):
        col = f'Tables_in_{database or "honeypot_db"}'
        return _resultset([(col, MYSQL_TYPE_VAR_STRING)],
                          [[t] for t in _FAKE_TABLES])
    if low.startswith(('show variables', 'show global variables', 'show session variables')):
        rows = [['version', _BAIT_VARIABLES['version']],
                ['version_comment', _BAIT_VARIABLES['version_comment']],
                ['version_compile_os', _BAIT_VARIABLES['version_compile_os']],
                ['max_allowed_packet', _BAIT_VARIABLES['max_allowed_packet']]]
        return _resultset([('Variable_name', MYSQL_TYPE_VAR_STRING),
                           ('Value', MYSQL_TYPE_VAR_STRING)], rows)
    if low.startswith('show status'):
        return _resultset([('Variable_name', MYSQL_TYPE_VAR_STRING),
                           ('Value', MYSQL_TYPE_VAR_STRING)],
                          [['Uptime', '128736'], ['Threads_connected', '1']])
    if low.startswith(('show grants', 'show create')):
        return _resultset([('Grants/Statement', MYSQL_TYPE_VAR_STRING)],
                          [["GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost'"]])
    if low.startswith(('describe ', 'desc ', 'explain ', 'show columns', 'show index')):
        return _resultset([('Field', MYSQL_TYPE_VAR_STRING), ('Type', MYSQL_TYPE_VAR_STRING),
                           ('Null', MYSQL_TYPE_VAR_STRING), ('Key', MYSQL_TYPE_VAR_STRING)],
                          [['id', 'int(11) unsigned', 'NO', 'PRI'],
                           ['username', 'varchar(64)', 'NO', 'UNI'],
                           ['password', 'varchar(128)', 'NO', '']])

    # mysql.user 敏感表
    if 'mysql.user' in low:
        return _resultset(
            [('Host', MYSQL_TYPE_VAR_STRING), ('User', MYSQL_TYPE_VAR_STRING),
             ('authentication_string', MYSQL_TYPE_VAR_STRING)],
            [['localhost', 'root', '*THISISANAUTHSTRING000000000000000000'],
             ['%', 'backup', '*THISISANAUTHSTRING000000000000000001']])
    if 'information_schema.tables' in low:
        return _resultset([('TABLE_SCHEMA', MYSQL_TYPE_VAR_STRING),
                           ('TABLE_NAME', MYSQL_TYPE_VAR_STRING)],
                          [['honeypot_db', t] for t in _FAKE_TABLES]
                          + [['mysql', 'user']])
    if 'information_schema.columns' in low:
        return _resultset([('TABLE_NAME', MYSQL_TYPE_VAR_STRING),
                           ('COLUMN_NAME', MYSQL_TYPE_VAR_STRING)],
                          [['users', 'id'], ['users', 'username'], ['users', 'password']])
    if 'information_schema.schemata' in low:
        return _resultset([('SCHEMA_NAME', MYSQL_TYPE_VAR_STRING)],
                          [[db] for db in _FAKE_DATABASES])

    # select 函数 / 变量
    if low.startswith(('select', 'with', 'table ', 'values ')):
        if any(k in low for k in ('version(', '@@version')):
            return _resultset([('version()', MYSQL_TYPE_VAR_STRING)],
                              [[_BAIT_VARIABLES['version']]])
        if any(k in low for k in ('user(', 'system_user(', 'session_user(', 'current_user(')):
            return _resultset([('user()', MYSQL_TYPE_VAR_STRING)], [['root@localhost']])
        if 'database(' in low or 'schema(' in low:
            return _resultset([('database()', MYSQL_TYPE_VAR_STRING)],
                              [[database or 'information_schema']])
        if '@@' in low:
            value = '1'
            for var, val in _BAIT_VARIABLES.items():
                if f'@@{var}' in low:
                    value = val
                    break
            col = s[s.find('@@'):s.find('@@') + 32] if '@@' in s else 'result'
            return _resultset([(col, MYSQL_TYPE_VAR_STRING)], [[value]])
        # 其它 SELECT：返回单行占位结果
        return _resultset([('result', MYSQL_TYPE_VAR_STRING)], [['1']])

    # 未识别语句：回 OK，避免直接断开暴露蜜罐特征
    return _ok_packet(seq=1)


# ------------------------------------------------------------
# 连接处理
# ------------------------------------------------------------
class MySQLHoneypot:
    """单条 MySQL 连接的协议处理器。guard/reporter 由 server 注入。"""

    def __init__(self, guard, reporter, logger):
        self.guard = guard
        self.reporter = reporter
        self.logger = logger

    def handle(self, conn: socket.socket, client_ip: str):
        conn.settimeout(30)
        database = ''
        authenticated = False
        try:
            scramble = os.urandom(20)
            conn_id = abs(hash((client_ip, os.urandom(4)))) & 0x7FFFFFFF
            conn.sendall(_build_handshake(conn_id, scramble))

            seq, payload = _read_packet(conn)
            if payload is None:
                return
            parsed = _parse_handshake_response(payload)
            if not parsed:
                conn.sendall(_access_denied(seq=2))
                return
            user = parsed['user'] or 'unknown'
            database = parsed['database'] or ''

            matched_pw = next(
                (pw for pw in _PASSWORD_MAP.get(user, ())
                 if _native_password_valid(pw, scramble, parsed['auth'])),
                None,
            )
            if matched_pw is not None:
                authenticated = True
                self.guard.record_auth_success(client_ip)
                conn.sendall(_ok_packet(seq=2))
                self.reporter.event(
                    'db_auth_success', client_ip, score=60,
                    payload=f"MySQL 登录成功 user={user} db={database or '(none)'}",
                    tags=['mysql', 'valid_accounts', 'attack_technique:T1078'],
                )
            else:
                conn.sendall(_access_denied(seq=2))
                ban_seconds = self.guard.record_auth_failure(client_ip)
                self.reporter.event(
                    'db_auth_attempt', client_ip, score=40,
                    payload=f"MySQL 认证失败 user={user}",
                    tags=['mysql', 'bruteforce', 'attack_technique:T1110'],
                )
                if ban_seconds:
                    self.reporter.event(
                        'db_bruteforce_ban', client_ip, score=60,
                        payload=f"MySQL 爆破触发封禁 {ban_seconds}s user={user}",
                        tags=['mysql', 'bruteforce', 'rate_ban'],
                    )
                return

            # 命令阶段
            while True:
                seq, payload = _read_packet(conn)
                if payload is None:
                    return
                if not payload:
                    continue
                cmd = payload[0]
                body = payload[1:]

                if cmd == COM_QUIT:
                    return
                if cmd == COM_PING:
                    conn.sendall(_ok_packet(seq=seq + 1))
                    continue
                if cmd == COM_INIT_DB:
                    database = body.decode('utf-8', errors='replace')
                    conn.sendall(_ok_packet(seq=seq + 1))
                    continue
                if cmd == COM_CHANGE_USER:
                    # 简化处理：重新要求认证，直接拒绝
                    conn.sendall(_access_denied(seq=seq + 1))
                    continue
                if cmd != COM_QUERY:
                    conn.sendall(_ok_packet(seq=seq + 1))
                    continue

                sql = body.decode('utf-8', errors='replace')
                score, tags, hits = score_query(sql)
                response = _query_response(sql, database)

                # LOAD DATA LOCAL：读取客户端回传的“文件内容”作为攻击证据
                if len(response) > 4 and response[4] == 0xFB:
                    conn.sendall(response)
                    file_packets = []
                    try:
                        for _ in range(16):  # 最多收集 16 个包，防止无限读取
                            fseq, fdata = _read_packet(conn)
                            if fdata is None or len(fdata) == 0:
                                break
                            file_packets.append(fdata)
                    except Exception:
                        pass
                    leaked = b''.join(file_packets)
                    conn.sendall(_ok_packet(seq=4))
                    self.reporter.event(
                        'db_query', client_ip, score=max(score, 40),
                        payload=f"LOAD DATA LOCAL 利用，客户端回传 {len(leaked)} 字节，"
                                f"预览: {leaked.decode('utf-8', errors='replace')!r}; SQL: {sql[:256]}",
                        tags=tags,
                        force_alert=True,
                    )
                    continue

                conn.sendall(response)
                if hits:
                    # LOAD DATA LOCAL / INTO OUTFILE 属单项即高危的文件类命令
                    dangerous = {'load_data_local', 'into_outfile'}
                    force = bool(dangerous.intersection(hits))
                    self.reporter.event(
                        'db_query', client_ip, score=max(score, 40) if force else score,
                        payload=f"命中 {','.join(hits)}; SQL: {sql[:512]}",
                        tags=tags,
                        force_alert=force or score >= 60,
                    )
        except (OSError, ConnectionResetError, BrokenPipeError):
            return
        except Exception as exc:
            if self.logger:
                self.logger.debug(f"[mysql] 连接处理异常 {client_ip}: {exc}")
        finally:
            if authenticated:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            try:
                conn.close()
            except OSError:
                pass
