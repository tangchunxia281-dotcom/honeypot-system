# -*- coding: utf-8 -*-
"""
Redis RESP2 协议仿真处理器（纯 Socket，无第三方依赖）
======================================================

伪装无密码 Redis 6.2.6：
1. 连接内首条命令即记录 redis_unauthorized（critical，未授权访问）
2. CONFIG SET dir/dbfilename、SLAVEOF、MODULE LOAD、FLUSHALL 等高危命令
   一律“仿真成功”并触发高危/严重告警（RCE 写文件、主从复制、恶意模块、数据破坏）
3. KEYS/GET 返回诱饵键值，INFO 等返回拟真服务器信息

仅用于合法授权的教学、演示和防御研究。
"""
import os
import socket
import time

REDIS_VERSION = '6.2.6'
_RUN_ID = os.urandom(20).hex()

# 诱饵键值（模拟内网敏感配置，诱导攻击者进一步利用）
_BAIT_KEYS = ['backup_db.sql', 'db_password', 'api_secret', 'access_key', 'session:admin']
_BAIT_VALUES = {
    'backup_db.sql': '2024-06-01 full backup, see /var/backups/backup_db.sql',
    'db_password': 'MySQL@Prod_2024!',
    'api_secret': 'eyJhbGciOiJIUzI1NiJ9.DECOY-DO-NOT-USE.signature',
    'access_key': 'AKIADECOYEXAMPLEKEY01',
    'session:admin': 'admin|10.0.12.10|superuser',
}

# 危险落盘路径特征（cron/ssh/webshell）
_DANGER_PATH_HINTS = ('cron', '/spool/', '/.ssh', '/etc/', 'authorized_keys',
                      '/var/www', '/www/', 'shell.php', '.so')


def _b(s) -> bytes:
    return s if isinstance(s, bytes) else str(s).encode('utf-8')


def encode_simple(msg) -> bytes:
    return b'+' + _b(msg) + b'\r\n'


def encode_error(msg) -> bytes:
    return b'-' + _b(msg) + b'\r\n'


def encode_integer(n: int) -> bytes:
    return b':' + str(int(n)).encode('ascii') + b'\r\n'


def encode_bulk(data) -> bytes:
    if data is None:
        return b'$-1\r\n'
    raw = _b(data)
    return b'$' + str(len(raw)).encode('ascii') + b'\r\n' + raw + b'\r\n'


def encode_array(items) -> bytes:
    if items is None:
        return b'*-1\r\n'
    out = b'*' + str(len(items)).encode('ascii') + b'\r\n'
    for item in items:
        if isinstance(item, list):
            out += encode_array(item)
        elif item is None:
            out += encode_bulk(None)
        elif isinstance(item, int):
            out += encode_integer(item)
        else:
            out += encode_bulk(item)
    return out


def _info_text(section: str = '') -> str:
    sec = (section or '').lower()
    lines = []
    if sec in ('', 'server', 'all', 'default'):
        lines += [
            '# Server',
            f'redis_version:{REDIS_VERSION}',
            'redis_git_sha1:00000000',
            'redis_build_id:0000000000000000',
            'redis_mode:standalone',
            'os:Linux 5.10.0-28-amd64 x86_64',
            'arch_bits:64',
            'tcp_port:6379',
            'uptime_in_seconds:128736',
            'uptime_in_days:1',
            f'run_id:{_RUN_ID}',
        ]
    if sec in ('', 'clients', 'all', 'default'):
        lines += ['# Clients', 'connected_clients:1']
    if sec in ('', 'memory', 'all', 'default'):
        lines += ['# Memory', 'used_memory:873016', 'used_memory_human:852.55K',
                  'maxmemory:0', 'maxmemory_human:0B']
    if sec in ('', 'persistence', 'all', 'default'):
        lines += ['# Persistence', 'loading:0', 'rdb_changes_since_last_save:0',
                  'rdb_last_bgsave_status:ok', 'aof_enabled:0']
    if sec in ('', 'stats', 'all', 'default'):
        lines += ['# Stats', 'total_connections_received:42', 'total_commands_processed:318']
    if sec in ('', 'replication', 'all', 'default'):
        lines += ['# Replication', 'role:master', 'connected_slaves:0']
    if sec in ('', 'keyspace', 'all', 'default'):
        lines += ['# Keyspace', 'db0:keys=5,expires=0,avg_ttl=0']
    return '\r\n'.join(lines) + '\r\n'


class RedisHoneypot:
    """单条 Redis 连接的 RESP2 处理器。"""

    def __init__(self, guard, reporter, logger):
        self.guard = guard
        self.reporter = reporter
        self.logger = logger

    # ---------------- RESP 读取 ----------------
    def _read_command(self, rfile):
        """读取一条 RESP2/内联命令，返回小写命令名 + 参数(bytes)列表；EOF 返回 None。"""
        line = rfile.readline(4097)
        if len(line)>4096:raise ValueError("RESP line limit")
        if not line:
            return None
        line = line.rstrip(b'\r\n')
        if not line:
            return ('', [])
        if line[:1] == b'*':
            try:
                count = int(line[1:])
            except ValueError:
                return ('', [])
            if not 1<=count<=64:raise ValueError("RESP argument limit")
            args = [];total=0
            for _ in range(count):
                raw_header=rfile.readline(65)
                if len(raw_header)>64:raise ValueError('RESP header limit')
                hdr = raw_header.rstrip(b'\r\n')
                if not hdr or hdr[:1] != b'$':
                    return ('', [])
                size = int(hdr[1:])
                total+=max(size,0)
                if not 0<=size<=65536 or total>65536:raise ValueError('RESP bulk limit')
                data = rfile.read(size)
                if len(data)!=size or rfile.read(2)!=b'\r\n':raise ValueError('RESP truncated bulk')
                args.append(data)
            if not args:
                return ('', [])
            return args[0].decode('utf-8', errors='replace').lower(), args[1:]
        # 内联命令（如手工 nc 发送 PING）
        parts = line.split()
        if not parts:
            return ('', [])
        return parts[0].decode('utf-8', errors='replace').lower(), parts[1:]

    # ---------------- 连接处理 ----------------
    def handle(self, conn: socket.socket, client_ip: str):
        conn.settimeout(60)
        unauthorized_reported = False
        try:
            rfile = conn.makefile('rb')
            while True:
                parsed = self._read_command(rfile)
                if parsed is None:
                    return
                cmd, args = parsed
                if not cmd:
                    continue

                # 首条命令即代表未授权访问成功（蜜罐不设密码）
                if not unauthorized_reported:
                    unauthorized_reported = True
                    self.reporter.event(
                        'redis_unauthorized', client_ip, score=80,
                        payload=f'未授权 Redis 访问，首条命令: {cmd.upper()}',
                        tags=['redis', 'unauthorized', 'attack_technique:T1190'],
                        force_alert=True,
                    )

                reply, close_after = self._dispatch(cmd, args, client_ip)
                if reply is not None:
                    conn.sendall(reply)
                if close_after:
                    return
        except (OSError, ConnectionResetError, BrokenPipeError):
            return
        except Exception as exc:
            if self.logger:
                self.logger.debug(f"[redis] 连接处理异常 {client_ip}: {exc}")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _dispatch(self, cmd: str, args: list, client_ip: str):
        """返回 (RESP 回复 bytes, 是否关闭连接)。"""
        send = lambda data: (data, False)

        if cmd in ('quit', 'shutdown', 'debug'):
            return encode_simple('OK'), True

        if cmd == 'ping':
            return send(encode_simple('PONG'))
        if cmd == 'echo' and args:
            return send(encode_bulk(args[0]))
        if cmd == 'select':
            return send(encode_simple('OK'))
        if cmd == 'auth':
            return send(encode_error('ERR Client sent AUTH, but no password is set'))
        if cmd in ('command', 'command docs', 'command count', 'command list', 'command info'):
            return send(encode_array([]))
        if cmd == 'hello':
            # HELLO 2 返回服务信息 map；HELLO 3（RESP3）也降级回 RESP2 map
            return send(encode_array([
                'server', 'redis', 'version', REDIS_VERSION, 'proto', 2,
                'id', abs(hash((client_ip, time.time()))) % 100000,
                'mode', 'standalone', 'role', 'master', 'modules', [],
            ]))
        if cmd == 'info':
            section = args[0].decode('utf-8', errors='replace') if args else ''
            return send(encode_bulk(_info_text(section)))
        if cmd == 'client':
            sub = args[0].decode('utf-8', errors='replace').lower() if args else ''
            if sub == 'setname':
                return send(encode_simple('OK'))
            return send(encode_bulk(None))
        if cmd == 'config':
            return self._config(args, client_ip)
        if cmd in ('save', 'bgsave', 'bgrewriteaof'):
            return send(encode_simple('Background saving started' if cmd != 'save' else 'OK'))
        if cmd in ('flushall', 'flushdb'):
            self.reporter.event(
                'redis_command', client_ip, score=40,
                payload=f'破坏性命令: {cmd.upper()}',
                tags=['redis', 'destructive', 'data_destroy'],
                force_alert=True,
            )
            return send(encode_simple('OK'))
        if cmd in ('slaveof', 'replicaof'):
            target = b' '.join(args).decode('utf-8', errors='replace')
            if args and args[0].lower() == b'no' and len(args) == 1:
                return send(encode_simple('OK'))
            self.reporter.event(
                'redis_command', client_ip, score=45,
                payload=f'主从复制利用尝试: {cmd.upper()} {target}',
                tags=['redis', 'master_slave', 'rce', 'attack_technique:T1059'],
                force_alert=True,
            )
            return send(encode_simple('OK'))
        if cmd == 'replconf':
            return send(encode_simple('OK'))
        if cmd == 'psync':
            # 伪装主从全量同步开始，随后断开（真实场景服务端会推 RDB）
            self.reporter.event(
                'redis_command', client_ip, score=45,
                payload=f'PSYNC 主从同步探测: {b" ".join(args).decode("utf-8", "replace")}',
                tags=['redis', 'master_slave', 'rce', 'attack_technique:T1059'],
                force_alert=True,
            )
            return encode_simple(f'FULLRESYNC {_RUN_ID} 0'), True
        if cmd == 'module':
            if args and args[0].lower() == b'load':
                path = b' '.join(args[1:]).decode('utf-8', errors='replace')
                self.reporter.event(
                    'redis_command', client_ip, score=60,
                    payload=f'恶意模块加载: MODULE LOAD {path}',
                    tags=['redis', 'module_load', 'rce', 'attack_technique:T1505'],
                    force_alert=True,
                )
                return send(encode_simple('OK'))
            return send(encode_array([]))

        # 键值类
        if cmd == 'keys':
            return send(encode_array(_BAIT_KEYS))
        if cmd in ('scan', 'hkeys', 'hvals', 'hgetall'):
            return send(encode_array(['cursor', _BAIT_KEYS] if cmd == 'scan' else _BAIT_KEYS))
        if cmd == 'get' and args:
            key = args[0].decode('utf-8', errors='replace')
            return send(encode_bulk(_BAIT_VALUES.get(key)))
        if cmd == 'mget' and args:
            return send(encode_array([_BAIT_VALUES.get(a.decode('utf-8', 'replace')) for a in args]))
        if cmd == 'type' and args:
            key = args[0].decode('utf-8', errors='replace')
            return send(encode_simple('string' if key in _BAIT_VALUES else 'none'))
        if cmd == 'exists' and args:
            return send(encode_integer(1 if args[0].decode('utf-8', 'replace') in _BAIT_VALUES else 0))
        if cmd in ('set', 'setex', 'setnx', 'setrange', 'append', 'getset',
                   'hset', 'hsetnx', 'hmset', 'lpush', 'rpush', 'sadd', 'zadd',
                   'incr', 'incrby', 'decr', 'decrby', 'expire', 'expireat',
                   'persist', 'rename', 'renamenx', 'move', 'del', 'unlink'):
            if cmd in ('set', 'setex') and args:
                key = args[0].decode('utf-8', 'replace')
                val = args[2] if cmd == 'setex' and len(args) > 2 else (args[1] if len(args) > 1 else b'')
                preview = _b(val)[:120].decode('utf-8', errors='replace')
                self.reporter.event(
                    'redis_command', client_ip, score=10,
                    payload=f'写入键 {key}，预览: {preview}',
                    tags=['redis', 'key_write'],
                )
            if cmd in ('del', 'unlink'):
                return send(encode_integer(len(args)))
            return send(encode_simple('OK'))
        if cmd in ('ttl', 'pttl'):
            return send(encode_integer(-1))
        if cmd == 'dbsize':
            return send(encode_integer(len(_BAIT_KEYS)))
        if cmd == 'time':
            return send(encode_array([str(int(time.time())), '0']))
        if cmd == 'lastsave':
            return send(encode_integer(int(time.time()) - 3600))
        if cmd in ('role',):
            return send(encode_array(['master']))
        if cmd in ('wait',):
            return send(encode_integer(0))

        return send(encode_error(f"ERR unknown command `{cmd}`, with args beginning with: "
                                 f"{args[0].decode('utf-8', 'replace')!r}" if args else
                                 f"ERR unknown command `{cmd}`"))

    def _config(self, args: list, client_ip: str):
        if not args:
            return encode_error('ERR wrong number of arguments'), False
        sub = args[0].lower()
        if sub == b'get':
            name = args[1].decode('utf-8', errors='replace').lower() if len(args) > 1 else ''
            if name == 'dir':
                return encode_array(['dir', '/var/lib/redis']), False
            if name == 'dbfilename':
                return encode_array(['dbfilename', 'dump.rdb']), False
            if name == 'requirepass':
                return encode_array(['requirepass', '']), False
            if name in ('*', ''):
                return encode_array(['dir', '/var/lib/redis', 'dbfilename', 'dump.rdb',
                                     'requirepass', '', 'bind', '', 'protected-mode', 'no']), False
            return encode_array([name, '']), False
        if sub == b'set' and len(args) >= 3:
            name = args[1].decode('utf-8', errors='replace').lower()
            value = b' '.join(args[2:]).decode('utf-8', errors='replace')
            danger = any(hint in value.lower() for hint in _DANGER_PATH_HINTS)
            if name in ('dir', 'dbfilename') and danger:
                self.reporter.event(
                    'redis_command', client_ip, score=60,
                    payload=f'CONFIG SET 落盘利用: {name}={value}（cron/SSH key/webshell 写入）',
                    tags=['redis', 'config_write', 'rce', 'attack_technique:T1053'],
                    force_alert=True,
                )
            elif name in ('dir', 'dbfilename', 'requirepass', 'masterauth', 'bind', 'protected-mode'):
                self.reporter.event(
                    'redis_command', client_ip, score=40,
                    payload=f'配置篡改: CONFIG SET {name}={value}',
                    tags=['redis', 'config_write', 'attack_technique:T1565'],
                )
            else:
                self.reporter.event(
                    'redis_command', client_ip, score=25,
                    payload=f'配置修改: CONFIG SET {name}={value}',
                    tags=['redis', 'config_write'],
                )
            return encode_simple('OK'), False
        if sub == b'rewrite' or sub == b'resetstat':
            return encode_simple('OK'), False
        return encode_error('ERR CONFIG subcommand must be one of GET, SET, REWRITE'), False
