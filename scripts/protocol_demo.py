"""Finite loopback-only protocol fixtures. No scanners, command execution or brute force."""
import argparse
import ftplib
import json
import socket
import time
import pymysql
import paramiko

def exercise(ports):
    results={}
    with pymysql.connect(host='127.0.0.1',port=ports['mysql'],user='root',password='123456',connect_timeout=3,read_timeout=3,write_timeout=3)as conn:
        with conn.cursor()as c:
            c.execute('SHOW DATABASES');assert c.fetchall()
            c.execute('SELECT version()');assert c.fetchone()
            try:c.execute("LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE test")
            except pymysql.MySQLError:pass
            else:raise AssertionError('LOCAL INFILE must be disabled')
        results['mysql']='handshake, virtual query, client-file request disabled'
    with socket.create_connection(('127.0.0.1',ports['redis']),timeout=3)as s:
        s.sendall(b'PING\r\n');assert b'PONG'in s.recv(4096)
        s.sendall(b'INFO\r\n');assert b'redis_version'in s.recv(8192)
        s.sendall(b'KEYS *\r\n');assert s.recv(4096)
        results['redis']='RESP, virtual info and keys'
    with ftplib.FTP()as ftp:
        ftp.connect('127.0.0.1',ports['ftp'],timeout=4);ftp.login('anonymous','synthetic@example.test')
        assert ftp.nlst();chunks=[];ftp.retrbinary('RETR .env',chunks.append)
        assert b'DB_'in b''.join(chunks)
        results['ftp']='anonymous login, passive list, virtual decoy download'
    with socket.create_connection(('127.0.0.1',ports['telnet']),timeout=4)as s:
        s.recv(4096);s.sendall(b'root\r\n');time.sleep(.2);s.recv(4096)
        s.sendall(b'123456\r\n');time.sleep(.3);s.recv(4096)
        s.sendall(b'uname -a\r\n');time.sleep(.2);data=s.recv(8192)
        assert b'Linux'in data,data
        s.sendall(b'exit\r\n');results['telnet']='device login and virtual uname'
    if ports.get('ssh'):
        c=paramiko.SSHClient();c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:c.connect('127.0.0.1',port=ports['ssh'],username='synthetic_invalid_user',password='not-a-real-password',timeout=3,auth_timeout=3,look_for_keys=False,allow_agent=False)
        except paramiko.AuthenticationException:results['ssh']='one synthetic rejected login recorded'
        finally:c.close()
    return results

if __name__=='__main__':
    p=argparse.ArgumentParser(description='本机有限协议测试；仅127.0.0.1，无外部目标选项。')
    for name,port in [('mysql',13306),('redis',16379),('ftp',2121),('telnet',2223),('ssh',2222)]:p.add_argument('--'+name+'-port',type=int,default=port)
    a=p.parse_args();ports={name:getattr(a,name+'_port')for name in ('mysql','redis','ftp','telnet','ssh')}
    if any(not 1<=v<=65535 for v in ports.values()):p.error('端口无效')
    print(json.dumps(exercise(ports),ensure_ascii=False,indent=2))
