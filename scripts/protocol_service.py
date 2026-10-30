"""Bounded local protocol listener shared by four virtual decoy adapters."""
import argparse
import signal
import socket
import sys
import threading
import time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from utils.protocol_guard import ConnectionGuard,ProtocolReporter
from utils.logger import setup_logger

def serve(protocol,host,port):
    from db_honeypot.mysql_handler import MySQLHoneypot
    from db_honeypot.redis_handler import RedisHoneypot
    from file_honeypot.ftp_handler import FTPHoneypot
    from remote_honeypot.telnet_handler import TelnetHoneypot
    adapter={'mysql':MySQLHoneypot,'redis':RedisHoneypot,'ftp':FTPHoneypot,'telnet':TelnetHoneypot}[protocol]
    guard=ConnectionGuard(protocol,max_workers=32,max_active_total=32,max_active_per_ip=8)
    logger=setup_logger(protocol+'_listener',protocol+'.log');stop=threading.Event();connections={};lock=threading.Lock()
    def handle(conn,ip):
        admitted=False
        try:
            admitted,_=guard.admit(ip)
            if not admitted:return
            reporter=ProtocolReporter(protocol,logger)
            scan=guard.record_preauth_connection(ip)
            if scan:reporter.event(protocol+'_scan',ip,score=45,payload='Repeated unauthenticated connections',tags=['scan'])
            adapter(guard,reporter,logger).handle(conn,ip)
        except Exception as error:logger.debug('connection ended: %s',type(error).__name__)
        finally:
            if admitted:guard.release(ip)
            guard.release_worker()
            with lock:connections.pop(conn,None)
            conn.close()
    def shutdown(*args):stop.set()
    signal.signal(signal.SIGINT,shutdown);signal.signal(signal.SIGTERM,shutdown)
    with socket.socket() as server:
        if sys.platform=='win32' and hasattr(socket,'SO_EXCLUSIVEADDRUSE'):server.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
        else:server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        server.bind((host,port));server.listen(32);server.settimeout(.5)
        print(f'{protocol.upper()} virtual service listening {host}:{port}',flush=True)
        while not stop.is_set():
            with lock:expired=[conn for conn,deadline in connections.items()if deadline<time.monotonic()]
            for conn in expired:
                try:conn.shutdown(socket.SHUT_RDWR);conn.close()
                except OSError:pass
            try:conn,addr=server.accept()
            except socket.timeout:continue
            if not guard.acquire_worker(timeout=0):conn.close();continue
            with lock:connections[conn]=time.monotonic()+180
            threading.Thread(target=handle,args=(conn,addr[0]),daemon=True).start()
        with lock:
            for conn in connections:
                try:conn.shutdown(socket.SHUT_RDWR);conn.close()
                except OSError:pass

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--protocol',required=True,choices=('mysql','redis','ftp','telnet'));p.add_argument('--host',default='127.0.0.1');p.add_argument('--port',type=int,required=True)
    args=p.parse_args();serve(args.protocol,args.host,args.port)
