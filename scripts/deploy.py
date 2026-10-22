"""Deployment roles, prerequisites and diagnostics without rewriting original data."""
import argparse
import configparser
import hashlib
import importlib.util
import json
import os
import secrets
import socket
import subprocess
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))


def private_write(path,text):
    if path.exists():raise ValueError('已有部署文件，先备份后使用不同名称；不会覆盖现有配置')
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text,encoding='utf-8')
    try:os.chmod(path,0o600)
    except OSError:pass
    if os.name=='nt':
        from utils.logger import _harden_permissions
        _harden_permissions(str(path.parent),True);_harden_permissions(str(path),False)


def configure(args):
    folder=ROOT/'deployment'/args.name
    if folder.exists():raise ValueError('该部署名称已存在')
    if args.role=='center':
        from scripts.team_center import validate_bind
        validate_bind(args.host,args.center_port,args.allow_lan_http)
        import getpass
        from team_center.store import CenterStore
        store=CenterStore(folder/'center.sqlite')
        password=getpass.getpass('设置中心管理员密码（至少12位，不回显）：')
        store.create_user('admin',password,'admin',[])
        private_write(folder/'center.json',json.dumps({'database':str(store.path),'secret':secrets.token_urlsafe(48),'host':args.host,'port':args.center_port,'allow_lan_http':args.allow_lan_http,'ai_config':str(Path(args.ai_config).resolve())}))
        private_write(folder/'启动.cmd',f'@echo off\npowershell.exe -NoProfile -ExecutionPolicy Bypass -File "{ROOT / "scripts/start_deployment.ps1"}" -Directory "{folder}"\npause\n')
    elif args.role=='gateway':
        import ipaddress
        address=ipaddress.ip_address(args.host)
        if not (address.is_loopback or address.version==4 and any(address in ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))):raise ValueError('网关只绑定具体本机或局域网地址')
        clients={};issued={}
        for n in range(1,args.members+1):
            token=secrets.token_urlsafe(36);name='member-'+str(n);clients[name]={'token_hash':hashlib.sha256(token.encode()).hexdigest(),'per_minute':30,'max_pending':4};issued[name]=token
        cfg={'host':args.host,'port':args.gateway_port,'model':args.model,'ollama_url':'http://127.0.0.1:11434','capacity':1,'database':str(folder/'gateway.sqlite'),'clients':clients}
        private_write(folder/'gateway.json',json.dumps(cfg,indent=2));private_write(folder/'发给成员的令牌.json',json.dumps(issued,indent=2))
        private_write(folder/'启动.cmd',f'@echo off\npowershell.exe -NoProfile -ExecutionPolicy Bypass -File "{ROOT / "scripts/start_deployment.ps1"}" -Directory "{folder}"\npause\n')
        print('共享服务配置已生成。分别发给成员自己的令牌；服务器只保存令牌哈希。')
    else:
        p=configparser.ConfigParser(interpolation=None);p.read(ROOT/'ai.local.ini.example',encoding='utf-8-sig')
        p['ai']['provider']='gateway' if args.role=='collector' else 'local';p['ai']['enabled']='false' if args.role=='rules' else 'true'
        p['ai']['model']=args.model;p['ai']['runtime_db']=str(folder/'ai.sqlite')
        if args.role=='collector':
            if not args.token:
                import getpass
                args.token=getpass.getpass('输入所属成员令牌（不回显）：')
            if len(args.token)<32:raise ValueError('采集端需要所属成员令牌')
            p['ai']['gateway_url']=args.gateway_url;p['ai']['client_token']=args.token;p['ai']['allow_insecure_lan']='true' if args.allow_lan_http else 'false';p['ai']['gateway_wait']='90'
        import io
        data=io.StringIO();p.write(data);private_write(folder/'ai.ini',data.getvalue())
        admin=secrets.token_urlsafe(18);sensor=secrets.token_hex(12)
        cfg=f'[app]\nproduction_mode=false\n[admin]\nuser=admin\npassword={admin}\n[services.dashboard]\nhost=127.0.0.1\nport={args.dashboard_port}\n'
        private_write(folder/'project.ini',cfg)
        private_write(folder/'runtime.json',json.dumps({'sensor':sensor,'web_port':args.web_port,'dashboard_port':args.dashboard_port,'ssh_port':args.ssh_port}))
        if getattr(args,'center_url',''):
            from utils.team_collector import endpoint_ok
            if not endpoint_ok(args.center_url,args.allow_lan_http):raise ValueError('中心地址无效')
            import getpass
            center_token=getpass.getpass('输入中心设备令牌（与共享AI令牌不同，不回显）：')
            if len(center_token)<32:raise ValueError('中心令牌长度无效')
            private_write(folder/'collector.json',json.dumps({'sensor_id':sensor,'endpoint':args.center_url,'token':center_token,'sources':[str(folder/'events.sqlite')],'ai_database':str(folder/'ai.sqlite'),'spool':str(folder/'outbox.sqlite'),'allow_lan_http':args.allow_lan_http,'origin':'operational'}))
            private_write(folder/'启动采集.cmd',f'@echo off\npowershell.exe -NoProfile -ExecutionPolicy Bypass -File "{ROOT / "scripts/start_deployment.ps1"}" -Directory "{folder}" -Collect\npause\n')
        private_write(folder/'启动.cmd',f'@echo off\npowershell.exe -NoProfile -ExecutionPolicy Bypass -File "{ROOT / "scripts/start_deployment.ps1"}" -Directory "{folder}"\npause\n')
        print('独立部署已生成，管理员密码保存在此部署的project.ini；原配置、数据库和日志保留。')
    print('目录：'+str(folder));return folder


def doctor():
    report={'python':sys.version.split()[0],'python_supported':sys.version_info>=(3,11),'dependencies':{},'ports':{},'ai':{}}
    for name in ('flask','paramiko','requests','pymysql','psutil'):report['dependencies'][name]=importlib.util.find_spec(name) is not None
    for name,port in (('web',5000),('dashboard',5001),('ssh',2222)):
        try:
            with socket.socket() as s:s.bind(('127.0.0.1',port));report['ports'][name]='available'
        except OSError:report['ports'][name]='in_use'
    if report['dependencies']['requests']:
        from utils import local_ai
        report['ai']={'provider':local_ai.SETTINGS.get('provider','local'),'configured':local_ai.SETTINGS['configured'],'model':local_ai.SETTINGS['model'],'health':local_ai.health(force=True)}
    print(json.dumps(report,ensure_ascii=False,indent=2));return report


def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('action',choices=['configure','doctor','install']);p.add_argument('--role',choices=['standalone','collector','gateway','rules','center'],default='standalone');p.add_argument('--name',default='local');p.add_argument('--model',default='maternion/mimo-v2.6:9b');p.add_argument('--host',default='127.0.0.1');p.add_argument('--members',type=int,default=3);p.add_argument('--ai-config',default=str(ROOT/'ai.local.ini'));p.add_argument('--center-port',type=int,default=5169);p.add_argument('--center-url',default='');p.add_argument('--gateway-port',type=int,default=11500);p.add_argument('--gateway-url',default='http://127.0.0.1:11500');p.add_argument('--token',default='');p.add_argument('--allow-lan-http',action='store_true');p.add_argument('--web-port',type=int,default=5000);p.add_argument('--dashboard-port',type=int,default=5001);p.add_argument('--ssh-port',type=int,default=2222);args=p.parse_args(argv)
    import re
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,32}',args.name) or not 1<=args.members<=20 or any(not 1<=n<=65535 for n in (args.gateway_port,args.web_port,args.dashboard_port,args.ssh_port)):p.error('名称、成员数或端口无效')
    if args.action=='doctor':doctor()
    elif args.action=='install':subprocess.run([sys.executable,str(ROOT/'scripts/setup_local.py')],check=True)
    else:configure(args)


if __name__=='__main__':
    try:main()
    except (ValueError,OSError) as e:print(str(e));raise SystemExit(1)



