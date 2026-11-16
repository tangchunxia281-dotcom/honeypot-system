"""Initialize a private hub, serve it, or collect without installing a model."""
import argparse
import getpass
import json
import os
import secrets
import sys
import threading
import time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))

def validate_bind(host,port,allow_lan_http=False):
    from utils.team_collector import endpoint_ok
    if not endpoint_ok(f'http://{host}:{port}',allow_lan_http):raise ValueError('中心只允许具体本机/私网IPv4地址；局域网HTTP必须明确启用allow_lan_http。')

def main():
    p=argparse.ArgumentParser(description='团队数据中心 / 采集端')
    p.add_argument('action',choices=['init','serve','collect','doctor']);p.add_argument('--config',default=str(ROOT/'deployment/center/center.json'));p.add_argument('--name',default='admin');p.add_argument('--host',default='127.0.0.1');p.add_argument('--port',type=int,default=5169);p.add_argument('--once',action='store_true');p.add_argument('--allow-lan-http',action='store_true');p.add_argument('--ai-config',default=str(ROOT/'ai.local.ini'));args=p.parse_args();path=Path(args.config).resolve()
    if args.action=='init':
        if path.exists():raise ValueError('配置已存在，不覆盖。')
        validate_bind(args.host,args.port,args.allow_lan_http)
        from scripts.deploy import private_write
        from team_center.store import CenterStore
        folder=path.parent;password=getpass.getpass('设置中心管理员密码（至少12位，不回显）：')
        store=CenterStore(folder/'center.sqlite');store.create_user(args.name,password,'admin',[])
        private_write(path,json.dumps({'database':str(store.path),'secret':secrets.token_urlsafe(48),'host':args.host,'port':args.port,'allow_lan_http':args.allow_lan_http,'ai_config':str(Path(args.ai_config).resolve())},indent=2))
        print('中心已初始化。请自行保管密码；中心默认仅本机监听。');return
    config=json.loads(path.read_text(encoding='utf-8-sig'))
    if args.action=='collect':
        from utils.team_collector import Collector
        collector=Collector(config['spool'],config['sources'],config['sensor_id'],config['endpoint'],config['token'],config.get('max_bytes',16777216),config.get('allow_lan_http',False),config.get('origin','unknown'),config.get('ai_database'))
        delay=3
        while True:
            collector.stage();state=collector.flush_once();print(json.dumps(state,ensure_ascii=False),flush=True)
            if args.once:return
            delay=min(60,delay*2) if state['error'] else .2 if state['pending'] else 3;time.sleep(delay)
    os.environ['HONEYPOT_AI_CONFIG']=config.get('ai_config',str(ROOT/'ai.local.ini'));os.environ['HONEYPOT_AI_DB']=str(path.parent/'center-ai.sqlite')
    import app_config
    app_config.Config.LOG_DIR=str(path.parent/'logs')
    if args.action=='doctor':
        from utils.local_ai import health
        print(json.dumps(health(),ensure_ascii=False,indent=2));return
    from utils.team_collector import endpoint_ok
    host=config.get('host','127.0.0.1');port=int(config.get('port',5169))
    validate_bind(host,port,config.get('allow_lan_http',False) or args.allow_lan_http)
    from team_center.store import CenterStore
    from team_center.server import create_app
    from utils.active_investigation import process_one
    store=CenterStore(config['database']);app=create_app(store,config['secret']);stop=threading.Event()
    def work():
        while not stop.is_set():
            try:
                if not process_one(store,app.center_jobs):stop.wait(.5)
            except Exception as error:
                print('调查工作器暂停重试：'+type(error).__name__,flush=True);stop.wait(2)
    threading.Thread(target=work,daemon=True,name='center-investigator').start()
    print(f'团队数据中心：http://{host}:{port}（独立登录）',flush=True)
    try:
        from waitress import serve
        serve(app,host=host,port=port,threads=6,max_request_body_size=262144)
    except ImportError:app.run(host=host,port=port,debug=False,use_reloader=False,threaded=True)
    finally:stop.set()

if __name__=='__main__':
    for stream in (sys.stdout,sys.stderr):
        if hasattr(stream,'reconfigure'):stream.reconfigure(encoding='utf-8',errors='replace')
    main()
