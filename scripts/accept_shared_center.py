"""Two real HTTP gateway clients call the installed model, without test doubles."""
import argparse,hashlib,json,secrets,sys,threading,time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import requests
from werkzeug.serving import make_server
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',default=str(ROOT/'demo-results/shared-acceptance'));args=p.parse_args();out=Path(args.output).resolve();out.mkdir(parents=True,exist_ok=True)
    from ai_gateway.server import Gateway,create_app
    from utils.gateway_client import transport
    model='maternion/mimo-v2.6:9b';client=requests.Session();client.trust_env=False
    r=client.post('http://127.0.0.1:11434/api/generate',json={'model':model,'prompt':'','stream':False,'keep_alive':'10m','options':{'num_ctx':4096}},timeout=(3,120));r.raise_for_status()
    tokens={name:secrets.token_urlsafe(36) for name in ('member-a','member-b')}
    gateway=Gateway(out/'gateway.sqlite',model,{n:{'token_hash':hashlib.sha256(t.encode()).hexdigest(),'per_minute':30,'max_pending':4} for n,t in tokens.items()})
    app=create_app(gateway);server=make_server('127.0.0.1',0,app,threaded=True);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();gateway.start();base='http://127.0.0.1:'+str(server.server_port)
    schema={'type':'object','properties':{'reply':{'type':'string'}},'required':['reply'],'additionalProperties':False}
    def run(name):
        start=time.monotonic();settings={'timeout':30,'gateway_wait':60,'gateway_url':base,'client_token':tokens[name],'context_length':4096,'think':False}
        raw=transport(settings,[{'role':'user','content':'只输出JSON，reply字段用中文确认共享模型连接正常。'}],schema,{'request_id':secrets.token_hex(12),'task':'probe','timeout':30})
        obj=json.loads(raw['message']['content']);return {'member':name,'valid':raw.get('done') is True and set(obj)=={'reply'} and isinstance(obj['reply'],str) and bool(obj['reply']),'seconds':round(time.monotonic()-start,3)}
    report={'model':model,'scope':'本机两成员身份真实HTTP共享推理；不等于两台电脑局域网验收。'}
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:report['members']=list(pool.map(run,tokens))
        a=gateway.enqueue('member-a',{'request_id':secrets.token_hex(12),'task':'probe','messages':[{'role':'user','content':'reply OK'}],'schema':schema,'options':{'timeout':30,'num_predict':64,'num_ctx':4096,'think':False}})
        response=client.get(base+'/v1/jobs/'+a['id'],headers={'Authorization':'Bearer '+tokens['member-b']},timeout=3);report['cross_member_status']=response.status_code;gateway.cancel(a['id'],'member-a');report['passed']=all(r['valid'] for r in report['members']) and response.status_code==404
    except Exception as e:report['passed']=False;report['error']=type(e).__name__+': '+str(e)[:180]
    finally:client.close();gateway.close();server.shutdown();server.server_close();thread.join(2)
    (out/'real-shared-acceptance.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(report,ensure_ascii=False,indent=2));return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
