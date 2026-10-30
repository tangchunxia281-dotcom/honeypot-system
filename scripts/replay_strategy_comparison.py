"""Compare the same finite preview policy cases with real AI selection."""
import argparse,hashlib,json,os,secrets,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
def main():
    p=argparse.ArgumentParser();p.add_argument('--output',default=str(ROOT/'demo-results/replay'));args=p.parse_args();out=Path(args.output).resolve();out.mkdir(parents=True,exist_ok=True)
    os.environ.update(HONEYPOT_AI_ENABLED='true',HONEYPOT_AI_PROVIDER='local',HONEYPOT_AI_DB=str(out/'replay-ai.sqlite'))
    import app_config
    app_config.Config.LOG_DIR=str(out/'logs')
    from utils import local_ai
    from utils.ai_interaction import choose,WEB_STRATEGIES
    cases=[{'target':'http://example.test/demo'},{'target':''}];arms={};details=[]
    for arm in ('fixed','ai'):
        valid=0;start=time.monotonic()
        for i,case in enumerate(cases):
            expected='preview_pending' if case['target'] else 'format_error'
            result={'status':'success','data':{'strategy':expected}} if arm=='fixed' else choose('web_reply',{'resource':'preview','url':case['target'],'has_target':bool(case['target'])},WEB_STRATEGIES,'replay-'+secrets.token_hex(8),'synthetic')
            valid+=int(result['status']=='success' and result.get('data',{}).get('strategy')==expected);details.append({'arm':arm,'case':i,'status':result['status'],'strategy':result.get('data',{}).get('strategy'),'reason':result.get('reason','')})
        arms[arm]={'steps':len(cases),'valid_steps':valid,'latency_ms':round((time.monotonic()-start)*1000,3)}
    report={'run_id':secrets.token_hex(12),'dataset_sha256':hashlib.sha256(json.dumps(cases,sort_keys=True).encode()).hexdigest(),'model':local_ai.SETTINGS['model'],'origin':'synthetic','arms':arms,'scope':'两条合成预览策略案例的固定策略/真实AI对照。未测量真实攻击会话延长或额外证据，不能据此宣称AI提升这些指标。'}
    (out/'replay-comparison.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8');(out/'replay-details.json').write_text(json.dumps(details,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(report,ensure_ascii=False));local_ai._pool.shutdown(wait=True)
if __name__=='__main__':main()
