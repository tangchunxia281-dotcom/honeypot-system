import argparse,json,os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
if __name__=='__main__':
    for stream in (sys.stdout,sys.stderr):
        if hasattr(stream,'reconfigure'):stream.reconfigure(encoding='utf-8',errors='replace')
    p=argparse.ArgumentParser();p.add_argument('--mode',choices=['rules','ai'],default='rules');p.add_argument('--dataset',default=str(ROOT/'evaluation/fixtures.jsonl'));p.add_argument('--split',choices=['calibration','test'],default='test');p.add_argument('--output',default=str(ROOT/'evaluation/results'));p.add_argument('--save-dashboard',action='store_true');args=p.parse_args()
    from utils.evaluation import run
    result=run(args.dataset,args.mode,args.split,progress=lambda i,n,r:print(f'{i}/{n} {r["id"]} {r["status"]} {r["prediction"]}',flush=True))
    folder=Path(args.output);folder.mkdir(parents=True,exist_ok=True);target=folder/(args.mode+'-'+result['run_id']+'.json');target.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    if args.save_dashboard:
        from utils.ai_analyst import get_store
        from utils.team_store import TeamStore
        TeamStore(get_store()).record_evaluation(result)
    print(json.dumps(result['metrics'],ensure_ascii=False,indent=2));print('结果：'+str(target))
    from utils import local_ai
    local_ai._pool.shutdown(wait=True)
