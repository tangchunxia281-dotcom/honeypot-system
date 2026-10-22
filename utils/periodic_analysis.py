"""Idempotent closed-window summaries with explicit coverage and noise grouping."""
import hashlib
import json
import re
import time
from datetime import datetime,timezone,timedelta
from contextlib import closing
from utils.evidence_selection import hints,select
from utils.team_store import TeamStore

ZONE=timezone(timedelta(hours=8))


def metrics(records,total,start,end,previous_total):
    groups={};families={};sources={}
    for r in records:
        types=hints(r);family=types[0];families[family]=families.get(family,0)+1;sources[r['src_ip']]=sources.get(r['src_ip'],0)+1
        # Group repeated same-source, same-session and same route/type in one
        # 15-minute slot. Different high-signal families are never merged.
        try:slot=int(datetime.fromisoformat(r['timestamp']).replace(tzinfo=ZONE).timestamp())//900
        except ValueError:slot=0
        path=re.search(r'(?:GET|POST|PUT|DELETE)\s+([^\s?]+)',r['excerpt']);route=path.group(1) if path else r['kind']
        key=(r['src_ip'],r['session_id'],family,route,slot)
        group=groups.setdefault(key,{'src_ip':r['src_ip'],'family':family,'route':route,'count':0,'first':r['timestamp'],'last':r['timestamp'],'evidence_ids':[]})
        group['count']+=1;group['first']=min(group['first'],r['timestamp']);group['last']=max(group['last'],r['timestamp'])
        if len(group['evidence_ids'])<4:group['evidence_ids'].append(r['id'])
    alerts=[g for g in groups.values() if g['family']!='normal'];alerts.sort(key=lambda g:(-g['count'],g['first']))
    return {'start':start,'end':end,'total_indexed':total,'sampled':len(records),'sample_limit':5000,'previous_total':previous_total,'change':total-previous_total,
            'hint_counts':families,'source_counts':sorted(sources.items(),key=lambda x:-x[1])[:10],
            'alert_occurrences_sampled':sum(g['count'] for g in alerts),'alert_groups_sampled':len(alerts),'alerts':alerts[:100],
            'scope':'统计针对当前索引；类别／降噪最多5000条样本。程序特征分组不是AI确认，也不删除原始日志。'}


def make_period(store,kind='hour',now=None,manual=False):
    now=time.time() if now is None else now;duration=3600 if kind=='hour' else 86400
    end=int((now+8*3600)//duration)*duration-8*3600;start=end-duration
    stamp=lambda n:datetime.fromtimestamp(n,ZONE).strftime('%Y-%m-%d %H:%M:%S')
    with closing(store.connect()) as c:
        total=c.execute('SELECT COUNT(*) FROM analyst_evidence WHERE timestamp>=? AND timestamp<?',(stamp(start),stamp(end))).fetchone()[0]
        previous=c.execute('SELECT COUNT(*) FROM analyst_evidence WHERE timestamp>=? AND timestamp<?',(stamp(start-duration),stamp(start))).fetchone()[0]
        records=[dict(r) for r in c.execute('SELECT * FROM analyst_evidence WHERE timestamp>=? AND timestamp<? ORDER BY timestamp,id LIMIT 5000',(stamp(start),stamp(end)))]
    from utils import ai_analyst
    summary=metrics(records,total,start,end,previous);summary['index_lag']=ai_analyst._state.get('lag',0);summary['scan_error']=ai_analyst._state.get('scan_error','')
    team=TeamStore(store);identifier=team.reserve_period(kind,start,end,summary)
    if not identifier:
        with closing(team.connect()) as c:
            existing=c.execute('SELECT id,task_id FROM period_reports WHERE kind=? AND start=? AND end=?',(kind,start,end)).fetchone()
        if not existing or existing['task_id'] or not total:return {'status':'already_exists','start':start,'end':end}
        identifier=existing['id']
        with closing(team.connect()) as c,c:c.execute('UPDATE period_reports SET metrics_json=? WHERE id=?',(json.dumps(summary,ensure_ascii=False),identifier))

    if summary['index_lag'] or summary['scan_error']:return {'id':identifier,'status':'waiting_index','metrics':summary}

    selected=select(records,24)['records']
    if selected:
        job=store.enqueue('report',{'records':selected,'selected':len(selected),'period_id':identifier,'period_metrics':summary,'scope':f'固定周期 {stamp(start)} 至 {stamp(end)}，程序计数独立，AI仅分析{len(selected)}/{total}条代表证据。'},'period:'+identifier)
        if job.get('id'):team.period_task(identifier,job['id'])
    return {'id':identifier,'status':'created','metrics':summary}


def tick(store):
    from utils import local_ai
    if not local_ai.SETTINGS.get('periodic_enabled',False):return
    team=TeamStore(store);cfg=team.period_config()
    if cfg['enabled']:make_period(store,cfg['period'])
