"""Every displayed fraction has a denominator and an explicit provenance."""
import json
import statistics
from collections import Counter
from contextlib import closing
import re

def validate_replay(obj):
    if not isinstance(obj,dict) or set(obj)!={'run_id','dataset_sha256','model','origin','arms','scope'} or not isinstance(obj['run_id'],str) or not re.fullmatch(r'[a-f0-9]{24}',obj['run_id']) or not isinstance(obj['dataset_sha256'],str) or not re.fullmatch(r'[a-f0-9]{64}',obj['dataset_sha256']):raise ValueError('replay_identity_invalid')
    if not isinstance(obj['arms'],dict) or set(obj['arms'])!={'fixed','ai'} or obj['origin']!='synthetic' or not isinstance(obj['model'],str) or len(obj['model'])>160 or not isinstance(obj['scope'],str) or len(obj['scope'])>500:raise ValueError('replay_schema_invalid')
    for arm in obj['arms'].values():
        if not isinstance(arm,dict) or set(arm)!={'steps','valid_steps','latency_ms'} or type(arm['steps']) is not int or not 1<=arm['steps']<=100 or type(arm['valid_steps']) is not int or not 0<=arm['valid_steps']<=arm['steps'] or type(arm['latency_ms']) not in (int,float) or not 0<=arm['latency_ms']<=3600000:raise ValueError('replay_denominator_invalid')
    return obj

def percentiles(values):
    values=sorted(values)
    return {'p50_ms':statistics.median(values) if values else None,'p95_ms':values[min(len(values)-1,int(len(values)*.95))] if values else None}

def snapshot(center,jobs,user_id,filters):
    meta={k:filters[k] for k in ('model','version') if filters.get(k)}
    if any(not isinstance(v,str) or len(v)>160 for v in meta.values()):raise ValueError('model_version_filter_invalid')
    filters={k:v for k,v in filters.items() if k not in ('model','version')}
    where,args=center.query(user_id,filters);allowed=set(center.scope(user_id));selected=set(filters.get('sensors',allowed))
    with closing(center.connect()) as c:
        total=c.execute('SELECT COUNT(*) FROM evidence WHERE '+where,args).fetchone()[0]
        origins={r[0]:r[1] for r in c.execute('SELECT origin,COUNT(*) FROM evidence WHERE '+where+' GROUP BY origin',args)}
        jobrows=[jobs.decode(r) for r in c.execute('SELECT * FROM center_jobs ORDER BY created DESC LIMIT 10000')]
        member=[json.loads(r['document']) for r in c.execute('SELECT sensor_id,document FROM member_metrics ORDER BY created DESC LIMIT 10000') if r['sensor_id'] in selected]
        feedback={r['job_id']:dict(r) for r in c.execute('SELECT * FROM center_feedback')}
        audited=[(r['job_id'],json.loads(r['document'])) for r in c.execute('SELECT job_id,document FROM center_calls')]
        waits=[(r['job_id'],json.loads(r['document']).get('queued_ms')) for r in c.execute("SELECT job_id,document FROM center_steps WHERE json_extract(document,'$.type')='initial'")]
    start=filters.get('start');end=filters.get('end');origin=filters.get('origin')
    def time_ok(value):
        from datetime import datetime
        from team_center.store import ZONE,stamp
        return (not start or value>=datetime.fromisoformat(stamp(start)).replace(tzinfo=ZONE).timestamp()) and (not end or value<=datetime.fromisoformat(stamp(end)).replace(tzinfo=ZONE).timestamp())
    precise={k:v for k,v in filters.items() if k in ('ip','session','kind','term') and v}
    visible=[j for j in jobrows if set(j['query']['sensors']).issubset(selected) and time_ok(j['created']) and (not origin or j['query'].get('origin')==origin) and all(j['query'].get(k)==v for k,v in precise.items())]
    if meta:
        matched={jid for jid,call in audited if all(call.get('code_version' if k=='version' else k)==v for k,v in meta.items())}
        visible=[j for j in visible if j['id'] in matched]
    visible_ids={j['id'] for j in visible};calls=[call for job_id,call in audited if job_id in visible_ids and all(call.get('code_version' if k=='version' else k)==v for k,v in meta.items())]
    reviewed=[feedback[j['id']] for j in visible if j['status']=='completed' and j['id'] in feedback]
    accepted=sum(r['verdict']=='accepted' for r in reviewed)
    declared=[m for m in member if time_ok(m.get('timestamp',0)) and (not origin or m.get('origin')==origin) and all(m.get('code_version' if k=='version' else k,'unknown')==v for k,v in meta.items())] if not precise else []
    checked=[c for c in calls if c.get('references_checked')];citation_valid=sum(c.get('references_valid',False) for c in checked)
    detected=[m for m in declared if type(m.get('rule_attack')) is bool and type(m.get('ai_attack')) is bool]
    comparisons=Counter('both' if m['rule_attack'] and m['ai_attack'] else 'rule_only' if m['rule_attack'] else 'ai_only' if m['ai_attack'] else 'neither' for m in detected)
    return {'evidence':{'total':total,'origins':origins},'investigations':dict(Counter(j['status'] for j in visible)),
            'calls':{'total':len(calls),'valid':sum(c['status']=='success' for c in calls),'failures':dict(Counter(c.get('reason','') for c in calls if c['status']!='success')),**percentiles([c.get('latency_ms',0) for c in calls])},
            'human_acceptance':{'reviewed':len(reviewed),'accepted':accepted,'rate':accepted/len(reviewed) if reviewed else None,'note':'仅已完成并被人工复核的调查，存在选择偏差；不是检测准确率。'},
            'supplement_queries':sum(j['result'].get('supplement_queries',0) for j in visible),'provided_evidence':sum(j['result'].get('model_records',0) for j in visible),
            'candidate_evidence':sum(j['result'].get('candidate_records',0) for j in visible),
            'citation_checks':{'checked_story_calls':len(checked),'valid':citation_valid,'rate':citation_valid/len(checked) if checked else None,'note':'只验证引用编号属于实际提供的证据；不证明模型解释正确。'},
            'queue_latency':percentiles([wait for jid,wait in waits if jid in visible_ids and wait is not None]),'call_latency_scope':'调用耗时包含共享排队与生成；没有将它伪装为纯推理时间。',
            'generation_latency':percentiles([c['model_timing']['generation_ms'] for c in calls if c.get('model_timing',{}).get('generation_ms') is not None]),
            'gateway_queue_latency':percentiles([c['model_timing']['gateway_queue_ms'] for c in calls if c.get('model_timing',{}).get('gateway_queue_ms') is not None]),
            'model_versions':sorted({(c.get('model','unknown'),c.get('code_version','unknown')) for c in calls}),
            'member_declared':{'total':len(declared),'comparisons':dict(comparisons),'note':'成员采集元数据，AI单独命中未经复核不等于正确发现；不与中心实际调用混算。'},
            'scope':{'sensors':list(selected),'filters':filters,'max_jobs':10000,'max_member_metrics':10000},'model_accuracy':None,
            'limitations':'展示当前授权范围的索引和最多10000条任务/成员指标。IP/会话/类别/关键词筛选仅纳入调查范围明确匹配的任务；成员汇总指标无法按这些字段细分时不展示。没有独立真值不能计算模型准确率。'}
