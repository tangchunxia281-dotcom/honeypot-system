"""Reproducible grouped evaluation; failures/abstentions are not normal traffic."""
import hashlib
import html
import json
import re
import secrets
import statistics
import time
from pathlib import Path
from urllib.parse import unquote
from utils import ai_detection,local_ai


def canonical(row):
    fields={}
    for k,v in row['fields'].items():
        for _ in range(2):v=html.unescape(unquote(v))
        fields[k]=re.sub(r'\s+',' ',v).strip().lower()
    return hashlib.sha256(json.dumps(fields,sort_keys=True).encode()).hexdigest()


def load(path):
    data=Path(path).read_bytes()
    if len(data)>5_000_000:raise ValueError('dataset_too_large')
    rows=[json.loads(line) for line in data.decode('utf-8-sig').splitlines() if line.strip()]
    if not rows or len(rows)>10000:raise ValueError('dataset_size_invalid')
    ids=set();groups={};payloads={}
    for r in rows:
        if not isinstance(r,dict) or r.get('label') not in ('attack','benign','uncertain') or r.get('split') not in ('calibration','test') or not isinstance(r.get('group'),str) or not r['group'] or not isinstance(r.get('fields'),dict) or set(r['fields'])!=set(ai_detection.FIELD_LIMITS):raise ValueError('dataset_schema_invalid')
        if not isinstance(r.get('id'),str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',r['id']) or len(r['group'])>128:raise ValueError('dataset_id_invalid')
        if not all(isinstance(v,str) and len(v)<=10000 for v in r['fields'].values()) or r['id'] in ids:raise ValueError('dataset_fields_invalid')
        if r['label']=='attack' and r.get('attack_type') not in ai_detection.ATTACK_TYPES:raise ValueError('dataset_label_invalid')
        ids.add(r['id']);groups.setdefault(r['group'],set()).add(r['split']);payloads.setdefault(canonical(r),set()).add(r['split'])
    if any(len(v)>1 for v in groups.values()):raise ValueError('group_leakage')
    if any(len(v)>1 for v in payloads.values()):raise ValueError('normalized_payload_leakage')
    return rows,hashlib.sha256(data).hexdigest()


def messages(snapshot):
    # Reuse the exact production request review definitions, without labels,
    # group IDs, annotation text or previously judged model answers.
    return ai_detection.review_messages(snapshot)


def summarize(cases):
    tp=fp=tn=fn=abstain_positive=abstain_negative=failures=0
    types={};valid=0;ambiguous=[]
    for r in cases:
        if r['status']!='success':failures+=1
        else:valid+=1
        if r['expected']=='uncertain':ambiguous.append(r);continue
        abstain=r['status']!='success' or r['prediction']=='uncertain'
        positive=r['expected']=='attack';predicted=r['prediction']=='suspicious' and not abstain
        if positive:
            tp+=int(predicted);fn+=int(not predicted);abstain_positive+=int(abstain)
            stats=types.setdefault(r['attack_type'],{'total':0,'detected':0,'type_correct':0});stats['total']+=1;stats['detected']+=int(predicted);stats['type_correct']+=int(predicted and r['attack_type'] in r['predicted_types'])
        else:
            fp+=int(predicted);tn+=int(not predicted and not abstain);abstain_negative+=int(abstain)
    precision=tp/(tp+fp) if tp+fp else 0;recall=tp/(tp+fn) if tp+fn else 0
    for kind,stats in types.items():
        predicted=sum(r['status']=='success' and r['prediction']=='suspicious' and kind in r['predicted_types'] for r in cases if r['expected']!='uncertain')
        stats['type_precision']=stats['type_correct']/predicted if predicted else 0
        stats['type_recall']=stats['type_correct']/stats['total']
        a=stats['type_precision'];b=stats['type_recall'];stats['type_f1']=2*a*b/(a+b) if a+b else 0
    times=sorted(r['latency_ms'] for r in cases)
    return {'model_quality_available':valid>0,'tp':tp,'fp':fp,'tn':tn,'fn_including_abstained_attacks':fn,'positive_abstentions':abstain_positive,'negative_abstentions':abstain_negative,'call_failures':failures,
            'precision':precision,'system_recall':recall,'f1':2*precision*recall/(precision+recall) if precision+recall else 0,
            'coverage':valid/len(cases) if cases else 0,'normal_false_positive_rate':fp/(fp+tn+abstain_negative) if fp+tn+abstain_negative else 0,
            'per_attack_type':types,'macro_type_f1':sum(t['type_f1'] for t in types.values())/len(types) if types else 0,'ambiguous_cases':len(ambiguous),'ambiguous_abstentions':sum(r['prediction']=='uncertain' or r['status']!='success' for r in ambiguous),
            'latency_p50_ms':statistics.median(times) if times else 0,'latency_p95_ms':times[min(len(times)-1,int(len(times)*.95))] if times else 0}


def run(path,mode='rules',split='test',progress=None):
    rows,digest=load(path);rows=[r for r in rows if r['split']==split];run_id=secrets.token_hex(12);cases=[]
    if not rows:raise ValueError('empty_evaluation_split')
    if mode=='ai' and len(rows)>500:raise ValueError('ai_evaluation_limit_500')
    from db.http_requests import calculate_threat_score,_classify_web_event_type
    mapping={'xss_probe':'xss','sqli_probe':'sqli','path_traversal':'path_traversal','lfi_probe':'path_traversal','file_probe':'path_traversal','webshell_probe':'command_injection','ssrf_probe':'ssrf','ssti_probe':'ssti','xxe_probe':'xxe','scanner_probe':'scanner','admin_probe':'scanner','exploit_attempt':'other'}
    for index,row in enumerate(rows,1):
        start=time.perf_counter();f=row['fields'];headers={'User-Agent':f['user_agent'],'Referer':f['referer'],'Content-Type':f['content_type']}
        score,suspicious,signals=calculate_threat_score(f['method'],f['path'],f['query'],headers,f['body']);snapshot=ai_detection.make_snapshot(f['method'],f['path'],f['query'],f['body'],headers,score,signals,'evaluation')
        if mode=='rules':
            event=_classify_web_event_type(f['method'],f['path'],f['query'],f['body'],signals);result={'status':'success','data':{'verdict':'suspicious' if suspicious else 'no_clear_attack','attack_types':[mapping.get(event,'other')] if suspicious else []},'call_id':''}
        else:
            result=local_ai.call_model('web_detect',messages(snapshot),'evaluation:'+run_id[:8]+':'+row['id'][:8],'evaluation',schema=ai_detection.SCHEMA,validator=lambda obj:ai_detection.validate_result(obj,snapshot),budget=100,options={'timeout':local_ai.SETTINGS.get('analysis_timeout',20),'num_predict':512})
        obj=result.get('data',{});entry={'id':row['id'],'group':row['group'],'expected':row['label'],'attack_type':row.get('attack_type',''),'prediction':obj.get('verdict','uncertain'),'predicted_types':obj.get('attack_types',[]),'status':result['status'],'reason':result.get('reason',''),'latency_ms':round((time.perf_counter()-start)*1000,3),'call_id':result.get('call_id',''),'rule_score':score,'validated_result':obj}
        cases.append(entry)
        if progress:progress(index,len(rows),entry)
    code=Path(ai_detection.__file__).read_bytes()+Path(calculate_threat_score.__code__.co_filename).read_bytes()
    return {'run_id':run_id,'created':time.time(),'mode':mode,'split':split,'dataset_sha256':digest,'code_sha256':hashlib.sha256(code).hexdigest(),'model':local_ai.SETTINGS['model'] if mode=='ai' else '',
            'samples':len(rows),'groups':len({r['group'] for r in rows}),'metrics':summarize(cases),'cases':cases,
            'scope':'固定合成分组测试集；同族变形不是独立真实流量。开发与测试按族隔离且规范化重复不跨集合。不能据此承诺真实场景准确率。'}
