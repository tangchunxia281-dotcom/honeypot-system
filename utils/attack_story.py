"""Observed order is program data. Model stages are explicitly inferences."""
from collections import Counter
from team_center.store import clean

STAGES=('reconnaissance','credential_attempt','injection_attempt','access_attempt','collection','unknown')
STORY_SCHEMA={'type':'object','properties':{'summary':{'type':'string','maxLength':240},'stages':{'type':'array','maxItems':6,'items':{'type':'object','properties':{'name':{'type':'string','enum':list(STAGES)},'description':{'type':'string','maxLength':160},'refs':{'type':'array','maxItems':4,'items':{'type':'string'}}},'required':['name','description','refs'],'additionalProperties':False}},'limitations':{'type':'string','maxLength':240}},'required':['summary','stages','limitations'],'additionalProperties':False}

def validate_interpretation(obj,provided):
    if not isinstance(obj,dict) or set(obj)!={'summary','stages','limitations'}:raise ValueError('story_format_invalid')
    if any(not isinstance(obj[k],str) or len(obj[k])>240 for k in ('summary','limitations')) or not isinstance(obj['stages'],list) or len(obj['stages'])>6:raise ValueError('story_length_invalid')
    mapping={r['id']:r for r in provided}
    for stage in obj['stages']:
        if not isinstance(stage,dict) or set(stage)!={'name','description','refs'} or stage['name'] not in STAGES or not isinstance(stage['description'],str) or len(stage['description'])>160:raise ValueError('stage_invalid')
        refs=stage['refs']
        if not isinstance(refs,list) or not 1<=len(refs)<=4 or any(not isinstance(v,str) or v not in mapping for v in refs):
            from utils.ai_detection import EvidenceValidationError
            raise EvidenceValidationError('evidence_id_mismatch')
    return {'summary':clean(obj['summary'],240),'limitations':clean(obj['limitations'],240),'stages':[{'name':s['name'],'description':clean(s['description'],160),'refs':list(dict.fromkeys(s['refs']))} for s in obj['stages']]}

def build_story(records,interpretation=None):
    rows=sorted(records,key=lambda r:(r['timestamp'],r.get('sensor_id',''),r['id']))[:60]
    same=Counter(r['timestamp'] for r in rows);mapping={r['id']:r for r in rows}
    facts=[{**r,'certainty':'observed_record','simultaneous':same[r['timestamp']]>1} for r in rows]
    obj=validate_interpretation(interpretation,rows) if interpretation is not None else None
    inferences=[]
    for s in obj['stages'] if obj else []:
        inferences.append({**s,'certainty':'ai_inference','evidence':[{'id':identifier,'quote':mapping[identifier]['excerpt'][:180]} for identifier in s['refs']]})
    sessions={(r.get('sensor_id',''),r.get('session_id','')) for r in rows}
    return {'facts':facts,'inferences':inferences,'summary':obj['summary'] if obj else '程序已整理可见记录；AI解释尚未完成。','ai_status':'completed' if obj else 'not_completed',
            'same_session':len(sessions)==1 and bool(next(iter(sessions))[1]) if sessions else False,'host_compromise_confirmed':False,
            'limitations':'同刻记录不确定先后，同IP不证明同一攻击者；关联不证明因果，虚拟登录或数据访问不证明真实主机被攻破。'+(obj['limitations'] if obj else ''),
            'coverage':{'available':len(records),'displayed':len(rows),'truncated':len(records)>60,'model_provided':None if obj else 0}}
