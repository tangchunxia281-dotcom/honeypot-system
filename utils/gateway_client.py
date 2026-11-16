"""Shared queue adapter. Tokens stay in backend settings, never browser output."""
import time
import json
import re
import requests


def bounded_json(response,deadline):
    raw=bytearray()
    for chunk in response.iter_content(chunk_size=1):
        if time.monotonic()>deadline:raise TimeoutError('gateway_timeout')
        raw.extend(chunk)
        if len(raw)>70000:raise ValueError('invalid_model_output')
    data=json.loads(raw)
    if not isinstance(data,dict):raise ValueError('invalid_model_output')
    return data


def transport(settings,messages,schema,options):
    timeout=int((options or {}).get('timeout',settings['timeout']))
    wait=max(1,min(settings.get('gateway_wait',90),(options or {}).get('gateway_wait',settings.get('gateway_wait',90))))
    deadline=time.monotonic()+wait
    job=None;completed=False
    with requests.Session() as client:
        client.trust_env=False;client.headers['Authorization']='Bearer '+settings['client_token']
        base=settings['gateway_url']
        try:
            response=client.post(base+'/v1/jobs',json={'request_id':options['request_id'],'task':options['task'],'messages':messages,'schema':schema,
                'options':{'timeout':max(5,min(30,timeout)),'num_predict':options.get('num_predict',512),'num_ctx':settings['context_length'],'think':settings['think']}},timeout=(3,min(5,timeout)),allow_redirects=False,stream=True)
            try:body=bounded_json(response,deadline)
            finally:response.close()
            if response.status_code!=202:raise ValueError(body.get('reason','model_http_error'))
            job=body['data']['id']
            if not isinstance(job,str) or not re.fullmatch(r'[a-f0-9]{24}',job):raise ValueError('invalid_model_output')
            while time.monotonic()<deadline:
                with client.get(base+'/v1/jobs/'+job,timeout=(2,max(1,min(3,deadline-time.monotonic()))),allow_redirects=False,stream=True) as r:
                    if r.status_code!=200:raise ValueError('model_http_error')
                    row=bounded_json(r,deadline)['data']
                if row['status']=='completed':
                    completed=True;data=row['result']
                    if options.get('include_timing') and type(row.get('started')) in (int,float) and type(row.get('created')) in (int,float):data=dict(data,gateway_queue_ms=max(0,round((row['started']-row['created'])*1000,3)))
                    return data
                if row['status'] in ('fallback','cancelled'):raise ValueError(row['reason'] or 'gateway_cancelled')
                time.sleep(.15)
            raise TimeoutError('gateway_timeout')
        finally:
            if job and not completed:
                try:client.post(base+'/v1/jobs/'+job+'/cancel',json={},timeout=(1,1),allow_redirects=False)
                except requests.RequestException:pass


def status(settings):
    with requests.Session() as client:
        client.trust_env=False
        with client.get(settings['gateway_url']+'/v1/status',headers={'Authorization':'Bearer '+settings['client_token']},timeout=(1,2),allow_redirects=False,stream=True) as r:
            if r.status_code!=200:raise ValueError('gateway_auth_failed')
            return bounded_json(r,time.monotonic()+3)['data']
