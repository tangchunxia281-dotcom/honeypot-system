"""Local Ollama adapter: bounded text replies, audited fallback, no host actions."""
import hashlib
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

import requests
from utils.ai_settings import load_settings
from utils.ai_store import CallStore

SETTINGS=load_settings()
STORE=CallStore(SETTINGS['db_path'])
_pool=ThreadPoolExecutor(max_workers=SETTINGS['concurrency'],thread_name_prefix='local-ai')
_slots=threading.BoundedSemaphore(SETTINGS['concurrency'])
_guard=threading.Lock()
_health_cache={'expires':0,'result':None}
_health_lock=threading.Lock()
_CONTROL=re.compile(r'\x1b\][\s\S]*?(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b.|[\x00-\x08\x0b-\x1f\x7f-\x9f]')
_SECRET=re.compile(r'''(?i)(["']?(?:password|passwd|pwd|token|api_key|authorization)["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^&,;\r\n}]+)''')
REPLY_SCHEMA={'type':'object','properties':{'reply':{'type':'string'}},'required':['reply'],'additionalProperties':False}

@dataclass
class TimedOutput:
    value: object
    timing: dict

def model_timing(data):
    result={}
    for source,target in {'eval_duration':'generation_ms','prompt_eval_duration':'prompt_ms','load_duration':'load_ms','total_duration':'model_total_ms'}.items():
        value=data.get(source);result[target]=round(value/1000000,3) if type(value) is int and 0<=value<=3600*10**9 else None
    value=data.get('gateway_queue_ms');result['gateway_queue_ms']=value if type(value) in (int,float) and 0<=value<=120000 else None
    tokens=data.get('total_tokens');result['total_tokens']=tokens if type(tokens) is int and 0<=tokens<=1000000 else None
    return result


def safe_text(text,limit=1200):
    return _SECRET.sub(r'\1[redacted]',_CONTROL.sub('',str(text or ''))).strip()[:limit]


def _read_json(response,limit,deadline):
    if response.status_code != 200:
        raise ValueError('model_http_error')
    chunks=bytearray()
    total=0
    # Byte-wise streaming checks the total deadline even if a server drips data
    # just fast enough to keep resetting the socket's read timeout.
    for chunk in response.iter_content(chunk_size=1):
        if time.monotonic()>deadline:
            raise TimeoutError('deadline_exceeded')
        total+=len(chunk)
        if total>limit:
            raise ValueError('invalid_model_output')
        chunks.extend(chunk)
    return json.loads(chunks)


def _parse_model_json(content):
    """解析模型返回的 JSON 对象。

    严格模式优先；真实 API 偶尔会在 JSON 外包裹 ```json 围栏或一句说明，
    这里只提取第一个括号平衡的对象，字段校验仍由调用方完成。
    """
    try:
        return json.loads(content)
    except (TypeError, ValueError):
        pass
    text = str(content or '').strip()
    start = text.find('{')
    while start != -1:
        depth = 0
        for index in range(start, len(text)):
            char = text[index]
            if char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:index + 1])
                    except ValueError:
                        break
        start = text.find('{', start + 1)
    raise ValueError('invalid_model_output')


def _transport(messages,schema=None,options=None):
    timeout=(options or {}).get('timeout',SETTINGS['timeout'])
    deadline=time.monotonic()+timeout
    if SETTINGS.get('provider','local')=='gateway':
        from utils.gateway_client import transport
        data=transport(SETTINGS,messages,schema,options or {})
    elif SETTINGS.get('provider','local')=='deepseek':
        with requests.Session() as client:
            client.trust_env=False
            body={'model':SETTINGS['model'],'messages':messages,'stream':False,'temperature':0.2,
                  'max_tokens':(options or {}).get('num_predict',512 if schema else SETTINGS['max_output_tokens']),
                  'response_format':{'type':'json_object'}}
            with client.post(SETTINGS['base_url']+'/v1/chat/completions',
                headers={'Authorization':'Bearer '+SETTINGS.get('api_key','')},
                json=body,timeout=(min(3,timeout),timeout),allow_redirects=False,stream=True) as response:
                data=_read_json(response,65536,deadline)
        # Normalize the OpenAI-compatible response to the Ollama-like shape used below.
        try:
            choice=data['choices'][0]
            content=choice['message']['content']
            if choice.get('finish_reason')=='length':
                raise ValueError('model_output_truncated')
            usage=data.get('usage') or {}
            data={'message':{'content':content},'done':True,'total_tokens':usage.get('total_tokens')}
        except (KeyError,IndexError,TypeError):
            raise ValueError('invalid_model_output')
    else:
        with requests.Session() as client:
            client.trust_env=False
            with client.post(SETTINGS['base_url']+'/api/chat',json={
                'model':SETTINGS['model'],'messages':messages,'stream':False,'think':SETTINGS['think'],
                'format':schema or REPLY_SCHEMA,'keep_alive':'5m','options':{'num_ctx':SETTINGS['context_length'],
                    'num_predict':(options or {}).get('num_predict',512 if schema else SETTINGS['max_output_tokens']),'temperature':0.2}},
                timeout=(min(3,timeout),timeout),allow_redirects=False,stream=True) as response:
                data=_read_json(response,65536,deadline)
    if not isinstance(data,dict) or not isinstance(data.get('message'),dict):
        raise ValueError('invalid_model_output')
    if data.get('done_reason')=='length':raise ValueError('model_output_truncated')
    if data.get('done') is not True or data['message'].get('tool_calls'):
        raise ValueError('invalid_model_output')
    content=data.get('message',{}).get('content')
    if not isinstance(content,str) or len(content)>4096:
        raise ValueError('invalid_model_output')
    obj=_parse_model_json(content)
    if schema is not None:
        if not isinstance(obj,dict):raise ValueError('invalid_model_output')
        return TimedOutput(obj,model_timing(data)) if (options or {}).get('include_timing') else obj
    if not isinstance(obj,dict) or set(obj)!={'reply'} or not isinstance(obj['reply'],str):
        raise ValueError('invalid_model_output')
    reply=safe_text(obj['reply'])
    if not reply:
        raise ValueError('invalid_model_output')
    return reply


def _augment_with_schema(messages, schema):
    """把本地校验用的 JSON Schema 明确写进系统提示。

    Ollama 原生支持 `format=schema`，但 DeepSeek/网关走的是
    `response_format=json_object`，模型看不到字段约束，容易多输出
    `type`/`answer` 等键或漏掉 `evidence_id`。这里把 Schema 附加到 system
    消息，保持用户载荷仍是纯 JSON（审计与测试契约不变），字段校验仍由
    调用方执行，不放宽任何安全约束。
    """
    hint = ('\n\n[输出格式] 只输出一个 JSON 对象，键必须与下面 Schema 的 properties '
            '完全一致：不得新增、删除或改名，也不要输出 type 字段。\nSchema: '
            + json.dumps(schema, ensure_ascii=False))
    out = [dict(message) for message in messages]
    if out and str(out[0].get('role')) == 'system':
        out[0]['content'] = str(out[0].get('content') or '') + hint
        return out
    out.insert(0, {'role': 'system', 'content': hint.lstrip('\n')})
    return out


def call_model(task,messages,session_id,src_ip='',schema=None,validator=None,budget=None,options=None):
    if schema is not None and SETTINGS.get('provider') in ('deepseek','gateway'):
        messages=_augment_with_schema(messages,schema)
    started=time.monotonic()
    store=STORE
    call={'id':secrets.token_hex(12),'task':task,'session_id':str(session_id)[:64],
          'src_ip':str(src_ip)[:64],
          'input_sha256':hashlib.sha256(json.dumps(messages,ensure_ascii=False).encode()).hexdigest()}
    result={'call_id':call['id'],'status':'fallback','reason':'','reply':'','latency_ms':0}
    acquired=False
    try:
        admission=dict(SETTINGS)
        if options:
            admission['timeout']=options.get('timeout',admission['timeout'])
            admission['bypass_circuit']=bool(options.get('bypass_circuit'))
        if SETTINGS.get('provider','local')=='gateway':
            gateway_wait=min(SETTINGS.get('gateway_wait',90),(options or {}).get('gateway_wait',SETTINGS.get('gateway_wait',90)))
            admission['timeout']=max(admission['timeout'],gateway_wait)
        if budget:
            admission.update(max_calls_per_session=budget,min_interval=0)
        foreground=task in ('probe','ssh_reply','web_reply')
        wait_until=time.monotonic()+SETTINGS.get('interactive_wait',0) if foreground else 0
        if foreground:store.register_waiter(call['id'],SETTINGS.get('interactive_wait',0)+2)
        try:
            reason=store.start(call,admission,waitable=foreground and time.monotonic()<wait_until)
            while reason=='capacity_limit' and foreground and time.monotonic()<wait_until:
                time.sleep(.05)
                reason=store.start(call,admission,waitable=time.monotonic()<wait_until)
        finally:
            if foreground:store.unregister_waiter(call['id'])
        if reason:
            result['reason']=reason
            return result
        if not _slots.acquire(blocking=False):
            result['reason']='capacity_limit'
        else:
            acquired=True
            def work():
                try:
                    gateway_options=dict(options or {},request_id=call['id'],task=task) if SETTINGS.get('provider','local')=='gateway' else options
                    return _transport(messages,schema,gateway_options) if gateway_options else _transport(messages,schema) if schema is not None else _transport(messages)
                finally:
                    _slots.release()
                    try:
                        store.release(call['id'])
                    except Exception:
                        pass
            try:
                future=_pool.submit(work)
            except Exception:
                _slots.release()
                acquired=False
                raise ValueError('worker_unavailable')
            def finished(_future):
                if _future.cancelled():
                    _slots.release()
                    try:
                        store.release(call['id'])
                    except Exception:
                        pass
            future.add_done_callback(finished)
            try:
                reply=future.result(timeout=admission['timeout'])
                if isinstance(reply,TimedOutput):result['model_timing']=reply.timing;reply=reply.value
                if validator is not None:
                    structured=validator(reply)
                    result.update(status='success',data=structured,reply=json.dumps(structured,ensure_ascii=False))
                else:
                    result.update(status='success',reply=reply)
            except FutureTimeout:
                future.cancel()
                result['reason']='deadline_exceeded'
    except (requests.RequestException,ConnectionError):
        result['reason']='model_unavailable'
    except TimeoutError:
        result['reason']='deadline_exceeded'
    except (ValueError,TypeError,KeyError) as error:
        reason=str(error)
        result['reason']=reason if reason in ('model_unavailable','model_http_error','worker_unavailable','invalid_model_output','model_output_truncated','gateway_auth_failed','gateway_queue_full','gateway_client_pending','gateway_client_budget','gateway_timeout','gateway_cancelled','gateway_worker_interrupted','gateway_worker_error') else 'invalid_model_output'
        result['validation_detail']=getattr(error,'code','schema_or_evidence_invalid') if result['reason']=='invalid_model_output' else ''
    except Exception:
        result['reason']='audit_storage_unavailable'
    finally:
        result['latency_ms']=round((time.monotonic()-started)*1000)
        try:
            # Rejected calls are already final; admitted calls are finalized here.
            store.finish(call['id'],result['status'],result['reason'],result['latency_ms'],result['reply'],result.get('validation_detail',''))
            if not acquired:
                store.release(call['id'])
        except Exception:
            if result['status']=='success':
                result.update(status='fallback',reason='audit_storage_unavailable',reply='')
                result.pop('data',None)
    return result


def probe(session_id,src_ip=''):
    return call_model('probe',[{'role':'system','content':'Return only JSON {"reply":"..."}. '
        'This is a local honeypot connection test. You have no tools or host access.'},
        {'role':'user','content':'请在 reply 中用一句中文确认本地模型连接验收成功。'}],session_id,src_ip)


def ssh_reply(shell,command):
    # Only validated strategies may produce a simulated response.
    from utils.ai_interaction import ssh_reply as controlled_reply
    return controlled_reply(shell,command)


def health(force=False):
    with _health_lock:
        if not force and time.monotonic()<_health_cache['expires']:
            return dict(_health_cache['result'])
        result=dict(service_reachable=False,model_available=False,model_loaded=False,
                    reason='not_checked',checked_at=time.time())
        if not SETTINGS['configured']:
            result['reason']='configuration_invalid'
        elif SETTINGS.get('provider','local')=='gateway':
            try:
                from utils.gateway_client import status as gateway_status
                shared=gateway_status(SETTINGS)
                result.update(service_reachable=bool(shared.get('model_reachable')),model_available=shared['model']==SETTINGS['model'] and bool(shared.get('model_available')),model_loaded=shared.get('model_loaded'),
                    reason='shared_gateway_ready' if shared['model']==SETTINGS['model'] and shared.get('model_available') else 'gateway_model_mismatch' if shared['model']!=SETTINGS['model'] else 'gateway_connected_model_unavailable',gateway=shared)
            except Exception:result['reason']='gateway_unavailable'
        elif SETTINGS.get('provider','local')=='deepseek':
            try:
                with requests.Session() as client:
                    client.trust_env=False
                    with client.get(SETTINGS['base_url']+'/v1/models',
                        headers={'Authorization':'Bearer '+SETTINGS.get('api_key','')},
                        timeout=(2,5),stream=True,allow_redirects=False) as response:
                        data=_read_json(response,2_000_000,time.monotonic()+6)
                    result['service_reachable']=True
                    listed=[str(m.get('id') or '') for m in data.get('data',[]) if isinstance(m,dict)]
                    exact=SETTINGS['model'] in listed
                    # DeepSeek 会用别名把 deepseek-chat 指向当前在售模型，
                    # /v1/models 可能只列出新代号，因此按同一 family 兜底判断。
                    family=str(SETTINGS['model']).split('-')[0]
                    family_match=any(item.split('-')[0]==family for item in listed if item)
                    result['model_available']=bool(exact or family_match)
                    result['model_loaded']=result['model_available']
                    result['model_listed']=exact
                    result['available_models']=listed[:20]
                    result['reason']='ready_for_call' if exact else ('ready_for_call_alias' if family_match else 'model_not_installed')
            except Exception:
                result['reason']='model_unavailable'
        else:
            try:
                with requests.Session() as client:
                    client.trust_env=False
                    with client.get(SETTINGS['base_url']+'/api/tags',timeout=(1,1),stream=True,allow_redirects=False) as response:
                        data=_read_json(response,2_000_000,time.monotonic()+2)
                    result['service_reachable']=True
                    result['model_available']=any(m.get('name')==SETTINGS['model'] for m in data.get('models',[]))
                    result['reason']='ready_for_call' if result['model_available'] else 'model_not_installed'
                    try:
                        with client.get(SETTINGS['base_url']+'/api/ps',timeout=(1,1),stream=True,allow_redirects=False) as response:
                            loaded=_read_json(response,2_000_000,time.monotonic()+2)
                        result['model_loaded']=any(m.get('name')==SETTINGS['model'] for m in loaded.get('models',[]))
                    except Exception:
                        pass
            except Exception:
                result['reason']='model_unavailable'
        _health_cache.update(expires=time.monotonic()+5,result=result)
        return dict(result)


def status():
    view={k:SETTINGS[k] for k in ('enabled','ssh_enabled','configured','model','timeout','concurrency')}
    view['health']=health()
    view['provider']=SETTINGS.get('provider','local')
    try:
        view.update(STORE.snapshot(),storage_available=True)
    except Exception:
        view.update(storage_available=False,counts={},active=0,recent=[],last_success_at=None)
    return view
