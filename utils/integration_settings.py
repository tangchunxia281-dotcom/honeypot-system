"""Validated integration configuration, shared by UI and command-line tools."""
import configparser
import io
import ipaddress
import os
import re
import threading
from pathlib import Path
from urllib.parse import urlsplit
from utils.ai_setup import _atomic

LOCK=threading.RLock()
ROOT=Path(__file__).resolve().parents[1]
PROTOCOLS={'mysql':13306,'redis':16379,'ftp':2121,'telnet':2223}
def parser(path):
    p=configparser.ConfigParser(interpolation=None)
    if Path(path).exists():p.read(path,encoding='utf-8-sig')
    return p
def write(path,p):
    out=io.StringIO();p.write(out);_atomic(Path(path),out.getvalue())
def cloud_endpoint(value):
    try:
        u=urlsplit(value)
        valid=u.scheme=='https' and u.hostname and not u.username and not u.password and not u.query and not u.fragment and (u.port is None or 1<=u.port<=65535)
        try:
            if ipaddress.ip_address(u.hostname).is_private:valid=False
        except ValueError:pass
    except (ValueError,TypeError):valid=False
    if not valid:raise ValueError('cloud_https_endpoint_required')
    return value.rstrip('/')
def cloud_public(path):
    p=parser(path)
    return {'provider':p.get('ai','provider',fallback='local'),'base_url':p.get('ai','base_url',fallback='https://api.deepseek.com'),
            'model':p.get('ai','model',fallback=''),'enabled':p.getboolean('ai','enabled',fallback=False),
            'key_configured':bool(p.get('ai','api_key',fallback='')or os.environ.get('HONEYPOT_AI_API_KEY')),'restart_required':True}
def save_cloud(path,data):
    if not isinstance(data,dict) or set(data)-{'provider','base_url','model','api_key','enabled','consent','clear_key'}:raise ValueError('unknown_fields')
    if data.get('provider')not in('deepseek','openai')or type(data.get('enabled'))is not bool:raise ValueError('cloud_provider_invalid')
    if data['enabled'] and data.get('consent')is not True:raise ValueError('cloud_consent_required')
    base=cloud_endpoint(data.get('base_url',''));model=data.get('model','')
    if not isinstance(model,str) or not re.fullmatch(r'[A-Za-z0-9_./:-]{1,160}',model):raise ValueError('model_invalid')
    key=data.get('api_key','')
    if not isinstance(key,str)or len(key)>512 or any(ord(x)<33 or ord(x)>126 for x in key):raise ValueError('api_key_invalid')
    with LOCK:
        p=parser(path)
        if not p.has_section('ai'):p.add_section('ai')
        if data.get('clear_key')is True:p.remove_option('ai','api_key')
        if key:p.set('ai','api_key',key)
        if data['enabled']and not (p.get('ai','api_key',fallback='')or os.environ.get('HONEYPOT_AI_API_KEY')):raise ValueError('api_key_required')
        for k,v in {'provider':data['provider'],'base_url':base,'model':model,'enabled':str(data['enabled']).lower()}.items():p.set('ai',k,v)
        if data['enabled']:
            for k in ('ssh_enabled','analysis_enabled','detection_enabled','web_interaction_enabled'):p.set('ai',k,'true')
        write(path,p)
    return cloud_public(path)

def protocol_settings(path=None):
    from app_config import env_bool,env_int,env_str
    p=parser(path or os.environ.get('HONEYPOT_CONFIG',ROOT/'honeypot.ini'));out=[]
    for name,port in PROTOCOLS.items():
        section='services.'+name
        out.append({'protocol':name,'enabled':p.getboolean(section,'enabled',fallback=True),'host':p.get(section,'host',fallback='127.0.0.1'),'port':p.getint(section,'port',fallback=port)})
    return out
def save_protocols(path,items):
    if not isinstance(items,list)or len(items)!=4:raise ValueError('four_protocol_settings_required')
    if {x.get('protocol')for x in items if isinstance(x,dict)}!=set(PROTOCOLS):raise ValueError('protocol_invalid')
    ports=[]
    with LOCK:
        p=parser(path)
        for x in items:
            if set(x)-{'protocol','enabled','host','port'} or type(x.get('enabled'))is not bool or type(x.get('port'))is not int or not 1024<=x['port']<=65535:raise ValueError('protocol_setting_invalid')
            # Local contest deployment. LAN publication requires an explicit deployment change.
            if x.get('host')!='127.0.0.1':raise ValueError('local_listener_required')
            if x['enabled']:ports.append(x['port'])
            section='services.'+x['protocol']
            if not p.has_section(section):p.add_section(section)
            for k in ('enabled','host','port'):p.set(section,k,str(x[k]).lower()if k=='enabled'else str(x[k]))
        ports += [p.getint('services.'+s,'port',fallback=d)for s,d in [('ssh',2222),('web',5000),('dashboard',5001)]]
        if len(set(ports))!=len(ports):raise ValueError('port_conflict')
        write(path,p)
    return {'restart_required':True}
