"""Separate local-model settings; preserve the project's original real config."""
import configparser
import os
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


def load_settings():
    parser = configparser.ConfigParser(interpolation=None)
    path = Path(os.environ.get('HONEYPOT_AI_CONFIG', ROOT / 'ai.local.ini'))
    error = ''
    try:
        parser.read(path, encoding='utf-8-sig')
    except (OSError, configparser.Error):
        error = 'configuration_parse_error'

    def value(key, default):
        return os.environ.get('HONEYPOT_AI_' + key.upper(), parser.get('ai', key, fallback=str(default)))

    def integer(key, default, low, high):
        try:
            return max(low, min(high, int(value(key, default))))
        except (TypeError, ValueError):
            return default

    def boolean(key, default):
        return str(value(key, default)).strip().lower() in ('true', '1', 'yes', 'on')

    base = value('base_url', 'http://127.0.0.1:11434').strip().rstrip('/')
    model = value('model', '').strip()
    try:
        url = urlsplit(base)
        valid = (url.scheme in ('http', 'https') and url.hostname in ('127.0.0.1', 'localhost', '::1')
                 and not url.username and not url.password and not url.query and not url.fragment
                 and url.path in ('', '/') and (url.port is None or 1 <= url.port <= 65535))
    except ValueError:
        valid = False
    configured = bool(valid and model and len(model) <= 160 and not error)
    provider=value('provider','local').strip().lower()
    gateway=value('gateway_url','http://127.0.0.1:11500').strip().rstrip('/')
    token=value('client_token','').strip()
    api_key=value('api_key','').strip()
    deepseek_base=value('deepseek_base_url','https://api.deepseek.com').strip().rstrip('/')
    deepseek_model=value('deepseek_model','deepseek-chat').strip()
    if provider=='gateway':
        try:
            remote=urlsplit(gateway);addr=ipaddress.ip_address(remote.hostname)
            safe_addr=addr.is_loopback or addr.version==4 and any(addr in ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')) or addr.version==6 and addr in ipaddress.ip_network('fc00::/7')
            valid_remote=remote.scheme in ('http','https') and safe_addr and not remote.username and not remote.password and not remote.query and not remote.fragment and remote.path in ('','/') and (remote.port is None or 1<=remote.port<=65535)
            valid_remote=valid_remote and (addr.is_loopback or remote.scheme=='https' or boolean('allow_insecure_lan',False))
        except ValueError:valid_remote=False
        configured=bool(valid_remote and re.fullmatch(r'[A-Za-z0-9_-]{32,256}',token) and model and not error)
    elif provider=='deepseek':
        try:
            durl=urlsplit(deepseek_base)
            valid_deepseek=(durl.scheme=='https' and durl.hostname and not durl.username and not durl.password
                            and not durl.query and not durl.fragment and durl.path in ('','/')
                            and (durl.port is None or 1<=durl.port<=65535))
        except ValueError:
            valid_deepseek=False
        if not model:
            model=deepseek_model
        base=deepseek_base
        configured=bool(valid_deepseek and re.fullmatch(r'sk-[A-Za-z0-9]{20,}',api_key)
                        and model and len(model)<=160 and not error)
    elif provider!='local':configured=False
    db_path = Path(os.environ.get('HONEYPOT_AI_DB', value('runtime_db', 'database/ai_runtime.db')))
    if not db_path.is_absolute():
        db_path = ROOT / db_path
    return dict(enabled=boolean('enabled', False) and not error, ssh_enabled=boolean('ssh_enabled', False),
                base_url=base, model=model[:160], configured=configured,provider=provider,gateway_url=gateway,client_token=token,
                api_key=api_key,
                configuration_error=error or ('' if configured else 'local_endpoint_or_model_invalid'),
                timeout=integer('timeout', 30 if provider=='deepseek' else 10, 1, 30), concurrency=integer('concurrency', 1, 1, 4),
                max_calls_per_session=integer('max_calls_per_session', 10, 1, 100),
                min_interval=integer('min_interval', 2, 0, 60), think=boolean('think', False),
                context_length=integer('context_length', 4096, 512, 8192),
                max_output_tokens=integer('max_output_tokens', 256, 64, 512), db_path=str(db_path),
                analysis_enabled=boolean('analysis_enabled', False),periodic_enabled=boolean('periodic_enabled',True),
                analysis_timeout=integer('analysis_timeout',20,5,30),gateway_wait=integer('gateway_wait',90,10,120),
                analysis_batch=integer('analysis_batch',24,6,48),
                analysis_samples=integer('analysis_samples',6,3,8),
                analysis_flush=integer('analysis_flush',60,15,300),
                analyst_retention_days=integer('analyst_retention_days',30,1,365),
                interactive_wait=integer('interactive_wait',2,0,5),
                web_interaction_enabled=boolean('web_interaction_enabled', False),
                interaction_ttl=integer('interaction_ttl', 1800, 60, 7200),
                interaction_sessions=integer('interaction_sessions', 128, 8, 512),
                interaction_steps=integer('interaction_steps', 100, 5, 1000),
                interaction_per_ip_hour=integer('interaction_per_ip_hour', 40, 1, 200),
                detection_enabled=boolean('detection_enabled', False),
                detection_delay=integer('detection_delay',3,0,10),
                detection_queue_max=integer('detection_queue_max', 32, 1, 128),
                detection_per_ip_hour=integer('detection_per_ip_hour', 20, 1, 100),
                normal_sample_every=integer('normal_sample_every', 10, 1, 1000))
