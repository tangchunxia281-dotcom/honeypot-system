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
    api_key=value('api_key','').strip()
    if provider in ('deepseek','openai'):
        from utils.integration_settings import cloud_endpoint
        try:cloud_endpoint(base);valid=True
        except ValueError:valid=False
        configured=bool(valid and model and len(model)<=160 and api_key and len(api_key)<=512 and not any(ord(c)<33 or ord(c)>126 for c in api_key) and not error)
    elif provider!='local':configured=False
    db_path = Path(os.environ.get('HONEYPOT_AI_DB', value('runtime_db', 'database/ai_runtime.db')))
    if not db_path.is_absolute():
        db_path = ROOT / db_path
    return dict(enabled=boolean('enabled', False) and not error, ssh_enabled=boolean('ssh_enabled', False),
                base_url=base, model=model[:160], configured=configured,provider=provider,api_key=api_key,
                configuration_error=error or ('' if configured else 'local_endpoint_or_model_invalid'),
                timeout=integer('timeout', 10, 1, 30), concurrency=integer('concurrency', 1, 1, 4),
                max_calls_per_session=integer('max_calls_per_session', 10, 1, 100),
                min_interval=integer('min_interval', 2, 0, 60), think=boolean('think', False),
                context_length=integer('context_length', 4096, 512, 8192),gpu_layers=integer('gpu_layers',-1,-1,256),
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
