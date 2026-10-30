"""Authenticated, CSRF-protected local AI wizard routes."""
import json
import os
import threading
from functools import wraps
from pathlib import Path

from flask import jsonify, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge
from utils.ai_setup import AISetup

BODY_LIMIT = 4096


def register(app, login, csrf):
    state = {};guard = threading.Lock()

    def wizard():
        with guard:
            if 'wizard' not in state:
                root = Path(__file__).resolve().parents[1]
                path = app.config.get('AI_SETUP_CONFIG') or os.environ.get('HONEYPOT_AI_CONFIG') or root / 'ai.local.ini'
                state['wizard'] = AISetup(path)
            return state['wizard']

    def body(optional=False):
        if request.content_length is not None and request.content_length > BODY_LIMIT:raise RequestEntityTooLarge()
        raw = request.stream.read(BODY_LIMIT + 1)
        if len(raw) > BODY_LIMIT:raise RequestEntityTooLarge()
        if optional and not raw:return {}
        if request.mimetype != 'application/json':raise ValueError('json_object_required')
        try:data = json.loads(raw)
        except (ValueError, UnicodeError, RecursionError):raise ValueError('invalid_json') from None
        if not isinstance(data, dict):raise ValueError('json_object_required')
        return data

    def route(path, methods=('GET',)):
        def decorate(fn):
            @wraps(fn)
            def safe(*args, **kwargs):
                try:return fn(*args, **kwargs)
                except RequestEntityTooLarge:return jsonify(error='request_too_large'), 413
                except BadRequest:return jsonify(error='invalid_json'), 400
                except (ValueError, TypeError) as error:
                    return jsonify(error=str(error)[:120]), 409 if str(error) == 'task_running' else 400
                except (ConnectionError, TimeoutError):return jsonify(error='local_service_unavailable'), 503
                except OSError:return jsonify(error='local_storage_unavailable'), 503
            endpoint = safe
            if 'POST' in methods:
                protected = csrf(safe)
                @wraps(fn)
                def endpoint(*args, **kwargs):
                    # Run this before the dashboard CSRF decorator, whose form
                    # fallback otherwise parses a body before our JSON limit.
                    if request.content_length is not None and request.content_length > BODY_LIMIT:
                        return jsonify(error='request_too_large'), 413
                    if not request.headers.get('X-CSRF-Token'):
                        return jsonify(error='csrf_header_required'), 403
                    return protected(*args, **kwargs)
            app.add_url_rule(path, 'ai_setup_' + fn.__name__, login(endpoint), methods=list(methods))
            return fn
        return decorate

    @route('/api/setup/environment')
    def environment():return jsonify(wizard().environment())

    @route('/api/setup/config', ('POST',))
    def configure():return jsonify(wizard().configure(body()))

    @route('/api/setup/tasks', ('POST',))
    def start():
        data = body()
        if set(data) != {'kind', 'model'}:raise ValueError('task_fields_required')
        return jsonify(wizard().start(data['kind'], data['model'])), 202

    @route('/api/setup/tasks/current')
    def current():return jsonify(wizard().status())

    @route('/api/setup/tasks/current/cancel', ('POST',))
    def cancel():
        if body(optional=True):raise ValueError('unknown_cancel_fields')
        return jsonify(wizard().cancel())

    app.ai_setup = wizard
