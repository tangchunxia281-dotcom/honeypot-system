"""Wizard checks use fake Ollama responses; they never install or fetch weights."""
import configparser
import json
import sys
import tempfile
import threading
import time
import unittest
from functools import wraps
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class Response:
    def __init__(self, data=None, lines=None, status=200):
        self.status_code = status
        self.payload = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.lines = lines
    def __enter__(self):return self
    def __exit__(self, *args):pass
    def close(self):pass
    def iter_content(self, chunk_size=1):
        payload = b'\n'.join(self.lines) + b'\n' if self.lines is not None else self.payload
        for start in range(0, len(payload), chunk_size):yield payload[start:start + chunk_size]


def answer(verdict, reference='E1', quote='GET /products?page=1'):
    return Response({'done': True, 'message': {'role': 'assistant', 'content': json.dumps({
        'verdict': verdict, 'citations': [{'evidence_id': reference, 'quote': quote}]})}})


class Session:
    replies = []
    requests = []
    trust_env = True
    def __enter__(self):return self
    def __exit__(self, *args):pass
    def get(self, url, **kwargs):
        self.requests.append(('GET', url, kwargs, self.trust_env))
        return self.replies.pop(0)
    def post(self, url, **kwargs):
        self.requests.append(('POST', url, kwargs, self.trust_env))
        return self.replies.pop(0)


class SetupChecks(unittest.TestCase):
    def setUp(self):
        from utils.ai_setup import AISetup
        self.tmp = tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'ai.ini'
        self.wizard = AISetup(self.path)
        Session.replies = [];Session.requests = []
    def client(self, *responses):
        Session.replies = list(responses)
        return patch('utils.ai_setup.requests.Session', Session)
    def wait(self):
        deadline = time.monotonic() + 2
        while self.wizard.status()['status'] in ('running', 'cancelling') and time.monotonic() < deadline:
            time.sleep(.01)
        return self.wizard.status()
    def test_rejects_remote_endpoints_and_unknown_downloads_before_network(self):
        from utils.ai_setup import AISetup
        for url in ('http://example.com', 'http://127.0.0.1.evil', 'http://user@127.0.0.1',
                    'http://127.0.0.1:11434/api', 'http://127.0.0.1?target=x'):
            with self.assertRaises(ValueError):AISetup(self.path, url)
        with self.assertRaises(ValueError):self.wizard.start('download', 'unknown:huge')
        with self.assertRaises(ValueError):self.wizard.start('test', 'a' * 161)
    def test_installed_models_use_bounded_direct_loopback_requests(self):
        with self.client(Response({'models': [{'name': 'fixture:small', 'size': 100}]})):
            self.assertEqual(self.wizard.installed(), [{'name': 'fixture:small', 'size': 100}])
        _, url, options, trust_env = Session.requests[0]
        self.assertEqual(url, 'http://127.0.0.1:11434/api/tags')
        self.assertFalse(trust_env);self.assertFalse(options['allow_redirects'])
        with self.client(Response(b'x' * 70000)):
            with self.assertRaises(ValueError):self.wizard.installed()
    def test_configuration_preserves_values_and_requires_exact_installed_name(self):
        self.path.write_text('[ai]\nenabled=false\nssh_enabled=false\nanalysis_enabled=false\ndetection_enabled=false\nweb_interaction_enabled=false\nanalysis_batch=24\n[other]\nname=keep\n', encoding='utf-8')
        with patch.object(self.wizard, 'installed', return_value=[{'name': 'fixture:small', 'size': 1}]):
            with self.assertRaises(ValueError):self.wizard.configure({'enabled': True, 'model': 'fixture'})
            result = self.wizard.configure({'enabled': True, 'model': 'fixture:small'})
        parser = configparser.ConfigParser();parser.read(self.path)
        self.assertEqual(parser['ai']['analysis_batch'], '24');self.assertEqual(parser['other']['name'], 'keep')
        self.assertTrue(result['restart_required']);self.assertTrue(parser.getboolean('ai', 'enabled'))
        for flag in ('ssh_enabled', 'analysis_enabled', 'detection_enabled', 'web_interaction_enabled'):
            self.assertTrue(parser.getboolean('ai', flag))
        self.assertFalse(list(self.path.parent.glob('*.tmp')))
        with patch.object(self.wizard, 'installed', side_effect=AssertionError('no service call')):
            self.wizard.configure({'enabled': False, 'model': ''})
    def test_low_disk_download_never_starts(self):
        with patch('utils.ai_setup.shutil.disk_usage', return_value=type('Disk', (), {'total': 100, 'free': 1})()):
            with self.assertRaisesRegex(ValueError, 'insufficient_disk'):self.wizard.start('download', 'qwen3:1.7b')
        self.assertEqual(self.wizard.status()['status'], 'idle')
    def test_download_stream_completes_without_claiming_model_quality(self):
        with self.client(Response(lines=[b'{"status":"pulling","digest":"sha256:x","total":100,"completed":50}', b'{"status":"success"}'])):
            self.wizard._download('qwen3:1.7b')
        result = self.wizard.status()
        self.assertEqual(result['status'], 'completed');self.assertEqual(result['progress'], 100)
        self.assertNotIn('passed', result)
        audit = self.wizard.history_path.read_text(encoding='utf-8')
        self.assertIn('completed', audit);self.assertNotIn('messages', audit)
    def test_truncated_and_oversized_download_streams_fail(self):
        for lines in ([b'{"status":"pulling"}'], [b'x' * 17000]):
            with self.client(Response(lines=lines)):
                self.wizard._download('qwen3:1.7b')
            self.assertEqual(self.wizard.status()['status'], 'failed')
    def test_one_task_and_cancel_keep_slot_until_worker_stops(self):
        entered = threading.Event();release = threading.Event()
        def waiting(model):
            entered.set();release.wait(2)
        with patch.object(self.wizard, '_download', side_effect=waiting):
            self.wizard.start('download', 'qwen3:1.7b');self.assertTrue(entered.wait(1))
            self.wizard.cancel()
            with self.assertRaisesRegex(ValueError, 'task_running'):self.wizard.start('download', 'qwen3:4b')
            release.set();result = self.wait()
        self.assertEqual(result['status'], 'cancelled')
    def test_selected_model_test_is_isolated_and_checks_two_fixed_samples(self):
        self.path.write_text('[ai]\nenabled=false\nmodel=old\n', encoding='utf-8')
        before = self.path.read_bytes()
        tags = Response({'models': [{'name': 'fixture:small', 'size': 1}]})
        with self.client(tags, answer('benign'), answer('injection', quote="GET /products?id=1 UNION SELECT password FROM users")):
            self.wizard.start('test', 'fixture:small');result = self.wait()
        self.assertEqual(result['status'], 'completed');self.assertTrue(result['passed'])
        self.assertEqual(result['checks'], {'http_reachable': True, 'format_valid': True, 'fixed_samples_correct': True, 'references_valid': True})
        self.assertEqual(self.path.read_bytes(), before)
        chats = [row for row in Session.requests if row[0] == 'POST']
        self.assertEqual(len(chats), 2)
        self.assertTrue(all(row[2]['json']['model'] == 'fixture:small' for row in chats))
    def test_invented_reference_and_wrong_verdict_are_distinct_failures(self):
        tags = Response({'models': [{'name': 'fixture:small', 'size': 1}]})
        with self.client(tags, answer('injection', reference='E9'), answer('injection', quote='invented')):
            self.wizard.start('test', 'fixture:small');result = self.wait()
        self.assertEqual(result['status'], 'completed');self.assertFalse(result['passed'])
        self.assertTrue(result['checks']['format_valid']);self.assertFalse(result['checks']['references_valid'])
        self.assertFalse(result['checks']['fixed_samples_correct'])
    def test_invalid_model_json_is_reachable_but_not_format_valid(self):
        tags = Response({'models': [{'name': 'fixture:small', 'size': 1}]})
        with self.client(tags, Response({'done': True, 'message': {'content': 'not JSON'}}), answer('injection')):
            self.wizard.start('test', 'fixture:small');result = self.wait()
        self.assertEqual(result['status'], 'completed');self.assertFalse(result['passed'])
        self.assertTrue(result['checks']['http_reachable']);self.assertFalse(result['checks']['format_valid'])
    def test_stream_deadline_and_cancellation_are_checked_before_success(self):
        class LateResponse(Response):
            def iter_content(inner, chunk_size=1):
                self.wizard._cancel.set()
                yield b'{"status":"success"}\n'
        with self.client(LateResponse()):self.wizard._download('qwen3:1.7b')
        self.assertEqual(self.wizard.status()['status'], 'cancelled')
        with self.assertRaises(TimeoutError):
            list(self.wizard._bytes(Response({'models': []}), 65536, time.monotonic() - 1, cancellable=False))
    def test_environment_lists_candidates_without_starting_a_task(self):
        self.path.write_text('[ai]\nenabled=false\nmodel=old\n', encoding='utf-8')
        with self.client(Response({'models': []})):
            result = self.wizard.environment()
        self.assertTrue(result['service_reachable']);self.assertEqual(result['current'], {'enabled': False, 'model': 'old'})
        self.assertTrue({'qwen3:1.7b', 'qwen3:4b', 'qwen3:8b'}.issubset(row['name'] for row in result['catalog']))
        self.assertTrue(all(row['benchmark_status'] == 'not_benchmarked' for row in result['catalog']))
        self.assertGreater(result['hardware']['ram_total_bytes'], 0)
        self.assertEqual(result['download_status']['status'], 'idle')
        self.assertFalse(self.wizard.history_path.exists())
    def test_candidate_catalog_has_distinct_families_and_verified_registry_links(self):
        from utils.ai_setup import GIB
        with self.client(Response({'models': []})):
            rows = self.wizard.environment()['catalog']
        families = {row.get('family') for row in rows}
        self.assertGreaterEqual(len(families - {None}), 4)
        self.assertTrue({'gemma3:1b', 'gemma3:4b', 'llama3.2:1b', 'llama3.2:3b', 'phi4-mini:3.8b'}.issubset(row['name'] for row in rows))
        self.assertEqual(len({row['name'] for row in rows}), len(rows))
        for row in rows:
            self.assertTrue(row['parameter_label'].endswith('B'))
            self.assertEqual(row['official_url'], 'https://ollama.com/library/' + row['name'])
            self.assertEqual(row['benchmark_status'], 'not_benchmarked')
            self.assertIn('估算', row['description'])
            self.assertGreaterEqual(row['estimated_download_bytes'], GIB)
        self.assertEqual(self.wizard.status()['status'], 'idle')
        self.assertEqual([r[0] for r in Session.requests], ['GET'])
    def test_new_family_downloads_use_the_same_whitelist_and_sized_disk_guard(self):
        for model in ('gemma3:1b', 'gemma3:4b', 'llama3.2:1b', 'llama3.2:3b', 'phi4-mini:3.8b'):
            with self.subTest(model=model):
                with patch('utils.ai_setup.shutil.disk_usage', return_value=type('Disk', (), {'total': 100, 'free': 1})()):
                    with self.assertRaisesRegex(ValueError, 'insufficient_disk'):
                        self.wizard.start('download', model)
        for model in ('gemma3:27b', 'llama3.2:70b', 'phi4-mini:latest', 'gemma3:1b?url=evil'):
            with self.subTest(model=model), self.assertRaises(ValueError):
                self.wizard.start('download', model)
        self.assertEqual(Session.requests, [])
    def test_replace_failure_keeps_original_configuration_and_cleans_temp(self):
        self.path.write_text('[ai]\nenabled=false\nmodel=old\n', encoding='utf-8')
        before = self.path.read_bytes()
        with patch('utils.ai_setup.os.replace', side_effect=OSError('fixture')):
            with self.assertRaises(OSError):self.wizard.configure({'enabled': False})
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(list(self.path.parent.glob('*.tmp')))
    def test_job_history_survives_recreation_and_is_bounded(self):
        from utils.ai_setup import AISetup
        for index in range(35):
            with self.client(Response(lines=[b'{"status":"success"}'])):
                self.wizard._download('qwen3:1.7b')
        rows = json.loads(self.wizard.history_path.read_text(encoding='utf-8'))
        self.assertEqual(len(rows), 30)
        self.assertTrue(all(row['status'] == 'completed' for row in rows))
        self.assertLess(self.wizard.history_path.stat().st_size, 65536)
        resumed = AISetup(self.path)
        self.assertEqual(resumed.status()['status'], 'completed')
        self.assertEqual(resumed.status()['model'], 'qwen3:1.7b')
        with patch.object(resumed, 'installed', return_value=[]):
            self.assertEqual(len(resumed.environment()['history']), 30)
    def test_simultaneous_start_admits_only_one_worker(self):
        entered = threading.Event();release = threading.Event();ready = threading.Barrier(3)
        outcomes = []
        def worker(model):entered.set();release.wait(2)
        def start():
            ready.wait()
            try:outcomes.append(self.wizard.start('download', 'qwen3:1.7b')['status'])
            except ValueError as error:outcomes.append(str(error))
        with patch.object(self.wizard, '_download', side_effect=worker):
            callers = [threading.Thread(target=start) for _ in range(2)]
            for thread in callers:thread.start()
            ready.wait()
            for thread in callers:thread.join(1)
            self.assertTrue(entered.wait(1))
            self.wizard.cancel();release.set();self.wait()
        self.assertEqual(sorted(outcomes), ['running', 'task_running'])
    def test_service_failure_keeps_previous_config_and_returns_json(self):
        self.path.write_text('[ai]\nenabled=false\nmodel=old\n', encoding='utf-8')
        before = self.path.read_bytes()
        with patch.object(self.wizard, 'installed', side_effect=ConnectionError('unavailable')):
            with self.assertRaises(ConnectionError):self.wizard.configure({'enabled': True, 'model': 'fixture:small'})
        self.assertEqual(self.path.read_bytes(), before)
    def test_interrupted_task_is_not_resumed_after_restart(self):
        from utils.ai_setup import AISetup
        with self.wizard._lock:self.wizard._begin('download', 'qwen3:1.7b')
        resumed = AISetup(self.path)
        self.assertEqual(resumed.status()['status'], 'interrupted')
        self.assertEqual(resumed.status()['reason'], 'process_restarted')
    def test_cancelled_before_worker_start_never_sends_pull(self):
        with self.wizard._lock:self.wizard._begin('download', 'qwen3:1.7b')
        self.wizard.cancel()
        with self.client():self.wizard._download('qwen3:1.7b')
        self.assertEqual(self.wizard.status()['status'], 'cancelled')
        self.assertEqual(Session.requests, [])
    def test_audit_failure_never_leaves_a_phantom_running_task(self):
        with patch('utils.ai_setup._atomic', side_effect=OSError('fixture')):
            with self.assertRaises(OSError):self.wizard.start('download', 'qwen3:1.7b')
        self.assertEqual(self.wizard.status()['status'], 'failed')
        self.assertEqual(self.wizard.status()['reason'], 'audit_storage_unavailable')
    def test_worker_start_failure_is_reported_and_does_not_occupy_slot(self):
        with patch('utils.ai_setup.threading.Thread.start', side_effect=RuntimeError('fixture')):
            with self.assertRaises(OSError):self.wizard.start('download', 'qwen3:1.7b')
        self.assertEqual(self.wizard.status()['status'], 'failed')
        self.assertEqual(self.wizard.status()['reason'], 'worker_unavailable')
        with self.client(Response(lines=[b'{"status":"success"}'])):
            self.wizard.start('download', 'qwen3:1.7b');result = self.wait()
        self.assertEqual(result['status'], 'completed')
    def test_deeply_nested_service_json_is_rejected_as_invalid_data(self):
        nested = '[' * 4000 + '0' + ']' * 4000
        with self.client(Response(('{"models":' + nested + '}').encode())):
            with self.assertRaises(ValueError):self.wizard.installed()
        from utils.ai_setup import AISetup
        result = AISetup._validate_answer({'done': True, 'message': {'content': nested}}, 'benign', 'E1')
        self.assertFalse(result['format_valid'])
        self.wizard.history_path.write_text(nested, encoding='utf-8')
        self.assertEqual(AISetup(self.path).status()['status'], 'idle')


class APIChecks(unittest.TestCase):
    def setUp(self):
        from flask import Flask, jsonify, request
        from dashboard.ai_setup_api import register
        self.tmp = tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.app = Flask(__name__);self.app.config['AI_SETUP_CONFIG'] = str(Path(self.tmp.name) / 'ai.ini')
        def login(fn):
            @wraps(fn)
            def wrapped(*a, **kw):
                if request.headers.get('X-Admin') != 'yes':return jsonify(error='login_required'), 401
                return fn(*a, **kw)
            return wrapped
        def csrf(fn):
            @wraps(fn)
            def wrapped(*a, **kw):
                # Match the dashboard's form-token fallback: this must never run
                # before the wizard rejects oversized bodies or missing headers.
                if not request.headers.get('X-CSRF-Token'):
                    request.form
                    self.csrf_form_reads += 1
                if request.headers.get('X-CSRF-Token') != 'fixture':return jsonify(error='csrf_failed'), 403
                return fn(*a, **kw)
            return wrapped
        register(self.app, login, csrf)
        self.csrf_form_reads = 0
        self.client = self.app.test_client()
        self.headers = {'X-Admin': 'yes', 'X-CSRF-Token': 'fixture'}
    def test_every_endpoint_requires_login_and_mutations_require_csrf(self):
        for path in ('environment', 'tasks/current'):
            self.assertEqual(self.client.get('/api/setup/' + path).status_code, 401)
        for path in ('config', 'tasks', 'tasks/current/cancel'):
            self.assertEqual(self.client.post('/api/setup/' + path, json={}).status_code, 401)
            self.assertEqual(self.client.post('/api/setup/' + path, json={}, headers={'X-Admin': 'yes'}).status_code, 403)
        self.assertEqual(self.client.get('/api/setup/tasks/current', headers={'X-Admin': 'yes'}).status_code, 200)
    def test_bounded_json_and_browser_endpoint_override_rejected(self):
        for body in ({'enabled': False, 'base_url': 'http://example.com'}, {'enabled': 'false'}, ['bad']):
            self.assertEqual(self.client.post('/api/setup/config', json=body, headers=self.headers).status_code, 400)
        result = self.client.post('/api/setup/tasks', data=b'x' * 5000, headers=self.headers, content_type='application/json')
        self.assertEqual(result.status_code, 413);self.assertTrue(result.is_json)
        result = self.client.post('/api/setup/config', json={'enabled': False}, headers=self.headers)
        self.assertEqual(result.status_code, 200);self.assertTrue(result.json['restart_required'])
    def test_size_guard_runs_before_csrf_form_fallback(self):
        response = self.client.post('/api/setup/tasks', data={'field': 'x' * 5000}, headers={'X-Admin': 'yes'})
        self.assertEqual(response.status_code, 413)
        self.assertEqual(self.csrf_form_reads, 0)
        response = self.client.post('/api/setup/tasks', json={}, headers={'X-Admin': 'yes'})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.csrf_form_reads, 0)
    def test_deeply_nested_browser_json_returns_bounded_json_error(self):
        nested = b'{"enabled":' + b'[' * 1500 + b'0' + b']' * 1500 + b'}'
        result = self.client.post('/api/setup/config', data=nested, headers=self.headers, content_type='application/json')
        self.assertEqual(result.status_code, 400);self.assertTrue(result.is_json)


if __name__ == '__main__':unittest.main(verbosity=2)
