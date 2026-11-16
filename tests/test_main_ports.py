import os
import sys

import main


def test_service_ports_include_db_redis_port():
    db_services = [service for service in main.SERVICES if service.get('short') == 'DB']
    assert db_services, '数据库蜜罐应默认启用'
    db_service = db_services[0]
    ports = main._service_ports_of(db_service)
    assert db_service['port'] in ports
    assert db_service['redis_port'] in ports
    assert set(ports).issubset(set(main._service_port_numbers()))


def test_is_project_service_process_matches_absolute_script(monkeypatch):
    script = os.path.join(main.BASE_DIR, 'web_honeypot', 'server.py')
    monkeypatch.setattr(
        main, '_process_cmdline',
        lambda pid: [sys.executable, '-u', script, '--port', '5000'],
    )
    assert main._is_project_service_process(4321) is True

    monkeypatch.setattr(
        main, '_process_cmdline',
        lambda pid: [sys.executable, '-u', r'C:\other-project\web_honeypot\server.py'],
    )
    assert main._is_project_service_process(4321) is False


def test_check_all_ports_auto_cleans_own_stale_instance(monkeypatch):
    service = main.SERVICES[0]
    conflicts = [{'service': service, 'port': service['port'], 'pid': 4321, 'ours': True}]
    stopped = []
    scans = []

    def scan():
        scans.append(True)
        return [] if len(scans) > 1 else list(conflicts)

    monkeypatch.setattr(main, 'safe_print', lambda *args, **kwargs: None)
    monkeypatch.setattr(main, '_describe_owner', lambda pid: f'PID {pid}')
    monkeypatch.setattr(main, '_scan_port_conflicts', scan)
    monkeypatch.setattr(main, 'stop_running_instance', lambda *args, **kwargs: stopped.append(True) or True)

    assert main.check_all_ports(auto_clean=True) is True
    assert stopped, '启动时应自动停止占用端口的旧实例'


def test_check_all_ports_reports_foreign_owner(monkeypatch):
    service = main.SERVICES[0]
    conflicts = [{'service': service, 'port': service['port'], 'pid': 4321, 'ours': False}]
    stopped = []

    monkeypatch.setattr(main, 'safe_print', lambda *args, **kwargs: None)
    monkeypatch.setattr(main, '_describe_owner', lambda pid: f'PID {pid}')
    monkeypatch.setattr(main, '_scan_port_conflicts', lambda: list(conflicts))
    monkeypatch.setattr(main, 'stop_running_instance', lambda *args, **kwargs: stopped.append(True) or True)

    assert main.check_all_ports(auto_clean=True) is False
    assert not stopped, '外部程序占用端口时不应结束对方进程'


def test_auto_clean_can_be_disabled(monkeypatch):
    service = main.SERVICES[0]
    conflicts = [{'service': service, 'port': service['port'], 'pid': 4321, 'ours': True}]
    stopped = []

    monkeypatch.setattr(main, 'safe_print', lambda *args, **kwargs: None)
    monkeypatch.setattr(main, '_describe_owner', lambda pid: f'PID {pid}')
    monkeypatch.setattr(main, '_scan_port_conflicts', lambda: list(conflicts))
    monkeypatch.setattr(main, 'stop_running_instance', lambda *args, **kwargs: stopped.append(True) or True)

    assert main.check_all_ports(auto_clean=False) is False
    assert not stopped, '--no-auto-clean 时不应结束旧实例'
