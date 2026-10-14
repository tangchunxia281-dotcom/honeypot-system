# -*- coding: utf-8 -*-
"""密标模块端到端自检脚本。

用法（在项目根目录执行）：

    python -m risk_mark.selftest

脚本会依次验证：写入密标 → 查询 → 列表 / 批量查询 → 重复标注覆盖 →
识别器评估 → 移除清理，且不会残留任何测试数据。
"""
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from db.connection import USE_MYSQL  # noqa: E402  (需先补齐 sys.path)
from db.event_logs import log_event  # noqa: E402

from risk_mark import detectors, service  # noqa: E402
from risk_mark import config as mark_config  # noqa: E402
from risk_mark.constants import LEVEL_HIGH, TARGET_IP  # noqa: E402

# RFC 5737 文档专用网段，避免与真实数据混淆
TEST_IP = '203.0.113.77'
ABSENT_IP = '198.51.100.9'
LOOPBACK_TEST_IP = '203.0.113.78'


def _check(title: str, ok: bool, detail: str = '') -> bool:
    flag = 'PASS' if ok else 'FAIL'
    suffix = f" -> {detail}" if detail else ''
    print(f"[{flag}] {title}{suffix}")
    return bool(ok)


def main() -> int:
    ok = True
    print('=== 密标模块自检 ===')
    print(f"数据库类型: {'MySQL' if USE_MYSQL else 'SQLite'}")
    print(f"已注册识别器: {', '.join(d.name for d in detectors.get_detectors()) or '无'}")
    print('-' * 52)

    # 1. 写入密标
    created = {}
    try:
        created = service.mark(
            TARGET_IP, TEST_IP, LEVEL_HIGH, '自检用测试密标',
            created_by='selftest', ttl_days=1,
        )
        ok &= _check('写入密标', bool(created.get('id')), f"id={created.get('id')} level={created.get('level')}")
    except Exception as e:
        ok &= _check('写入密标', False, repr(e))

    if not created.get('id'):
        # 写入失败时后续断言无意义，先清理再给出结论
        try:
            service.unmark(target_type=TARGET_IP, target_value=TEST_IP)
        except Exception:
            pass
        print('=== 自检结束: HAS FAILURE ===')
        return 1

    # 2. 覆盖写入（同对象只应保留一条）
    service.mark(TARGET_IP, TEST_IP, 'medium', '自检覆盖测试', created_by='selftest')
    service.mark(TARGET_IP, TEST_IP, LEVEL_HIGH, '自检原始原因', created_by='selftest', ttl_days=1)

    got = service.get_mark(TARGET_IP, TEST_IP)
    ok &= _check('查询密标', bool(got) and got.get('target_value') == TEST_IP, f"level={got and got.get('level')}")

    listed = service.list_marks(keyword='自检')
    hits = [i for i in listed['items'] if i['target_value'] == TEST_IP]
    ok &= _check('列表查询与去重', len(hits) == 1, f"命中 {len(hits)} 条, 列表总数 {listed['total']}")
    ok &= _check('密级统计', 'high' in listed.get('stats', {}), f"stats={listed.get('stats')}")

    batch = service.marks_for_ips([TEST_IP, ABSENT_IP])
    ok &= _check('批量查询', TEST_IP in batch and ABSENT_IP not in batch, f"命中 {list(batch.keys())}")

    # 3. 识别器评估（不落库）
    proposals = service.evaluate_event(
        src_ip=TEST_IP, severity='critical', event_type='sql_injection', source='web',
    )
    ok &= _check(
        '识别器评估',
        any(p['target_value'] == TEST_IP for p in proposals),
        f"建议 {len(proposals)} 条: {[p['detector'] for p in proposals]}",
    )
    ok &= _check('识别器注册表', len(detectors.get_detectors()) >= 2,
                 ', '.join(d.name for d in detectors.get_detectors()))

    # 4. 识别结果落库（显式 apply，避免依赖配置开关）
    applied = service.apply_proposals(proposals, created_by='selftest')
    ok &= _check('识别结果落标', bool(applied), f"落标 {len(applied)} 条")

    # 4.5 事件链路闭环：log_event 落库后应自动触发 on_event 并落标
    #     （临时打开总开关与落库开关，验证 db/event_logs.py 的 [risk-mark] 钩子）
    loop_marked = None
    old_enabled, old_apply = mark_config.AUTO_DETECT_ENABLED, mark_config.AUTO_DETECT_APPLY
    mark_config.AUTO_DETECT_ENABLED, mark_config.AUTO_DETECT_APPLY = True, True
    try:
        new_id = log_event(
            source='web', severity='critical', event_type='sql_injection',
            src_ip=LOOPBACK_TEST_IP, payload='自检闭环事件',
        )
        loop_marked = service.get_mark(TARGET_IP, LOOPBACK_TEST_IP)
        ok &= _check(
            '事件链路闭环',
            bool(new_id) and loop_marked is not None,
            f"event_id={new_id} source={loop_marked and loop_marked.get('source')}",
        )
    except Exception as e:
        ok &= _check('事件链路闭环', False, repr(e))
    finally:
        mark_config.AUTO_DETECT_ENABLED, mark_config.AUTO_DETECT_APPLY = old_enabled, old_apply
        try:
            service.unmark(target_type=TARGET_IP, target_value=LOOPBACK_TEST_IP)
        except Exception:
            pass

    # 5. 清理
    removed = service.unmark(target_type=TARGET_IP, target_value=TEST_IP)
    ok &= _check('移除密标', removed >= 1, f"removed={removed}")
    ok &= _check('清理确认', service.get_mark(TARGET_IP, TEST_IP) is None)

    print('-' * 52)
    print('=== 自检结束:', 'ALL PASS' if ok else 'HAS FAILURE', '===')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
