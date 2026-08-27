#!/usr/bin/env python3
"""Стенд мягкости self-check: `--warn-only` обязан смягчать ЛЮБУЮ ошибку, а не названную.

Зачем. В публикующей сборке selfcheck идёт с `--warn-only`, и это осознанный выбор: списки
на этот момент уже собраны, и уронить шаг перед коммитом значит оставить все установленные
роутеры на прошлом снапшоте из-за расхождения в метаданных, которое маршрутизации не
касается. Обещание «этот шаг не отменяет публикацию» держалось только для тех ошибок,
которые проверка НАЗЫВАЕТ списком; исключение внутри неё роняло шаг трассировкой, и код
возврата не спрашивали вовсе.

Замерено: копия снапшота 2026-08-25 с одной битой строкой в rkn.lst даёт
`ValueError: '300.1.2.3/24' does not appear to be an IPv4 or IPv6 network` из
`_measured_groups`, а `python generator/selfcheck.py --warn-only` возвращает 1 (I-121).
Причина не в проверке, а в порядке: четыре группы вычислялись списком ДО цикла печати.

Проверяется поэтому не текст сообщений, а именно код возврата в обоих режимах — и то, что
упавшая группа названа, а не проглочена молча.

Сети не требует: группы проверок подменяются заглушками.

Запуск: sh tests/run.sh  (или python3 tests/selfcheck_warn_only.py)
"""

from __future__ import annotations

import contextlib
import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "generator"))

import selfcheck  # noqa: E402

fails: list[str] = []
checks = 0


def check(ok: bool, what: str) -> None:
    global checks
    checks += 1
    if not ok:
        fails.append(what)


def run(argv: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = selfcheck.main(argv)
    return rc, out.getvalue()


def boom() -> list[str]:
    raise ValueError("'300.1.2.3/24' does not appear to be an IPv4 or IPv6 network")


GROUPS = {
    "схема категорий": ("schema", "validate"),
    "выпущенные списки против схемы": (None, "check_lists"),
    "манифест": (None, "check_manifest"),
    "наш доменный список": (None, "check_local_lists"),
}

# ── 1. На здоровых данных шаг зелёный в обоих режимах ───────────────────────────
rc_warn, _ = run(["--warn-only"])
rc_hard, _ = run([])
check(rc_warn == 0, f"--warn-only на здоровых данных вернул {rc_warn}")
check(rc_hard == 0, f"строгий режим на здоровых данных вернул {rc_hard}")

# ── 2. Исключение в любой группе: мягкий режим не роняет, строгий роняет ─────────
for name, (holder, attr) in GROUPS.items():
    obj = getattr(selfcheck, holder) if holder else selfcheck
    real = getattr(obj, attr)
    setattr(obj, attr, boom)
    try:
        rc_warn, text_warn = run(["--warn-only"])
        rc_hard, _ = run([])
    except Exception as exc:  # noqa: BLE001 — именно это и чинилось
        setattr(obj, attr, real)
        fails.append(f"группа «{name}»: исключение долетело до вызывающего ({exc})")
        checks += 3
        continue
    setattr(obj, attr, real)
    check(rc_warn == 0,
          f"группа «{name}»: --warn-only вернул {rc_warn} на исключении внутри проверки")
    check(rc_hard == 1,
          f"группа «{name}»: строгий режим вернул {rc_hard} на исключении — падать обязан")
    check(name in text_warn and "ValueError" in text_warn,
          f"группа «{name}»: упавшая проверка не названа в выводе")

# ── 3. Отчёт про сиды тоже не роняет шаг ────────────────────────────────────────
real_report = selfcheck.report_thematic_seeds
selfcheck.report_thematic_seeds = boom
try:
    rc_warn, _ = run(["--warn-only"])
    rc_hard, _ = run([])
except Exception as exc:  # noqa: BLE001
    fails.append(f"отчёт про сиды: исключение долетело до вызывающего ({exc})")
    checks += 2
else:
    check(rc_warn == 0, f"отчёт про сиды уронил --warn-only (rc={rc_warn})")
    check(rc_hard == 0, f"отчёт про сиды уронил строгий режим (rc={rc_hard}) — он не проверка")
finally:
    selfcheck.report_thematic_seeds = real_report

print(f"selfcheck_warn_only: проверок {checks}, провалов {len(fails)}")
for f in fails:
    print(f"  FAIL: {f}")
sys.exit(1 if fails else 0)
