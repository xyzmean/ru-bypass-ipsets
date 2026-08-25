#!/usr/bin/env python3
"""Гейт «резолв не просел относительно прошлой сборки» — против тихой публикации огрызка.

Зачем. Почти всё содержимое адресных списков берётся из резолва доменов, и провал резолва
не выглядит провалом: файлы на месте, счётчики в манифесте заполнены, гейт по числу строк
ipsum.lst зелёный. Хуже того, счётчик СТРОК на просевшей сборке РАСТЁТ: чем меньше
адресов найдено, тем меньше соседних /24 слипается в один префикс. Измерено на двух
сборках подряд: rkn.lst 11 667 строк на 4,51 млн адресов (2026-08-22T11:49) против 11 231
строки на 6,07 млн адресов (2026-08-25T04:16). По строкам просадка выглядит как рост.

Поэтому мерой берётся число доменов, ДАВШИХ адреса, и сравнивается оно с прошлым
опубликованным манифестом — единственным следом прошлой сборки, который есть у текущей.

Чего этот гейт не умеет: он не поймает медленное сползание на десяток процентов за
сборку, потому что планка каждый раз новая. Он ловит обвал — тот, что уже случился
одиннадцать раз из четырнадцати.

Сети не требует: проверяется чистая функция и форма манифеста.

Запуск: sh tests/run.sh  (или python3 tests/gate_resolve_volume.py)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "generator"))

import aggregate  # noqa: E402

fails: list[str] = []
checks = 0


def check(ok: bool, what: str) -> None:
    global checks
    checks += 1
    if not ok:
        fails.append(what)


# ── 1. Решение гейта ────────────────────────────────────────────────────────────
gate = aggregate.RESOLVE_DROP_GATE
check(0.0 < gate < 1.0, f"порог гейта {gate} вне (0, 1)")

# Прошлого значения нет — гейт молчит: первая сборка после появления поля не должна
# отменять публикацию из-за того, что сравнивать не с чем.
check(not aggregate.resolve_volume_collapsed(3381, None),
      "гейт сработал, хотя прошлого значения нет")
check(not aggregate.resolve_volume_collapsed(3381, 0),
      "гейт сработал от нулевого прошлого значения (деление на ноль / храповик от нуля)")

# Настоящие числа из журналов сборок.
check(aggregate.resolve_volume_collapsed(3381, 14381),
      "обвал 14381 → 3381 (2026-08-22T11:49) гейтом не назван")
check(aggregate.resolve_volume_collapsed(3307, 14816),
      "обвал 14816 → 3307 (2026-08-20T22:10) гейтом не назван")
check(not aggregate.resolve_volume_collapsed(14381, 14512),
      "обычная разница между двумя здоровыми сборками принята за обвал")
check(not aggregate.resolve_volume_collapsed(14816, 14381),
      "рост принят за обвал")

# Ровно на пороге — публикуем; чуть ниже — нет. Граница названа явно, чтобы правка
# порога не превратилась в правку смысла.
base = 10_000
check(not aggregate.resolve_volume_collapsed(int(base * gate), base),
      "значение ровно на пороге отменяет публикацию")
check(aggregate.resolve_volume_collapsed(int(base * gate) - 1, base),
      "значение ниже порога публикацию не отменяет")

# ── 2. Прошлое значение читается из манифеста, а не из воздуха ───────────────────
tmp = Path(__file__).resolve().parent / ".gate_resolve_volume.tmp.json"
try:
    tmp.write_text(json.dumps({"sources": {"resolved_domains": 14381}}), encoding="utf-8")
    check(aggregate.previous_resolved_count(tmp) == 14381,
          "число из манифеста прошлой сборки не прочитано")
    tmp.write_text(json.dumps({"sources": {}}), encoding="utf-8")
    check(aggregate.previous_resolved_count(tmp) is None,
          "манифест без поля должен давать None, а не ноль")
    tmp.write_text("{ это не json", encoding="utf-8")
    check(aggregate.previous_resolved_count(tmp) is None,
          "битый манифест прошлой сборки обязан читаться как «сравнивать не с чем»")
finally:
    tmp.unlink(missing_ok=True)
check(aggregate.previous_resolved_count(ROOT / "lists" / "нет-такого-файла.json") is None,
      "отсутствующий манифест обязан читаться как «сравнивать не с чем»")

# ── 3. Поле уезжает в манифест ──────────────────────────────────────────────────
idx = aggregate.build_index({}, {"resolved_domains": 14381})
check(idx["sources"].get("resolved_domains") == 14381,
      "поле resolved_domains не публикуется в манифесте — следующей сборке нечего читать")

print(f"gate_resolve_volume: проверок {checks}, провалов {len(fails)}")
for f in fails:
    print(f"  FAIL: {f}")
sys.exit(1 if fails else 0)
