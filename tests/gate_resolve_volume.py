#!/usr/bin/env python3
"""Гейт «резолв не просел относительно последних сборок» — против тихой публикации огрызка.

Зачем. Почти всё содержимое адресных списков берётся из резолва доменов, и провал резолва
не выглядит провалом: файлы на месте, счётчики в манифесте заполнены, гейт по числу строк
ipsum.lst зелёный. Хуже того, счётчик СТРОК на просевшей сборке РАСТЁТ: чем меньше
адресов найдено, тем меньше соседних /24 слипается в один префикс. Измерено на двух
сборках подряд: rkn.lst 11 667 строк на 4,51 млн адресов (2026-08-22T11:49) против 11 231
строки на 6,07 млн адресов (2026-08-25T04:16). По строкам просадка выглядит как рост.

Поэтому мерой берётся число доменов, ДАВШИХ адреса, и сравнивается оно с прошлым
опубликованным манифестом — единственным следом прошлой сборки, который есть у текущей.

Планка — не прошлая сборка, а МЕДИАНА последних опубликованных. Планка «от прошлой»
ловила обвал и по построению пропускала сползание: каждая сборка сравнивалась с уже
просевшей предыдущей, и три шага по 25% проходили там, где один шаг на 50% отменял
публикацию. Медиана этого не умеет забывать, а перекоситься от одной странной сборки не
может. В истории только ОПУБЛИКОВАННЫЕ сборки: отменённая манифест не переписывает, то
есть просадка планку не задирает и запереть публикацию навсегда не может.

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

# ── 3. Планка: медиана последних сборок, а не последняя сборка ──────────────────
check(aggregate.resolve_baseline_of([14381, 14512, 14816]) == 14512,
      "планка по трём сборкам — не медиана")
check(aggregate.resolve_baseline_of([14381, 14512, 14816, 14900]) == 14664,
      "планка по чётному числу сборок — не середина между средними")
check(aggregate.resolve_baseline_of([]) is None, "пустая история обязана давать None")

# Сползание по 25% за сборку. Планка «от прошлой» пропускает каждый шаг (0.75 > 0.7),
# и через три сборки от 14 000 доменов остаётся 5 906. Медиана ловит на втором шаге.
check(not aggregate.resolve_volume_collapsed(10_500, 14_000),
      "премисса теста неверна: шаг сползания сам по себе обязан проходить старую планку")
check(aggregate.resolve_volume_collapsed(7_875, aggregate.resolve_baseline_of([10_500, 14_000])),
      "сползание 14 000 → 10 500 → 7 875 медианной планкой не поймано")
check(not aggregate.resolve_volume_collapsed(14_381, aggregate.resolve_baseline_of([14_512, 14_816])),
      "здоровая сборка отменена медианной планкой")

# История ограничена по длине и хранит СВЕЖИЕ значения первыми.
hist = aggregate.next_resolve_history(15_000, [14_381, 14_512, 14_816])
check(hist[0] == 15_000, "новая сборка не встала в голову истории")
check(len(aggregate.next_resolve_history(1, list(range(100))))
      == aggregate.RESOLVE_HISTORY_LEN,
      "история не обрезана до RESOLVE_HISTORY_LEN")

# ── 4. История читается из манифеста ────────────────────────────────────────────
tmp = Path(__file__).resolve().parent / ".gate_resolve_history.tmp.json"
try:
    tmp.write_text(json.dumps({"sources": {
        "resolved_domains": 14381, "resolved_domains_recent": [14381, 14512, 14816]}}),
        encoding="utf-8")
    check(aggregate.previous_resolved_history(tmp) == [14381, 14512, 14816],
          "история из манифеста прошлой сборки не прочитана")
    check(aggregate.resolve_baseline(tmp) == 14512, "планка из манифеста — не медиана истории")
    # Манифест старой формы (поля истории ещё нет): планкой служит прошлое число, иначе
    # первая же сборка после правки осталась бы без охраны вовсе.
    tmp.write_text(json.dumps({"sources": {"resolved_domains": 14381}}), encoding="utf-8")
    check(aggregate.previous_resolved_history(tmp) == [], "истории нет — обязан быть пустой список")
    check(aggregate.resolve_baseline(tmp) == 14381,
          "без истории планкой обязано остаться прошлое число")
    tmp.write_text(json.dumps({"sources": {}}), encoding="utf-8")
    check(aggregate.resolve_baseline(tmp) is None, "манифест без чисел обязан давать None")
finally:
    tmp.unlink(missing_ok=True)

# ── 5. Поля уезжают в манифест ──────────────────────────────────────────────────
idx = aggregate.build_index({}, {"resolved_domains": 14381,
                                 "resolved_domains_recent": [14381, 14512]})
check(idx["sources"].get("resolved_domains") == 14381,
      "поле resolved_domains не публикуется в манифесте — следующей сборке нечего читать")
check(idx["sources"].get("resolved_domains_recent") == [14381, 14512],
      "история не публикуется — планка следующей сборки снова станет однодневной")

# ── 6. Планки гейтов не должны исчезнуть из манифеста молча ─────────────────────
# Обе планки живут в самом манифесте, и это делает их уязвимыми так же, как
# same_prefixes_as: манифест собирается заново ЦЕЛИКОМ, поле пропадает при перестройке
# source_meta, и гейт после этого не падает и не предупреждает — он просто перестаёт
# сравнивать. Поэтому состав полей проверяется дважды: генератором до записи манифеста и
# self-check'ом по уже опубликованному.
good = {
    "sources": {"resolved_domains": 14381, "resolved_domains_recent": [14381, 14512]},
    "categories": [{"id": "rkn", "addresses": 6_307_504,
                    "addresses_recent": [6_307_504, 6_069_680]}],
    "aggregates": [{"id": "ipsum", "addresses": 7_272_640,
                    "addresses_recent": [7_272_640]}],
}
check(aggregate.gate_inputs_missing(good) == [], "полный манифест назван неполным")

import copy  # noqa: E402

for drop, what in (
    (lambda d: d["sources"].pop("resolved_domains"), "sources.resolved_domains"),
    (lambda d: d["sources"].pop("resolved_domains_recent"), "sources.resolved_domains_recent"),
    (lambda d: d["categories"][0].pop("addresses"), "addresses у категории"),
    (lambda d: d["aggregates"][0].pop("addresses"), "addresses у агрегата"),
    # История покрытия — такая же планка, как история резолва, и уязвима так же: по ней
    # считается СВОЙ порог каждого списка, и потеря поля молча вернула бы один порог на всех
    # (I-144, I-151).
    (lambda d: d["categories"][0].pop("addresses_recent"), "addresses_recent у категории"),
    (lambda d: d["aggregates"][0].pop("addresses_recent"), "addresses_recent у агрегата"),
    (lambda d: d["categories"][0].update(addresses_recent=[]), "пустая история у категории"),
):
    broken = copy.deepcopy(good)
    drop(broken)
    check(aggregate.gate_inputs_missing(broken) != [],
          f"потерянное поле {what} генератором не замечено")

check(aggregate.gate_inputs_missing({"sources": {"resolved_domains": 14381,
                                                 "resolved_domains_recent": []}}) != [],
      "пустая история принята за планку")

# Тот же вопрос по УЖЕ опубликованному манифесту — вторым рубежом, в self-check.
import selfcheck  # noqa: E402

check(not [e for e in selfcheck.check_manifest() if "resolved_domains" in e],
      "self-check ругается на планку в настоящем опубликованном манифесте")
tmp = Path(__file__).resolve().parent / ".gate_manifest.tmp.json"
try:
    tmp.write_text(json.dumps({"sources": {}, "categories": [], "aggregates": []}),
                   encoding="utf-8")
    real, selfcheck.MANIFEST = selfcheck.MANIFEST, tmp
    check([e for e in selfcheck.check_manifest() if "resolved_domains" in e],
          "манифест без планки self-check'ом не назван — гейт замолчал бы навсегда")
finally:
    selfcheck.MANIFEST = real
    tmp.unlink(missing_ok=True)

print(f"gate_resolve_volume: проверок {checks}, провалов {len(fails)}")
for f in fails:
    print(f"  FAIL: {f}")
sys.exit(1 if fails else 0)
