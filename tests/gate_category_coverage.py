#!/usr/bin/env python3
"""Гейт «ни один список не потерял покрытие» — против просадки ОДНОЙ категории.

Зачем отдельно от gate_resolve_volume. Тот гейт меряет сборку целиком: сколько доменов
дали адреса. Просадку одного списка при здоровом общем числе он не видит по построению —
ровно так вышла I-105, где `fastly.lst` опубликовался пустым (0 адресов против 363 008 в
соседних сборках), а всё остальное было на месте.

Мера здесь та же, что и там, и по той же причине: АДРЕСА, а не строки. На просадке строк
становится больше — меньше найденных адресов, меньше соседних /24 слипается в один
префикс, — поэтому по числу строк просадка выглядит ростом.

Числа в проверках — настоящие, из опубликованных снапшотов (git log lists/):
`fastly` 363 008 → 0 → 363 008; `tiktok` 2 816 ↔ 4 864 (мелкий список шумит на 42%);
`rkn` 6 069 680 → 6 307 504 и `geoblock` 171 456 → 199 872 (здоровый разброс).

Сети не требует: проверяются чистые функции и форма манифеста.

Запуск: sh tests/run.sh  (или python3 tests/gate_category_coverage.py)
"""

from __future__ import annotations

import ipaddress
import json
import os
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


# ── 1. Пороги ───────────────────────────────────────────────────────────────────
gate = aggregate.CATEGORY_DROP_GATE
check(0.0 < gate < 1.0, f"порог {gate} вне (0, 1)")
check(gate < aggregate.RESOLVE_DROP_GATE,
      "покатегорийный порог обязан быть ГРУБЕЕ общего: разброс у одного списка между "
      "здоровыми сборками больше, чем у суммы")
check(aggregate.CATEGORY_DROP_MIN > 0, "нижняя граница доли должна быть положительной")

# ── 2. Мера — адреса, а не строки ───────────────────────────────────────────────
nets = [ipaddress.ip_network("1.2.3.0/24"), ipaddress.ip_network("10.0.0.1/32")]
check(aggregate.category_addresses(nets) == 257,
      "покрытие считается не по адресам")
check(aggregate.category_addresses([]) == 0, "пустой список покрывает не ноль адресов")

# ── 3. Решение гейта ────────────────────────────────────────────────────────────
# I-105 дословно: список, который был, вышел пустым. Ловится независимо от размера —
# «стало ноль» не бывает шумом.
check(aggregate.coverage_collapsed({"fastly": 0}, {"fastly": 363_008}),
      "пустой fastly.lst (I-105) гейтом не назван")
check(aggregate.coverage_collapsed({"tiktok": 0}, {"tiktok": 2_816}),
      "мелкий список, вышедший пустым, гейтом не назван")

# Здоровый разброс — не просадка.
check(not aggregate.coverage_collapsed({"fastly": 363_008}, {"fastly": 362_752}),
      "разница между двумя здоровыми сборками принята за просадку")
check(not aggregate.coverage_collapsed({"rkn": 6_307_504}, {"rkn": 6_069_680}),
      "рост rkn принят за просадку")
check(not aggregate.coverage_collapsed({"geoblock": 199_872}, {"geoblock": 171_456}),
      "рост geoblock принят за просадку")

# Мелкие списки шумят на десятки процентов (tiktok 4 864 → 2 816 — это соседние сборки,
# обе здоровые), поэтому доля у них не считается вовсе.
check(not aggregate.coverage_collapsed({"tiktok": 2_816}, {"tiktok": 4_864}),
      "шум мелкого списка (tiktok 4 864 → 2 816) принят за просадку")

# Крупный список, потерявший половину, — просадка.
check(aggregate.coverage_collapsed({"rkn": 3_000_000}, {"rkn": 6_307_504}),
      "rkn, потерявший половину покрытия, гейтом не назван")

# Список, которого в этой сборке нет вовсе, — это переименование или исключение из
# схемы, а не просадка: файл при этом удаляется, и говорить о его покрытии не о чем.
check(not aggregate.coverage_collapsed({}, {"fastly": 363_008}),
      "исчезнувшая из схемы категория принята за просадку")
check(not aggregate.coverage_collapsed({"fastly": 0}, {"fastly": 0}),
      "нулевое прошлое покрытие не может быть планкой")

# Граница названа явно, чтобы правка порога не превратилась в правку смысла.
base = aggregate.CATEGORY_DROP_MIN * 4
check(not aggregate.coverage_collapsed({"x": int(base * gate)}, {"x": base}),
      "значение ровно на пороге отменяет публикацию")
check(aggregate.coverage_collapsed({"x": int(base * gate) - 1}, {"x": base}),
      "значение ниже порога публикацию не отменяет")

# Гейт называет ВСЕ просевшие списки, а не первый: человек, читающий журнал упавшей
# сборки, должен видеть масштаб беды, а не одну строку из десяти.
many = aggregate.coverage_collapsed(
    {"fastly": 0, "rkn": 0, "geoblock": 199_872}, {"fastly": 363_008, "rkn": 6_307_504, "geoblock": 171_456})
check(len(many) == 2, f"названо {len(many)} просевших списков вместо двух")

# ── 4. Прошлое покрытие читается из манифеста ───────────────────────────────────
tmp = Path(__file__).resolve().parent / ".gate_category_coverage.tmp.json"
try:
    tmp.write_text(json.dumps({
        "categories": [{"id": "fastly", "addresses": 363_008}, {"id": "rkn"}],
        "aggregates": [{"id": "ipsum", "addresses": 7_272_640}],
    }), encoding="utf-8")
    prev = aggregate.previous_category_addresses(tmp)
    check(prev.get("fastly") == 363_008, "покрытие категории из манифеста не прочитано")
    check(prev.get("ipsum") == 7_272_640,
          "агрегаты тоже публикуются, и их просадка тоже беда — покрытие не прочитано")
    check("rkn" not in prev, "запись без поля addresses обязана читаться как «нечем сравнивать»")
    tmp.write_text("{ это не json", encoding="utf-8")
    check(aggregate.previous_category_addresses(tmp) == {},
          "битый манифест прошлой сборки обязан читаться как «сравнивать не с чем»")
finally:
    tmp.unlink(missing_ok=True)
check(aggregate.previous_category_addresses(ROOT / "lists" / "нет-такого-файла.json") == {},
      "отсутствующий манифест обязан читаться как «сравнивать не с чем»")

# ── 5. Поле уезжает в манифест ──────────────────────────────────────────────────
idx = aggregate.build_index({}, {}, addresses={"fastly": 363_008})
byid = {c["id"]: c for c in idx["categories"] + idx["aggregates"]}
check(byid["fastly"]["addresses"] == 363_008,
      "поле addresses не публикуется — следующей сборке нечего читать")
check(all("addresses" in c for c in byid.values()),
      "поле addresses есть не у всех записей — гейт следующей сборки увидит не все списки")

# ── 6. Осознанное сокращение состава ────────────────────────────────────────────
# Склейка, переименование и исключение категорий — работа владельца, и гейт обязан иметь
# выключатель на одну сборку. Иначе он запрёт публикацию именно в тот день, когда списки
# меняли нарочно.
was = os.environ.get("ALLOW_SHRINK")
try:
    os.environ.pop("ALLOW_SHRINK", None)
    check(not aggregate.shrink_allowed(), "сокращение разрешено без просьбы")
    os.environ["ALLOW_SHRINK"] = "1"
    check(aggregate.shrink_allowed(), "ALLOW_SHRINK=1 не разрешает сокращение")
    os.environ["ALLOW_SHRINK"] = "0"
    check(not aggregate.shrink_allowed(), "ALLOW_SHRINK=0 разрешает сокращение")
finally:
    os.environ.pop("ALLOW_SHRINK", None)
    if was is not None:
        os.environ["ALLOW_SHRINK"] = was

print(f"gate_category_coverage: проверок {checks}, провалов {len(fails)}")
for f in fails:
    print(f"  FAIL: {f}")
sys.exit(1 if fails else 0)
