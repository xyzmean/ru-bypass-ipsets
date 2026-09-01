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
# ── 5. Порог по СОБСТВЕННОМУ разбросу списка (I-144, I-151) ─────────────────────
#
# Один порог 0,5 на все списки перекошен в обе стороны, и оба плеча измерены на выпущенных
# данных. Плечо первое: изъятие по размеру не действует на 10 записей из 32, и три из них
# включены по умолчанию — у telegram 15 104 адреса лежат в восьми префиксах из анонсов ASN,
# такой список не шумит вовсе, а доля у него не проверялась. Плечо второе: geoblock за три
# сборки шёл в пределах ±3%, а четвёртая дала минус 34,8% при НЕИЗМЕННОЙ входной базе — доля
# 0,65 выше порога, размер выше CATEGORY_DROP_MIN, правило применимо и молчит.
#
# Числа ниже — настоящие, из опубликованных снапшотов.
check(0.0 < aggregate.CATEGORY_BAND_MIN < (1.0 - gate),
      "нижняя граница разброса обязана лежать между нулём и прежним порогом")
check(aggregate.CATEGORY_HISTORY_MIN >= 3,
      "по двум наблюдениям разброс не измеряется, а угадывается")

# Разброс не измерен — правило не применяется, и охрана остаётся прежней.
check(aggregate.category_band([]) is None, "пустая история дала порог")
check(aggregate.category_band([100, 100]) is None,
      "двух наблюдений хватило на порог — это уже не измерение")

# Тесный ряд (geoblock ±3%) получает нижнюю границу разброса, а не свой крошечный.
band = aggregate.category_band([198_592, 195_520, 186_304, 190_100])
check(band is not None and abs(band[1] - aggregate.CATEGORY_BAND_MIN) < 1e-9,
      f"тесный ряд получил порог {band}, а должен получить нижнюю границу")

# Шумный ряд (tiktok 2 816 ↔ 4 864) получает прежний грубый порог, а не свой ещё грубее.
band = aggregate.category_band([2_816, 4_864, 3_072, 4_096])
check(band is not None and abs(band[1] - (1.0 - gate)) < 1e-9,
      f"шумный ряд получил порог {band}, а должен упереться в прежнюю границу")

HIST_GEO = {"geoblock": [198_592, 195_520, 186_304, 190_100]}
# I-151 дословно: минус 34,8% в ряду ±3%.
check(aggregate.coverage_collapsed({"geoblock": 127_424}, {"geoblock": 195_520}, HIST_GEO),
      "просадка geoblock на треть при тесной истории гейтом не названа")
# Здоровая сборка того же ряда — не просадка.
check(not aggregate.coverage_collapsed({"geoblock": 190_000}, {"geoblock": 195_520}, HIST_GEO),
      "здоровая сборка geoblock принята за просадку")

# I-144 дословно: мелкий список, включённый по умолчанию, теперь охраняется.
HIST_TG = {"telegram": [15_104, 15_104, 15_360, 15_104]}
check(aggregate.coverage_collapsed({"telegram": 9_800}, {"telegram": 15_104}, HIST_TG),
      "просадка telegram на треть не названа, хотя список мелкий и не шумит")
check(not aggregate.coverage_collapsed({"telegram": 14_300}, {"telegram": 15_104}, HIST_TG),
      "просадка telegram на 5% названа, хотя это в пределах нижней границы разброса")

# А шумному списку его шум по-прежнему разрешён — иначе гейт валил бы публикацию через день.
HIST_TT = {"tiktok": [2_816, 4_864, 3_072, 4_096]}
check(not aggregate.coverage_collapsed({"tiktok": 2_816}, {"tiktok": 4_864}, HIST_TT),
      "шум tiktok назван просадкой, хотя обе сборки здоровые")

# Пустой список — провал независимо от истории: правило «был непустым, стал пустым» ни
# разброса, ни размера не спрашивает.
check(aggregate.coverage_collapsed({"tiktok": 0}, {"tiktok": 4_864}, HIST_TT),
      "пустой список с историей перестал считаться провалом")

# Без истории работает запасное правило, и ровно как прежде.
check(aggregate.coverage_collapsed({"rkn": 3_000_000}, {"rkn": 6_307_504}, {}),
      "список без истории потерял охрану запасным правилом")

# ── 6. История покрытия: чтение, продление, обрезка ─────────────────────────────
hist_tmp = Path(__file__).resolve().parent / ".gate_category_history.tmp.json"
try:
    hist_tmp.write_text(json.dumps({
        "categories": [
            {"id": "geoblock", "addresses": 195_520, "addresses_recent": [195_520, 198_592]},
            {"id": "rkn", "addresses": 100},
            {"id": "bad", "addresses": 1, "addresses_recent": ["строка", 0, -5]},
        ],
        "aggregates": [{"id": "ipsum", "addresses": 7, "addresses_recent": [7, 8]}],
    }), encoding="utf-8")
    hist = aggregate.previous_category_history(hist_tmp)
    check(hist.get("geoblock") == [195_520, 198_592], "история категории не прочитана")
    check(hist.get("ipsum") == [7, 8],
          "агрегаты публикуются такими же файлами — их история тоже нужна")
    check("rkn" not in hist, "запись без истории обязана читаться как «истории нет»")
    check("bad" not in hist, "мусор в истории обязан читаться как «истории нет»")
    hist_tmp.write_text("{ это не json", encoding="utf-8")
    check(aggregate.previous_category_history(hist_tmp) == {},
          "битый манифест обязан читаться как «истории нет»")
finally:
    hist_tmp.unlink(missing_ok=True)

nxt = aggregate.next_addresses_history(500, [400, 300])
check(nxt == [500, 400, 300], f"свежее значение не в голове истории: {nxt}")
long = aggregate.next_addresses_history(1, list(range(2, 40)))
check(len(long) == aggregate.CATEGORY_HISTORY_LEN,
      f"история не обрезана: длина {len(long)}")
check(aggregate.next_addresses_history(7, [0, -1, "x"]) == [7],  # type: ignore[list-item]
      "мусор из прошлой истории уехал в новую")

# ── 7. Выброс резолва: третье состояние гейта (I-151) ───────────────────────────
#
# У гейта было два состояния — отменить публикацию или молчать. Сборка 1 сентября прошла с
# запасом 50 доменов из 11 481 (0,44%) при собственном разбросе ряда ±0,6% и опубликовала
# списки на треть короче без единого слова. Ряд ниже — настоящий, из манифестов.
REAL = [16_299, 16_324, 16_336, 16_250, 16_378, 16_301, 16_369, 16_443]
out = aggregate.resolve_outlier(11_481, REAL)
check(out is not None, "сборка 1 сентября не названа выбросом")
check(not aggregate.resolve_volume_collapsed(11_481, aggregate.resolve_baseline_of(REAL)),
      "стенд опирается на то, что гейт эту сборку ПРОПУСКАЛ — а он её валит")
check(aggregate.resolve_outlier(16_299, REAL) is None,
      "здоровая сборка названа выбросом")
check(aggregate.resolve_outlier(16_000, REAL) is None,
      "просадка внутри нижней границы разброса названа выбросом — гейт станет крикливым")
check(aggregate.resolve_outlier(11_481, [16_299, 16_324]) is None,
      "выброс назван по двум наблюдениям, то есть по угаданному разбросу")

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
