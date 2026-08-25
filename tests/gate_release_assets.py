#!/usr/bin/env python3
"""Стенд релизных ассетов: у двух выпускаемых файлов не бывает одного имени.

Зачем. Релиз собирается одной командой `gh release create` из двух каталогов сразу —
`lists/*.lst` и `lists/domains/*.lst`, — а ассеты релиза лежат в ПЛОСКОМ пространстве
имён. Каталоги пересекаются: `geoblock.lst` и `hodca.lst` есть и там, и там (адресный
список и доменный список одной категории). Второй файл с тем же именем GitHub отвергает
(HTTP 422 «ReleaseAsset.name already exists»), gh откатывает уже созданный релиз, и в
журнале остаётся строка «release не создан (возможно уже существует)» — объяснение, не
имеющее отношения к причине.

Следствие: последний релиз репозитория — 2026-08-01_06-24, а доменные списки появились
2026-08-02 (c598fcc). То есть все сборки после этого дня релиз не выпускали вовсе, а
сборка при этом оставалась зелёной.

Сети не требует: проверяется план ассетов по каталогу lists/.

Запуск: sh tests/run.sh  (или python3 tests/gate_release_assets.py)
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "generator"))

import release_assets  # noqa: E402

LISTS = ROOT / "lists"

fails: list[str] = []
checks = 0


def check(ok: bool, what: str) -> None:
    global checks
    checks += 1
    if not ok:
        fails.append(what)


plan = release_assets.plan(LISTS)
names = [asset for _, asset in plan]

# ── 1. Причина бага всё ещё существует ──────────────────────────────────────────
# Имена файлов в двух каталогах пересекаются — и это нормально, они про разное. Стенд
# фиксирует это как условие задачи: если пересечение исчезнет, префикс станет не нужен,
# но пока оно есть, план обязан его разводить.
addr = {p.name for p in LISTS.glob("*.lst")}
dom = {p.name for p in (LISTS / "domains").glob("*.lst")}
check(bool(addr & dom),
      "имена в lists/ и lists/domains/ больше не пересекаются — стенд потерял смысл")

# ── 2. План: имена уникальны и ничего не потеряно ───────────────────────────────
dupes = sorted({n for n in names if names.count(n) > 1})
check(not dupes, f"в плане релиза повторяются имена ассетов: {', '.join(dupes)}")

sources = sorted(LISTS.glob("*.lst")) + sorted((LISTS / "domains").glob("*.lst"))
planned = {src for src, _ in plan}
missing = [p.name for p in sources if p not in planned]
check(not missing, f"из релиза выпали файлы: {', '.join(missing[:5])}")
check((LISTS / "categories.json") in planned, "манифест не попал в релиз")
check(len(plan) == len(sources) + 1,
      f"в плане {len(plan)} ассетов, а файлов {len(sources) + 1} — что-то лишнее или потеряно")

# ── 3. Адресные списки сохраняют свои имена ─────────────────────────────────────
# Их имена уже опубликованы прошлыми релизами; разводить пространство имён надо той
# половиной, которой в релизах ещё не было.
by_src = dict(plan)
for p in sorted(LISTS.glob("*.lst")):
    check(by_src[p] == p.name, f"адресный список {p.name} переименован в ассете: {by_src[p]}")
for p in sorted((LISTS / "domains").glob("*.lst")):
    check(by_src[p] != p.name and p.name in by_src[p],
          f"доменный список {p.name} не разведён с адресным: {by_src[p]}")

# ── 4. Раскладка на диск даёт ровно эти имена ───────────────────────────────────
tmp = Path(__file__).resolve().parent / ".release_assets.tmp"
try:
    staged = release_assets.stage(tmp, plan)
    check(sorted(f.name for f in staged) == sorted(names),
          "имена разложенных файлов расходятся с планом")
    check(all(f.is_file() and f.stat().st_size == src.stat().st_size
              for (src, _), f in zip(plan, staged)),
          "разложенный файл пуст или короче исходного")
finally:
    if tmp.is_dir():
        for f in tmp.iterdir():
            f.unlink()
        tmp.rmdir()

print(f"gate_release_assets: проверок {checks}, провалов {len(fails)}")
for f in fails:
    print(f"  FAIL: {f}")
sys.exit(1 if fails else 0)
