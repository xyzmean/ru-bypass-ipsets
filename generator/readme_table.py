#!/usr/bin/env python3
"""Таблица категорий в README — из манифеста, а не руками.

ЗАЧЕМ. Числа в таблице проставлялись руками и с тех пор не двигались: на 1 сентября
расходились 11 значений из 26, заметнее всего geoblock (494 в README против 266 в данных) и
rkn (11 923 против 11 196), а двух новых категорий — openwrt и github_cdn — в таблице не было
вовсе (I-084). Для человека это ровно тот случай, когда документация выглядит точнее данных:
числа конкретные, выглядят посчитанными, и проверить их читателю нечем.

Руками это не лечится: состав списков пересобирается раз в три дня, и любое вписанное число
неверно уже через сборку. Поэтому таблица СОБИРАЕТСЯ — из lists/categories.json, где лежит
всё, что ей нужно: имя, описание, число префиксов, признак геоблока и включённость по
умолчанию.

Два режима:
    python generator/readme_table.py            — перезаписать таблицу в README.md
    python generator/readme_table.py --check     — только проверить (код 1, если разошлось)

Первый вызывается публикующей сборкой сразу после aggregate.py — до гейтов и до коммита,
чтобы опубликованный README отвечал опубликованному манифесту. Второй стоит стендом
(tests/gate_readme_table.py): он ловит правку таблицы руками на коммите человека.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
MANIFEST = ROOT / "lists" / "categories.json"

HEADER = "| Категория | Русское название | Описание | Префиксов | По умолч. |"
RULER = "|---|---|---|---:|:--:|"


def row(entry: dict) -> str:
    """Одна строка таблицы. Знак 🌐 у геоблока — тот же, что объясняется под таблицей."""
    mark = " 🌐" if entry.get("is_geoblock") else ""
    on = "✅" if entry.get("default_on") else "⬜"
    # Вертикальная черта в описании разорвала бы таблицу. Экранируем, а не вырезаем: текст
    # приезжает из схемы, и молча менять его здесь нельзя.
    desc = str(entry.get("description_ru", "")).replace("|", "\\|")
    return (f"| `{entry['id']}`{mark} | {entry.get('name_ru', '')} | {desc} "
            f"| {entry.get('count', 0)} | {on} |")


def build_table(manifest: dict) -> str:
    lines = [HEADER, RULER]
    lines += [row(e) for e in manifest.get("categories") or ()]
    return "\n".join(lines)


def replace_table(text: str, table: str) -> str:
    """Подменить таблицу целиком. Границы — строка заголовка и первая пустая строка после."""
    at = text.find(HEADER)
    if at < 0:
        raise SystemExit("в README не найдена таблица категорий (строка заголовка изменилась)")
    end = text.find("\n\n", at)
    if end < 0:
        raise SystemExit("в README не найден конец таблицы категорий")
    return text[:at] + table + text[end:]


def main(argv: list[str]) -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    text = README.read_text(encoding="utf-8")
    table = build_table(manifest)
    updated = replace_table(text, table)
    if "--check" in argv:
        if updated == text:
            print("README: таблица категорий сходится с манифестом")
            return 0
        have = re.findall(r"^\| `([a-z0-9_]+)`.*?\| (\d+) \|", text, re.M)
        want = {e["id"]: e.get("count", 0) for e in manifest.get("categories") or ()}
        seen = {i for i, _ in have}
        for cid, n in have:
            if want.get(cid) != int(n):
                print(f"  {cid}: в README {n}, в манифесте {want.get(cid)}")
        for cid in want:
            if cid not in seen:
                print(f"  {cid}: категории нет в таблице README вовсе")
        print("README: таблица категорий разошлась с манифестом — "
              "python generator/readme_table.py")
        return 1
    if updated != text:
        README.write_text(updated, encoding="utf-8")
        print("README: таблица категорий пересобрана из манифеста")
    else:
        print("README: таблица категорий уже сходится с манифестом")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
