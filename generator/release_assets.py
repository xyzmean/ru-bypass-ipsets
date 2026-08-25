#!/usr/bin/env python3
"""Раскладка файлов для ассетов релиза: плоское пространство имён без столкновений.

Релиз выпускается из двух каталогов сразу — `lists/*.lst` (адресные списки) и
`lists/domains/*.lst` (доменные), — а ассеты релиза лежат ПЛОСКО, одним пространством
имён. Каталоги пересекаются по именам: `geoblock.lst` и `hodca.lst` есть и там, и там,
и это нормально — адресный и доменный список одной категории про разное. Плоскому
хранилищу от этого не легче: второй файл с тем же именем GitHub отвергает (HTTP 422
«ReleaseAsset.name already exists»), а `gh release create` откатывает уже созданный
релиз целиком. Так репозиторий не выпускал релизов с 2026-08-02, оставаясь зелёным.

Разводятся доменные списки, а не адресные: имена адресных уже опубликованы прошлыми
релизами, а доменные в релизах не были ни разу — переименовывать надо ту половину,
на которую никто не мог сослаться.

Запуск в сборке:  python generator/release_assets.py --stage "$RUNNER_TEMP/release"
Печатает каталог, содержимое которого и передаётся `gh release create`.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LISTS = ROOT / "lists"

# Префикс доменных списков в плоском пространстве имён релиза.
DOMAIN_ASSET_PREFIX = "domains_"


def plan(lists_dir: Path = LISTS) -> list[tuple[Path, str]]:
    """Пары (файл, имя ассета) для всего, что уезжает в релиз."""
    out: list[tuple[Path, str]] = []
    for path in sorted(lists_dir.glob("*.lst")):
        out.append((path, path.name))
    for path in sorted((lists_dir / "domains").glob("*.lst")):
        out.append((path, DOMAIN_ASSET_PREFIX + path.name))
    manifest = lists_dir / "categories.json"
    if manifest.is_file():
        out.append((manifest, manifest.name))
    return out


def stage(dest: Path, assets: list[tuple[Path, str]] | None = None) -> list[Path]:
    """Разложить файлы в `dest` под именами ассетов. Возвращает разложенные пути."""
    assets = plan() if assets is None else assets
    dest.mkdir(parents=True, exist_ok=True)
    staged: list[Path] = []
    for src, name in assets:
        target = dest / name
        shutil.copyfile(src, target)
        staged.append(target)
    return staged


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stage", metavar="DIR", required=True,
                    help="каталог, куда разложить файлы под именами ассетов")
    args = ap.parse_args()

    assets = plan()
    names = [name for _, name in assets]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        # Не «пропустим и посмотрим»: столкновение имён отвергает GitHub, и релиз
        # откатывается целиком. Лучше сказать об этом здесь, чем прочитать 422 в журнале.
        print("столкновение имён ассетов: " + ", ".join(dupes), file=sys.stderr)
        return 2
    staged = stage(Path(args.stage), assets)
    print(f"ассетов разложено: {len(staged)} → {args.stage}", file=sys.stderr)
    print(args.stage)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
