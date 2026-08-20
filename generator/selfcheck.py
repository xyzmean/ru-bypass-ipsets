"""Проверки, которые не требуют ни сети, ни резолва — прогон за секунды.

Зачем отдельный вход. `lists/categories.json` перезаписывается сборкой ЦЕЛИКОМ, а сборка
идёт около получаса и только в CI по расписанию. Значит поле манифеста существует ровно
до тех пределов, до которых его пишет генератор, и расхождение между манифестом и
выпущенными списками обычным взглядом не ловится: файлы лежат рядом, но сравнивать их
руками никто не будет. Отсюда три группы проверок:

  1. схема сама по себе — `categories_schema.validate()`;
  2. заявленное против выпущенного — совпадают ли наборы префиксов у категорий, про
     которые манифест говорит «тот же список адресов», и нет ли ПАР, про которые он
     молчит (именно так meta и whatsapp жили одинаковыми и не связанными);
  3. манифест как контракт — у доменных списков есть признак внешнего источника, у
     категорий поле симметрично и указывает на существующие id.

Плюс отчёт про тематические сиды: он ничего не роняет, но говорит вслух, сколько ручных
доменов в доменные списки не попало (см. domain_lists.check_thematic_seed_coverage).

Запуск:  python generator/selfcheck.py               (код возврата 1 при ошибках)
         python generator/selfcheck.py --warn-only  (то же, но код 0 и ::warning::)

`--warn-only` существует для публикующей сборки (resolve.yml). Там цена падения другая:
списки уже собраны, и уронить шаг перед коммитом значит оставить ВСЕ установленные
роутеры на списках прошлой сборки из-за расхождения в метаданных, которое маршрутизации
не касается. Поэтому там ошибки печатаются аннотациями GitHub Actions и видны в сводке
прогона, а гейтом остаётся ipsum (>= 5000 префиксов) и проверка схемы в самом начале
aggregate.py. В проверочном прогоне (validate.yml) публикации нет — там гейт жёсткий.
"""

from __future__ import annotations

import ipaddress
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import categories_schema as schema  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
LISTS = ROOT / "lists"
MANIFEST = LISTS / "categories.json"

UPSTREAM_KEYS = ("repo", "folder", "file", "url", "suggest_url", "editable_locally")


def _read_networks(path: Path) -> frozenset:
    return frozenset(
        ipaddress.ip_network(line.strip(), strict=False)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    )


def _measured_groups() -> tuple[dict[str, frozenset], dict[str, list[str]]]:
    """По выпущенным файлам: (набор префиксов у категории, группы полного совпадения)."""
    nets: dict[str, frozenset] = {}
    for cat in schema.CATEGORIES:
        f = LISTS / f"{cat['id']}.lst"
        if not f.is_file():
            continue  # список ещё не собран — это не ошибка схемы
        nets[cat["id"]] = _read_networks(f)
    buckets: dict[frozenset, list[str]] = {}
    for cid, s in nets.items():
        if s:
            buckets.setdefault(s, []).append(cid)
    measured = {cid: sorted(i for i in ids if i != cid)
                for ids in buckets.values() if len(ids) > 1 for cid in ids}
    return nets, measured


def check_lists() -> list[str]:
    """Совпадения наборов префиксов по выпущенным файлам против заявленного в схеме."""
    errs: list[str] = []
    nets, measured = _measured_groups()
    declared = {cid: v["with"] for cid, v in schema.declared_same_prefixes().items()}

    for cid, others in sorted(measured.items()):
        if cid not in declared:
            errs.append(f"{cid}.lst побайтово совпадает с {', '.join(others)}.lst, но в "
                        f"SAME_PREFIXES_GROUPS этой группы нет — манифест не скажет об этом")
        elif declared[cid] != others:
            errs.append(f"{cid}: схема заявляет совпадение с {declared[cid]}, а фактически "
                        f"с {others}")
    for cid, others in sorted(declared.items()):
        if cid not in nets:
            continue
        if cid not in measured:
            errs.append(f"{cid}: схема заявляет совпадение с {', '.join(others)}, но "
                        f"выпущенные списки различаются — причина устарела")
    return errs


def check_manifest() -> list[str]:
    """Манифест как контракт с потребителем: поля на месте и не противоречат файлам."""
    if not MANIFEST.is_file():
        return []
    errs: list[str] = []
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    cats = {c["id"]: c for c in data.get("categories", [])}

    for cid, c in cats.items():
        same = c.get("same_prefixes_as")
        if same is None:
            continue
        if not c.get("same_prefixes_reason_ru"):
            errs.append(f"манифест: у {cid} есть same_prefixes_as без "
                        f"same_prefixes_reason_ru — интерфейсу нечего показать")
        for other in same:
            if other not in cats:
                errs.append(f"манифест: {cid}.same_prefixes_as ссылается на неизвестную "
                            f"категорию {other}")
                continue
            back = cats[other].get("same_prefixes_as") or []
            if cid not in back:
                errs.append(f"манифест: {cid} → {other} есть, обратной ссылки нет; "
                            f"«тот же список» — отношение симметричное")
            fa, fb = LISTS / cats[cid]["file"], LISTS / cats[other]["file"]
            if fa.is_file() and fb.is_file() and _read_networks(fa) != _read_networks(fb):
                errs.append(f"манифест: {cid} обещает тот же список, что у {other}, "
                            f"а файлы различаются")

    # Поле, потерянное при регенерации, — главный способ сломать эту работу молча:
    # манифест собирается заново целиком, и «поля просто не стало» ничем не отличается
    # от «поля никогда не было». Поэтому совпадение по файлам ТРЕБУЕТ поля в манифесте.
    _, measured = _measured_groups()
    for cid, others in sorted(measured.items()):
        if cid in cats and not cats[cid].get("same_prefixes_as"):
            errs.append(f"манифест: {cid} побайтово совпадает с {', '.join(others)}, но "
                        f"same_prefixes_as в манифесте нет — поле потеряно при регенерации")

    svc = {s["id"]: s for s in data.get("services", [])}
    for cid, c in cats.items():
        if cid in svc and (c.get("same_prefixes_as") or []) != (
                svc[cid].get("same_prefixes_as") or []):
            errs.append(f"манифест: у {cid} same_prefixes_as в categories и в services "
                        f"расходятся — интерфейс читает services")

    for d in data.get("domain_lists", []):
        up = d.get("upstream")
        if not isinstance(up, dict):
            errs.append(f"манифест: у доменного списка {d.get('id')} нет upstream — "
                        f"интерфейс не сможет сказать, что список внешний")
            continue
        for k in UPSTREAM_KEYS:
            if k not in up:
                errs.append(f"манифест: {d.get('id')}.upstream без поля {k!r}")
        if up.get("editable_locally") is not False:
            errs.append(f"манифест: {d.get('id')}.upstream.editable_locally должно быть "
                        f"false — зеркало перезаписывается синхронизацией целиком")
    return errs


def report_thematic_seeds() -> None:
    """Не проверка, а отчёт: сколько ручных сидов в доменные списки не попало."""
    try:
        import domain_lists
    except Exception as exc:  # noqa: BLE001  (requests может быть не установлен)
        print(f"  тематические сиды: пропущено ({exc})")
        return
    r = domain_lists.check_thematic_seed_coverage()
    print(f"  тематических сидов: {r['total']}, из них есть в доменных списках "
          f"{r['in_domain_lists']}, только префиксами {len(r['prefix_only'])}")
    for name, st in sorted(r["by_file"].items()):
        print(f"    {name}: сидов {st['seeds']}, только префиксами {st['prefix_only']}")
    if r["prefix_only"]:
        print("    например: " + ", ".join(r["prefix_only"][:5]))
        print("    (такой домен идёт в резолв и становится префиксом; для сайта за общим "
              "CDN это не покрытие — см. I-077)")


def main(argv: list[str] | None = None) -> int:
    warn_only = "--warn-only" in (argv if argv is not None else sys.argv[1:])
    groups = [
        ("схема категорий", schema.validate()),
        ("выпущенные списки против схемы", check_lists()),
        ("манифест", check_manifest()),
    ]
    bad = 0
    for name, errs in groups:
        if errs:
            bad += len(errs)
            print(f"✗ {name}: {len(errs)} ошибк(и)")
            for e in errs:
                if warn_only:
                    print(f"::warning file=lists/categories.json::{name}: {e}")
                else:
                    print(f"  - {e}")
        else:
            print(f"✓ {name}")
    print("отчёт:")
    report_thematic_seeds()
    if bad:
        print(f"ИТОГО: {bad} ошибк(и)")
        return 0 if warn_only else 1
    print("ИТОГО: ошибок нет")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
