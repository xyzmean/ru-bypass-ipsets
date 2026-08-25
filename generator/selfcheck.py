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
  3. манифест как контракт — у каждого доменного списка есть признак источника (зеркало
     `upstream` либо наш `maintained_here`, ровно один), у категорий поле симметрично и
     указывает на существующие id;
  4. наш собственный доменный список (sources/domains -> lists/domains/own_*.lst) —
     опубликован, помечен как наш и совпадает с исходником. Регенерация собирает и файлы,
     и манифест заново целиком, поэтому «нашего списка не стало» неотличимо от «его
     никогда не было»: единственная защита — проверка, что исходник ТРЕБУЕТ выпущенного
     файла и записи в манифесте.

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

    # Планка гейта просадки живёт в этом же манифесте, и потерять её можно ровно так же,
    # как same_prefixes_as выше: перестроили source_meta — поля не стало. Разница в том,
    # что тут никто не заметит. Гейт не падает и не предупреждает, он молча перестаёт
    # сравнивать, и следующий обвал резолва уедет к роутерам как обычная сборка.
    if not isinstance((data.get("sources") or {}).get("resolved_domains"), int):
        errs.append("манифест: нет sources.resolved_domains — гейту просадки резолва в "
                    "следующей сборке нечем мерить, и он замолчит, ни о чём не сказав")

    svc = {s["id"]: s for s in data.get("services", [])}
    for cid, c in cats.items():
        if cid in svc and (c.get("same_prefixes_as") or []) != (
                svc[cid].get("same_prefixes_as") or []):
            errs.append(f"манифест: у {cid} same_prefixes_as в categories и в services "
                        f"расходятся — интерфейс читает services")

    # Признак источника обязателен у КАЖДОГО доменного списка, и он ровно один: список
    # либо зеркалится (`upstream`), либо ведётся здесь (`maintained_here`). Разница —
    # единственное, что отвечает человеку на вопрос «куда нести домен, которого нет»,
    # и потерять её при регенерации значит вернуть ровно то непонимание, из-за которого
    # оба поля и заведены (I-077, splify2#7).
    doms = {d.get("id"): d for d in data.get("domain_lists", [])}
    for cid, d in doms.items():
        up, own = d.get("upstream"), d.get("maintained_here")
        if isinstance(up, dict) and isinstance(own, dict):
            errs.append(f"манифест: у {cid} сразу upstream и maintained_here — список "
                        f"либо зеркало, либо наш, третьего значения у этого нет")
        elif isinstance(own, dict):
            for k in UPSTREAM_KEYS:
                if k not in own:
                    errs.append(f"манифест: {cid}.maintained_here без поля {k!r}")
            if own.get("editable_locally") is not True:
                errs.append(f"манифест: {cid}.maintained_here.editable_locally должно быть "
                            f"true — этот список синхронизация не перезаписывает")
            if own.get("repo") != domain_lists_const("SELF_REPO"):
                errs.append(f"манифест: {cid}.maintained_here.repo ведёт не в наш "
                            f"репозиторий — предложить домен будет некуда")
        elif isinstance(up, dict):
            for k in UPSTREAM_KEYS:
                if k not in up:
                    errs.append(f"манифест: {cid}.upstream без поля {k!r}")
            if up.get("editable_locally") is not False:
                errs.append(f"манифест: {cid}.upstream.editable_locally должно быть "
                            f"false — зеркало перезаписывается синхронизацией целиком")
        else:
            errs.append(f"манифест: у доменного списка {cid} нет ни upstream, ни "
                        f"maintained_here — интерфейс не сможет сказать, чей это список")

    # «Дополняет» — отношение симметричное, как и «тот же набор префиксов»: интерфейс
    # читает его с любой стороны, и односторонняя связь показала бы наш список рядом с
    # зеркалом, но не зеркало рядом с нашим.
    for cid, d in doms.items():
        for other in d.get("complements", []):
            if other not in doms:
                errs.append(f"манифест: {cid}.complements ссылается на неизвестный "
                            f"доменный список {other}")
            elif cid not in (doms[other].get("complemented_by") or []):
                errs.append(f"манифест: {cid} дополняет {other}, а обратной ссылки "
                            f"complemented_by нет")
        for other in d.get("complemented_by", []):
            if other not in doms:
                errs.append(f"манифест: {cid}.complemented_by ссылается на неизвестный "
                            f"доменный список {other}")
            elif cid not in (doms[other].get("complements") or []):
                errs.append(f"манифест: {cid} дополняется {other}, а тот про это молчит")
    return errs


def domain_lists_const(name: str):
    """Значение константы генератора без падения, если модуль не импортируется."""
    try:
        import domain_lists
    except Exception:  # noqa: BLE001
        return None
    return getattr(domain_lists, name, None)


def check_local_lists() -> list[str]:
    """Наш собственный доменный список: опубликован, помечен и не потерян регенерацией.

    Ровно та ошибка, ради которой этот файл и заведён, только на новой сущности: манифест
    и lists/domains собираются заново ЦЕЛИКОМ, и «нашего списка не стало» ничем не
    отличается от «его никогда не было» — ни для человека, который его вёл, ни для
    роутера, который его качал. Поэтому исходник в sources/domains ТРЕБУЕТ и файла, и
    записи в манифесте, и совпадения их содержимого.
    """
    errs: list[str] = []
    try:
        import domain_lists
    except Exception as exc:  # noqa: BLE001
        return [f"наш доменный список: проверка не выполнена ({exc})"]

    sources = domain_lists.read_local_sources()
    entries = {}
    if MANIFEST.is_file():
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        entries = {d["id"]: d for d in data.get("domain_lists", [])
                   if d["id"].startswith(domain_lists.LOCAL_PREFIX)}

    for cid, info in sorted(sources.items()):
        for line in info["bad"]:
            errs.append(f"sources/domains/{info['src']}: строка не разбирается в домен "
                        f"и в список не попадёт: {line!r}")
        if not info["domains"]:
            continue
        out = LISTS / "domains" / f"{cid}.lst"
        if not out.is_file():
            errs.append(f"sources/domains/{info['src']}: списка {out.name} нет — наш "
                        f"список потерян при регенерации")
            continue
        published = [l.strip() for l in out.read_text(encoding="utf-8").splitlines()
                     if l.strip()]
        if published != info["domains"]:
            errs.append(f"{out.name}: содержимое разошлось с sources/domains/"
                        f"{info['src']} (в файле {len(published)}, в исходнике "
                        f"{len(info['domains'])})")
        if not MANIFEST.is_file():
            continue
        e = entries.get(cid)
        if e is None:
            errs.append(f"манифест: нашего списка {cid} нет, хотя файл опубликован — "
                        f"запись потеряна при регенерации, и потребитель его не увидит")
            continue
        if e.get("count") != len(published):
            errs.append(f"манифест: у {cid} count={e.get('count')}, а в файле "
                        f"{len(published)} доменов")
        if not isinstance(e.get("maintained_here"), dict):
            errs.append(f"манифест: у {cid} нет maintained_here — наш список выглядит "
                        f"как зеркало, и предлагать домен человеку будет некуда")

    for f in sorted((LISTS / "domains").glob(f"{domain_lists.LOCAL_PREFIX}*.lst")):
        cid = f.stem
        if cid not in sources:
            errs.append(f"{f.name}: опубликован, а исходника sources/domains/"
                        f"{cid[len(domain_lists.LOCAL_PREFIX):]}.lst нет — файл ничем "
                        f"не воспроизводится")

    # Дубли зеркала — не ошибка (см. domain_lists), но заявленное в манифесте должно
    # совпадать с измеренным: устаревшее число здесь — та же опубликованная неправда.
    dups = domain_lists.check_local_duplicates()
    for cid, e in entries.items():
        claimed = (e.get("already_in_upstream") or {}).get("count", 0)
        actual = len(dups.get(cid, {}))
        if claimed != actual:
            errs.append(f"манифест: {cid}.already_in_upstream обещает {claimed}, а с "
                        f"зеркалом пересекается {actual} домен(ов)")
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
    # Наш список: сколько доменов ведём сами и сколько из них уже приехало из зеркала.
    # Не ошибка — сигнал, что сид можно убрать, наш список остаётся дополнением.
    for cid, info in sorted(domain_lists.read_local_sources().items()):
        dups = domain_lists.check_local_duplicates().get(cid, {})
        print(f"  наш список {cid}: доменов {len(info['domains'])}, "
              f"уже есть в зеркале {len(dups)}"
              + (f" ({', '.join(sorted(dups)[:5])})" if dups else ""))


def main(argv: list[str] | None = None) -> int:
    warn_only = "--warn-only" in (argv if argv is not None else sys.argv[1:])
    groups = [
        ("схема категорий", schema.validate()),
        ("выпущенные списки против схемы", check_lists()),
        ("манифест", check_manifest()),
        ("наш доменный список", check_local_lists()),
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
