"""Этап E + оркестратор всего пайплайна.

АРХИТЕКТУРА С ЕДИНЫМ КЕШЕМ РЕЗОЛВА:
  1. Собираю все домены из всех источников в единый пул (с меткой категории).
  2. Резолвлю КАЖДЫЙ домен ОДИН РАЗ (кеш), а не отдельно по категориям.
     Это убирает дубли (~190k → ~93k доменов) и ускоряет в разы.
  3. rkn_other (мусорный пул мёртвых доменов) резолвится с pre-check (1 NS):
     только живые идут в полный резолв.
  4. Результат резолва + ASN/CDN-CIDR собирается по категориям, collapse/сорт.

Запуск:  python generator/aggregate.py
Env:
  SAMPLE=<N>     — ограничить РКН до N доменов (для локальной проверки)
  SKIP_GEO=1     — пропустить GeoLite2
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import logging
import os
import sys
from pathlib import Path

import categories_schema as schema
import lib

import fetch_sources
import resolve as resolver
import asn_pull
import categorize

ROOT = Path(__file__).resolve().parent.parent
LISTS = ROOT / "lists"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(ROOT / "generator" / "build.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("aggregate")

IPSUM_MIN_COUNT = 5000  # gate splify (common.sh IPSUM_MIN_COUNT=5000)


# ─────────────── сбор доменов из источников по категориям ───────────────


def _service_domains(category: dict) -> list[str]:
    src = category["source"]
    domains: list[str] = []
    for fname in src.get("files", []):
        domains += lib.read_domains(ROOT / "sources" / "services" / fname)
    domains += src.get("extra_domains", [])
    flt = src.get("domain_filter")
    if flt == "whatsapp":
        domains = [d for d in domains if "whatsapp" in d]
    elif flt == "not_whatsapp":
        domains = [d for d in domains if "whatsapp" not in d]
    return domains


def collect_domains_by_category(
    rkn_domains: list[str],
    community_ooni: list[str],
    geoblock_domains: list[str],
) -> dict[str, set[str]]:
    """Собрать {category_id -> set(доменов)} из всех источников.

    Сервисные — из sources/services; `rkn` и `geoblock` — из categorize() плюс
    тематические сиды в sources/thematic. Категории с готовыми CIDR (`cidr_url`) доменов
    не имеют и в пул резолва не попадают.
    """
    # 1) категоризация РКН/community/geoblock по правилам → два ведра: rkn и geoblock
    rule_domains = categorize.categorize(rkn_domains, community_ooni, geoblock_domains)

    categories: dict[str, set[str]] = {k: set(v) for k, v in rule_domains.items()}

    # 2) сервисные домены
    for cat in schema.CATEGORIES:
        if cat["source"]["kind"] == "service":
            for d in _service_domains(cat):
                categories.setdefault(cat["id"], set()).add(d)

    # 3) тематические сиды. Раньше каждый лежал в своей категории (news, adult, media);
    # после склейки тематик они все относятся к `rkn`. Потерять их нельзя: это ручной
    # отбор, которого нет ни в снапшоте, ни в правилах.
    thematic_dir = ROOT / "sources" / "thematic"
    for f in sorted(thematic_dir.glob("*.lst")):
        # geoblock_domains.lst читается отдельно (fetch_sources.load_geoblock_domains)
        # и уже разложен категоризатором — второй раз он тут не нужен.
        if f.name == "geoblock_domains.lst":
            continue
        for d in lib.read_domains(f):
            categories.setdefault("rkn", set()).add(d)

    return categories


# ─────────────── единый пул доменов + резолв ───────────────

# Порог: пулы доменов крупнее этого идут через быстрый pre-check (отсев мёртвых).
PRECHECK_THRESHOLD = 500


def build_resolve_pool(
    domains_by_cat: dict[str, set[str]]
) -> tuple[list[str], list[str]]:
    """Разделить все домены на два пула: (direct, precheck).

    Большие пулы (>= PRECHECK_THRESHOLD доменов) — через pre-check (отсев мёртвых),
    малые — напрямую. Возвращает (direct_domains, precheck_domains), оба уникальные.
    Малый пул имеет приоритет: домен из обоих пулов остаётся в direct.
    """
    direct: set[str] = set()
    precheck: set[str] = set()
    big: set[str] = set()
    small: set[str] = set()
    for cid, doms in domains_by_cat.items():
        if len(doms) >= PRECHECK_THRESHOLD:
            big |= doms
        else:
            small |= doms
    # малый пул имеет приоритет (без precheck): домены из обоих — в small
    big -= small
    return sorted(small), sorted(big)


# ГРАНИЦА, шире которой ASN-сеть GeoLite2 в список не идёт целиком. /20 — 4096
# адресов: достаточно, чтобы накрыть соседние адреса сервиса при ротации, и на
# порядки меньше, чем целые облака.
#
# Зачем граница. GeoLite2 отдаёт сеть ПРОВАЙДЕРА адреса, и один заблокированный
# сайт на AWS приносил в свою категорию диапазон AWS в миллионы адресов. Отсюда
# два следствия сразу: категории раздувались (adult — 17,5 млн адресов, dev_GB —
# 59 млн) и НАКЛАДЫВАЛИСЬ друг на друга долями в 30–90% — adult ∩ hodca 74%,
# news ∩ news_GB 76%, dev ∩ aws 76%, потому что все делили одни и те же блоки
# хостингов. Человек включал две категории и уводил в туннель пол-интернета
# дважды. Вместо широкой сети берётся /24 вокруг самого адреса: это соседи по
# стойке, а не весь провайдер.
ASN_NETWORK_MAX_SIZE_PREFIXLEN = 20


def result_to_networks(res: resolver.ResolveResult) -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []
    for ip in res.ips:
        if n := lib.parse_cidr(f"{ip}/24"):
            nets.append(n)
    for net_str in res.networks:  # GeoLite2 ASN-network (более крупно)
        if (n := lib.parse_cidr(net_str)) and n.prefixlen >= ASN_NETWORK_MAX_SIZE_PREFIXLEN:
            nets.append(n)
    return nets


# ─────────────── ASN / CDN ───────────────


def _asn_cidrs(category: dict, asn_map: dict) -> list[ipaddress.IPv4Network]:
    src = category["source"]
    if not (src["kind"] == "service" and src.get("asn")):
        return []
    nets = []
    for asn in asn_map.get(category["id"], []):
        nets += asn_pull.asn_to_cidrs(int(asn))
    return nets


def _cdn_cidrs(category: dict) -> list[ipaddress.IPv4Network]:
    cdn = category["source"].get("cdn")
    if not cdn:
        return []
    return asn_pull.pull_cdn(cdn)


def _cidr_url(category: dict) -> list[ipaddress.IPv4Network]:
    """Готовый ipset по ссылке, со снапшотом в репозитории как запасным путём.

    Снапшот обновляется при каждой удачной загрузке и лежит в репозитории намеренно: без
    него недоступный источник означал бы список из нуля префиксов, а нулевой список — это
    «канал включён, и в нём ничего», то есть сервис молча перестал ходить в туннель.
    Порядок именно такой: сеть — источник правды, файл — память о последнем удачном разе.
    """
    import requests

    src = category["source"]
    cid = category["id"]
    snapshot = ROOT / "sources" / src["fallback_file"] if src.get("fallback_file") else None

    text = None
    try:
        resp = requests.get(src["url"], timeout=fetch_sources.HTTP_TIMEOUT)
        resp.raise_for_status()
        text = resp.text
        if snapshot is not None:
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            snapshot.write_text(text, encoding="utf-8")
        log.info("%s: список загружен (%d байт)", cid, len(text))
    except Exception as exc:  # noqa: BLE001
        log.warning("%s: источник недоступен (%s)", cid, exc)
        if snapshot is not None and snapshot.is_file():
            text = snapshot.read_text(encoding="utf-8", errors="replace")
            log.warning("%s: взят снапшот %s", cid, snapshot.name)

    if not text:
        log.error("%s: ни источника, ни снапшота — список останется пустым", cid)
        return []
    nets = list(lib.clean_lines(text))
    log.info("%s: %d CIDR из готового списка", cid, len(nets))
    return nets


def _extra_cidrs(category: dict) -> list[ipaddress.IPv4Network]:
    """Готовые CIDR сервиса из вендорного снапшота.

    Нужно там, где своего ASN у сервиса нет и по ASN его не собрать. Discord — ровно этот
    случай: голос живёт блоками в Google Cloud, и они перечислены снапшотом, а не выводятся
    из номера автономной системы, которого не существует.
    """
    rel = category["source"].get("extra_cidr_file")
    if not rel:
        return []
    f = ROOT / "sources" / rel
    if not f.is_file():
        log.warning("%s: снапшот %s не найден", category["id"], rel)
        return []
    nets = list(lib.clean_lines(f.read_text(encoding="utf-8", errors="replace")))
    log.info("%s: %d CIDR из снапшота %s", category["id"], len(nets), rel)
    return nets


# ─────────────── вычитание инфраструктуры ───────────────

# ГРАНИЦА, ниже которой префикс считается «своим адресом», а не «диапазоном провайдера».
# /24 и мельче остаются даже внутри CDN: это конкретные узлы сервиса, найденные резолвом
# его же доменов, и в них вся точность. Убрать их значило бы выкинуть ровно то, ради чего
# список и нужен, — а «лишнее» приносят широкие диапазоны, не отдельные адреса.
INFRA_SUBTRACT_MAX_PREFIXLEN = 24


# Доля от прошлой сборки, ниже которой снапшот не публикуется. Здоровые сборки
# различаются между собой на проценты (14 381, 14 512, 14 816 доменов с адресами), а
# просевшие давали 3 307–3 462 — то есть 0.7 оставляет обвалу запас в обе стороны.
RESOLVE_DROP_GATE = 0.7


def previous_resolved_count(manifest: Path | None = None) -> int | None:
    """Сколько доменов дали адреса в ПРОШЛОЙ опубликованной сборке.

    Читается из манифеста, лежащего на диске: сборка идёт в чекауте main, и до записи
    нового `lists/categories.json` там лежит именно прошлый. Ни файла, ни поля, ни
    разбираемого json — значит сравнивать не с чем, и гейт молчит, а не падает.
    """
    path = manifest if manifest is not None else LISTS / "categories.json"
    try:
        got = json.loads(path.read_text(encoding="utf-8"))["sources"]["resolved_domains"]
    except Exception:  # noqa: BLE001
        return None
    return got if isinstance(got, int) else None


def resolve_volume_collapsed(resolved: int, previous: int | None) -> bool:
    """Просел ли резолв настолько, что публиковать нельзя.

    Мера — число доменов, ДАВШИХ адреса, а не число строк в списках: строк на просевшей
    сборке становится БОЛЬШЕ (меньше адресов — меньше соседних /24 слипается в префикс),
    поэтому по строкам обвал выглядит ростом, и гейт по ipsum.lst его пропускает.

    Храповик здесь односторонний: планка берётся от прошлой сборки, поэтому медленное
    сползание гейт не поймает, а обвал — поймает. Просевшая прошлая сборка планку не
    задирает, то есть запереть публикацию навсегда этот гейт не может.
    """
    if not previous or previous <= 0:
        return False
    return resolved < previous * RESOLVE_DROP_GATE


def subtract_shared_proxy(
    nets: list[ipaddress.IPv4Network], proxy: list[ipaddress.IPv4Network]
) -> tuple[list[ipaddress.IPv4Network], int]:
    """Убрать адреса общих обратных прокси — ОТКУДА УГОДНО и без порога по размеру.

    Cloudflare, CloudFront и Akamai отдают anycast-края, за которыми тысячи сайтов. Резолв
    выдал такой адрес потому, что в ту минуту он ответил за нужный домен; завтра за ним
    другой сайт. Маршрутизировать его — увести в туннель всех остальных заодно, и никакой
    порог по размеру префикса тут не спасает: /32 у Cloudflare не «узел сервиса», а край.
    
    Это отличает прокси от хостинга: у Hetzner адрес обычно закреплён за одним клиентом, и
    заблокированный сайт по нему ловится законно. Поэтому у хостингов вычитаются только
    широкие диапазоны (см. subtract_infra), а у прокси — всё.

    Покрытие того, что живёт за прокси, даёт доменная половина сервиса. Ради этого склейка
    адресов с доменами и сделана: адресами то, что сервису принадлежит, доменами то, что по
    адресу не ловится.

    Вырезается ПЕРЕСЕЧЕНИЕ, а не отбрасывается вся сеть. Разница не теоретическая: проверка
    `subnet_of` пропускала префикс, который прокси не вложен, а СОДЕРЖИТ. В снапшоте РКН
    так и лежал 104.16.0.0/12 — внутри него весь 104.16.0.0/13 и 104.24.0.0/14 Cloudflare,
    897 024 адреса, и всё вычитание обходилось одной строкой вендорного файла. Отбросить
    его целиком тоже нельзя: за пределами Cloudflare в нём 3,2 млн чужих адресов.
    """
    if not proxy:
        return nets, 0
    ranges = list(ipaddress.collapse_addresses(proxy))
    return lib.punch_out_counted(nets, ranges)


def empty_shared_proxy(categories: list[dict], cat_networks: dict) -> list[str]:
    """Категории общих обратных прокси, у которых список вышел пустым.

    Пустой список прокси — не «файл, который никто не включил». Эти категории служат
    двум целям сразу: публикуются файлом и одновременно являются вычитаемым для всех
    остальных (`subtract_shared_proxy`). Значит ноль префиксов у провайдера означает,
    что вычитание этого провайдера не выполнилось НИ У ОДНОЙ категории, и его
    anycast-края уехали в списки, включённые по умолчанию.

    Ноль здесь никогда не значит «у провайдера нет префиксов» — значит «pull провалился».
    У девяти из десяти прокси источник это ASN с тремя фолбэками (`asn_to_cidrs`), у
    cloudfront — фид AWS; и тот и другой при отказе возвращают пустой список, печатают
    warning и идут дальше. Ровно так cloudfront.lst выпускался пустым из-за имени вида в
    диспетчере (см. `asn_pull.pull_cdn`), и ровно так 2026-08-22T04:20Z вышел пустым
    fastly.lst: 38 префиксов Fastly остались лежать в rkn.lst и ipsum.lst (оба
    default_on), 6 — в twitter_x.lst.

    Заметить это по выпущенным спискам невозможно, поэтому проверка стоит в сборке, а не
    в selfcheck: единственный источник правды о том, что надо было вычесть, — тот самый
    файл, который вышел пустым. Проверка «пересекается ли rkn.lst с fastly.lst» на плохой
    сборке зелёная, потому что пересекать не с чем.

    Хостинги (`is_infra` без `is_shared_proxy`) сюда не входят: у них вычитаются только
    широкие диапазоны и только у сервисов, и пустой список хостинга чужие сайты в туннель
    не уводит.
    """
    return [c["id"] for c in categories
            if c.get("is_shared_proxy") and not cat_networks.get(c["id"])]


def subtract_infra(
    nets: list[ipaddress.IPv4Network], infra: list[ipaddress.IPv4Network]
) -> tuple[list[ipaddress.IPv4Network], int]:
    """Убрать из сервисного списка широкие диапазоны инфраструктуры.

    Зачем. Сервис за Cloudflare резолвится в адреса Cloudflare. Включить их целиком —
    увести в туннель половину интернета вместо одного сервиса; ровно это и означало
    «лишнее уходит». Инфраструктура при этом остаётся своими списками: кому она нужна,
    тот выбирает её отдельно и осознанно.

    Что НЕ убирается: префиксы /24 и мельче. Они не диапазон провайдера, а конкретные узлы
    сервиса на нём. Проверено на Discord: 4% его адресов лежат внутри Cloudflare, и это
    именно его края — выкинув их, список потерял бы смысл.

    Как и у общих прокси, вырезается пересечение, а не отбрасывается сеть целиком: широкий
    префикс, который несёт внутри себя диапазон хостинга, теряет ровно этот диапазон.
    """
    if not infra:
        return nets, 0
    infra_set = list(ipaddress.collapse_addresses(infra))
    narrow = [n for n in nets if n.prefixlen > INFRA_SUBTRACT_MAX_PREFIXLEN]
    wide = [n for n in nets if n.prefixlen <= INFRA_SUBTRACT_MAX_PREFIXLEN]
    punched, touched = lib.punch_out_counted(wide, infra_set)
    return narrow + punched, touched


# ─────────────── индекс ───────────────


def same_prefixes_groups(
    cat_networks: dict[str, list[ipaddress.IPv4Network]]
) -> dict[str, dict]:
    """Категории, у которых набор префиксов ОДИН И ТОТ ЖЕ: id → {"with", "reason_ru"}.

    Считается по СОБРАННЫМ спискам, а не по схеме. Разница принципиальная: поле
    `same_prefixes_as` в манифесте — утверждение о выпущенных файлах, и оно должно быть
    верным на день сборки, а не на день, когда кто-то дописал группу в схему. Схема
    (`SAME_PREFIXES_GROUPS`) даёт только человеческую причину совпадения.

    Отсюда два сообщения в лог, и оба нужны:
      * совпадение НАЙДЕНО, но в схеме не описано — новая пара категорий с общей AS
        появилась сама, и человеку об этом никто не сказал (ровно так жили meta и
        whatsapp);
      * совпадение ЗАЯВЛЕНО, но списки разошлись — причина устарела, и публиковать
        «тот же список, что у Meta» уже неправда.
    Пустые списки в группы не собираются: два пустых файла совпадают, но это не «та же
    цель», а провал сборки, и он виден по count.
    """
    buckets: dict[frozenset, list[str]] = {}
    for cat in schema.CATEGORIES:
        nets = cat_networks.get(cat["id"])
        if not nets:
            continue
        buckets.setdefault(frozenset(nets), []).append(cat["id"])

    declared = schema.declared_same_prefixes()
    out: dict[str, dict] = {}
    for ids in buckets.values():
        if len(ids) < 2:
            continue
        for cid in ids:
            others = sorted(i for i in ids if i != cid)
            known = declared.get(cid)
            if known and known["with"] == others:
                reason = known["reason_ru"]
            else:
                reason = ("совпадение обнаружено при сборке: наборы префиксов совпали "
                          "полностью, причина в схеме не описана")
                log.warning("same_prefixes: %s совпадает с %s, но в SAME_PREFIXES_GROUPS "
                            "этой группы нет — причина не названа", cid, ", ".join(others))
            out[cid] = {"with": others, "reason_ru": reason}

    for cid, known in declared.items():
        if cid not in out:
            log.error("same_prefixes: схема заявляет совпадение %s с %s, но собранные "
                      "списки различаются — поле не публикуется",
                      cid, ", ".join(known["with"]))
    return out


def seeds_behind_shared_proxy(
    domains: list[str], resolve_cache: dict, proxy_nets: list[ipaddress.IPv4Network]
) -> list[str]:
    """Из доменов — те, чьи адреса ЦЕЛИКОМ лежат за общими обратными прокси.

    Худший случай из I-077 и есть этот список: домена нет в доменных списках (значит он
    попадёт только префиксами), а префиксы у него — края Cloudflare или CloudFront.
    Такой адрес либо вычтется как инфраструктура, либо уведёт в туннель всё, что за
    прокси живёт. То есть покрытия у домена нет ни одного, и сказать об этом надо в
    сборке, а не в переписке с пользователем.
    """
    ranges = list(ipaddress.collapse_addresses(proxy_nets)) if proxy_nets else []
    if not ranges:
        return []
    out: list[str] = []
    for dom in domains:
        res = resolve_cache.get(dom)
        nets = result_to_networks(res) if res else []
        if nets and all(any(n.overlaps(r) for r in ranges) for n in nets):
            out.append(dom)
    return out


def build_index(
    counts: dict[str, int],
    source_meta: dict,
    domain_entries: list[dict] | None = None,
    same_prefixes: dict[str, dict] | None = None,
) -> dict:
    """Собрать манифест. `same_prefixes` — результат same_prefixes_groups() по
    собранным спискам; None означает «списков под рукой нет», и тогда берётся
    заявленное в схеме, а сверка остаётся за generator/selfcheck.py."""
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    version = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    if same_prefixes is None:
        same_prefixes = schema.declared_same_prefixes()

    def entry(c, aggregate=False):
        old = schema.RENAMED_FROM.get(c["id"], [])
        # Агрегаты в группы не входят: они объединения, и «тот же список» про них
        # говорилось бы про совсем другое отношение.
        same = None if aggregate else same_prefixes.get(c["id"])
        return {
            "id": c["id"],
            "name_ru": c["name_ru"],
            "description_ru": c["description_ru"],
            "file": f"{c['id']}.lst",
            "default_on": c["default_on"],
            "is_geoblock": c["is_geoblock"],
            "count": counts.get(c["id"], 0),
            # Какие списки схлопнулись в этот. Потребитель по этому полю переносит
            # настройку молча вместо того, чтобы молча перестать обновлять файл.
            **({"renamed_from": [f"{o}.lst" for o in old]} if old else {}),
            # Категории, чей адресный список совпадает с этим ПОЛНОСТЬЮ, и почему.
            # Файлы при этом остаются отдельными: на их имена ссылаются уже настроенные
            # каналы. Поле нужно интерфейсу, чтобы напечатать «тот же список адресов,
            # что у Meta: общая автономная система», а не показывать два переключателя,
            # из которых один выглядит узким и таковым не является.
            **({"same_prefixes_as": same["with"],
                "same_prefixes_reason_ru": same["reason_ru"]} if same else {}),
            **({"aggregate": True} if aggregate else {}),
        }

    return {
        "version": version,
        "generated_at": now,
        "base_url": schema.BASE_URL,
        "ipsum_min_count": IPSUM_MIN_COUNT,
        "sources": source_meta,
        # Карта «старое имя файла → новое» рядом с категориями: читателю, который разбирает
        # spec.json со старыми путями, не нужно обходить весь массив категорий. Без неё
        # переименование ломается ТИХО — скрипт обновления пишет «нет в манифесте,
        # пропущен», список остаётся старой копией и признак ошибки не выставляется.
        #
        # Массивом объектов, а не объектом-словарём: главный потребитель — sh-скрипт на
        # роутере, который читает манифест через jsonfilter, а тот умеет доставать
        # `@.aliases[*].from`, но не перечисляет ключи произвольного объекта.
        "aliases": [{"from": f"{o}.lst", "to": f"{n}.lst"}
                    for o, n in sorted(schema.alias_map().items())],
        "categories": [entry(c) for c in schema.CATEGORIES],
        # Доменные списки — отдельным ключом, а не внутри categories: у записей другая
        # форма (kind, overlaps, same_as_ip) и другое назначение — их потребляет
        # доменный канал движка напрямую, без разрешения в адреса. Существующие
        # читатели categories.json от нового ключа не ломаются.
        "domain_lists": domain_entries or [],
        "aggregates": [entry(a, aggregate=True) for a in schema.AGGREGATES],
        # ─────────── services: сервис как ОДНА сущность ───────────
        #
        # Ключ существует ради одного: чтобы человек кликал сервис, а не выбирал форму.
        # Раньше интерфейсу приходилось решать за него, брать адреса или домены, — а
        # правильный ответ «и то и другое, каждое там, где работает»: адресами то, что
        # сервису принадлежит, доменами то, что живёт на общих CDN и по адресу не
        # ловится. Отсюда и вычитание инфраструктуры: без него адресная половина тащила
        # за собой половину интернета, и «двойное покрытие» превращалось в «лишнее».
        #
        # Отдельным ключом, а не полем внутри categories, по той же причине, по которой
        # отдельно лежат domain_lists: у записи другая форма и другое назначение, а
        # существующие читатели categories.json от нового ключа не ломаются.
        "services": _service_entries(counts, domain_entries or [], same_prefixes),
    }


def _service_entries(
    counts: dict[str, int], domain_entries: list[dict], same_prefixes: dict[str, dict]
) -> list[dict]:
    """Пары «адреса + домены» по одному сервису.

    Сопоставление по имени файла доменного списка: `svc_<id>` у издателя доменов против
    `<id>` категории адресов. Пары нет — сервис всё равно попадает в список, но с одной
    половиной: молча пропустить его значило бы, что в интерфейсе исчез сервис, у которого
    просто нет доменного списка.
    """
    by_id = {d["id"]: d for d in domain_entries}
    out = []
    for c in schema.CATEGORIES:
        # cidr_url здесь наравне с service: Discord собирается готовым ipset'ом, но остаётся
        # сервисом, который человек включает галочкой. Проверять тип источника значило бы
        # решать за интерфейс, чем сервис наполняется, — а ему важно, что это сервис.
        if c["source"]["kind"] not in ("service", "cidr_url"):
            continue
        cid = c["id"]
        # Доменные списки берём по явному соответствию, а где его нет — по имени.
        # Соответствие нужно потому, что у издателя доменов своя нумерация: twitter_x
        # против svc_twitter, а Google вообще разложен на три списка. Без этого сервис
        # оставался бы с одной половиной покрытия — то есть ровно с той дыркой, которую
        # склейка и закрывает.
        ids = schema.SERVICE_DOMAIN_LISTS.get(cid, [f"svc_{cid}", cid])
        doms = [by_id[i] for i in ids if i in by_id]
        out.append({
            "id": cid,
            "name_ru": c["name_ru"],
            "description_ru": c["description_ru"],
            "default_on": c["default_on"],
            "is_geoblock": c["is_geoblock"],
            "is_infra": bool(c.get("is_infra")),
            "prefixes_file": f"{cid}.lst",
            "prefixes_count": counts.get(cid, 0),
            # Список, а не одно поле: у Google их три, и склеивать их в один файл значило
            # бы завести четвёртый источник правды рядом с тремя существующими.
            "domains_files": [d["file"] for d in doms],
            "domains_count": sum(d.get("count", 0) for d in doms),
            # То же поле, что у категорий: интерфейс строит каталог по `services`, и без
            # него «YouTube» и «Google» остались бы двумя строками с одинаковым числом
            # префиксов и без объяснения, почему они одинаковые.
            **({"same_prefixes_as": same["with"],
                "same_prefixes_reason_ru": same["reason_ru"]}
               if (same := same_prefixes.get(cid)) else {}),
        })
    return out


# ─────────────── main ───────────────


def main():
    log.info("=== ru-bypass-ipsets build (v2: кеш + параллельный DNS) ===")

    # Схема проверяется ДО первого запроса в сеть. Полчаса резолва ради манифеста, у
    # которого поле противоречит данным, — худший из вариантов: он ещё и публикуется.
    schema_errors = schema.validate()
    for e in schema_errors:
        log.error("схема категорий: %s", e)
    if schema_errors:
        log.error("сборка прервана: %d ошибк(и) в схеме", len(schema_errors))
        sys.exit(2)

    geolite_path = None
    if os.environ.get("SKIP_GEO") != "1":
        try:
            geolite_path = fetch_sources.ensure_geolite()
        except Exception as exc:
            log.warning("GeoLite2 недоступен (%s) — без ASN-network.", exc)

    # A: источники
    rkn_domains, rkn_source = fetch_sources.fetch_rkn_domains()
    sample = os.environ.get("SAMPLE")
    if sample:
        n = int(sample)
        rkn_domains = rkn_domains[:n]
        log.info("SAMPLE: РКН ограничен до %d", len(rkn_domains))
    community_ooni = fetch_sources.load_community_ooni()
    geoblock_domains = fetch_sources.load_geoblock_domains()

    # D: категоризация
    domains_by_cat = collect_domains_by_category(rkn_domains, community_ooni, geoblock_domains)
    for cid, doms in sorted(domains_by_cat.items()):
        log.info("категория %s: %d доменов (до резолва)", cid, len(doms))

    # B: единый пул резолва
    direct, precheck_pool = build_resolve_pool(domains_by_cat)
    log.info("пул резолва: direct=%d, precheck=%d (всего %d)",
             len(direct), len(precheck_pool), len(direct) + len(precheck_pool))

    log.info("--- резолв direct-пула ---")
    cache_direct = resolver.resolve_domains(direct, geolite_path, precheck=False)
    log.info("--- резолв precheck-пула (большие пулы: rkn) ---")
    cache_pre = resolver.resolve_domains(precheck_pool, geolite_path, precheck=True)

    # объединённый кеш: домен -> ResolveResult
    resolve_cache = {**cache_direct, **cache_pre}
    log.info("кеш резолва: %d доменов", len(resolve_cache))

    # Гейт просадки резолва — ДО того, как записан хоть один список: почти всё содержимое
    # списков берётся отсюда, и провал резолва в файлах не виден (см. tests/
    # gate_resolve_volume.py). Планка — прошлая опубликованная сборка.
    resolved_domains = sum(1 for r in resolve_cache.values() if r.ips)
    prev_resolved = previous_resolved_count()
    log.info("доменов с адресами: %d (в прошлой сборке %s)",
             resolved_domains, prev_resolved if prev_resolved is not None else "неизвестно")
    if resolve_volume_collapsed(resolved_domains, prev_resolved) and not sample:
        log.error("GATE FAIL: адреса дали %d доменов против %d в прошлой сборке (порог %.0f%%) "
                  "— резолв просел, а по числу строк в списках это не видно. Публикация "
                  "отменена, роутеры остаются на прошлой сборке.",
                  resolved_domains, prev_resolved, RESOLVE_DROP_GATE * 100)
        sys.exit(2)
    if resolve_volume_collapsed(resolved_domains, prev_resolved):
        log.warning("SAMPLE-режим: просадка резолва не валит сборку (%d против %d)",
                    resolved_domains, prev_resolved)

    # ASN-карта
    asn_map = asn_pull.load_asn_map()

    # E: сборка сетей по категориям
    counts: dict[str, int] = {}
    cat_networks: dict[str, list[ipaddress.IPv4Network]] = {}
    LISTS.mkdir(parents=True, exist_ok=True)

    # Инфраструктура собирается ПЕРВОЙ: её префиксы нужны, чтобы вычесть их из сервисных
    # списков. Порядок здесь смысловой, а не случайный — переставив, получим сервисы с
    # неубранными диапазонами провайдеров и молча вернём «лишнее».
    infra_nets: list[ipaddress.IPv4Network] = []
    proxy_nets: list[ipaddress.IPv4Network] = []
    ordered = ([c for c in schema.CATEGORIES if c.get("is_infra")]
               + [c for c in schema.CATEGORIES if not c.get("is_infra")])
    subtracted: dict[str, int] = {}

    for cat in ordered:
        cid = cat["id"]
        src = cat["source"]
        nets: list[ipaddress.IPv4Network] = []

        if src["kind"] == "cidr_url":
            nets = _cidr_url(cat)
        elif src["kind"] == "rkn":
            # Два источника сразу: готовые CIDR снапшота (без резолва) и адреса доменов,
            # которые категоризатор отправил в `rkn`. До склейки это были разные категории
            # (rkn_other и восемь тематик), и потому их префиксы не могли схлопнуться
            # между собой — 3 246 строк существовали только из-за границы между файлами.
            vfile = ROOT / "sources" / src["file"]
            if vfile.is_file():
                nets = list(lib.clean_lines(vfile.read_text(encoding="utf-8", errors="replace")))
            log.info("%s: %d CIDR из снапшота %s", cid, len(nets), vfile.name)
            for dom in domains_by_cat.get(cid, ()):
                if dom in resolve_cache:
                    nets += result_to_networks(resolve_cache[dom])
        else:
            # домены категории → из кеша резолва
            for dom in domains_by_cat.get(cid, ()):
                if dom in resolve_cache:
                    nets += result_to_networks(resolve_cache[dom])
            # ASN/CDN для сервисов
            nets += _asn_cidrs(cat, asn_map)
            nets += _cdn_cidrs(cat)
            nets += _extra_cidrs(cat)

        if cat.get("is_infra"):
            infra_nets += nets
            if cat.get("is_shared_proxy"):
                proxy_nets += nets
        elif cat.get("no_subtract"):
            # Список берётся как есть — по решению владельца. Не молча: раз вычитание
            # пропущено, в лог идёт, сколько адресов инфраструктуры в списке осталось,
            # иначе «взяли как есть» и «случайно затащили половину Cloudflare» выглядят
            # в сборке одинаково.
            # Склейка диапазонов СЧИТАЕТСЯ ОДИН РАЗ, а не внутри перебора: в первой версии
            # collapse_addresses стоял в генераторном выражении и пересчитывался на каждый
            # префикс списка — 2 322 раза по трём тысячам диапазонов. Сборка не падала, она
            # просто вставала намертво на этой строке.
            proxy_ranges = list(ipaddress.collapse_addresses(proxy_nets)) if proxy_nets else []
            left = sum(1 for n in nets if any(n.overlaps(r) for r in proxy_ranges))
            log.info("%s: вычитания отключены (no_subtract), пересекается с общими прокси: %d",
                     cid, left)
        else:
            # Общие прокси вычитаются У ВСЕХ, включая тематические категории РКН: адрес
            # Cloudflare никогда не указывает на один сайт, поэтому он бесполезен как цель
            # и вреден как маршрут — уводит заодно всё остальное, что за ним живёт.
            nets, dropped = subtract_shared_proxy(nets, proxy_nets)
            if dropped:
                subtracted[f"{cid}/proxy"] = dropped
                log.info("%s: убрано %d адресов общих прокси", cid, dropped)
            if src["kind"] == "service":
                # Хостинги вычитаются только у СЕРВИСОВ, и только широкими диапазонами. У
                # тематических категорий сайт на Hetzner — законная цель: его блокируют
                # именно по этому адресу, и вычесть значило бы его потерять.
                nets, dropped = subtract_infra(nets, infra_nets)
                if dropped:
                    subtracted[f"{cid}/hosting"] = dropped
                    log.info("%s: убрано %d диапазонов хостингов", cid, dropped)

        cidrs = lib.finalize(nets)
        cat_networks[cid] = [ipaddress.ip_network(c, strict=False) for c in cidrs]
        counts[cid] = len(cidrs)
        lib.write_list(LISTS / f"{cid}.lst", cidrs)
        log.info("%s: %d CIDR", cid, counts[cid])

    # Гейт общих прокси — до агрегатов и до записи манифеста. Если у провайдера вышел
    # пустой список, его вычитание не выполнилось у всех остальных категорий, и снапшот
    # публиковать нельзя: он уводит в туннель чужие сайты за anycast-краем. Оставить
    # роутеры на прошлой сборке здесь дешевле — та сборка вычитание выполнила.
    blind_proxy = empty_shared_proxy(schema.CATEGORIES, cat_networks)
    if blind_proxy and not sample:
        log.error("GATE FAIL: пустые списки общих прокси: %s — вычитание этих провайдеров "
                  "не выполнилось ни у одной категории, их края уехали бы в default_on. "
                  "Публикация отменена, роутеры остаются на прошлой сборке.",
                  ", ".join(blind_proxy))
        sys.exit(2)
    if blind_proxy:
        log.warning("SAMPLE-режим: пустые списки общих прокси не валят сборку: %s",
                    ", ".join(blind_proxy))

    # агрегаты
    _build_aggregates(schema.CATEGORIES, cat_networks, counts)

    # Кто с кем совпал ПОЛНОСТЬЮ — по собранным спискам, а не по схеме. Идёт в манифест
    # полем same_prefixes_as: две категории с общей автономной системой дают один и тот
    # же файл, и человек имеет право знать это до включения, а не после.
    same_prefixes = same_prefixes_groups(cat_networks)
    for cid, info in sorted(same_prefixes.items()):
        log.info("same_prefixes: %s = %s (%s)", cid, ", ".join(info["with"]), info["reason_ru"])

    # Файлы исчезнувших категорий убираются здесь же. Иначе они остаются лежать в
    # публикации навсегда: сборка их больше не пересобирает, но издатель их по-прежнему
    # отдаёт — то есть кто-то качает список, который замер в день переименования, и узнать
    # об этом ему неоткуда. Ровно так после склейки семнадцати категорий в две осталось
    # висеть восемнадцать мёртвых файлов.
    live = {f"{c['id']}.lst" for c in schema.CATEGORIES} | \
           {f"{a['id']}.lst" for a in schema.AGGREGATES}
    for f in sorted(LISTS.glob("*.lst")):
        if f.name not in live:
            f.unlink()
            log.info("убран файл исчезнувшей категории: %s", f.name)

    # индекс
    source_meta = {
        "rkn": rkn_source,
        "community_ooni_count": len(community_ooni),
        "geoblock_count": len(geoblock_domains),
        "geolite": bool(geolite_path),
        "nameservers": resolver.NAMESERVERS,
        # Планка для гейта просадки в СЛЕДУЮЩЕЙ сборке: сравнивать ей больше не с чем.
        "resolved_domains": resolved_domains,
    }
    # Домены публикуются как есть. Сбой здесь не должен ронять адресную сборку:
    # это независимая часть, и лучше выпустить манифест без доменных списков, чем не
    # выпустить ничего.
    try:
        import domain_lists

        domain_entries = domain_lists.publish()
        log.info("доменных списков опубликовано: %d", len(domain_entries))
    except Exception as exc:  # noqa: BLE001
        log.warning("доменные списки не опубликованы: %s", exc)
        domain_entries = []

    # Отдельным try, а не внутри публикации: провал ПРОВЕРКИ не должен выкидывать из
    # манифеста уже опубликованные доменные списки. Проверка — про честность отчёта,
    # публикация — про содержимое манифеста, и цена ошибки у них разная.
    try:
        import domain_lists

        # Ручной сид из sources/thematic НЕ становится доменом в доменном списке: он
        # идёт в резолв и превращается в префиксы. Сборка говорит это вслух, потому что
        # снаружи выглядит наоборот — «домен добавлен в тематику» читается как «домен
        # добавлен в список» (splify2#7, I-077).
        seeds = domain_lists.check_thematic_seed_coverage()
        blind = seeds_behind_shared_proxy(seeds["prefix_only"], resolve_cache, proxy_nets)
        log.info("тематические сиды: %d, есть в доменных списках %d, только префиксами %d",
                 seeds["total"], seeds["in_domain_lists"], len(seeds["prefix_only"]))
        if blind:
            log.warning("сидов без покрытия вовсе (нет в доменных списках, а адреса "
                        "целиком за общими прокси): %d — %s",
                        len(blind), ", ".join(blind[:10]))
        source_meta["thematic_seeds"] = {
            "total": seeds["total"],
            "in_domain_lists": seeds["in_domain_lists"],
            "prefix_only": len(seeds["prefix_only"]),
            "behind_shared_proxy": len(blind),
        }
    except Exception as exc:  # noqa: BLE001
        log.warning("проверка тематических сидов не выполнена: %s", exc)

    (LISTS / "categories.json").write_text(
        json.dumps(build_index(counts, source_meta, domain_entries, same_prefixes),
                   ensure_ascii=False, indent=2)
        + "\n",
        encoding="utf-8",
    )
    log.info("categories.json записан.")

    ipsum_count = counts.get("ipsum", 0)
    if sample:
        log.info("SAMPLE-режим: gate пропущен (ipsum=%d)", ipsum_count)
    elif ipsum_count < IPSUM_MIN_COUNT:
        log.error("GATE FAIL: ipsum=%d < %d", ipsum_count, IPSUM_MIN_COUNT)
        sys.exit(2)
    else:
        log.info("GATE OK: ipsum=%d >= %d", ipsum_count, IPSUM_MIN_COUNT)

    log.info("=== build завершён ===")


def _build_aggregates(categories, cat_networks, counts):
    """Агрегаты. Инфраструктура в них НЕ входит — она целиком в `hodca`.

    Это главная правка всего разбора. Раньше `non_gb` собирался как «все категории без
    геоблока», а у всех четырнадцати провайдеров CDN и хостинга стоит `is_geoblock: False`
    — то есть в «сводный список заблокированного в РФ» попадали AWS, Akamai, Hetzner, OVH,
    DigitalOcean и Cloudflare целиком. Замерено на выпущенных списках: 97,95% адресного
    пространства `ipsum` приходилось на инфраструктуру, 7 609 из 17 301 строки были
    дословно строками инфра-категорий, и `3.0.0.0/8`, `104.64.0.0/10`, `23.32.0.0/11`
    лежали в файле, который включён по умолчанию.

    Человек, включивший «сводный список», уводил в туннель 203,7 млн адресов — 4,7% всего
    IPv4 — вместо 4,7 млн, и README при этом обещал «все категории, включённые по
    умолчанию». Расхождение на два порядка, и оно молчало.
    """
    def nets_of(pred):
        return [n for c in categories if pred(c) for n in cat_networks.get(c["id"], [])]

    non_gb = nets_of(lambda c: not c["is_geoblock"] and not c.get("is_infra"))
    gb = nets_of(lambda c: c["is_geoblock"] and not c.get("is_infra"))
    default_on = nets_of(lambda c: c["default_on"] and not c.get("is_infra"))
    infra = nets_of(lambda c: c.get("is_infra"))

    all_nets = non_gb + gb

    # ipsum = категории, включённые по умолчанию, — ровно то, что обещает README.
    # hodca — объединение провайдеров инфраструктуры. Имя файла сохранено: на hodca.lst
    # ссылаются установленные версии splify2, и уронить его значило бы «список скачан, а
    # канал его не находит» у тех, кто уже настроил.
    for aid, nets in (("rkn_all", non_gb), ("ipsum", default_on),
                      ("all", all_nets), ("hodca", infra)):
        cidrs = lib.finalize(nets)
        counts[aid] = len(cidrs)
        lib.write_list(LISTS / f"{aid}.lst", cidrs)
        log.info("агрегат %s: %d CIDR", aid, len(cidrs))


if __name__ == "__main__":
    main()
