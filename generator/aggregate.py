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

    Сервисные — из sources/services; тематические РКН — из categorize();
    geoblock/community — из categorize() (с форсированием _GB).
    rkn_other имеет тип vendor_cidr и сюда доменами не попадает.
    """
    # 1) категоризация РКН/community/geoblock по правилам
    rule_domains = categorize.categorize(rkn_domains, community_ooni, geoblock_domains)

    # 2) добавить сервисные/тематические домены (vendor_cidr сюда не входит)
    categories: dict[str, set[str]] = {k: set(v) for k, v in rule_domains.items()}
    vendor_cids = {
        c["id"] for c in schema.CATEGORIES if c["source"]["kind"] == "vendor_cidr"
    }
    # vendor_cidr-категории не резолвятся — их домены (если категоризатор
    # что-то туда положил) изымаем из пула резолва.
    for vid in vendor_cids:
        categories.pop(vid, None)
    for cat in schema.CATEGORIES:
        src = cat["source"]
        if src["kind"] == "service":
            for d in _service_domains(cat):
                categories.setdefault(cat["id"], set()).add(d)
        elif src["kind"] == "thematic":
            for d in lib.read_domains(ROOT / "sources" / "thematic" / src["file"]):
                categories.setdefault(cat["id"], set()).add(d)
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


def result_to_networks(res: resolver.ResolveResult) -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []
    for ip in res.ips:
        if n := lib.parse_cidr(f"{ip}/32"):
            nets.append(n)
    for net_str in res.networks:  # GeoLite2 ASN-network (более крупно)
        if n := lib.parse_cidr(net_str):
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
    """
    if not proxy:
        return nets, 0
    ranges = list(ipaddress.collapse_addresses(proxy))
    kept, dropped = [], 0
    for n in nets:
        if any(n.subnet_of(r) for r in ranges):
            dropped += 1
            continue
        kept.append(n)
    return kept, dropped


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
    """
    if not infra:
        return nets, 0
    infra_set = list(ipaddress.collapse_addresses(infra))
    kept, dropped = [], 0
    for n in nets:
        if n.prefixlen > INFRA_SUBTRACT_MAX_PREFIXLEN:
            kept.append(n)
            continue
        if any(n.subnet_of(r) for r in infra_set):
            dropped += 1
            continue
        kept.append(n)
    return kept, dropped


# ─────────────── индекс ───────────────


def build_index(
    counts: dict[str, int], source_meta: dict, domain_entries: list[dict] | None = None
) -> dict:
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    version = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")

    def entry(c, aggregate=False):
        return {
            "id": c["id"],
            "name_ru": c["name_ru"],
            "description_ru": c["description_ru"],
            "file": f"{c['id']}.lst",
            "default_on": c["default_on"],
            "is_geoblock": c["is_geoblock"],
            "count": counts.get(c["id"], 0),
            **({"aggregate": True} if aggregate else {}),
        }

    return {
        "version": version,
        "generated_at": now,
        "base_url": schema.BASE_URL,
        "ipsum_min_count": IPSUM_MIN_COUNT,
        "sources": source_meta,
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
        "services": _service_entries(counts, domain_entries or []),
    }


def _service_entries(counts: dict[str, int], domain_entries: list[dict]) -> list[dict]:
    """Пары «адреса + домены» по одному сервису.

    Сопоставление по имени файла доменного списка: `svc_<id>` у издателя доменов против
    `<id>` категории адресов. Пары нет — сервис всё равно попадает в список, но с одной
    половиной: молча пропустить его значило бы, что в интерфейсе исчез сервис, у которого
    просто нет доменного списка.
    """
    by_id = {d["id"]: d for d in domain_entries}
    out = []
    for c in schema.CATEGORIES:
        if c["source"]["kind"] != "service":
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
        })
    return out


# ─────────────── main ───────────────


def main():
    log.info("=== ru-bypass-ipsets build (v2: кеш + параллельный DNS) ===")

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
    log.info("--- резолв precheck-пула (rkn_other) ---")
    cache_pre = resolver.resolve_domains(precheck_pool, geolite_path, precheck=True)

    # объединённый кеш: домен -> ResolveResult
    resolve_cache = {**cache_direct, **cache_pre}
    log.info("кеш резолва: %d доменов", len(resolve_cache))

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

        if src["kind"] == "vendor_cidr":
            # готовые CIDR из вендорного снапшота (без резолва)
            vfile = ROOT / "sources" / src["file"]
            if vfile.is_file():
                nets = list(lib.clean_lines(vfile.read_text(encoding="utf-8", errors="replace")))
            log.info("%s: vendor_cidr из %s", cid, vfile.name)
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

    # агрегаты
    _build_aggregates(schema.CATEGORIES, cat_networks, counts)

    # индекс
    source_meta = {
        "rkn": rkn_source,
        "community_ooni_count": len(community_ooni),
        "geoblock_count": len(geoblock_domains),
        "geolite": bool(geolite_path),
        "nameservers": resolver.NAMESERVERS,
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

    (LISTS / "categories.json").write_text(
        json.dumps(build_index(counts, source_meta, domain_entries), ensure_ascii=False, indent=2)
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
    # non-geoblock сети = весь РКН (включая rkn_other).
    non_gb = [n for c in categories if not c["is_geoblock"]
              for n in cat_networks.get(c["id"], [])]
    gb = [n for c in categories if c["is_geoblock"]
          for n in cat_networks.get(c["id"], [])]

    all_nets = non_gb + gb

    # ipsum = ПОЛНЫЙ сводный список всего заблокированного в РФ (== rkn_all).
    # Это обеспечивает gate ≥5000 и даёт старому splify-потребителю один
    # исчерпывающий список. default_on остаётся рекомендацией для переключателей.
    # hodca — объединение провайдеров инфраструктуры. Имя файла сохранено: на hodca.lst
    # ссылаются установленные версии splify2, и уронить его значило бы «список скачан, а
    # канал его не находит» у тех, кто уже настроил.
    infra = [n for c in categories if c.get("is_infra")
             for n in cat_networks.get(c["id"], [])]

    for aid, nets in (("rkn_all", non_gb), ("geoblock_all", gb), ("ipsum", non_gb),
                      ("all", all_nets), ("hodca", infra)):
        cidrs = lib.finalize(nets)
        counts[aid] = len(cidrs)
        lib.write_list(LISTS / f"{aid}.lst", cidrs)
        log.info("агрегат %s: %d CIDR", aid, len(cidrs))


if __name__ == "__main__":
    main()
