"""Этап E + оркестратор всего пайплайна.

Собирает категории по источникам, резолвит домены, тянет ASN/CDN-CIDR,
схлопывает/сортирует, пишет lists/*.lst, собирает агрегаты и categories.json.

Запуск:  python generator/aggregate.py
Опции (env):
  SAMPLE=<N>     — ограничить РКН до N доменов (для локальной проверки)
  SKIP_GEO=1     — пропустить GeoLite2 (без IP→ASN network)
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

# Импорты этапов
import fetch_sources
import resolve as resolver
import asn_pull
import categorize

ROOT = Path(__file__).resolve().parent.parent
LISTS = ROOT / "lists"

# ─────────────── logging ───────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(ROOT / "generator" / "build.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("aggregate")

# Минимум CIDR в ipsum.lst — gate splify (common.sh IPSUM_MIN_COUNT=5000).
IPSUM_MIN_COUNT = 5000


# ─────────────── сбор CIDR по категориям ───────────────


def _service_domains(category: dict) -> list[str]:
    """Домены сервисной категории + опциональный фильтр whatsapp."""
    src = category["source"]
    domains: list[str] = []
    for fname in src.get("files", []):
        domains += lib.read_domains(ROOT / "sources" / "services" / fname)
    domains += src.get("extra_domains", [])

    # whatsapp/meta разделяем по фильтру на один и тот же meta.lst
    flt = src.get("domain_filter")
    if flt == "whatsapp":
        domains = [d for d in domains if "whatsapp" in d]
    elif flt == "not_whatsapp":
        domains = [d for d in domains if "whatsapp" not in d]
    return domains


def _resolve_to_cidrs(domains: list[str], geolite_path) -> list[ipaddress.IPv4Network]:
    """Резолв доменов → список IPv4-сетей (из IP и из GeoLite2 network)."""
    if not domains:
        return []
    results = resolver.resolve_domains(domains, geolite_path)
    nets: list[ipaddress.IPv4Network] = []
    for res in results.values():
        for ip in res.ips:
            if n := lib.parse_cidr(f"{ip}/32"):
                nets.append(n)
        # GeoLite2 ASN-network — более крупно (покрытие CDN по ASN).
        for net_str in res.networks:
            if n := lib.parse_cidr(net_str):
                nets.append(n)
    return nets


def _asn_cidrs_for(category: dict, asn_map: dict) -> list[ipaddress.IPv4Network]:
    """CIDR по ASN для сервисной категории."""
    src = category["source"]
    if not src.get("asn"):
        return []
    asns = asn_map.get(category["id"], [])
    # телеграм: доп. захардкоженные подсети
    nets = []
    for asn in asns:
        nets += asn_pull.asn_to_cidrs(int(asn))
    return nets


def _cdn_cidrs_for(category: dict) -> list[ipaddress.IPv4Network]:
    """CIDR из CDN-фидов (cloudflare/discord/hodca)."""
    cdn = category["source"].get("cdn")
    if not cdn:
        return []
    return asn_pull.pull_cdn(cdn)


def build_category_networks(
    category: dict,
    rule_domains: dict[str, set[str]],
    asn_map: dict,
    geolite_path,
) -> list[ipaddress.IPv4Network]:
    """Собрать все IPv4-сети для одной категории."""
    src = category["source"]
    kind = src["kind"]
    nets: list[ipaddress.IPv4Network] = []

    if kind == "service":
        domains = _service_domains(category)
        nets += _resolve_to_cidrs(domains, geolite_path)
        nets += _asn_cidrs_for(category, asn_map)
        nets += _cdn_cidrs_for(category)

    elif kind == "thematic":
        domains = lib.read_domains(ROOT / "sources" / "thematic" / src["file"])
        nets += _resolve_to_cidrs(domains, geolite_path)
        # тематические РКН-категории могут дополняться из rule-распределения
        if category["id"] in rule_domains:
            nets += _resolve_to_cidrs(
                sorted(rule_domains[category["id"]]), geolite_path
            )

    elif kind == "rule":
        domains = sorted(rule_domains.get(category["id"], set()))
        nets += _resolve_to_cidrs(domains, geolite_path)

    return nets


# ─────────────── индекс categories.json ───────────────


def build_index(
    counts: dict[str, int],
    source_meta: dict,
) -> dict:
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    version = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")

    cats = []
    for c in schema.CATEGORIES:
        cats.append(
            {
                "id": c["id"],
                "name_ru": c["name_ru"],
                "description_ru": c["description_ru"],
                "file": f"{c['id']}.lst",
                "default_on": c["default_on"],
                "is_geoblock": c["is_geoblock"],
                "count": counts.get(c["id"], 0),
            }
        )

    aggs = []
    for a in schema.AGGREGATES:
        aggs.append(
            {
                "id": a["id"],
                "name_ru": a["name_ru"],
                "description_ru": a["description_ru"],
                "file": f"{a['id']}.lst",
                "default_on": a["default_on"],
                "is_geoblock": a["is_geoblock"],
                "aggregate": True,
                "count": counts.get(a["id"], 0),
            }
        )

    return {
        "version": version,
        "generated_at": now,
        "base_url": schema.BASE_URL,
        "ipsum_min_count": IPSUM_MIN_COUNT,
        "sources": source_meta,
        "categories": cats,
        "aggregates": aggs,
    }


# ─────────────── main ───────────────


def main():
    log.info("=== ru-bypass-ipsets build ===")

    # GeoLite2 (опционально)
    geolite_path = None
    if os.environ.get("SKIP_GEO") != "1":
        try:
            geolite_path = fetch_sources.ensure_geolite()
        except Exception as exc:
            log.warning("GeoLite2 недоступен (%s) — продолжаю без ASN-network.", exc)

    # Этап A: источники
    rkn_domains, rkn_source = fetch_sources.fetch_rkn_domains()
    sample = os.environ.get("SAMPLE")
    if sample:
        n = int(sample)
        rkn_domains = rkn_domains[:n]
        log.info("SAMPLE: ограничил РКН до %d доменов", len(rkn_domains))
    community_ooni = fetch_sources.load_community_ooni()
    geoblock_domains = fetch_sources.load_geoblock_domains()

    # Этап D: категоризация доменов
    rule_domains = categorize.categorize(rkn_domains, community_ooni, geoblock_domains)

    # ASN-карта
    asn_map = asn_pull.load_asn_map()

    # Этап E: сборка сетей по категориям
    counts: dict[str, int] = {}
    cat_networks: dict[str, list[ipaddress.IPv4Network]] = {}

    for cat in schema.CATEGORIES:
        cid = cat["id"]
        log.info("--- категория: %s ---", cid)
        nets = build_category_networks(cat, rule_domains, asn_map, geolite_path)
        if not nets:
            log.warning("категория %s: пусто", cid)
        cidrs = lib.finalize(nets)
        cat_networks[cid] = [ipaddress.ip_network(c, strict=False) for c in cidrs]
        counts[cid] = len(cidrs)
        lib.write_list(LISTS / f"{cid}.lst", cidrs)
        log.info("%s: %d CIDR записано", cid, counts[cid])

    # Агрегаты
    _build_aggregates(schema.CATEGORIES, cat_networks, counts)

    # Индекс
    source_meta = {
        "rkn": rkn_source,
        "community_ooni_count": len(community_ooni),
        "geoblock_count": len(geoblock_domains),
        "geolite": bool(geolite_path),
        "nameservers": resolver.NAMESERVERS,
    }
    index = build_index(counts, source_meta)
    (LISTS / "categories.json").write_text(
        json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    log.info("categories.json записан.")

    # Gate: ipsum должен быть >= IPSUM_MIN_COUNT (только вне SAMPLE-режима)
    ipsum_count = counts.get("ipsum", 0)
    if sample:
        log.info("SAMPLE-режим: gate ipsum (%d >= %d) пропущен", ipsum_count, IPSUM_MIN_COUNT)
    elif ipsum_count < IPSUM_MIN_COUNT:
        log.error("GATE FAIL: ipsum.lst = %d CIDR < %d. Список НЕ валиден для splify.",
                  ipsum_count, IPSUM_MIN_COUNT)
        sys.exit(2)
    else:
        log.info("GATE OK: ipsum.lst = %d CIDR >= %d", ipsum_count, IPSUM_MIN_COUNT)

    log.info("=== build завершён ===")


def _build_aggregates(categories, cat_networks, counts):
    """Собрать rkn_all / geoblock_all / ipsum из категорий."""
    LISTS.mkdir(parents=True, exist_ok=True)

    non_gb = [n for c in categories if not c["is_geoblock"]
              for n in cat_networks.get(c["id"], [])]
    gb = [n for c in categories if c["is_geoblock"]
          for n in cat_networks.get(c["id"], [])]
    default_on = [n for c in categories if c["default_on"]
                  for n in cat_networks.get(c["id"], [])]

    for aid, nets in (
        ("rkn_all", non_gb),
        ("geoblock_all", gb),
        ("ipsum", default_on),
    ):
        cidrs = lib.finalize(nets)
        counts[aid] = len(cidrs)
        lib.write_list(LISTS / f"{aid}.lst", cidrs)
        log.info("агрегат %s: %d CIDR", aid, len(cidrs))


if __name__ == "__main__":
    main()
