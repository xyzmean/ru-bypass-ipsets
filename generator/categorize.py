"""Этап D: категоризация доменов.

Распределяет домены из РКН / community-ooni / geoblock по тематическим
категориям по правилам categorize_rules.json (substring → regex, первый
матч выигрывает).

Возвращает:
  categories_domains: {category_id: set(доменов)}  — домены на резолв
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

log = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
RULES_FILE = ROOT / "sources" / "rkn" / "categorize_rules.json"


def _compile_rules(rules_cfg: dict):
    """Прекомпилировать правила: список (category, geoblock, keyword-множество, [regex])."""
    compiled = []
    for rule in rules_cfg.get("rules", []):
        keywords = [k.lower() for k in rule.get("keywords", [])]
        patterns = [re.compile(p, re.IGNORECASE) for p in rule.get("regex", [])]
        compiled.append(
            (rule["category"], bool(rule.get("geoblock", False)), keywords, patterns)
        )
    return compiled


def classify_domain(domain: str, compiled_rules: list) -> tuple[str, bool] | None:
    """Вернуть (category_id, geoblock) для домена или None."""
    d = domain.lower()
    for category, geoblock, keywords, patterns in compiled_rules:
        if any(kw in d for kw in keywords):
            return category, geoblock
        if any(p.search(d) for p in patterns):
            return category, geoblock
    return None


def categorize(
    rkn_domains: list[str],
    community_ooni: list[str],
    geoblock_domains: list[str],
) -> dict[str, set[str]]:
    """Распределить домены по категориям.

    - РКН-домены → тематические категории РКН (без _GB).
    - geoblock-домены → тематические категории с _GB (по тем же правилам,
      но флаг geoblock форсируется).
    - community/ooni → если правило отдаёт geoblock-категорию, honour it;
      иначе fallback в dev_GB (прочие ограничивающие РФ).
    """
    rules_cfg = json.loads(RULES_FILE.read_text(encoding="utf-8"))
    compiled = _compile_rules(rules_cfg)

    fallback_cat = rules_cfg.get("_fallback_category", "rkn_other")
    fallback_gb = bool(rules_cfg.get("_fallback_geoblock", False))

    categories: dict[str, set[str]] = {}

    def add(cid: str, domain: str):
        categories.setdefault(cid, set()).add(domain)

    # РКН-домены
    rkn_assigned = 0
    rkn_fallback = 0
    for domain in rkn_domains:
        match = classify_domain(domain, compiled)
        if match:
            # РКН-источник → всегда в РКН-категорию (отменяем geoblock правила).
            cid, _ = match
            if cid.endswith("_GB"):
                cid = cid[:-3]
            add(cid, domain)
            rkn_assigned += 1
        else:
            add(fallback_cat, domain)
            rkn_fallback += 1
    log.info(
        "РКН: %d доменов расклассифицированы, %d в fallback (%s)",
        rkn_assigned, rkn_fallback, fallback_cat,
    )

    # community/ooni — сервисы, ограничивающие РФ (геоблок-семантика)
    co_assigned = 0
    co_fallback = 0
    for domain in community_ooni:
        match = classify_domain(domain, compiled)
        if match:
            cid, _ = match
            # форсируем геоблок-вариант категории
            if not cid.endswith("_GB"):
                cid = f"{cid}_GB"
            add(cid, domain)
            co_assigned += 1
        else:
            add("dev_GB", domain)
            co_fallback += 1
    log.info(
        "community/ooni: %d расклассифицированы, %d в fallback (dev_GB)",
        co_assigned, co_fallback,
    )

    # geoblock-домены (вендор) — принудительно в _GB варианты по правилам
    gb_assigned = 0
    gb_fallback = 0
    for domain in geoblock_domains:
        match = classify_domain(domain, compiled)
        if match:
            cid, _ = match
            if not cid.endswith("_GB"):
                cid = f"{cid}_GB"
            add(cid, domain)
            gb_assigned += 1
        else:
            add("dev_GB", domain)
            gb_fallback += 1
    log.info(
        "geoblock: %d расклассифицированы, %d в fallback (dev_GB)",
        gb_assigned, gb_fallback,
    )

    return categories
