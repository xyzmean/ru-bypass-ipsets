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
    """Распределить домены по двум спискам: `rkn` и `geoblock`.

    - РКН-домены → `rkn`. Не подошедшие ни под одно правило НЕ резолвятся: реестр
      покрыт вендорным снапшотом по адресам, и гонять по ним DNS значило бы платить
      резолвом за то, что уже есть (так было и раньше — они уходили в `rkn_other`,
      который из пула резолва изымался).
    - geoblock-домены (вендорный список сервисов, режущих РФ) → `geoblock`.
    - community/ooni → `rkn`, если правило не говорит прямо, что это геоблок.

    Почему ooni больше не форсируется в геоблок. Раньше каждый его домен получал суффикс
    `_GB` независимо от правила, и это было первопричиной всей GB-избыточности: 6 941 из
    6 953 доменов ooni лежат и в снапшоте РКН, то есть один домен проходил дважды и
    резолвился в один и тот же /24. Ooni измеряет ФАКТ блокировки в РФ — это `rkn`, а не
    «сервис сам режет РФ».
    """
    rules_cfg = json.loads(RULES_FILE.read_text(encoding="utf-8"))
    compiled = _compile_rules(rules_cfg)

    categories: dict[str, set[str]] = {"rkn": set(), "geoblock": set()}

    # РКН-домены: подошедшие под правило идут на резолв, остальные покрыты снапшотом.
    rkn_assigned = 0
    rkn_skipped = 0
    for domain in rkn_domains:
        if classify_domain(domain, compiled):
            categories["rkn"].add(domain)
            rkn_assigned += 1
        else:
            rkn_skipped += 1
    log.info(
        "РКН: %d доменов на резолв, %d без правила (покрыты снапшотом, не резолвятся)",
        rkn_assigned, rkn_skipped,
    )

    # community/ooni — измеренная блокировка в РФ. В геоблок попадают только те, чьё
    # правило прямо помечено geoblock.
    co_rkn = 0
    co_gb = 0
    for domain in community_ooni:
        match = classify_domain(domain, compiled)
        if match and match[1]:
            categories["geoblock"].add(domain)
            co_gb += 1
        else:
            categories["rkn"].add(domain)
            co_rkn += 1
    log.info("community/ooni: %d в rkn, %d в geoblock", co_rkn, co_gb)

    # geoblock-домены (вендорный список сервисов, режущих РФ) — целиком в geoblock.
    for domain in geoblock_domains:
        categories["geoblock"].add(domain)
    log.info("geoblock: %d доменов", len(geoblock_domains))

    return categories
