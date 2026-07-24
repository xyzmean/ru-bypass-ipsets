"""Этап B: DNS-резолв доменов в IPv4 (с кешем и параллельным опросом NS).

Ключевые отличия от первой версии (ускорение ~10×):
  1. Все NS опрашиваются ПАРАЛЛЕЛЬНО (не последовательно) → мёртвый домен
     отваливается за ОДИН таймаут, а не за 6.
  2. Короткий таймаут (QUERY_TIMEOUT=3.0).
  3. Двухфазный резолв: PRE-CHECK (1 быстрый NS) → FULL (все 6 NS, union).
     Применяется к большим «мусорным» пулам (rkn_other), чтобы отсечь мёртвые.

Возвращает ResolveMap: {domain -> (ips, networks)}.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
from dataclasses import dataclass, field

import dns.resolver
from idna import encode as idna_encode

log = logging.getLogger(__name__)

# 6 nameservers: 4 публичных + 2 российских.
NAMESERVERS = [
    "1.1.1.1",        # Cloudflare
    "8.8.8.8",        # Google
    "9.9.9.9",        # Quad9
    "208.67.222.222", # OpenDNS
    "77.88.8.8",      # Яндекс.DNS (РФ)
    "8.8.4.4",        # Google-secondary
]

# Короткие таймауты — мёртвые домены отваливаются быстро.
QUERY_TIMEOUT = 3.0      # один запрос к одному NS
QUERY_LIFETIME = 6.0     # общее время на NS (превышение = отмена)
PRECHECK_TIMEOUT = 2.0
PRECHECK_LIFETIME = 3.0

THREADS = 80             # доменов одновременно


@dataclass
class ResolveResult:
    ips: set[str] = field(default_factory=set)
    networks: set[str] = field(default_factory=set)  # GeoLite2 ASN-network


def _idna(domain: str) -> str | None:
    try:
        return idna_encode(domain).decode("utf-8")
    except Exception:
        return None


def _is_public_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified or ip.is_link_local
    )


def _query_ns(ns: str, idn: str) -> set[str]:
    """Один запрос к одному NS. Возвращает публичные A-записи или пустое."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [ns]
    resolver.timeout = QUERY_TIMEOUT
    resolver.lifetime = QUERY_LIFETIME
    out: set[str] = set()
    try:
        for rdata in resolver.resolve(idn, "A"):
            addr = str(rdata.address)
            if _is_public_ip(addr):
                out.add(addr)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        pass
    except Exception:
        pass
    return out


def _resolve_all_ns_parallel(idn: str) -> set[str]:
    """Опросить ВСЕ 6 NS параллельно, union A-записей."""
    ips: set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(NAMESERVERS)) as pool:
        futures = {pool.submit(_query_ns, ns, idn): ns for ns in NAMESERVERS}
        for fut in concurrent.futures.as_completed(futures):
            ips |= fut.result()
    return ips


def _precheck_alive(domain: str) -> bool:
    """Быстрый pre-check через 1 быстрый NS: жив ли домен вообще."""
    idn = _idna(domain)
    if not idn:
        return False
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1"]
    resolver.timeout = PRECHECK_TIMEOUT
    resolver.lifetime = PRECHECK_LIFETIME
    try:
        ans = resolver.resolve(idn, "A")
        return any(_is_public_ip(str(r.address)) for r in ans)
    except Exception:
        return False


def resolve_one(domain: str, reader=None) -> ResolveResult:
    """Полный резолв домена: 6 NS параллельно + GeoLite2 network."""
    res = ResolveResult()
    idn = _idna(domain)
    if not idn:
        return res
    ips = _resolve_all_ns_parallel(idn)
    if not ips:
        return res
    res.ips = ips
    if reader:
        for ip in ips:
            try:
                asn_resp = reader.asn(ip)
                if asn_resp.network:
                    res.networks.add(str(asn_resp.network))
            except Exception:
                pass
    return res


def resolve_domains(
    domains: list[str], geolite_path=None, precheck: bool = False
) -> dict[str, ResolveResult]:
    """Резолв списка доменов (каждый один раз). precheck=True — отсечь мёртвые
    быстрым 1-NS запросом перед полным резолвом (для больших мусорных пулов).

    Возвращает {domain -> ResolveResult}.
    """
    reader = None
    if geolite_path:
        try:
            import geoip2.database
            reader = geoip2.database.Reader(str(geolite_path))
        except Exception as exc:
            log.warning("GeoLite2 не открыт: %s", exc)

    # --- фаза pre-check ---
    to_resolve = domains
    if precheck:
        log.info("pre-check (%d доменов, 1 NS %ss): …", len(domains), PRECHECK_TIMEOUT)
        alive = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as pool:
            futures = {pool.submit(_precheck_alive, d): d for d in domains}
            done = 0
            for fut in concurrent.futures.as_completed(futures):
                if fut.result():
                    alive.append(futures[fut])
                done += 1
                if done % 5000 == 0:
                    log.info("pre-check: %d/%d", done, len(domains))
        log.info("pre-check: живых %d / %d", len(alive), len(domains))
        to_resolve = alive

    # --- фаза полного резолва ---
    results: dict[str, ResolveResult] = {}
    total = len(to_resolve)
    log.info("полный резолв %d доменов (%d NS параллельно)…", total, len(NAMESERVERS))
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as pool:
        futures = {pool.submit(resolve_one, d, reader): d for d in to_resolve}
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            domain = futures[fut]
            try:
                results[domain] = fut.result()
            except Exception:
                results[domain] = ResolveResult()
            done += 1
            if done % 2000 == 0:
                log.info("резолв: %d/%d", done, total)

    if reader:
        reader.close()

    resolved = sum(1 for r in results.values() if r.ips)
    log.info("резолв завершён: %d/%d доменов дали IP", resolved, total)
    return results
