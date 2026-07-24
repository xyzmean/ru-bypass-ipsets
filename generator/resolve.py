"""Этап B: DNS-резолв доменов в IPv4.

Резолв через dnspython по 6 nameservers (включая российские) с ОБЪЕДИНЕНИЕМ
ответов от всех резолверов. CDN отдают разные A-записи разным резолверам —
union даёт максимальное покрытие IP-адресов сервиса.

Дополнительно: IP→ASN→network через GeoLite2 (для summarization по ASN).
"""

from __future__ import annotations

import concurrent.futures
import gc
import ipaddress
import logging
from dataclasses import dataclass, field

import dns.resolver
import dns.name
import geoip2.database
from idna import encode as idna_encode

log = logging.getLogger(__name__)

# 6 nameservers: 4 публичных + 2 российских.
# Запрос идёт ко ВСЕМ; ответы объединяются (union).
NAMESERVERS = [
    "1.1.1.1",        # Cloudflare
    "8.8.8.8",        # Google
    "9.9.9.9",        # Quad9
    "208.67.222.222", # OpenDNS
    "77.88.8.8",      # Яндекс.DNS (РФ)
    "8.8.4.4",        # Google-secondary (доп. диверсификация)
]

DNS_TIMEOUT = 4.0
DNS_LIFETIME = 8.0
MAX_RETRIES = 1
THREADS = 50


@dataclass
class ResolveResult:
    domain: str
    ips: set[str] = field(default_factory=set)
    networks: set[str] = field(default_factory=set)  # CIDR из GeoLite2 ASN
    error: str = ""


def _idna(domain: str) -> str | None:
    try:
        return idna_encode(domain).decode("utf-8")
    except Exception:
        return None


def _resolve_all_ns(domain: str) -> set[str]:
    """Резолв домена через ВСЕ nameservers, union A-записей."""
    idn = _idna(domain)
    if not idn:
        return set()

    ips: set[str] = set()
    for ns in NAMESERVERS:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [ns]
        resolver.lifetime = DNS_LIFETIME
        resolver.timeout = DNS_TIMEOUT
        try:
            answers = resolver.resolve(idn, "A")
            for rdata in answers:
                addr = str(rdata.address)
                if _is_public_ip(addr):
                    ips.add(addr)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        except Exception as exc:
            log.debug("резолв %s @%s: %s", domain, ns, exc)
    return ips


def _is_public_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified or ip.is_link_local
    )


def resolve_domains(domains: list[str], geolite_path=None) -> dict[str, ResolveResult]:
    """Параллельный резолв доменов. Если есть GeoLite2 — мапит IP→network."""
    reader = None
    if geolite_path:
        try:
            reader = geoip2.database.Reader(str(geolite_path))
            log.info("GeoLite2-ASN загружен для маппинга IP→network.")
        except Exception as exc:
            log.warning("GeoLite2 не открыт: %s — работаю без ASN-сети.", exc)
            reader = None

    results: dict[str, ResolveResult] = {}
    total = len(domains)

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as pool:
        future_map = {
            pool.submit(_resolve_one, d, reader): d for d in domains
        }
        done = 0
        for fut in concurrent.futures.as_completed(future_map):
            domain = future_map[fut]
            try:
                res = fut.result()
                results[domain] = res
            except Exception as exc:
                results[domain] = ResolveResult(domain=domain, error=str(exc))
            done += 1
            if done % 500 == 0:
                log.info("резолв: %d/%d", done, total)
            if done % 2000 == 0:
                gc.collect()

    if reader:
        reader.close()

    resolved = sum(1 for r in results.values() if r.ips)
    log.info("резолв завершён: %d/%d доменов дали IP", resolved, total)
    return results


def _resolve_one(domain: str, reader) -> ResolveResult:
    res = ResolveResult(domain=domain)
    ips = _resolve_all_ns(domain)
    if not ips:
        res.error = "no-ip"
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
