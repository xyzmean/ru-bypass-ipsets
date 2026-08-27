"""Этап C: прямой pull CIDR по ASN и из CDN-фидов.

Для крупных сервисов (telegram, meta, ...) тянем ВСЕ префиксы ASN из
официальных API: RIPEstat → ip.guide → bgpview. Для CDN — готовые фиды
(Cloudflare, AWS CloudFront, Discord voice).

Переиспользована логика из Re-filter step4/step6 (multi-source fallback) и
allow-domains get-subnets.py (CDN endpoints).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
from pathlib import Path

import requests

import lib

log = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
ASN_SERVICES_FILE = ROOT / "sources" / "asn" / "asn_services.json"

HTTP_TIMEOUT = (10, 60)

CLOUDFLARE_URL = "https://www.cloudflare.com/ips-v4"
# AWS требует корректный User-Agent (иначе 403) и полный путь к JSON.
AWS_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
UA = "ru-bypass-ipsets/1.0 (https://github.com/xyzmean/ru-bypass-ipsets)"


def _valid_ipv4_prefix(p: str) -> ipaddress.IPv4Network | None:
    return lib.parse_cidr(p)


# ─────────────── ASN → CIDR (multi-source fallback) ───────────────


def _from_ripestat(asn: int) -> list[str]:
    try:
        r = requests.get(
            f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}",
            timeout=HTTP_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        return [
            p["prefix"]
            for p in data.get("data", {}).get("prefixes", [])
            if ":" not in p["prefix"]
        ]
    except Exception as exc:
        log.debug("RIPEstat ASN %s: %s", asn, exc)
        return []


def _from_ipguide(asn: int) -> list[str]:
    try:
        r = requests.get(f"https://ip.guide/as{asn}", timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        prefixes = data.get("prefixes", [])
        out = []
        for entry in prefixes:
            net = entry.get("net") or entry.get("prefix") or entry
            if isinstance(net, str) and ":" not in net:
                out.append(net)
        return out
    except Exception as exc:
        log.debug("ip.guide ASN %s: %s", asn, exc)
        return []


def _from_bgpview(asn: int) -> list[str]:
    try:
        r = requests.get(
            f"https://api.bgpview.io/asn/{asn}/prefixes", timeout=HTTP_TIMEOUT
        )
        if r.status_code == 429:
            time.sleep(30)
            return _from_bgpview(asn)
        r.raise_for_status()
        data = r.json()
        return [
            p["prefix"]
            for p in data.get("data", {}).get("ipv4_prefixes", [])
        ]
    except Exception as exc:
        log.debug("bgpview ASN %s: %s", asn, exc)
        return []


class AsnUnavailable(RuntimeError):
    """Ни один источник не отдал префиксы ASN.

    Это ОТСУТСТВУЮЩИЙ ВХОД, а не ответ «у ASN нет префиксов», и разница здесь не
    терминологическая. Пустой список молча собирал категорию из одних доменов, а
    недостачу замечал гейт покрытия — через пятнадцать минут, уже после резолва, и
    сообщением про просадку списка, то есть указанием не на ту причину. Хуже того,
    единственный выход, который гейт предлагает человеку, — ALLOW_SHRINK=1, то есть
    выпустить урезанный список.
    """

    def __init__(self, asn: int):
        self.asn = asn
        super().__init__(
            f"ASN {asn}: ни один из трёх источников не отдал префиксы. Это отсутствующий "
            f"вход, а не пустой ASN: список этого сервиса собрать не из чего. "
            f"ALLOW_SHRINK здесь не поможет и не предлагается — он выпускает урезанный "
            f"список, а урезан он не по составу, а по недостающему источнику."
        )


# Молчание всех трёх источников почти всегда мгновенное и почти всегда чужое. Замерено в
# сборке 2026-08-27T10:51: RIPEstat не ответила по ASN 15169 в 11:08:29, а в 11:08:31 —
# через две секунды, по тому же ASN, для соседней категории — отдала 1233 префикса.
# Поэтому цепочка источников переспрашивается, и паузы растут: короткая снимает всплеск,
# длинная переживает лимит запросов на стороне источника.
ASN_RETRY_PAUSES = (5, 20)


def asn_to_cidrs(asn: int, sleep=time.sleep) -> list[ipaddress.IPv4Network]:
    """Получить все IPv4-префиксы ASN из нескольких источников.

    Пустой ответ ВСЕХ источников на ВСЕХ попытках — исключение AsnUnavailable, а не
    пустой список: см. его док-строку.
    """
    attempts = len(ASN_RETRY_PAUSES) + 1
    for attempt in range(attempts):
        for getter in (_from_ripestat, _from_ipguide, _from_bgpview):
            prefixes = getter(asn)
            if prefixes:
                nets = [n for p in prefixes if (n := _valid_ipv4_prefix(p))]
                if nets:
                    log.info("ASN %s: %d префиксов (через %s)",
                             asn, len(nets), getattr(getter, "__name__", getter))
                    return nets
        if attempt < attempts - 1:
            pause = ASN_RETRY_PAUSES[attempt]
            log.warning("ASN %s: ни один источник не ответил (попытка %d из %d), "
                        "пауза %d с", asn, attempt + 1, attempts, pause)
            sleep(pause)
    log.error("ASN %s: префиксы не получены ниоткуда за %d попыт(ки)", asn, attempts)
    raise AsnUnavailable(asn)


def load_asn_map() -> dict:
    """Загрузить asn_services.json (без служебных _-ключей)."""
    raw = json.loads(ASN_SERVICES_FILE.read_text(encoding="utf-8"))
    return {k: v for k, v in raw.items() if not k.startswith("_")}


# ─────────────── CDN-фиды ───────────────


def _parse_prefix_lines(text: str) -> list[ipaddress.IPv4Network]:
    """Из текста (по строкам) — валидные IPv4-сети."""
    nets = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            if n := _valid_ipv4_prefix(line):
                nets.append(n)
    return nets


def pull_cloudflare() -> list[ipaddress.IPv4Network]:
    try:
        r = requests.get(CLOUDFLARE_URL, timeout=HTTP_TIMEOUT, headers={"User-Agent": UA})
        r.raise_for_status()
        nets = _parse_prefix_lines(r.text)
        log.info("Cloudflare CDN: %d подсетей", len(nets))
        return nets
    except Exception as exc:
        log.warning("Cloudflare CDN-фид провален: %s", exc)
        return []


def pull_cloudfront() -> list[ipaddress.IPv4Network]:
    try:
        r = requests.get(AWS_RANGES_URL, timeout=HTTP_TIMEOUT, headers={"User-Agent": UA})
        r.raise_for_status()
        data = r.json()
        nets = []
        for entry in data.get("prefixes", []):
            if entry.get("service") == "CLOUDFRONT":
                if n := _valid_ipv4_prefix(entry.get("ip_prefix", "")):
                    nets.append(n)
        log.info("AWS CloudFront: %d подсетей", len(nets))
        return nets
    except Exception as exc:
        log.warning("AWS CloudFront-фид провален: %s", exc)
        return []


def pull_cdn(kind: str) -> list[ipaddress.IPv4Network]:
    """Диспетчер CDN-фидов по идентификатору из categories_schema.
    Discord voice-фид убран (источник умер) — Discord покрывается по ASN 62041."""
    if kind == "cloudflare":
        return pull_cloudflare()
    if kind in ("cloudfront", "hodca"):
        # "hodca" — имя из времён, когда все провайдеры лежали одной категорией. Когда их
        # разделили, категория стала звать фид как "cloudfront", а диспетчер по-прежнему
        # знал только старое имя — и молча уходил в ветку «прямого фида нет».
        # Следствие: cloudfront.lst выпускался ПУСТЫМ, а раз он помечен is_shared_proxy,
        # вычитание CloudFront из сервисных списков не выполнялось вовсе. Ни одной ошибки
        # при этом не печаталось.
        return pull_cloudfront()
    # discord: voice-фид убран — Discord покрывается по ASN 62041.
    log.debug("CDN-вид %s не имеет прямого фида (покрытие по ASN).", kind)
    return []
