"""Этап A: сбор источников.

- РКН-домены: онлайн antifilter.download → fallback на вендорный снапшот.
- GeoLite2-ASN: FyraLabs-релиз с ETag-кешем (для IP→ASN при summarization).
- Домены сервисов/тематик/GB: только из локальных sources/ (вендор).
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from email.utils import parsedate_to_datetime
from pathlib import Path

import requests

log = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "sources"

RKN_ONLINE_URL = "https://antifilter.download/list/domains.lst"
RKN_SNAPSHOT = SOURCES / "rkn" / "domains_snapshot.lst"
COMMUNITY_OONI = SOURCES / "community_ooni.lst"
GEOBLOCK_DOMAINS = SOURCES / "thematic" / "geoblock_domains.lst"

GEOLITE_DB = ROOT / "generator" / ".cache" / "GeoLite2-ASN.mmdb"
GEOLITE_META = ROOT / "generator" / ".cache" / "GeoLite2-ASN.mmdb.meta"
GEOLITE_URL = (
    "https://github.com/FyraLabs/geolite2/releases/latest/download/GeoLite2-ASN.mmdb"
)

HTTP_TIMEOUT = (10, 120)


def _read_meta(path: Path) -> dict:
    data = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                data[k.strip()] = v.strip()
    return data


def _write_meta(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(f"{k}={data[k]}" for k in sorted(data)) + "\n", encoding="utf-8"
    )


def _remote_headers(url: str) -> dict:
    try:
        r = requests.head(url, allow_redirects=True, timeout=HTTP_TIMEOUT)
        return {
            "etag": (r.headers.get("ETag") or "").strip(),
            "last_modified": (r.headers.get("Last-Modified") or "").strip(),
            "final_url": r.url,
            "status": r.status_code,
        }
    except requests.RequestException as exc:
        log.warning("HEAD %s провален: %s", url, exc)
        return {}


def _download(url: str, dest: Path) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with requests.get(url, stream=True, timeout=HTTP_TIMEOUT) as r:
            r.raise_for_status()
            fd, tmp = tempfile.mkstemp(
                prefix=dest.stem + "-", suffix=".tmp", dir=str(dest.parent)
            )
            with os.fdopen(fd, "wb") as f:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        f.write(chunk)
            os.replace(tmp, dest)
        return True
    except requests.RequestException as exc:
        log.warning("скачивание %s провалено: %s", url, exc)
        return False


def ensure_geolite() -> Path:
    """Скачать GeoLite2-ASN только если удалённый новее (ETag/mtime)."""
    GEOLITE_DB.parent.mkdir(parents=True, exist_ok=True)
    meta = _read_meta(GEOLITE_META)
    headers = _remote_headers(GEOLITE_URL)

    need = not GEOLITE_DB.is_file()
    if GEOLITE_DB.is_file() and headers:
        etag = headers.get("etag", "")
        if etag and meta.get("etag") == etag:
            need = False
        else:
            lm = headers.get("last_modified")
            if lm:
                try:
                    remote_ts = parsedate_to_datetime(lm).timestamp()
                    if GEOLITE_DB.stat().st_mtime >= remote_ts:
                        need = False
                except Exception:
                    pass

    if need:
        log.info("Скачиваю GeoLite2-ASN …")
        if _download(GEOLITE_URL, GEOLITE_DB):
            _write_meta(
                GEOLITE_META,
                {
                    "etag": headers.get("etag", ""),
                    "last_modified": headers.get("last_modified", ""),
                    "source_url": headers.get("final_url", GEOLITE_URL),
                },
            )
            log.info("GeoLite2-ASN обновлён: %s", GEOLITE_DB)
        elif GEOLITE_DB.is_file():
            log.warning("Скачивание провалено, использую существующий GeoLite2.")
        else:
            raise RuntimeError("GeoLite2-ASN недоступен и локальной копии нет")
    else:
        log.info("GeoLite2-ASN актуален, пропуск.")
    return GEOLITE_DB


def _read_domain_file(path: Path) -> list[str]:
    domains = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        d = raw.split("#", 1)[0].strip().lower()
        if d:
            domains.append(d)
    return domains


def fetch_rkn_domains() -> tuple[list[str], str]:
    """Вернуть (домены, источник).

    По умолчанию — вендорный снапшот Re-filter domains_all.lst (~86k, уже
    отфильтрован от фрода/мусора). Онлайн antifilter.download отдаёт ~1.2M
    доменов (массовые казино-зеркала) — резолв нереален, поэтому онлайн
    включается только явно через env RKN_ONLINE=1.
    """
    # Онлайн (только по явному запросу).
    if os.environ.get("RKN_ONLINE") == "1":
        try:
            r = requests.get(RKN_ONLINE_URL, timeout=HTTP_TIMEOUT)
            r.raise_for_status()
            domains = [
                d for raw in r.text.splitlines() if (d := raw.split("#", 1)[0].strip().lower())
            ]
            if domains:
                log.warning("РКН ОНЛАЙН antifilter: %d доменов (ОЧЕНЬ много — резолв долгий)",
                            len(domains))
                return domains, f"online:{RKN_ONLINE_URL}"
        except requests.RequestException as exc:
            log.warning("Онлайн РКН недоступен (%s), беру снапшот.", exc)

    # По умолчанию — снапшот.
    if RKN_SNAPSHOT.is_file():
        domains = _read_domain_file(RKN_SNAPSHOT)
        log.info("РКН из снапшота %s: %d доменов", RKN_SNAPSHOT.name, len(domains))
        return domains, f"snapshot:{RKN_SNAPSHOT.name}"

    log.error("Снапшот РКН отсутствует %s", RKN_SNAPSHOT)
    return [], "none"


def load_community_ooni() -> list[str]:
    """community + ooni (Re-filter) — сервисы, ограничивающие РФ (→ GB)."""
    domains: list[str] = []
    if COMMUNITY_OONI.is_file():
        for raw in COMMUNITY_OONI.read_text(encoding="utf-8", errors="replace").splitlines():
            d = raw.split("#", 1)[0].strip().lower()
            if d:
                domains.append(d)
    log.info("community+ooni: %d доменов", len(domains))
    return domains


def load_geoblock_domains() -> list[str]:
    """Геоблок-домены (вендор) — база для GB-категорий."""
    domains: list[str] = []
    if GEOBLOCK_DOMAINS.is_file():
        for raw in GEOBLOCK_DOMAINS.read_text(encoding="utf-8", errors="replace").splitlines():
            d = raw.split("#", 1)[0].strip().lower()
            if d:
                domains.append(d)
    log.info("geoblock_domains: %d доменов", len(domains))
    return domains
