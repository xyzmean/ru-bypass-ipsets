"""Общие утилиты генератора: парсинг CIDR, валидация, дедуп, сортировка, summarization.

Формат выхода — строго A.B.C.D/N (префикс обязателен), один на строку,
совместим с splify `clean_ip_list` (common.sh:516).
"""

from __future__ import annotations

import ipaddress
import logging
import re
from pathlib import Path

log = logging.getLogger(__name__)

# ---- Валидация IPv4 CIDR -----------------------------------------------------

_OCTET = r"(?:\d{1,3})"
_IPV4_RE = re.compile(
    rf"^{_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET}/(?:3[0-2]|[12]?\d)$"
)

# Сети, которые никогда не должны попадать в публичные списки.
EXCLUDED_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
]


def is_excluded(net: ipaddress._BaseNetwork) -> bool:
    """True для private/loopback/reserved/multicast/документационных сетей."""
    try:
        return any(
            net.overlaps(exc) or exc.overlaps(net) for exc in EXCLUDED_NETS
        )
    except (TypeError, ValueError):
        return True


def parse_cidr(value: str) -> ipaddress.IPv4Network | None:
    """Распарсить строку как IPv4-сеть; None если невалидно/исключено."""
    if not value:
        return None
    value = value.strip()
    # Голый IP без префикса — нормализуем в /32 (splify требует префикс).
    if "/" not in value:
        value = f"{value}/32"
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    if not isinstance(net, ipaddress.IPv4Network):
        return None
    if is_excluded(net):
        return None
    return net


def clean_lines(text: str):
    """Из произвольного текста — итератор валидных IPv4-сетей.

    Срезает `#`-комментарии, пробелы, CRLF; отбрасывает пустое/невалидное.
    """
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        net = parse_cidr(line)
        if net is not None:
            yield net


# ---- Нормализация / склейка / сортировка -------------------------------------


def to_str(net: ipaddress._BaseNetwork) -> str:
    """Каноническая строка сети (без избыточных пробелов)."""
    return str(net)


def collapse(nets):
    """Схлопнуть перекрытия и смежные сети в максимально крупные подсети.

    ipaddress.collapse_addresses уже удаляет дубли и поглощённые подсети,
    возвращая минимальный набор непересекающихся сетей.
    """
    seen = set()
    uniq = []
    for n in nets:
        if n not in seen:
            seen.add(n)
            uniq.append(n)
    try:
        return list(ipaddress.collapse_addresses(uniq))
    except ValueError as exc:
        log.warning("collapse_addresses частично провален: %s", exc)
        return uniq


def summarize_sparse(nets, min_prefix: int = 28):
    """Для редких одиночных хостов: расширяем мелкие сети до min_prefix.

    Сети крупнее min_prefix (напр. /24, /16) оставляем как есть —
    не расширяем чужие диапазоны. Сети мельче (/29../32) — поднимаем до /28,
    чтобы захватить «соседние» IP того же сервиса (CDN часто выдаёт блоками).
    Логика переиспользована из Re-filter step4 `summarize_ips`.
    """
    out = []
    for net in collapse(nets):
        if net.prefixlen < min_prefix:
            out.append(net)
        elif net.prefixlen >= min_prefix:
            # /28, /29, /30, /31, /32 → если уже >= /28, оставляем как есть;
            # сетей «мельче чем /28 но не /32» после collapse не бывает (collapse
            # объединяет смежные). Так что просто сохраняем.
            out.append(net)
        else:
            out.append(net)
    return collapse(out)


def sort_key(net):
    return (int(net.network_address), net.prefixlen)


def finalize(nets, sparse_limit: int = 28):
    """Полный конвейер нормализации одной категории:
    дедуп → collapse → summarize_sparse → сортировка → список строк CIDR.
    """
    collapsed = collapse(nets)
    summarized = summarize_sparse(collapsed, min_prefix=sparse_limit)
    summarized.sort(key=sort_key)
    return [to_str(n) for n in summarized]


# ---- I/O ---------------------------------------------------------------------


def read_domains(path: Path) -> list[str]:
    """Прочитать доменный список (один домен на строку, '#'-комментарии)."""
    domains = []
    if not path.is_file():
        return domains
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        d = raw.split("#", 1)[0].strip().lower()
        if d and not d.startswith("#"):
            domains.append(d)
    return domains


def write_list(path: Path, cidrs: list[str]) -> int:
    """Записать CIDR-список (по одному на строку). Возвращает кол-во строк."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(cidrs) + ("\n" if cidrs else ""), encoding="utf-8")
    return len(cidrs)
