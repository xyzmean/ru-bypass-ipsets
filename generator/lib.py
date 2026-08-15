"""Общие утилиты генератора: парсинг CIDR, валидация, дедуп, сортировка, summarization.

Формат выхода — строго A.B.C.D/N (префикс обязателен), один на строку,
совместим с splify `clean_ip_list` (common.sh:516).
"""

from __future__ import annotations

import bisect
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

    Сети крупнее min_prefix (напр. /24, /16) оставляем как есть — не расширяем чужие
    диапазоны. Сети мельче (/29../32) — поднимаем до /28, чтобы захватить «соседние» IP
    того же сервиса (CDN часто выдаёт блоками).
    Логика переиспользована из Re-filter step4 `summarize_ips`.

    До этой правки функция была мёртвой: все три ветки условия делали `out.append(net)`,
    то есть возвращали сеть как есть, а докстрока обещала подъём. Ошибка молчаливая —
    выход валиден, просто на четверть длиннее обещанного. Цена измерена: в снапшоте РКН
    92,6% записей это /32, и подъём их до /28 снимает 25,2% префиксов самого тяжёлого
    списка (17 120 → 12 810) ценой +203 тыс. адресов, то есть +4,6% к его пространству.
    На роутере префиксы стоят памяти, а адреса не стоят ничего: nftables хранит набор
    интервалов, и /28 занимает в нём ровно столько же, сколько /32.
    """
    out = []
    for net in collapse(nets):
        if net.prefixlen > min_prefix:
            # /29../32 — одиночный хост; поднимаем до /28 вокруг него.
            out.append(net.supernet(new_prefix=min_prefix))
        else:
            # /28 и крупнее — уже диапазон, чужие сети не расширяем.
            out.append(net)
    return collapse(out)


# ---- Публичные резолверы -----------------------------------------------------

# Адреса публичных DNS-резолверов. В списки обхода они попадают потому, что резолвер
# отвечает за домен сам собой (а `result_to_networks` берёт /24 вокруг каждого ответа) и
# потому, что вендорные снапшоты их иногда содержат.
#
# Увести резолвер в туннель — это отказ, который потом ловят как «DNS отвалился после
# включения списка»: запрос уходит в туннель, ответ приходит с другого маршрута, и имя не
# резолвится вовсе. Замерено до правки: 8.8.8.0/24 лежал в шести списках (google, youtube,
# rkn_other, ipsum, rkn_all, all), 1.1.1.0/24 — в пяти.
#
# Отдельным списком, а НЕ в EXCLUDED_NETS: там проверка симметрична (`net.overlaps(exc) or
# exc.overlaps(net)`), и 8.8.8.0/24 в ней выкинул бы заодно всякий префикс, который его
# содержит, — вплоть до 8.0.0.0/8 целиком. Здесь дырка вырезается ровно по границе
# резолвера, а остальная часть префикса остаётся в списке.
RESOLVER_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "8.8.8.0/24",       # Google Public DNS
        "8.8.4.0/24",       # Google Public DNS
        "1.1.1.0/24",       # Cloudflare DNS
        "1.0.0.0/24",       # Cloudflare DNS
        "9.9.9.0/24",       # Quad9
        "149.112.112.0/24", # Quad9
        "208.67.222.0/24",  # OpenDNS
        "208.67.220.0/24",  # OpenDNS
        "94.140.14.0/24",   # AdGuard DNS
        "94.140.15.0/24",   # AdGuard DNS
        "77.88.8.0/24",     # Яндекс DNS
    )
]


def punch_out(nets, holes):
    """Вырезать из списка сетей адреса `holes`, сохранив всё остальное.

    Сеть, целиком лежащая в дырке, исчезает; сеть, которая дырку содержит, распадается на
    части вокруг неё. Именно это отличает вырезание от отбрасывания: 104.16.0.0/12 внутри
    себя несёт Cloudflare, но выкинуть его целиком значило бы потерять 3,2 млн адресов,
    которые к Cloudflare отношения не имеют.
    """
    if not holes:
        return list(nets)
    # Дырки склеены (значит непересекающиеся) и отсортированы — это позволяет искать
    # пересечения двоичным поиском, а не перебором всех дырок на каждую сеть. Разница не
    # косметическая: у списка РКН 30 тыс. префиксов против 3 тыс. диапазонов прокси, и
    # честный перебор — это 90 млн проверок на каждой сборке.
    ranges = sorted(ipaddress.collapse_addresses(holes), key=lambda r: int(r.network_address))
    starts = [int(r.network_address) for r in ranges]
    out = []
    for net in nets:
        lo, hi = int(net.network_address), int(net.broadcast_address)
        # Первая дырка, которая может пересечься: та, что начинается не позже конца сети.
        i = bisect.bisect_right(starts, hi) - 1
        # Отступаем назад, пока предыдущая дырка ещё накрывает начало сети.
        while i >= 0 and int(ranges[i].broadcast_address) >= lo:
            i -= 1
        i += 1
        pieces = [net]
        while i < len(ranges) and starts[i] <= hi and pieces:
            r = ranges[i]
            nxt = []
            for p in pieces:
                if not p.overlaps(r):
                    nxt.append(p)
                elif p.subnet_of(r):
                    continue  # целиком внутри дырки — исчезает
                elif r.subnet_of(p):
                    nxt += list(p.address_exclude(r))
                else:
                    # Частичное перекрытие невозможно для IPv4-сетей: две сети либо
                    # вложены одна в другую, либо не пересекаются вовсе.
                    nxt.append(p)
            pieces = nxt
            i += 1
        out += pieces
    return out


def sort_key(net):
    return (int(net.network_address), net.prefixlen)


def finalize(nets, sparse_limit: int = 28, keep_resolvers: bool = False):
    """Полный конвейер нормализации одной категории:
    дедуп → collapse → summarize_sparse → вырезание резолверов → сортировка → строки CIDR.

    Резолверы вырезаются ПОСЛЕ подъёма до /28, а не до него: иначе /32 рядом с 8.8.8.8
    поднялся бы до /28 и вернул бы резолвер обратно в список уже расширенным.
    """
    collapsed = collapse(nets)
    summarized = summarize_sparse(collapsed, min_prefix=sparse_limit)
    if not keep_resolvers:
        summarized = collapse(punch_out(summarized, RESOLVER_NETS))
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
