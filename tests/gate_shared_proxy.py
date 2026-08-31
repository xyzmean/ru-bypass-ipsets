#!/usr/bin/env python3
"""Гейт «список общего прокси не бывает пустым» — против молчаливо пропущенного вычитания.

Зачем именно эта проверка, а не проверка выпущенных списков. Категории с
`is_shared_proxy` служат ДВУМ разным целям сразу: они и сами публикуются файлом, и
одновременно являются вычитаемым — `aggregate.subtract_shared_proxy` убирает их края из
каждой сервисной и тематической категории. Поэтому пустой список прокси не выглядит как
пустой файл, который никто не включил: он означает, что вычитание этого провайдера не
выполнилось НИ У ОДНОЙ категории, и его anycast-края уехали в списки, включённые по
умолчанию.

Заметить это по выпущенным спискам нельзя — и это главный довод в пользу гейта в сборке.
Единственный источник правды о том, какие адреса надо было вычесть, — тот самый файл,
который вышел пустым. Проверка «пересекается ли rkn.lst с fastly.lst» на плохой сборке
зелёная: пересекать не с чем. Измерено на снапшоте 2026-08-22T04:20Z (ad44211): 38
префиксов Fastly лежали в rkn.lst и ipsum.lst (оба default_on), 6 — в twitter_x.lst, а
проверка пересечений по опубликованным файлам не нашла ничего.

Запуск: sh tests/run.sh  (или python3 tests/gate_shared_proxy.py)
"""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "generator"))

import aggregate  # noqa: E402
import categories_schema as schema  # noqa: E402

LISTS = ROOT / "lists"

fails: list[str] = []
checks = 0


def check(ok: bool, what: str) -> None:
    global checks
    checks += 1
    if not ok:
        fails.append(what)


def read_nets(path: Path) -> list[ipaddress.IPv4Network]:
    if not path.is_file():
        return []
    return [
        ipaddress.ip_network(line.strip(), strict=False)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ── 1. Сам детектор: пустой список общего прокси обязан быть назван ──────────────
proxy_ids = [c["id"] for c in schema.CATEGORIES if c.get("is_shared_proxy")]
check(bool(proxy_ids), "в схеме нет ни одной категории с is_shared_proxy")

full = {c["id"]: [ipaddress.ip_network("192.0.2.0/24")] for c in schema.CATEGORIES}
check(
    aggregate.empty_shared_proxy(schema.CATEGORIES, full) == [],
    "детектор ругается, когда все списки прокси непустые",
)

for pid in proxy_ids:
    holed = dict(full)
    holed[pid] = []
    check(
        aggregate.empty_shared_proxy(schema.CATEGORIES, holed) == [pid],
        f"пустой список прокси {pid} детектором не назван",
    )

missing = {k: v for k, v in full.items() if k not in proxy_ids}
check(
    sorted(aggregate.empty_shared_proxy(schema.CATEGORIES, missing)) == sorted(proxy_ids),
    "отсутствие ключа в cat_networks не считается пустым списком",
)

# Непрокси-инфраструктура (хостинги) под гейт не попадает: её вычитание касается только
# широких диапазонов у сервисов, и пустой список хостинга не уводит в туннель чужие сайты.
hosting = [c["id"] for c in schema.CATEGORIES
           if c.get("is_infra") and not c.get("is_shared_proxy")]
check(bool(hosting), "в схеме нет инфраструктуры вне общих прокси — проверка потеряла смысл")
for hid in hosting:
    holed = dict(full)
    holed[hid] = []
    check(
        aggregate.empty_shared_proxy(schema.CATEGORIES, holed) == [],
        f"пустой список хостинга {hid} ошибочно валит гейт общих прокси",
    )

# ── 2. Выпущенные списки: ни один общий прокси не вышел пустым ───────────────────
published = {c["id"]: read_nets(LISTS / f"{c['id']}.lst") for c in schema.CATEGORIES}
empty_now = aggregate.empty_shared_proxy(schema.CATEGORIES, published)
check(
    empty_now == [],
    "выпущены пустыми списки общих прокси: "
    + ", ".join(f"{cid}.lst" for cid in empty_now)
    + " — вычитание этих провайдеров не выполнилось ни у одной категории",
)

# ── 3. Цена отключённого вычитания названа в той же мере, что и само вычитание ───
#
# `no_subtract` — единственное исключение из контракта выше: по такому списку не гоняются
# НИ общие прокси, НИ хостинги. Исключение осознанное, поэтому единственное, что от него
# требуется, — называть свою цену вслух; иначе «взяли как есть» и «случайно затащили
# половину Cloudflare» выглядят в журнале сборки одинаково.
#
# Мера обязана совпадать с мерой самого вычитания, и это не педантизм. Считать сети вместо
# адресов — ровно та ошибка, из-за которой H-092 менял единственный числовой гейт: на
# просадке строк становится БОЛЬШЕ, а адресов меньше. А назвать одни прокси, когда
# отключены обе половины, значит промолчать про вторую.
#
# Числа ниже посчитаны на выпущенном openwrt.lst (14 сетей, 4608 адресов): вычитание
# оставило бы 4 сети и 2048 адресов, то есть цена отключения — 2560 адресов в 10 сетях,
# из них 1280 у общих прокси (Fastly) и 1280 у хостингов (Hetzner, DigitalOcean).
PROXY = [ipaddress.ip_network("185.199.108.0/22")]
HOSTING = [ipaddress.ip_network("167.235.28.0/24")]
SAMPLE = PROXY + HOSTING + [ipaddress.ip_network("45.140.183.0/24")]

cost = getattr(aggregate, "no_subtract_cost", None)
if cost is None:
    fails.append("нет aggregate.no_subtract_cost: цена отключённого вычитания считается "
                 "на месте и в сетях — той мерой, которую H-092 из репозитория убрал")
    checks += 4
else:
    addrs, nets_n = cost(SAMPLE, PROXY + HOSTING, PROXY, True)
    check(addrs == 1024 + 256,
          f"цена у сервиса посчитана не в адресах или без хостингов: {addrs} вместо 1280")
    check(nets_n == 2, f"сетей в цене у сервиса: {nets_n} вместо 2")

    addrs, nets_n = cost(SAMPLE, PROXY + HOSTING, PROXY, False)
    check(addrs == 1024,
          "у не-сервиса вычитаются только общие прокси, а в цену попали хостинги: "
          f"{addrs} вместо 1024")

    check(cost([], PROXY + HOSTING, PROXY, True) == (0, 0),
          "пустой список получил ненулевую цену")

    # Выпущенные данные: цена каждой категории с no_subtract названа, и она не нулевая
    # там, где список действительно держит края провайдеров.
    infra_all = [n for c in schema.CATEGORIES if c.get("is_infra")
                 for n in read_nets(LISTS / f"{c['id']}.lst")]
    proxy_all = [n for c in schema.CATEGORIES if c.get("is_shared_proxy")
                 for n in read_nets(LISTS / f"{c['id']}.lst")]
    for cat in [c for c in schema.CATEGORIES if c.get("no_subtract")
                and not c.get("is_infra")]:
        cid = cat["id"]
        addrs, nets_n = cost(read_nets(LISTS / f"{cid}.lst"), infra_all, proxy_all,
                             cat["source"]["kind"] == "service")
        check(addrs >= nets_n,
              f"{cid}: адресов в цене меньше, чем сетей ({addrs} против {nets_n}) — "
              "мера перепутана")
        if cid == "openwrt":
            check((addrs, nets_n) == (2560, 10),
                  f"openwrt: цена отключённого вычитания {addrs} адрес(ов) в {nets_n} "
                  "сет(ях), а на выпущенном списке это 2560 в 10")

print(f"gate_shared_proxy: проверок {checks}, провалов {len(fails)}")
for f in fails:
    print(f"  FAIL: {f}")
sys.exit(1 if fails else 0)
