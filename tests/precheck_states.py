#!/usr/bin/env python3
"""Стенд pre-check: молчание нейм-сервера не считается ответом «домена нет».

Зачем. Большие пулы доменов (РКН и geoblock, вместе 20 867 в сборке 2026-08-25) идут в
резолв через быстрый pre-check по ОДНОМУ нейм-серверу: живой домен потом резолвится по
шести, мёртвый не резолвится вовсе. Пока pre-check отвечал «да/нет», любая причина
неответа — таймаут, отказ, потеря пакета, лимит запросов на стороне резолвера — означала
«домена нет», и домен исчезал из сборки целиком.

Измерено по журналам сборок: pre-check оставлял живыми 16 039 из 20 867 (2026-08-25T04:01)
и 5 289 из 20 867 (2026-08-20T21:50) на одном и том же пуле, причём direct-пул, который
идёт без pre-check, в обеих сборках дал одинаковые 88 из 123 — то есть сеть была в
порядке, а терял домены именно фильтр. Следствие в публикации: rkn.lst (default_on) на
плохой сборке покрывал 4,51 млн адресов вместо 6,07 млн, geoblock.lst — 420 префиксов
против 77, а СТРОК в rkn.lst становилось БОЛЬШЕ (11 667 против 11 231, слипается меньше),
поэтому существующий гейт по числу строк ipsum.lst оставался зелёным.

Проверяется поэтому не «сколько доменов выжило» (это зависит от сети), а классификация:
отрицательный ОТВЕТ (NXDOMAIN, нет A-записи, только приватные адреса) отбрасывает домен,
а НЕОТВЕТ оставляет его в полном резолве по шести нейм-серверам.

Сети не требует: dns.resolver.Resolver подменяется заглушкой.

Запуск: sh tests/run.sh  (или python3 tests/precheck_states.py)
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "generator"))

import dns.exception  # noqa: E402
import dns.resolver  # noqa: E402

import resolve as rs  # noqa: E402

fails: list[str] = []
checks = 0


def check(ok: bool, what: str) -> None:
    global checks
    checks += 1
    if not ok:
        fails.append(what)


class _Rdata:
    def __init__(self, address: str) -> None:
        self.address = address


class _FakeResolver:
    """Заглушка dns.resolver.Resolver: поведение задаётся по имени домена."""

    behaviour: dict[str, object] = {}

    def __init__(self, configure: bool = True) -> None:
        self.nameservers: list[str] = []
        self.timeout = 0.0
        self.lifetime = 0.0

    def resolve(self, qname: str, rdtype: str):  # noqa: ANN201
        got = _FakeResolver.behaviour[qname]
        if isinstance(got, Exception):
            raise got
        return [_Rdata(a) for a in got]


_FakeResolver.behaviour = {
    "alive.example":      ["93.184.216.34"],
    "private.example":    ["10.0.0.1"],
    "nxdomain.example":   dns.resolver.NXDOMAIN(),
    "noanswer.example":   dns.resolver.NoAnswer(),
    "timeout.example":    dns.exception.Timeout(),
    "refused.example":    dns.resolver.NoNameservers(),
}

_real_resolver = dns.resolver.Resolver
dns.resolver.Resolver = _FakeResolver  # type: ignore[misc,assignment]
try:
    # ── 1. Классификация: ответ против неответа ──────────────────────────────────
    expect = {
        "alive.example":    rs.PRECHECK_ALIVE,
        "private.example":  rs.PRECHECK_DEAD,   # ответ получен, публичных адресов нет
        "nxdomain.example": rs.PRECHECK_DEAD,   # ответ получен: домена нет
        "noanswer.example": rs.PRECHECK_DEAD,   # ответ получен: A-записи нет
        "timeout.example":  rs.PRECHECK_UNKNOWN,  # молчание — не «нет»
        "refused.example":  rs.PRECHECK_UNKNOWN,  # отказ резолвера — тоже не «нет»
    }
    for dom, want in expect.items():
        got = rs._precheck_state(dom)
        check(got == want, f"pre-check для {dom}: {got}, ожидалось {want}")
finally:
    dns.resolver.Resolver = _real_resolver  # type: ignore[misc,assignment]

# ── 2. Разбиение пула: в полный резолв идут живые И неответившие ─────────────────
_real_state = rs._precheck_state
table = {
    "a1": rs.PRECHECK_ALIVE,
    "a2": rs.PRECHECK_ALIVE,
    "d1": rs.PRECHECK_DEAD,
    "d2": rs.PRECHECK_DEAD,
    "u1": rs.PRECHECK_UNKNOWN,
    "u2": rs.PRECHECK_UNKNOWN,
}
rs._precheck_state = lambda d: table[d]  # type: ignore[assignment]
try:
    to_resolve, alive, unknown = rs.precheck_partition(sorted(table))
    check(sorted(to_resolve) == ["a1", "a2", "u1", "u2"],
          f"в полный резолв ушло {sorted(to_resolve)}, а не живые плюс неответившие")
    check(sorted(alive) == ["a1", "a2"], f"живые определены как {sorted(alive)}")
    check(sorted(unknown) == ["u1", "u2"], f"неответившие определены как {sorted(unknown)}")

    # Худший случай из журналов: нейм-сервер молчит на весь пул. Пул обязан уехать в
    # полный резолв целиком, а не обнулиться.
    silent = {d: rs.PRECHECK_UNKNOWN for d in ("s1", "s2", "s3")}
    rs._precheck_state = lambda d: silent[d]  # type: ignore[assignment]
    to_resolve, alive, unknown = rs.precheck_partition(sorted(silent))
    check(sorted(to_resolve) == ["s1", "s2", "s3"],
          "нейм-сервер молчит на весь пул, а pre-check всё равно отбросил домены")
    check(alive == [], "при полном молчании кто-то назван живым")

    # Обратное: пул, на который получен отрицательный ОТВЕТ, отбрасывается целиком —
    # иначе фикс превратил бы pre-check в «пропускать всё» и потерял свой смысл.
    dead = {d: rs.PRECHECK_DEAD for d in ("x1", "x2")}
    rs._precheck_state = lambda d: dead[d]  # type: ignore[assignment]
    to_resolve, alive, unknown = rs.precheck_partition(sorted(dead))
    check(to_resolve == [], "домены с отрицательным ответом остались в полном резолве")
finally:
    rs._precheck_state = _real_state  # type: ignore[assignment]

print(f"precheck_states: проверок {checks}, провалов {len(fails)}")
for f in fails:
    print(f"  FAIL: {f}")
sys.exit(1 if fails else 0)
