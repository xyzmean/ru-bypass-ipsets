#!/usr/bin/env python3
"""Стенд pull по ASN: «источник не ответил» не то же самое, что «префиксов нет».

Зачем. Префиксы сервиса берутся у трёх источников по очереди (RIPEstat → ip.guide →
bgpview), и каждый из них при любой ошибке возвращает пустой список. Пока пустой ответ
всех трёх означал «у ASN нет префиксов», категория собиралась из одних доменов, а
недостача всплывала на пятнадцать минут позже гейтом покрытия — сообщением про просадку
списка, то есть указанием не на ту причину.

Замерено в сборке 2026-08-27T10:51 (прогон 33064816234): `ASN 15169: префиксы не получены
ниоткуда` в 11:08:29, `youtube` вышел на 28 CIDR, а в 11:08:31 — через ДВЕ секунды — тот
же ASN у той же RIPEstat отдал 1233 префикса для `google`. Публикация была отменена
целиком, роутеры остались на снапшоте 2026-08-25, и разблокировать её человеку предлагали
переключателем ALLOW_SHRINK=1 — то есть выпустить урезанный youtube.lst.

Отсюда две проверки: цепочка источников повторяется, а если и повторы пусты — это
ОТСУТСТВУЮЩИЙ ВХОД, и он называется исключением, а не пустым списком. Публикация от этого
всё так же отменяется, но по своей причине и до сборки списка, а не после.

Сети не требует: источники подменяются заглушками, пауза — счётчиком.

Запуск: sh tests/run.sh  (или python3 tests/asn_pull_states.py)
"""

from __future__ import annotations

import ipaddress
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "generator"))

import asn_pull  # noqa: E402

# Стенд нарочно устраивает молчание источников; его жалобы в вывод стенда не нужны.
logging.getLogger("asn_pull").setLevel(logging.CRITICAL)

fails: list[str] = []
checks = 0


def check(ok: bool, what: str) -> None:
    global checks
    checks += 1
    if not ok:
        fails.append(what)


class Sources:
    """Заглушка трёх источников: очередь ответов на каждую попытку."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = 0

    def __call__(self, asn):
        i = min(self.calls // 3, len(self.answers) - 1)
        self.calls += 1
        return list(self.answers[i])


class Clock:
    def __init__(self):
        self.pauses = []

    def __call__(self, seconds):
        self.pauses.append(seconds)


def with_sources(answers):
    src = Sources(answers)
    for name in ("_from_ripestat", "_from_ipguide", "_from_bgpview"):
        setattr(asn_pull, name, src)
    return src


REAL = {n: getattr(asn_pull, n)
        for n in ("_from_ripestat", "_from_ipguide", "_from_bgpview")}

try:
    # ── 1. Источник ответил сразу: ни повторов, ни пауз ──────────────────────────
    src = with_sources([["8.8.8.0/24", "185.1.2.0/24"]])
    clock = Clock()
    nets = asn_pull.asn_to_cidrs(15169, sleep=clock)
    check(len(nets) == 2, f"ответ первого источника потерян: {nets}")
    check(src.calls == 1, f"после успеха опрошены лишние источники: {src.calls}")
    check(clock.pauses == [], f"пауза без нужды: {clock.pauses}")

    # ── 2. Та самая сборка: первая попытка пуста, вторая отвечает ────────────────
    src = with_sources([[], ["185.1.2.0/24"]])
    clock = Clock()
    nets = asn_pull.asn_to_cidrs(15169, sleep=clock)
    check(len(nets) == 1,
          "молчание всех трёх источников не переспрошено — ровно это уронило сборку "
          f"2026-08-27T10:51: {nets}")
    check(src.calls == 4, f"вторая попытка опросила не всю цепочку: вызовов {src.calls}")
    check(len(clock.pauses) == 1 and clock.pauses[0] > 0,
          f"между попытками не выждали: {clock.pauses}")

    # ── 3. Молчат все попытки: это отсутствующий вход, а не пустой ASN ───────────
    src = with_sources([[]])
    clock = Clock()
    try:
        nets = asn_pull.asn_to_cidrs(15169, sleep=clock)
    except asn_pull.AsnUnavailable as exc:
        check("15169" in str(exc), f"в сообщении нет номера ASN: {exc}")
        checks += 1
    except AttributeError:
        fails.append("нет исключения AsnUnavailable: пустой ответ всех источников "
                     "по-прежнему выглядит как «у ASN нет префиксов»")
        checks += 2
    else:
        fails.append(f"молчание всех источников вернулось пустым списком {nets} — "
                     "категория соберётся урезанной, а причину назовёт гейт покрытия")
        checks += 2
    check(src.calls >= 6, f"повторов не было вовсе: вызовов {src.calls}")
    check(len(clock.pauses) >= 1, f"повторы без пауз: {clock.pauses}")

    # ── 4. Мусор в ответе не считается ответом ──────────────────────────────────
    src = with_sources([["не сеть", "10.0.0.0/8", "999.1.1.1/24"], ["185.1.2.0/24"]])
    clock = Clock()
    try:
        nets = asn_pull.asn_to_cidrs(15169, sleep=clock)
    except Exception as exc:  # noqa: BLE001
        nets = f"исключение {exc}"
    check(nets == [ipaddress.ip_network("185.1.2.0/24")],
          f"ответ из одних непригодных префиксов принят за ответ: {nets}")
finally:
    for name, fn in REAL.items():
        setattr(asn_pull, name, fn)

print(f"asn_pull_states: проверок {checks}, провалов {len(fails)}")
for f in fails:
    print(f"  FAIL: {f}")
sys.exit(1 if fails else 0)
