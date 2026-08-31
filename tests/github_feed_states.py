#!/usr/bin/env python3
"""Стенд фида GitHub: «фид ответил пусто» — такой же отсутствующий вход, как «не ответил».

Зачем. Снапшот `sources/github/meta_snapshot.lst` заведён ради одного обещания, записанного
в док-строке `pull_github`: сборка не выпустит GitHub с нулём префиксов, потому что список
нужен ровно тем, у кого GitHub закрыт (splify2#15), и собирается он на машине, которая в
такой день сама может не достучаться до api.github.com. Обещание держалось только для
ОБОРВАННОЙ загрузки: снапшот читался в блоке `except`. Ответ 200 с телом, в котором нужных
ключей нет (переименовали, отдали частичный ответ, вернули страницу вместо JSON), проходил
успешной веткой и возвращал пустой список.

Почему это не ловится ниже по течению. У категории `github_cdn` два источника: фид и анонсы
AS36459. Пустой фид не делает список пустым — остаётся адресная часть ASN, — но уносит из
него ровно 185.199.108.0/22. Это анонс Fastly, а не GitHub, поэтому в AS36459 его нет и
взять его больше неоткуда; с него отдаются raw.githubusercontent.com и
objects.githubusercontent.com, то есть тот самый хост, из-за которого категория и заведена.
Гейт покрытия этого не увидит: правило «был непустым, вышел пустым» не сработает, а правило
доли считается только у списков крупнее CATEGORY_DROP_MIN = 65 536 адресов, тогда как весь
`github_cdn` — 10 672 адреса. То есть снапшот молча не пригодился бы ровно там, где он и
нужен.

Сети не требует: `requests.get` подменяется заглушкой, снапшот — временным файлом.

Запуск: sh tests/run.sh  (или python3 tests/github_feed_states.py)
"""

from __future__ import annotations

import ipaddress
import json
import logging
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "generator"))

import asn_pull  # noqa: E402

# Стенд нарочно устраивает отказы фида; его жалобы в вывод стенда не нужны.
logging.getLogger("asn_pull").setLevel(logging.CRITICAL)

fails: list[str] = []
checks = 0


def check(ok: bool, what: str) -> None:
    global checks
    checks += 1
    if not ok:
        fails.append(what)


SNAPSHOT_TEXT = "140.82.112.0/20\n185.199.108.0/22\n192.30.252.0/22\n"
LIVE_BODY = {"web": ["140.82.112.0/20"], "pages": ["185.199.108.0/22"],
             "api": ["192.30.252.0/22", "2a0a:a440::/29"]}


class Response:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def feed(payload=None, exc: Exception | None = None):
    """Подменить фид: либо тело ответа, либо отказ загрузки."""
    def _get(url, **kwargs):
        if exc is not None:
            raise exc
        return Response(payload)
    asn_pull.requests.get = _get


REAL_GET = asn_pull.requests.get
REAL_SNAPSHOT = asn_pull.GITHUB_SNAPSHOT

with tempfile.TemporaryDirectory() as tmp:
    snap = Path(tmp) / "meta_snapshot.lst"
    asn_pull.GITHUB_SNAPSHOT = snap
    try:
        # ── 1. Фид ответил: берётся он, снапшот переписывается ───────────────────────
        snap.write_text("1.2.3.0/24\n", encoding="utf-8")
        feed(LIVE_BODY)
        nets = asn_pull.pull_github()
        check(len(nets) == 3, f"ответ фида потерян или взят не целиком: {nets}")
        check(ipaddress.ip_network("2a0a:a440::/29") not in nets,
              "IPv6 из фида попал в список IPv4")
        check("140.82.112.0/20" in snap.read_text(encoding="utf-8"),
              "удачная загрузка не обновила снапшот — память о последнем разе не растёт")

        # ── 2. Загрузка оборвалась: снапшот выручает (это работало и раньше) ─────────
        snap.write_text(SNAPSHOT_TEXT, encoding="utf-8")
        feed(exc=OSError("соединение сброшено"))
        nets = asn_pull.pull_github()
        check(len(nets) == 3, f"снапшот не подхвачен при обрыве загрузки: {nets}")

        # ── 3. Ответ 200 без нужных ключей — тот же отсутствующий вход ───────────────
        snap.write_text(SNAPSHOT_TEXT, encoding="utf-8")
        feed({"actions": ["4.4.4.0/24"], "message": "API rate limit exceeded"})
        nets = asn_pull.pull_github()
        check(len(nets) == 3,
              "ответ 200 без нужных ключей вернулся пустым списком вместо снапшота: "
              f"{nets} — github_cdn теряет 185.199.108.0/22, и ни один гейт этого не видит")
        check(ipaddress.ip_network("185.199.108.0/22") in nets,
              "потерян ровно тот префикс, ради которого категория заведена (splify2#15)")

        # ── 4. Ключи на месте, но пригодных префиксов в них нет ──────────────────────
        snap.write_text(SNAPSHOT_TEXT, encoding="utf-8")
        feed({"web": ["не сеть"], "pages": ["2a0a:a440::/29"], "api": []})
        nets = asn_pull.pull_github()
        check(len(nets) == 3,
              f"ответ из одних непригодных префиксов принят за ответ: {nets}")

        # ── 5. Пустой ответ не затирает снапшот ─────────────────────────────────────
        snap.write_text(SNAPSHOT_TEXT, encoding="utf-8")
        feed({})
        asn_pull.pull_github()
        check(snap.read_text(encoding="utf-8") == SNAPSHOT_TEXT,
              "пустой ответ переписал снапшот — память о последней удачной загрузке стёрта")

        # ── 6. Ни фида, ни снапшота: пусто и честно, без исключения ──────────────────
        snap.unlink()
        feed(exc=OSError("соединение сброшено"))
        try:
            nets = asn_pull.pull_github()
        except Exception as exc:  # noqa: BLE001
            nets = f"исключение {type(exc).__name__}: {exc}"
        check(nets == [], f"без фида и без снапшота вернулось не пустое: {nets}")
    finally:
        asn_pull.requests.get = REAL_GET
        asn_pull.GITHUB_SNAPSHOT = REAL_SNAPSHOT

print(f"github_feed_states: проверок {checks}, провалов {len(fails)}")
for f in fails:
    print(f"  FAIL: {f}")
sys.exit(1 if fails else 0)
