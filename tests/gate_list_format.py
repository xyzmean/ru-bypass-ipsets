#!/usr/bin/env python3
"""Гейт формы выпущенных списков: строка, которую роутер не загрузит, не публикуется.

Зачем отдельным стендом, если такая проверка уже есть. Она есть — тридцать строк на bash
в шаге «Validate .lst format» — и до ОПУБЛИКОВАННЫХ списков не доезжает вовсе: автокоммит
сборки уходит push'ем под `secrets.GITHUB_TOKEN`, а push этим токеном GitHub не считает
поводом запустить workflow (I-108). То есть форму сторожили ровно у тех коммитов, которые
толкает человек, — у тех, за которыми и так смотрят. Здесь та же проверка живёт одним
файлом, и вызывают его обе стороны: validate.yml на ручных коммитах и resolve.yml перед
шагом коммита, где данные уже собраны и ещё не опубликованы.

Замерено на копии снапшота 2026-08-25: `rkn.lst` с дописанными 10.0.0.0/8, 192.168.0.0/16,
8.8.8.0/24 и одним дублем проходит всю цепочку публикующей сборки зелёной — selfcheck
в режиме --warn-only молчит по построению, гейт ipsum считает строки и видит 11 153, а
стенды в resolve.yml не вызывались вообще.

Что здесь ошибка, а что предупреждение. Гейтом перед публикацией становится только то,
ошибка в чём портит МАРШРУТИЗАЦИЮ; всё, что портит вид данных, остаётся предупреждением —
уронить шаг после сборки значит оставить все роутеры на прошлом снапшоте.

  ошибки:
    * строка не разбирается как IPv4 CIDR, октет > 255, длина префикса > 32 — `ipset
      restore` отвергает файл, и список не встаёт ЦЕЛИКОМ, а не одной строкой;
    * выставлены биты хоста (10.1.2.3/24) — запись означает не то, что написано, и два
      снапшота с одним содержанием перестают быть равными;
    * дубль — `ipset add` без `-exist` возвращает ошибку на второй такой записи;
    * частная или зарезервированная сеть (lib.EXCLUDED_NETS) — весь локальный сегмент
      уезжает в туннель, и роутер теряет собственную сеть;
    * адрес публичного резолвера (lib.RESOLVER_NETS) — запрос уходит в туннель, ответ
      приходит другим маршрутом, и имена перестают резолвиться вовсе (I-030).

  предупреждения:
    * файл не отсортирован — diff между снапшотами перестаёт читаться;
    * набор не свёрнут до минимума (соседние или вложенные сети) — маршрутизация от
      этого не меняется, но лишние записи занимают память ipset на роутере.

Проверяется не только выпущенное, но и сам детектор: без этого зелёный стенд означает
«ничего не нашли», а не «нечего было находить».

Сети не требует.

Запуск: sh tests/run.sh  (или python3 tests/gate_list_format.py)
"""

from __future__ import annotations

import ipaddress
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "generator"))

import lib  # noqa: E402

LISTS = ROOT / "lists"

SHAPE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")

fails: list[str] = []
checks = 0


def check(ok: bool, what: str) -> None:
    global checks
    checks += 1
    if not ok:
        fails.append(what)


def line_error(raw: str) -> str | None:
    """Чем строка плоха для ipset. None — годная запись или пустая строка."""
    s = raw.strip()
    if not s:
        return None
    if not SHAPE.match(s):
        return f"не IPv4 CIDR: {s!r}"
    ip, _, plen = s.partition("/")
    if any(int(o) > 255 for o in ip.split(".")):
        return f"октет больше 255: {s}"
    if int(plen) > 32:
        return f"длина префикса больше 32: {s}"
    try:
        ipaddress.ip_network(s, strict=True)
    except ValueError:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError as exc:
            return f"не разбирается как сеть: {s} ({exc})"
        return f"выставлены биты хоста: {s} — сеть здесь {net}"
    return None


def net_error(net: ipaddress.IPv4Network) -> str | None:
    """Чем сеть плоха для публичного списка. None — годная."""
    if lib.is_excluded(net):
        return f"частная или зарезервированная сеть: {net}"
    for res in lib.RESOLVER_NETS:
        if net.overlaps(res):
            return f"перекрывает публичный резолвер {res}: {net}"
    return None


def file_errors(text: str) -> list[str]:
    """Ошибки одного списка: форма строк, дубли, запрещённые сети."""
    errs: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        s = raw.strip()
        err = line_error(s)
        if err:
            errs.append(err)
            continue
        if not s:
            continue
        if s in seen:
            errs.append(f"дубликат: {s}")
            continue
        seen.add(s)
        err = net_error(ipaddress.ip_network(s))
        if err:
            errs.append(err)
    return errs


def file_warnings(text: str) -> list[str]:
    """Замечания к виду списка: порядок и свёрнутость. Публикацию не отменяют."""
    warns: list[str] = []
    nets = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s or line_error(s):
            continue
        nets.append(ipaddress.ip_network(s))
    if nets != sorted(nets, key=lib.sort_key):
        warns.append("не отсортирован по адресу сети")
    collapsed = list(ipaddress.collapse_addresses(nets))
    if len(collapsed) < len(nets):
        warns.append(
            f"не свёрнут: {len(nets)} записей сворачиваются в {len(collapsed)}"
        )
    return warns


def annotate(level: str, path: str, message: str) -> None:
    """В CI — аннотацией GitHub Actions, в терминале — обычной строкой."""
    if os.environ.get("GITHUB_ACTIONS"):
        print(f"::{level} file={path}::{message}")
    else:
        print(f"  {level}: {path}: {message}")


# ── 1. Детектор строк: что он обязан пропустить и что назвать ────────────────────
for good in ("185.1.2.0/24", "77.75.76.0/22", "104.16.0.0/13", "5.6.7.8/32"):
    check(line_error(good) is None, f"годная строка названа плохой: {good}")

check(line_error("") is None, "пустая строка названа ошибкой")
check(line_error("   ") is None, "строка из пробелов названа ошибкой")

for bad in ("185.1.2.0", "185.1.2.0/24 # почему", "не строка", "185.1.2.0/24/8",
            "1.2.3.4.5/24", "::1/128"):
    check(line_error(bad) is not None, f"строка без формы CIDR пропущена: {bad!r}")

check(line_error("300.1.2.3/24") is not None, "октет больше 255 пропущен")
check(line_error("1.2.3.4/33") is not None, "длина префикса больше 32 пропущена")
check(line_error("010.1.2.0/24") is not None, "октет с ведущим нулём пропущен")
check("биты хоста" in (line_error("10.1.2.3/24") or ""),
      "запись с выставленными битами хоста не названа")

# ── 2. Детектор сетей: частные сети и резолверы ──────────────────────────────────
for net in ("10.0.0.0/8", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
            "224.0.0.0/4", "0.0.0.0/8"):
    check(net_error(ipaddress.ip_network(net)) is not None,
          f"частная или зарезервированная сеть пропущена: {net}")

check(bool(lib.RESOLVER_NETS), "список резолверов пуст — проверка потеряла смысл")
for res in lib.RESOLVER_NETS:
    check(net_error(res) is not None, f"сеть резолвера пропущена целиком: {res}")
    check(net_error(res.supernet(new_prefix=16)) is not None,
          f"сеть, содержащая резолвер, пропущена: {res.supernet(new_prefix=16)}")
    inside = ipaddress.ip_network(f"{res.network_address}/32")
    check(net_error(inside) is not None, f"адрес резолвера пропущен: {inside}")

check(net_error(ipaddress.ip_network("185.1.2.0/24")) is None,
      "обычная публичная сеть названа запрещённой")

# ── 3. Файл целиком: дубли, порядок, свёрнутость ─────────────────────────────────
check(file_errors("185.1.2.0/24\n185.1.4.0/24\n") == [], "чистый список назван грязным")
check(any("дубликат" in e for e in file_errors("185.1.2.0/24\n185.1.2.0/24\n")),
      "дубль не назван")
check(any("резолвер" in e for e in file_errors("185.1.2.0/24\n8.8.8.0/24\n")),
      "резолвер в файле не назван")
check(any("частная" in e for e in file_errors("10.0.0.0/8\n185.1.2.0/24\n")),
      "частная сеть в файле не названа")

check(file_warnings("185.1.2.0/24\n185.1.4.0/24\n") == [],
      "у отсортированного и свёрнутого списка появились замечания")
check(any("отсортирован" in w for w in file_warnings("185.1.4.0/24\n185.1.2.0/24\n")),
      "нарушенный порядок не назван")
check(any("свёрнут" in w for w in file_warnings("185.1.2.0/25\n185.1.2.128/25\n")),
      "несвёрнутая пара соседних сетей не названа")
check(file_errors("185.1.2.0/25\n185.1.2.128/25\n") == [],
      "несвёрнутость записана в ошибки, а она замечание")

# ── 4. Выпущенные списки ─────────────────────────────────────────────────────────
published = sorted(LISTS.glob("*.lst"))
check(bool(published), "в lists/ нет ни одного .lst — проверять нечего")

for path in published:
    rel = str(path.relative_to(ROOT))
    text = path.read_text(encoding="utf-8", errors="replace")
    errs = file_errors(text)
    for e in errs[:10]:
        annotate("error", rel, e)
    if len(errs) > 10:
        print(f"  ... и ещё {len(errs) - 10} у {rel}")
    check(not errs, f"{rel}: {len(errs)} ошибк(и) формы, первая — {errs[0]}" if errs else "")
    for w in file_warnings(text):
        annotate("warning", rel, w)

print(f"gate_list_format: проверок {checks}, провалов {len(fails)}, "
      f"списков {len(published)}")
for f in fails:
    print(f"  FAIL: {f}")
sys.exit(1 if fails else 0)
