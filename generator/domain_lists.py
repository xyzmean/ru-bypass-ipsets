"""Публикация ДОМЕННЫХ списков — как есть, без разрешения в адреса.

Зачем отдельно от остального генератора: движок steer умеет доменные каналы, и им
нужен именно список имён. Разрешать его в CIDR для этого не только лишняя работа, но
и потеря точности — у крупного сервиса десятки адресов, они меняются, и снимок
сегодняшнего резолва завтра неполон. Адресные списки остаются нужны там, где DNS
осмотреть нельзя (клиент с DoH, чужой резолвер), поэтому обе формы живут рядом.

Источник — itdoginfo/allow-domains, папки Categories и Services. Перечень файлов
берётся через API, а не прописан здесь: новый сервис в апстриме должен появляться сам.

Отдельно считается связь с АДРЕСНЫМИ категориями. Она вычисляется точно, а не на
глаз: в схеме у каждой адресной категории перечислены исходные доменные файлы, из
которых её адреса и получены. Значит "youtube адресами" и "youtube доменами" — одна и
та же цель в двух формах, и включать оба канала бессмысленно: адресный список это
снимок сегодняшнего резолва, доменный точнее (особенно с fake-IP), но стоит дороже —
пул адресов, элемент набора и запись в карте на каждый домен. Пусть выбор будет
осознанным, поэтому связь попадает в манифест.

Каждая запись манифеста несёт признак `upstream`: файл в lists/domains/ — ЗЕРКАЛО, а не
наш список. Практическое следствие пришло снаружи (splify2#7): человек включил категорию
«18+», сайта rule34.pw в ней нет, и узнать, что дописать домен в наш репозиторий нельзя
(следующая синхронизация затрёт правку), ему было негде. Теперь это в данных, и интерфейс
может сказать «список внешний: предложите домен апстриму или используйте свой список».

Обратная сторона того же — `check_thematic_seed_coverage()`: ручной сид в sources/thematic
в доменный список НЕ попадает вовсе, он идёт в резолв и превращается в ПРЕФИКСЫ. Для сайта
за общим CDN это не покрытие: адрес либо вычтен как инфраструктура, либо тянет за собой
весь CDN. Проверка называет такие домены при сборке, чтобы «я добавил домен в тематику» и
«домен появился в доменном списке» перестали выглядеть одним и тем же.

Отдельно считаются ПЕРЕСЕЧЕНИЯ между доменными списками. Они реальны (geoblock перекрывается с
тематическими, Services с Categories), а последствие практическое: два канала,
указывающие на пересекающиеся списки, держат одни и те же домены дважды и спорят за
приоритет. Пусть об этом скажет манифест, а не пользователь по факту странного
поведения.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import requests

log = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "lists" / "domains"
CACHE = ROOT / "sources" / "allow-domains"

REPO = "itdoginfo/allow-domains"
FOLDERS = ("Categories", "Services")
API = "https://api.github.com/repos/{repo}/contents/{path}"
HTTP_TIMEOUT = 30


# Ручной тематический сид — вход в РЕЗОЛВ, а не в доменный список. Нужен здесь, чтобы
# проверка покрытия читала ровно тот же каталог, что и aggregate.collect_domains_by_category.
THEMATIC = ROOT / "sources" / "thematic"

# Куда идти человеку, которому нужен домен, которого в зеркале нет. Ветка не называется
# специально: `HEAD` на github.com разрешается в ветку по умолчанию, и угадывать её имя
# (main или master) значило бы опубликовать ссылку, которая однажды отдаст 404.
UPSTREAM_URL = f"https://github.com/{REPO}"
UPSTREAM_SUGGEST_URL = f"https://github.com/{REPO}/issues"

# Порог, ниже которого пересечение не стоит упоминания: пара общих домена есть у всех.
OVERLAP_MIN = 25

# Домен: буквы/цифры/дефис в метках, минимум две метки. Запись вида "*.example.com"
# и ведущая точка приводятся к простому виду — движок сам решает про поддомены.
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,}$")

# name_ru для того, что уже понятно по имени файла; остальное получает имя как есть.
#
# Названия описывают, КТО кого не пускает, а не «что это за список». Прежние
# «Заблокированное в РФ» и «Блокирующие по стране» отличались одним словом и на
# различение уходили минуты — при том что стороны блокировки у них противоположные.
RU_NAMES = {
    "anime": "Аниме",
    "block": "Закрыто из РФ (заблокировал РКН)",
    "geoblock": "Не пускают из РФ (гео-блок сайта)",
    "hodca": "Хостинги и CDN",
    "news": "Новости",
    "porn": "Для взрослых",
    "cloudflare": "Cloudflare",
    "cloudfront": "CloudFront",
    "digitalocean": "DigitalOcean",
    "discord": "Discord",
    "google_ai": "Google AI",
    "google_meet": "Google Meet",
    "google_play": "Google Play",
    "hdrezka": "HDRezka",
    "hetzner": "Hetzner",
    "meta": "Meta",
    "ovh": "OVH",
    "roblox": "Roblox",
    "telegram": "Telegram",
    "tiktok": "TikTok",
    "twitter": "Twitter / X",
    "youtube": "YouTube",
}


def _list_folder(folder: str) -> list[dict]:
    r = requests.get(API.format(repo=REPO, path=folder), timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    return [x for x in r.json() if x["type"] == "file" and x["name"].endswith(".lst")]


def _clean(text: str) -> list[str]:
    """Нормализует список: нижний регистр, без комментариев, без дублей, отсортирован.

    Сортировка не косметика — она делает diff между сборками читаемым, иначе каждая
    выгрузка выглядит как полная переделка файла.
    """
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip().lower()
        if not line or line.startswith(("#", ";", "//")):
            continue
        line = line.lstrip("*.").lstrip(".")
        # Строки вида "0.0.0.0 example.com" (hosts-формат) встречаются в апстримах.
        if " " in line or "\t" in line:
            parts = line.replace("\t", " ").split()
            line = parts[-1]
        if DOMAIN_RE.match(line):
            seen.add(line)
    return sorted(seen)


def _overlaps(sets: dict[str, set[str]]) -> dict[str, list[dict]]:
    """Пары списков с существенным пересечением, в обе стороны.

    Доля считается от МЕНЬШЕГО списка: 300 общих домена — это почти весь discord и
    капля в block, и пользователю важно именно первое.
    """
    out: dict[str, list[dict]] = {}
    ids = sorted(sets)
    for i, a in enumerate(ids):
        for b in ids[i + 1 :]:
            common = sets[a] & sets[b]
            if len(common) < OVERLAP_MIN:
                continue
            for x, y in ((a, b), (b, a)):
                share = round(100 * len(common) / max(1, len(sets[x])))
                out.setdefault(x, []).append({"with": y, "domains": len(common), "percent": share})
    for k in out:
        out[k].sort(key=lambda e: -e["domains"])
    return out


def _ip_equivalents(domain_ids: dict[str, str]) -> dict[str, list[str]]:
    """Доменный список -> адресные категории, построенные из ТОГО ЖЕ файла.

    domain_ids: id доменного списка -> имя исходного файла (например svc_youtube ->
    youtube.lst). Связь берётся из схемы, поэтому она не догадка: если категория
    собрана из youtube.lst, то доменный youtube — её же цель, только другой формой.
    """
    try:
        import categories_schema as schema
    except ImportError:  # запуск как модуль из корня
        from generator import categories_schema as schema  # type: ignore

    by_file: dict[str, list[str]] = {}
    for cat in schema.CATEGORIES:
        src = cat.get("source", {})
        files = src.get("files") or ([src["file"]] if src.get("file") else [])
        for f in files:
            by_file.setdefault(f, []).append(cat["id"])

    out: dict[str, list[str]] = {}
    for cid, fname in domain_ids.items():
        hits = by_file.get(fname, [])
        if hits:
            out[cid] = sorted(hits)
    return out


def upstream_meta(folder: str, filename: str) -> dict:
    """Признак «этот список — зеркало чужого репозитория», как его читает интерфейс.

    `editable_locally: false` — не оговорка, а главное содержание записи: файл в
    lists/domains/ перезаписывается синхронизацией целиком, поэтому дописанный в него
    домен исчезает при следующей сборке, молча. Единственные честные пути —
    предложить домен апстриму (`suggest_url`) или держать свой список на роутере.
    """
    return {
        "repo": REPO,
        "folder": folder,
        "file": f"{folder}/{filename}",
        "url": f"{UPSTREAM_URL}/blob/HEAD/{folder}/{filename}",
        "suggest_url": UPSTREAM_SUGGEST_URL,
        "editable_locally": False,
    }


def _covered_by(domain: str, published: set[str]) -> str | None:
    """Домен или его родитель, уже лежащий в доменных списках; None — нет ни одного.

    Проверяются и родители: движок сопоставляет доменный список по суффиксу, поэтому
    `example.com` в списке покрывает и `cdn.example.com`. Считать иначе значило бы
    объявлять непокрытым то, что покрыто.
    """
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in published:
            return parent
    return None


def check_thematic_seed_coverage() -> dict:
    """Сколько ручных сидов из sources/thematic есть в доменных списках, а сколько нет.

    Ответ почти всегда «нет», и это не поломка, а устройство: сиды идут в резолв и
    становятся префиксами. Проверка существует, чтобы это было сказано вслух при каждой
    сборке — иначе «добавил домен в sources/thematic» читается как «добавил домен в
    список 18+», а это разные вещи, и для сайта за общим CDN вторая не работает вовсе.

    Читает только файлы репозитория: ни сети, ни резолва, поэтому её же гоняет
    generator/selfcheck.py в CI.
    """
    published: set[str] = set()
    for f in sorted(OUT.glob("*.lst")):
        published |= {l.strip() for l in f.read_text(encoding="utf-8").splitlines() if l.strip()}

    by_file: dict[str, dict] = {}
    prefix_only: list[str] = []
    total = 0
    for f in sorted(THEMATIC.glob("*.lst")):
        seeds = _clean(f.read_text(encoding="utf-8", errors="replace"))
        missing = [d for d in seeds if _covered_by(d, published) is None]
        total += len(seeds)
        prefix_only += missing
        by_file[f.name] = {"seeds": len(seeds), "prefix_only": len(missing)}
    return {
        "total": total,
        "in_domain_lists": total - len(prefix_only),
        "prefix_only": sorted(set(prefix_only)),
        "by_file": by_file,
        "published_domains": len(published),
    }


def publish() -> list[dict]:
    """Скачивает, нормализует, пишет lists/domains/*.lst и возвращает записи манифеста."""
    OUT.mkdir(parents=True, exist_ok=True)
    CACHE.mkdir(parents=True, exist_ok=True)

    sets: dict[str, set[str]] = {}
    meta: dict[str, dict] = {}
    src_file: dict[str, str] = {}   # id доменного списка -> имя файла в апстриме

    for folder in FOLDERS:
        try:
            files = _list_folder(folder)
        except Exception as exc:  # noqa: BLE001
            log.warning("не удалось перечислить %s/%s: %s", REPO, folder, exc)
            continue
        for f in files:
            stem = f["name"][:-4]
            # Одно имя в двух папках возможно; папка входит в id, чтобы не затирать.
            cid = stem if folder == "Categories" else f"svc_{stem}"
            try:
                text = requests.get(f["download_url"], timeout=HTTP_TIMEOUT).text
            except Exception as exc:  # noqa: BLE001
                log.warning("не скачался %s: %s", f["name"], exc)
                continue
            (CACHE / f"{folder}_{f['name']}").write_text(text, encoding="utf-8")
            domains = _clean(text)
            if not domains:
                log.warning("%s: после нормализации пусто — пропущен", f["name"])
                continue
            (OUT / f"{cid}.lst").write_text("\n".join(domains) + "\n", encoding="utf-8")
            sets[cid] = set(domains)
            src_file[cid] = f["name"]
            meta[cid] = {
                "id": cid,
                "kind": "domains",
                "name_ru": RU_NAMES.get(stem, stem),
                "file": f"domains/{cid}.lst",
                "count": len(domains),
                "source": f"{REPO}/{folder}",
                # Строковый `source` оставлен как был: его уже читают установленные
                # версии. `upstream` — то же самое, но разобранное на части, плюс главное,
                # чего строка не говорит: дописать домен локально нельзя.
                "upstream": upstream_meta(folder, f["name"]),
                # Ни один доменный список не включается сам: канал должен указать на
                # него осознанно, иначе первая же установка начнёт куда-то гнать почту.
                "default_on": False,
                "is_geoblock": stem == "geoblock",
            }
            log.info("%s: %d доменов", cid, len(domains))

    for cid, entries in _overlaps(sets).items():
        meta[cid]["overlaps"] = entries
    for cid, ids in _ip_equivalents(src_file).items():
        # "То же самое адресами" — самая вероятная ошибка настройки: два канала,
        # одна цель, двойной расход и спор за приоритет.
        meta[cid]["same_as_ip"] = ids

    return [meta[k] for k in sorted(meta)]


def patch_manifest() -> int:
    """Обновляет только ключ domain_lists в готовом lists/categories.json.

    Доменные списки не требуют разрешения адресов, то есть обновляются за секунды —
    а полный прогон резолва занимает около получаса. Гонять его ради того, чтобы
    подтянуть пару новых доменов, бессмысленно, поэтому этот режим правит ровно свою
    часть манифеста и не касается categories: их считает и перезапишет резолв на своём
    расписании.
    """
    entries = publish()
    manifest = ROOT / "lists" / "categories.json"
    if not manifest.exists():
        log.error("%s ещё не собран — нечего править", manifest)
        return 1
    data = json.loads(manifest.read_text(encoding="utf-8"))
    before = len(data.get("domain_lists") or [])
    data["domain_lists"] = entries
    manifest.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    log.info("domain_lists: было %d, стало %d", before, len(entries))
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    import sys as _sys

    if "--patch-manifest" in _sys.argv:
        raise SystemExit(patch_manifest())
    print(json.dumps(publish(), ensure_ascii=False, indent=2))
