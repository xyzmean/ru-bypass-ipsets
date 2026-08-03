"""Каноническая схема категорий.

Единый источник правды для всего генератора и для `lists/categories.json`
(который splify будет читать для UI-переключателей).

Каждая категория: id, name_ru, description_ru, file, тип источника,
default_on (рекомендация splify), is_geoblock (группа GB).

`source` описывает, откуда категория наполняется:
  - {"kind": "service", "files": [...], "asn": [...], "cdn": "..."}
      домены из sources/services + CIDR по ASN + прямой CDN-фид (если есть)
  - {"kind": "thematic", "file": "...", "geoblock": bool}
      домены из фиксированного thematic-сида
  - {"kind": "rule", "geoblock": bool}
      наполняется категоризатором из РКН/community_ooni по ключевым словам
  - {"kind": "aggregate", "of": [...]}
      объединение других категорий
"""

from __future__ import annotations

BASE_URL = (
    "https://raw.githubusercontent.com/xyzmean/ru-bypass-ipsets/main/lists"
)


# id → метаданные. Порядок = порядок в индексе/UI.
CATEGORIES = [
    # ─────────────── Сервисы (крупные — отдельно) ───────────────
    {
        "id": "telegram",
        "name_ru": "Telegram",
        "description_ru": "Мессенджер Telegram: домены и подсети по ASN.",
        "default_on": True,
        "is_geoblock": False,
        "source": {"kind": "service", "files": ["telegram.lst"], "asn": True},
    },
    {
        "id": "whatsapp",
        "name_ru": "WhatsApp",
        "description_ru": "Мессенджер WhatsApp (Meta).",
        "default_on": True,
        "is_geoblock": False,
        "source": {"kind": "service", "files": ["meta.lst"], "asn": True,
                   "domain_filter": "whatsapp"},
    },
    {
        "id": "discord",
        "name_ru": "Discord",
        "description_ru": "Голосовой чат Discord: домены и voice-подсети.",
        "default_on": True,
        "is_geoblock": False,
        # Своего ASN у Discord нет (AS62041 — Telegram, и однажды он затащил подсети
        # телеграма в этот список). Подсети берём из вендорного снапшота: это блоки
        # голосовых серверов в Google Cloud плюс найденные резолвом узлы — своё Discord,
        # а не «весь Google». Подробности в самом снапшоте.
        "source": {"kind": "service", "files": ["discord.lst"], "asn": True,
                   "extra_cidr_file": "discord/subnets.lst"},
    },
    {
        "id": "meta",
        "name_ru": "Meta (Facebook/Instagram)",
        "description_ru": "Соцсети Facebook и Instagram (без WhatsApp).",
        "default_on": True,
        "is_geoblock": False,
        "source": {"kind": "service", "files": ["meta.lst"], "asn": True,
                   "domain_filter": "not_whatsapp"},
    },
    {
        "id": "twitter_x",
        "name_ru": "Twitter / X",
        "description_ru": "Микроблоги Twitter и X.",
        "default_on": True,
        "is_geoblock": False,
        "source": {"kind": "service", "files": ["twitter.lst"], "asn": True},
    },
    {
        "id": "youtube",
        "name_ru": "YouTube",
        "description_ru": "Видеохостинг YouTube и CDN (Google Video).",
        "default_on": True,
        "is_geoblock": False,
        "source": {"kind": "service", "files": ["youtube.lst"], "asn": True},
    },
    {
        "id": "google",
        "name_ru": "Google (Meet/Play/AI)",
        "description_ru": "Google Meet, Play и AI-сервисы (Bard/Gemini).",
        "default_on": True,
        "is_geoblock": False,
        "source": {"kind": "service",
                   "files": ["google_meet.lst", "google_play.lst"],
                   "asn": True},
    },
    {
        "id": "tiktok",
        "name_ru": "TikTok",
        "description_ru": "Короткие видео TikTok (ByteDance).",
        "default_on": True,
        "is_geoblock": False,
        "source": {"kind": "service", "files": ["tiktok.lst"], "asn": True},
    },
    {
        "id": "roblox",
        "name_ru": "Roblox",
        "description_ru": "Игровая платформа Roblox.",
        "default_on": False,
        "is_geoblock": False,
        "source": {"kind": "service", "files": ["roblox.lst"], "asn": True},
    },
    {
        "id": "netflix",
        "name_ru": "Netflix",
        "description_ru": "Видеостриминг Netflix (геоблокирует РФ).",
        "default_on": False,
        "is_geoblock": True,
        "source": {"kind": "service", "files": [], "asn": True,
                   "extra_domains": ["netflix.com", "nflxvideo.net", "nflxext.com"]},
    },
    # ─────────────── CDN и хостинги: по одному на провайдера ───────────────
    #
    # Раньше это был один ком «hodca» из пяти провайдеров. Разделены по двум причинам,
    # и обе практические.
    #
    # Первая: их префиксы ВЫЧИТАЮТСЯ из сервисных списков (см. INFRA_IDS ниже и
    # aggregate.py). Вычитать надо каждого по отдельности — из общего кома нельзя ни
    # понять, что именно ушло, ни оставить один провайдер, убрав другой.
    #
    # Вторая: это сами по себе осмысленный выбор. «Мой сайт на Hetzner» и «половина
    # интернета за Cloudflare» — разные решения, и человек должен принимать их отдельно,
    # а не одной галочкой «хостинги и CDN».
    #
    # is_infra помечает их для вычитания и для интерфейса: это не сервис, которым
    # пользуются, а инфраструктура под чужими сервисами.
    {
        "id": "cloudflare",
        "name_ru": "Cloudflare CDN",
        "description_ru": "Все подсети Cloudflare. Очень широко: за ним живёт половина интернета.",
        "default_on": False,
        "is_geoblock": False,
        "is_infra": True,
        "is_shared_proxy": True,
        "source": {"kind": "service", "files": ["cloudflare.lst"], "cdn": "cloudflare"},
    },
    {
        "id": "cloudfront",
        "name_ru": "AWS CloudFront",
        "description_ru": "CDN Amazon CloudFront (официальный фид ip-ranges).",
        "default_on": False,
        "is_geoblock": False,
        "is_infra": True,
        "is_shared_proxy": True,
        "source": {"kind": "service", "files": [], "cdn": "cloudfront"},
    },
    {
        "id": "akamai",
        "name_ru": "Akamai CDN",
        "description_ru": "Подсети Akamai по ASN 20940.",
        "default_on": False,
        "is_geoblock": False,
        "is_infra": True,
        "is_shared_proxy": True,
        "source": {"kind": "service", "files": [], "asn": True},
    },
    {
        "id": "hetzner",
        "name_ru": "Hetzner",
        "description_ru": "Хостинг Hetzner по ASN 24940.",
        "default_on": False,
        "is_geoblock": False,
        "is_infra": True,
        "source": {"kind": "service", "files": [], "asn": True},
    },
    {
        "id": "ovh",
        "name_ru": "OVH",
        "description_ru": "Хостинг OVH по ASN 16276.",
        "default_on": False,
        "is_geoblock": False,
        "is_infra": True,
        "source": {"kind": "service", "files": [], "asn": True},
    },
    {
        "id": "digitalocean",
        "name_ru": "DigitalOcean",
        "description_ru": "Хостинг DigitalOcean по ASN 14061.",
        "default_on": False,
        "is_geoblock": False,
        "is_infra": True,
        "source": {"kind": "service", "files": [], "asn": True},
    },
    {
        "id": "aws",
        "name_ru": "Amazon AWS",
        "description_ru": "Подсети Amazon AWS по ASN 16509 (без CloudFront — он отдельно).",
        "default_on": False,
        "is_geoblock": False,
        "is_infra": True,
        "source": {"kind": "service", "files": [], "asn": True},
    },
    # ─────────────── Тематические: РКН-блок + GB-пара ───────────────
    {
        "id": "streaming",
        "name_ru": "Стриминг и кино (РКН)",
        "description_ru": "Заблокированные в РФ видеосервисы, онлайн-кинотеатры, торренты.",
        "default_on": True,
        "is_geoblock": False,
        "source": {"kind": "rule", "geoblock": False},
    },
    {
        "id": "streaming_GB",
        "name_ru": "Стриминг (геоблок)",
        "description_ru": "Зарубежные видеосервисы, сами блокирующие доступ из РФ (Netflix и т.п.).",
        "default_on": False,
        "is_geoblock": True,
        "source": {"kind": "rule", "geoblock": True},
    },
    {
        "id": "social",
        "name_ru": "Соцсети (РКН)",
        "description_ru": "Заблокированные в РФ социальные сети (кроме вынесенных отдельно).",
        "default_on": True,
        "is_geoblock": False,
        "source": {"kind": "rule", "geoblock": False},
    },
    {
        "id": "social_GB",
        "name_ru": "Соцсети (геоблок)",
        "description_ru": "Соцсети, сами блокирующие доступ из РФ.",
        "default_on": False,
        "is_geoblock": True,
        "source": {"kind": "rule", "geoblock": True},
    },
    {
        "id": "ai",
        "name_ru": "AI-сервисы (РКН)",
        "description_ru": "Заблокированные в РФ AI-сервисы.",
        "default_on": True,
        "is_geoblock": False,
        "source": {"kind": "rule", "geoblock": False},
    },
    {
        "id": "ai_GB",
        "name_ru": "AI-сервисы (геоблок)",
        "description_ru": "Зарубежные AI-сервисы, блокирующие РФ: ChatGPT, Claude, Gemini и др.",
        "default_on": True,
        "is_geoblock": True,
        "source": {"kind": "rule", "geoblock": True},
    },
    {
        "id": "gaming",
        "name_ru": "Игры (РКН)",
        "description_ru": "Заблокированные в РФ игровые сервисы.",
        "default_on": False,
        "is_geoblock": False,
        "source": {"kind": "rule", "geoblock": False},
    },
    {
        "id": "gaming_GB",
        "name_ru": "Игры (геоблок)",
        "description_ru": "Игровые сервисы, сами блокирующие доступ из РФ.",
        "default_on": False,
        "is_geoblock": True,
        "source": {"kind": "rule", "geoblock": True},
    },
    {
        "id": "news",
        "name_ru": "СМИ и новости (РКН)",
        "description_ru": "Заблокированные в РФ новостные ресурсы.",
        "default_on": False,
        "is_geoblock": False,
        "source": {"kind": "thematic", "file": "news.lst", "geoblock": False},
    },
    {
        "id": "news_GB",
        "name_ru": "СМИ (геоблок)",
        "description_ru": "Зарубежные СМИ, сами блокирующие доступ из РФ.",
        "default_on": False,
        "is_geoblock": True,
        "source": {"kind": "rule", "geoblock": True},
    },
    {
        "id": "dev",
        "name_ru": "Dev-инструменты (РКН)",
        "description_ru": "Заблокированные в РФ инструменты разработчиков.",
        "default_on": False,
        "is_geoblock": False,
        "source": {"kind": "rule", "geoblock": False},
    },
    {
        "id": "dev_GB",
        "name_ru": "Dev-инструменты (геоблок)",
        "description_ru": "Зарубежные dev-сервисы, сами блокирующие РФ: Notion, JetBrains, GitHub-вспомогательное.",
        "default_on": True,
        "is_geoblock": True,
        "source": {"kind": "rule", "geoblock": True},
    },
    {
        "id": "adult",
        "name_ru": "Контент 18+ (РКН)",
        "description_ru": "Заблокированные в РФ ресурсы для взрослых, казино, ставки.",
        "default_on": False,
        "is_geoblock": False,
        "source": {"kind": "thematic", "file": "adult.lst", "geoblock": False},
    },
    {
        "id": "adult_GB",
        "name_ru": "Контент 18+ (геоблок)",
        "description_ru": "Зарубежные ресурсы 18+, сами блокирующие РФ.",
        "default_on": False,
        "is_geoblock": True,
        "source": {"kind": "rule", "geoblock": True},
    },
    {
        "id": "media",
        "name_ru": "Аниме/манга (РКН)",
        "description_ru": "Заблокированные в РФ аниме/манга-ресурсы.",
        "default_on": False,
        "is_geoblock": False,
        "source": {"kind": "thematic", "file": "media.lst", "geoblock": False},
    },
    {
        "id": "media_GB",
        "name_ru": "Медиа (геоблок)",
        "description_ru": "Зарубежные медиа-сервисы (музыка, подкасты), сами блокирующие РФ.",
        "default_on": False,
        "is_geoblock": True,
        "source": {"kind": "rule", "geoblock": True},
    },
    {
        "id": "rkn_other",
        "name_ru": "Прочее РКН",
        "description_ru": "Прочие заблокированные в РФ ресурсы: казино-зеркала, фишинг и т.п. (без точной категории).",
        "default_on": True,
        "is_geoblock": False,
        "source": {"kind": "vendor_cidr", "file": "rkn/vendor_ipsum_snapshot.lst"},
    },
]

# Агрегаты (не категории-переключатели, но публичные списки).
AGGREGATES = [
    {
        "id": "rkn_all",
        "name_ru": "Всё заблокированное в РФ",
        "description_ru": "Объединение всех категорий, заблокированных в РФ (без геоблока).",
        "default_on": False,
        "is_geoblock": False,
        "aggregate_of": "non_geoblock",
    },
    {
        "id": "geoblock_all",
        "name_ru": "Весь геоблок",
        "description_ru": "Объединение всех категорий геоблока (сервисы, сами режущие РФ).",
        "default_on": False,
        "is_geoblock": True,
        "aggregate_of": "geoblock",
    },
    {
        "id": "ipsum",
        "name_ru": "Сводный список (по умолчанию)",
        "description_ru": "Все категории, включённые по умолчанию (для совместимости с одним списком splify).",
        "default_on": True,
        "is_geoblock": False,
        "aggregate_of": "default_on",
    },
    {
        "id": "all",
        "name_ru": "Общий список (всё)",
        "description_ru": "Полный объединяющий список: все категории РКН и геоблока вместе.",
        "default_on": False,
        "is_geoblock": False,
        "aggregate_of": "all",
    },
    {
        "id": "hodca",
        "name_ru": "Хостинги и CDN (все)",
        "description_ru": "Объединение всех провайдеров: Cloudflare, CloudFront, Akamai, Hetzner, OVH, DigitalOcean, AWS.",
        "default_on": False,
        "is_geoblock": False,
        # Был отдельной категорией из пяти провайдеров в одном коме. Стал агрегатом над
        # ними, потому что провайдеры теперь выбираются по одному. Имя файла сохранено:
        # на hodca.lst ссылаются установленные версии splify2, и молча уронить его —
        # это «список скачан, а канал его не находит» у тех, кто уже настроил.
        "aggregate_of": "infra",
    },
]

# Инфраструктура: CDN и хостинги. Ровно эти префиксы ВЫЧИТАЮТСЯ из сервисных списков.
#
# Смысл вычитания. YouTube по ASN 15169 — это Google, и это его собственные адреса. Но
# сервис, живущий за Cloudflare, резолвится в адреса Cloudflare, и включить их значит
# увести в туннель половину интернета вместо одного сервиса. Поэтому из сервисных списков
# широкие диапазоны инфраструктуры убираются, а сама инфраструктура остаётся отдельными
# списками — кому она нужна, тот выбирает её осознанно.
INFRA_IDS = [c["id"] for c in CATEGORIES if c.get("is_infra")]

# Общие обратные прокси: Cloudflare, CloudFront, Akamai. Их адреса вычитаются ОТКУДА
# УГОДНО и без порога по размеру префикса — в отличие от хостингов.
#
# Разница принципиальная, и она про то, кому принадлежит адрес. У Hetzner или OVH адрес
# обычно закреплён за одним клиентом: заблокированный сайт живёт по нему, и по нему его и
# надо ловить. У Cloudflare адрес — anycast-край, за которым тысячи сайтов. Резолв дал его
# потому, что в ту минуту он ответил за нужный домен; завтра за ним другой сайт, а
# маршрутизировать его означает увести в туннель всех остальных заодно.
#
# Поэтому /32 внутри Cloudflare — это НЕ «узел сервиса», как у хостинга, и порог
# INFRA_SUBTRACT_MAX_PREFIXLEN к общим прокси не применяется. Покрытие того, что живёт за
# ними, даёт доменная половина сервиса — ради этого склейка и сделана.
SHARED_PROXY_IDS = [c["id"] for c in CATEGORIES if c.get("is_shared_proxy")]

# Какие доменные списки издателя относятся к какому сервису.
#
# Нужно потому, что нумерация у двух источников своя: адресная категория `twitter_x`
# против доменного `svc_twitter`, а Google у издателя доменов разложен на три списка —
# AI, Meet и Play. Без явного соответствия сервис остаётся с одной половиной покрытия,
# то есть с той самой дыркой, которую склейка и закрывает.
#
# Пусто = у сервиса доменного списка нет вовсе, и это честный ответ: WhatsApp живёт на
# доменах Meta, а у Netflix и AWS доменных списков издатель не публикует.
SERVICE_DOMAIN_LISTS = {
    "telegram": ["svc_telegram"],
    "whatsapp": [],
    "discord": ["svc_discord"],
    "meta": ["svc_meta"],
    "twitter_x": ["svc_twitter"],
    "youtube": ["svc_youtube"],
    "google": ["svc_google_ai", "svc_google_meet", "svc_google_play"],
    "tiktok": ["svc_tiktok"],
    "roblox": ["svc_roblox"],
    "netflix": [],
    "cloudflare": ["svc_cloudflare"],
    "cloudfront": ["svc_cloudfront"],
    "akamai": [],
    "hetzner": ["svc_hetzner"],
    "ovh": ["svc_ovh"],
    "digitalocean": ["svc_digitalocean"],
    "aws": [],
}


def all_category_ids() -> list[str]:
    return [c["id"] for c in CATEGORIES]


def category_by_id(cid: str) -> dict:
    for c in CATEGORIES:
        if c["id"] == cid:
            return c
    raise KeyError(cid)
