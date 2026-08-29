"""Каноническая схема категорий.

Единый источник правды для всего генератора и для `lists/categories.json`
(который splify будет читать для UI-переключателей).

Каждая категория: id, name_ru, description_ru, file, тип источника,
default_on (рекомендация splify), is_geoblock (группа GB).

`source` описывает, откуда категория наполняется:
  - {"kind": "service", "files": [...], "asn": [...], "cdn": "..."}
      домены из sources/services + CIDR по ASN + прямой CDN-фид (если есть)
  - {"kind": "rule", "geoblock": bool}
      наполняется категоризатором из РКН/community_ooni по ключевым словам
  - {"kind": "rkn", "file": "..."}
      домены категоризатора ПЛЮС готовые CIDR вендорного снапшота
  - {"kind": "cidr_url", "url": "...", "fallback_file": "..."}
      готовый ipset по ссылке, со снапшотом в репозитории на случай недоступности
  - {"kind": "aggregate", "of": [...]}
      объединение других категорий

Категория с `no_subtract: True` берётся как есть: по ней не гоняются ни вычитание
инфраструктуры, ни вычитание общих обратных прокси.

ПОЛЯ МАНИФЕСТА, КОТОРЫХ НЕТ В ЭТОМ СПИСКЕ КАТЕГОРИЙ, но которые он объясняет:

  `same_prefixes_as` / `same_prefixes_reason_ru` — у категорий и у записей `services`.
      Две категории могут давать ОДИН И ТОТ ЖЕ набор префиксов: `meta` и `whatsapp`
      берут AS32934, `google` и `youtube` — AS15169, и файлы у них совпадают побайтово.
      Раньше манифест этого не говорил, и человек выбирал между двумя одинаковыми
      списками, думая, что один узкий (I-031). Файлы при этом НЕ склеиваются: на их
      имена ссылаются уже настроенные каналы на установленных роутерах.
      Значение поля не берётся из схемы на веру: `aggregate.same_prefixes_groups()`
      считает его по СОБРАННЫМ спискам, а группы ниже дают человеческую причину.

  `upstream` — у записей `domain_lists` (см. `domain_lists.upstream_meta`). Доменные
      списки зеркалятся из itdoginfo/allow-domains, локальная правка такого файла
      живёт до следующей синхронизации, и сказать об этом должен манифест, а не
      догадка пользователя (I-077).

`validate()` ниже проверяет всё, что здесь описано. Она вызывается из `aggregate.main()`
ДО сборки и из `generator/selfcheck.py` (быстрая проверка без сети, её же гоняет CI).
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
        "description_ru": "Мессенджер WhatsApp (Meta). Адресный список — тот же, что у Meta: "
                          "общая автономная система AS32934. Различаются только доменные списки.",
        "default_on": True,
        "is_geoblock": False,
        "source": {"kind": "service", "files": ["meta.lst"], "asn": True,
                   "domain_filter": "whatsapp"},
    },
    {
        "id": "discord",
        "name_ru": "Discord",
        "description_ru": "Голосовой чат Discord: готовый ipset внешнего списка, без вычитаний.",
        "default_on": True,
        "is_geoblock": False,
        # Discord собирается ГОТОВЫМ ipset'ом из внешнего списка, а не резолвом и не по
        # ASN. Решение владельца, и у него есть основание в данных: своего ASN у Discord
        # нет (AS62041 — Telegram, и однажды он затащил подсети телеграма в этот список),
        # а голосовые серверы живут блоками в чужих облаках, которые резолв доменов не
        # находит вовсе. Внешний список ведётся именно под это.
        #
        # no_subtract: по этому списку НЕ гоняются вычитания инфраструктуры и общих прокси.
        # Он берётся как есть — это тоже решение владельца. Следствие видно в данных и
        # названо вслух: в списке лежит 104.16.0.0/12, то есть 1 048 576 адресов
        # Cloudflare; вычитание убрало бы ровно его.
        "no_subtract": True,
        "source": {"kind": "cidr_url",
                   # files здесь не резолвится (kind не service) и нужен ровно для одного:
                   # связать адресный Discord с доменным svc_discord, который издаётся из
                   # того же discord.lst. Без этой строчки сервис в манифесте остался бы
                   # с одной половиной покрытия.
                   "files": ["discord.lst"],
                   "url": "https://raw.githubusercontent.com/1andrevich/Re-filter-lists"
                          "/refs/heads/main/discord_ips.lst",
                   # Снапшот того же списка в репозитории — на случай, когда источник
                   # недоступен. Обновляется при каждой удачной сборке. Без него сборка
                   # молча выпускала бы Discord с нулём префиксов.
                   "fallback_file": "discord/refilter_discord_ips.lst"},
    },
    {
        "id": "meta",
        "name_ru": "Meta (Facebook/Instagram)",
        # Было «Соцсети Facebook и Instagram (без WhatsApp)» — и это неправда на уровне
        # адресов: whatsapp.lst и meta.lst совпадают побайтово, потому что оба берут
        # префиксы AS32934, а domain_filter отделяет домены, а не адреса (I-031).
        "description_ru": "Соцсети Facebook и Instagram. Адресный список — тот же, что у "
                          "WhatsApp: общая автономная система AS32934. По адресам эти "
                          "категории не различаются, различаются только доменные списки.",
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
        "description_ru": "Видеохостинг YouTube и CDN (Google Video). Адресный список — тот "
                          "же, что у категории Google: общая автономная система AS15169, "
                          "поэтому включение YouTube уводит в туннель все адреса Google.",
        "default_on": True,
        "is_geoblock": False,
        "source": {"kind": "service", "files": ["youtube.lst"], "asn": True},
    },
    {
        "id": "google",
        "name_ru": "Google (Meet/Play/AI)",
        "description_ru": "Google Meet, Play и AI-сервисы (Bard/Gemini). Адресный список — "
                          "тот же, что у YouTube: общая автономная система AS15169.",
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
    {
        "id": "github",
        "name_ru": "GitHub",
        "description_ru": "GitHub: сайт, API, клон и релизные файлы. Официальный фид "
                          "api.github.com/meta; адреса раннеров Actions в список не входят.",
        "default_on": False,
        "is_geoblock": False,
        # Вычитание инфраструктуры по этой категории НЕ гоняется, и причина измерена, а не
        # предположена: 185.199.108.0/22 — это анонс Fastly (он лежит в fastly.lst), и
        # ровно с этих адресов отдаются raw.githubusercontent.com и
        # objects.githubusercontent.com. Вычитание сняло бы с GitHub ровно ту часть, ради
        # которой список и заводится: у людей из splify2#15 закрыт именно этот хост.
        #
        # Плата известна и невелика: /22 — это 1024 адреса, и других жильцов, кроме
        # GitHub Pages, у него нет; фид перечисляет его от имени самого GitHub.
        "no_subtract": True,
        "source": {"kind": "service", "files": ["github.lst"], "cdn": "github"},
    },
    {
        "id": "openwrt",
        "name_ru": "OpenWrt",
        "description_ru": "Обновление пакетов и прошивок самого роутера: downloads.openwrt.org, "
                          "зеркала и остальные узлы проекта.",
        "default_on": False,
        "is_geoblock": False,
        # Ни ASN, ни фида: своей автономной системы у проекта нет, а инфраструктура
        # размазана по хостерам (downloads — за Fastly, git — Hetzner, форум — DigitalOcean).
        # Значит адресная часть получается резолвом имён, как у любого сервиса без своей
        # сети: замерено — 14 доменов дают 14 префиксов /24. Вычитание инфраструктуры
        # трогает только префиксы ШИРЕ /24, поэтому 151.101.130.0/24 (downloads за Fastly)
        # вычитание Fastly переживает, а весь Fastly в туннель не уезжает.
        "source": {"kind": "service", "files": ["openwrt.lst"]},
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
        "description_ru": "Все подсети Cloudflare: официальный фид ips-v4 плюс анонсы AS13335.",
        "default_on": False,
        "is_geoblock": False,
        "is_infra": True,
        "is_shared_proxy": True,
        # ДВА источника, и второй добавлен не ради полноты.
        #
        # Официальный фид https://www.cloudflare.com/ips-v4 — это ровно 15 префиксов, и
        # описывает он только края обратного прокси. Всё остальное, что принадлежит
        # Cloudflare, в него не входит: замерено — AS13335 анонсирует 2361 префикс IPv4, и
        # 713 из них фид не покрывает ни одним битом.
        #
        # Нашлось на живом роутере: 8.6.112.0/24 принадлежит Cloudflare, но с включённым
        # списком «Cloudflare CDN» трафик к нему в туннель не шёл — потому что в списке его
        # не было. Описание при этом обещало «все подсети Cloudflare». Обещание расходилось
        # с данными, и расхождение молчало.
        #
        # Заодно это делает вычитание честным: подсети Cloudflare вычитаются из СЕРВИСНЫХ
        # списков, и вычитать по фиду из 15 префиксов значило оставлять в них те самые 713.
        "source": {"kind": "service", "files": ["cloudflare.lst"],
                   "cdn": "cloudflare", "asn": True},
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
    # Обратные прокси с anycast-краями. Каждый — своя категория, потому что вычитание
    # оставляет его адреса ТОЛЬКО в его же списке: если человек сознательно хочет увести в
    # туннель весь Fastly, ему есть что включить, а список сервиса от этого не портится.
    #
    # Измерено до добавления: 753 адреса этих провайдеров лежали в списках, из них 374 в
    # rkn_other (ddos-guard 186, fastly 113, sucuri 40). Каждый такой адрес — это «увести
    # заодно всё, что за ним живёт», а за обратным прокси живёт что угодно.
    {
        "id": "fastly",
        "name_ru": "Fastly CDN",
        "description_ru": "Подсети Fastly по ASN 54113. Обратный прокси: за адресом тысячи сайтов.",
        "default_on": False,
        "is_geoblock": False,
        "is_infra": True,
        "is_shared_proxy": True,
        "source": {"kind": "service", "files": [], "asn": True},
    },
    {
        "id": "ddos_guard",
        "name_ru": "DDoS-Guard",
        "description_ru": "Подсети DDoS-Guard по ASN 57724. Обратный прокси, много российских сайтов.",
        "default_on": False,
        "is_geoblock": False,
        "is_infra": True,
        "is_shared_proxy": True,
        "source": {"kind": "service", "files": [], "asn": True},
    },
    {
        "id": "qrator",
        "name_ru": "Qrator",
        "description_ru": "Подсети Qrator по ASN 197068. Обратный прокси.",
        "default_on": False,
        "is_geoblock": False,
        "is_infra": True,
        "is_shared_proxy": True,
        "source": {"kind": "service", "files": [], "asn": True},
    },
    {
        "id": "gcore",
        "name_ru": "Gcore CDN",
        "description_ru": "Подсети Gcore по ASN 199524.",
        "default_on": False,
        "is_geoblock": False,
        "is_infra": True,
        "is_shared_proxy": True,
        "source": {"kind": "service", "files": [], "asn": True},
    },
    {
        "id": "bunny",
        "name_ru": "Bunny CDN",
        "description_ru": "Подсети Bunny по ASN 200325.",
        "default_on": False,
        "is_geoblock": False,
        "is_infra": True,
        "is_shared_proxy": True,
        "source": {"kind": "service", "files": [], "asn": True},
    },
    {
        "id": "sucuri",
        "name_ru": "Sucuri",
        "description_ru": "Подсети Sucuri по ASN 30148. Обратный прокси с защитой сайтов.",
        "default_on": False,
        "is_geoblock": False,
        "is_infra": True,
        "is_shared_proxy": True,
        "source": {"kind": "service", "files": [], "asn": True},
    },
    {
        "id": "imperva",
        "name_ru": "Imperva",
        "description_ru": "Подсети Imperva (Incapsula) по ASN 19551. Обратный прокси.",
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
    # ─────────────── РКН и геоблок: по одному списку на признак ───────────────
    #
    # Раньше здесь стояли восемь тематик РКН, восемь их GB-двойников и rkn_other —
    # семнадцать переключателей. Свёрнуты в два, и вот почему.
    #
    # Тематики РКН («стриминг», «соцсети», «игры») делили один реестр и один резолв, а
    # значит и одни адреса: восемь файлов давали 18 241 префикс, их объединение — 14 995,
    # то есть 17,8% строк существовали только потому, что лежали в разных файлах.
    #
    # GB-двойники не были отдельными данными вовсе. Домены community_ooni принудительно
    # получали суффикс _GB (categorize.py), хотя 6 941 из 6 953 таких доменов лежат и в
    # снапшоте РКН, — то есть один домен проходил дважды и резолвился в тот же /24.
    # Замерено: adult_GB не имел НИ ОДНОГО уникального префикса из 126, social_GB — ни
    # одного из 22, media_GB — ни одного из 2.
    #
    # Что осталось разделённым — то, что разделено по существу: заблокированное в РФ
    # (`rkn`) против сервисов, которые сами режут РФ (`geoblock`). Это разные решения
    # человека: первое обходит блокировку, второе прячет страну.
    {
        "id": "rkn",
        "name_ru": "Заблокированное в РФ",
        "description_ru": "Единый реестр заблокированного в РФ: тематика РКН и прочие ресурсы из снапшота.",
        "default_on": True,
        "is_geoblock": False,
        # Два источника у одной категории: домены из категоризатора (резолвятся) и готовые
        # CIDR из вендорного снапшота (не резолвятся). Раньше это были разные категории с
        # разными kind, отчего снапшот и тематика не могли схлопнуться между собой.
        "source": {"kind": "rkn", "file": "rkn/vendor_ipsum_snapshot.lst"},
    },
    {
        "id": "geoblock",
        "name_ru": "Геоблок (сервисы, режущие РФ)",
        "description_ru": "Зарубежные сервисы, сами закрывающие доступ из РФ: AI, СМИ, стриминг, dev-инструменты.",
        "default_on": False,
        "is_geoblock": True,
        "source": {"kind": "rule", "geoblock": True},
    },
]

# Агрегаты (не категории-переключатели, но публичные списки).
AGGREGATES = [
    {
        "id": "rkn_all",
        "name_ru": "Всё заблокированное в РФ",
        "description_ru": "Объединение всех категорий, заблокированных в РФ, без геоблока и без инфраструктуры.",
        "default_on": False,
        "is_geoblock": False,
        "aggregate_of": "non_geoblock",
    },
    # geoblock_all убран: после склейки девяти GB-категорий в одну `geoblock` он был бы
    # её байтовой копией. Старое имя ведёт на `geoblock` через RENAMED_FROM.
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
        "description_ru": "Полный объединяющий список: все категории РКН и геоблока вместе (без инфраструктуры — она в hodca).",
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

# Категории, у которых адресный список получается ОДНИМ И ТЕМ ЖЕ, и почему.
#
# Причина всегда одна и та же: общий номер автономной системы. Префиксы AS в
# lib.finalize() поглощают все /24, полученные резолвом доменов, поэтому `domain_filter`
# («whatsapp» / «not_whatsapp») различает домены, но НЕ различает адреса. Замерено на
# выпущенных списках: meta.lst и whatsapp.lst совпадают побайтово, google.lst и
# youtube.lst тоже; больше ни одна пара категорий не пересекается даже на 2%.
#
# Что здесь НЕ делается: файлы не склеиваются и не переименовываются. На meta.lst,
# whatsapp.lst, google.lst и youtube.lst ссылаются каналы на уже настроенных роутерах —
# тот же случай, что с hodca.lst, чьё имя сохранено ровно поэтому. Вместо склейки
# манифест говорит правду: «тот же список адресов, что у Meta, потому что общая AS».
#
# `asn` в записи — не декоратив: validate() сверяет его с sources/asn/asn_services.json,
# иначе причина в описании и причина в данных могли бы разойтись молча.
SAME_PREFIXES_GROUPS = [
    {
        "ids": ["meta", "whatsapp"],
        "asn": 32934,
        "reason_ru": "общая автономная система AS32934 (Meta)",
    },
    {
        "ids": ["google", "youtube"],
        "asn": 15169,
        "reason_ru": "общая автономная система AS15169 (Google)",
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
    "github": [],
    "openwrt": [],
    "cloudflare": ["svc_cloudflare"],
    "cloudfront": ["svc_cloudfront"],
    "akamai": [],
    "hetzner": ["svc_hetzner"],
    "ovh": ["svc_ovh"],
    "digitalocean": ["svc_digitalocean"],
    "aws": [],
}


# Старое имя списка → новое. Публикуется в categories.json ключом `aliases`.
#
# Зачем это вообще нужно. Потребитель (splify2) хранит в /etc/steer/spec.json ПУТЬ к файлу
# списка, а не его идентификатор. Переименование категории поэтому ломается молча: скрипт
# обновления пишет «нет в манифесте, пропущен», список остаётся лежать старой копией и
# перестаёт обновляться, а признак ошибки не выставляется. Человек видит рабочий канал со
# списком, которому полгода.
#
# Здесь двадцать имён, то есть двадцать таких молчаний, если карту не опубликовать.
RENAMED_FROM = {
    "rkn": [
        "streaming", "social", "ai", "gaming", "news", "dev", "adult", "media",
        "rkn_other",
    ],
    "geoblock": [
        "streaming_GB", "social_GB", "ai_GB", "gaming_GB", "news_GB", "dev_GB",
        "adult_GB", "media_GB", "geoblock_all",
    ],
}


def alias_map() -> dict[str, str]:
    """Плоская карта «старое имя файла → новое», как её читает потребитель."""
    return {old: new for new, olds in RENAMED_FROM.items() for old in olds}


def all_category_ids() -> list[str]:
    return [c["id"] for c in CATEGORIES]


def category_by_id(cid: str) -> dict:
    for c in CATEGORIES:
        if c["id"] == cid:
            return c
    raise KeyError(cid)


def declared_same_prefixes() -> dict[str, dict]:
    """id категории → {"with": [другие id группы], "reason_ru": причина}.

    Заявленное, а не измеренное. Измеряет `aggregate.same_prefixes_groups()` по
    собранным спискам; отсюда берётся только человеческая формулировка причины, а
    расхождение между заявленным и измеренным — повод сказать об этом в логе сборки,
    а не опубликовать поле на веру.
    """
    out: dict[str, dict] = {}
    for grp in SAME_PREFIXES_GROUPS:
        for cid in grp["ids"]:
            out[cid] = {
                "with": sorted(i for i in grp["ids"] if i != cid),
                "reason_ru": grp["reason_ru"],
            }
    return out


def _asn_map_from_sources() -> dict | None:
    """ASN по категориям из sources/asn/asn_services.json (файл в репозитории, без сети)."""
    import json
    from pathlib import Path as _Path

    f = _Path(__file__).resolve().parent.parent / "sources" / "asn" / "asn_services.json"
    if not f.is_file():
        return None
    try:
        raw = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return {k: v for k, v in raw.items() if not k.startswith("_") and isinstance(v, list)}


def validate() -> list[str]:
    """Проверки схемы. Возвращает список ошибок; пустой список = всё в порядке.

    Зачем это отдельной функцией, а не тестом: `categories.json` перезаписывается
    сборкой ЦЕЛИКОМ, и каждое поле манифеста существует ровно потому, что его пишет
    генератор. Поле, которое никто не проверяет, тихо расходится с данными — именно так
    описание meta полгода обещало «без WhatsApp» при побайтово одинаковых списках.
    """
    import re

    errs: list[str] = []
    ids = [c["id"] for c in CATEGORIES]
    agg_ids = [a["id"] for a in AGGREGATES]

    for cid in set(ids) | set(agg_ids):
        n = ids.count(cid) + agg_ids.count(cid)
        if n > 1:
            errs.append(f"id {cid!r} встречается {n} раз(а) среди категорий и агрегатов")

    for c in CATEGORIES:
        for key in ("id", "name_ru", "description_ru", "default_on", "is_geoblock", "source"):
            if key not in c:
                errs.append(f"категория {c.get('id')!r}: нет обязательного поля {key!r}")
        if not str(c.get("description_ru", "")).strip():
            errs.append(f"категория {c.get('id')!r}: пустое описание")

    # ── same_prefixes: группы ──
    asn_map = _asn_map_from_sources()
    seen: dict[str, int] = {}
    for n, grp in enumerate(SAME_PREFIXES_GROUPS):
        gids = grp.get("ids") or []
        if len(gids) < 2:
            errs.append(f"SAME_PREFIXES_GROUPS[{n}]: в группе меньше двух категорий")
        if not str(grp.get("reason_ru", "")).strip():
            errs.append(f"SAME_PREFIXES_GROUPS[{n}]: нет reason_ru — интерфейсу нечего показать")
        for cid in gids:
            if cid not in ids:
                errs.append(f"SAME_PREFIXES_GROUPS[{n}]: неизвестная категория {cid!r}")
            if cid in seen:
                errs.append(f"категория {cid!r} состоит в двух группах same_prefixes "
                            f"({seen[cid]} и {n}) — набор префиксов не может совпадать "
                            f"с двумя разными наборами")
            seen[cid] = n
        # Причина заявлена как общая AS — сверяем с данными, а не с формулировкой.
        asn = grp.get("asn")
        if asn is not None and asn_map is not None:
            for cid in gids:
                have = asn_map.get(cid)
                if have is None:
                    errs.append(f"SAME_PREFIXES_GROUPS[{n}]: у {cid!r} нет записи в "
                                f"asn_services.json, а причина группы — общая AS{asn}")
                elif asn not in have:
                    errs.append(f"SAME_PREFIXES_GROUPS[{n}]: у {cid!r} в asn_services.json "
                                f"нет AS{asn} (есть {have}) — причина группы не подтверждается")
        # Описание не должно исключать участника той же группы: список у них ОДИН.
        for cid in gids:
            try:
                cat = category_by_id(cid)
            except KeyError:
                continue
            desc = cat["description_ru"]
            for other in gids:
                if other == cid:
                    continue
                o = category_by_id(other)
                for token in {other, o["name_ru"], o["name_ru"].split(" (")[0]}:
                    if re.search(r"без\s+[«\"]?" + re.escape(token), desc, re.I):
                        errs.append(
                            f"категория {cid!r}: описание обещает «без {token}», но её "
                            f"адресный список совпадает с {other!r} побайтово")
                        break

    # ── прочие карты ──
    for cid in SERVICE_DOMAIN_LISTS:
        if cid not in ids:
            errs.append(f"SERVICE_DOMAIN_LISTS: неизвестная категория {cid!r}")
    for new_id, olds in RENAMED_FROM.items():
        if new_id not in ids and new_id not in agg_ids:
            errs.append(f"RENAMED_FROM: цель {new_id!r} не существует")
        for old in olds:
            if old in ids or old in agg_ids:
                errs.append(f"RENAMED_FROM: старое имя {old!r} совпадает с живой "
                            f"категорией — alias указывал бы сам на себя")
    return errs
