# ru-bypass-ipsets

Категоризованные IPv4 ipset-списки для обхода блокировок (РФ). Резолвит домены в CIDR по категориям и публикует готовые `.lst` для маршрутизации трафика в VPN/прокси.

Основной потребитель — [splify](https://github.com/xyzmean/splify) (OpenWrt). Формат совместим с `clean_ip_list`: строго `A.B.C.D/N`, без голых IP.

## Принцип

1. **Источники** — только вендорные снапшоты в репо + надёжные онлайн-API (`antifilter.download`, RIPEstat, Cloudflare/AWS CDN). К чужим репозиториям напрямую не обращаемся.
2. **Резолв** — `dnspython` по 6 nameservers (включая Яндекс 77.88.8.8), объединение A-записей от всех резолверов для максимального покрытия CDN.
3. **ASN-pull** — для крупных сервисов (Telegram, Meta, …) CIDR берутся напрямую по ASN (RIPEstat → ip.guide → bgpview) и из CDN-фидов (Cloudflare, CloudFront).
4. **Склейка** — `collapse_addresses()` схлопывает перекрытия и смежные сети в максимально крупные подсети; дедуп + сортировка.
5. **Обновление** — GitHub Actions раз в 3 дня + по push + вручную.

## Категории

| Категория | Русское название | Описание | По умолч. |
|---|---|---|:--:|
| `telegram` | Telegram | Мессенджер Telegram (домены + ASN) | ✅ |
| `whatsapp` | WhatsApp | Мессенджер WhatsApp | ✅ |
| `discord` | Discord | Голосовой чат (домены + voice-подсети) | ✅ |
| `meta` | Meta (Facebook/Instagram) | Соцсети Facebook, Instagram | ✅ |
| `twitter_x` | Twitter / X | Микроблоги Twitter, X | ✅ |
| `youtube` | YouTube | Видеохостинг + CDN | ✅ |
| `google` | Google (Meet/Play/AI) | Meet, Play, AI (Bard/Gemini) | ✅ |
| `tiktok` | TikTok | Короткие видео (ByteDance) | ✅ |
| `roblox` | Roblox | Игровая платформа | ⬜ |
| `netflix` 🌐 | Netflix | Стриминг (геоблок РФ) | ⬜ |
| `cloudflare` | Cloudflare | CDN — полный список подсетей | ⬜ |
| `hodca` | Хостинги/CDN (HODCA) | Hetzner, OVH, DigitalOcean, CloudFront, Akamai | ⬜ |
| `streaming` | Стриминг и кино (РКН) | Заблокированные видеосервисы, торренты | ✅ |
| `streaming_GB` 🌐 | Стриминг (геоблок) | Netflix и др., сами блокируют РФ | ⬜ |
| `social` | Соцсети (РКН) | Заблокированные соцсети | ✅ |
| `social_GB` 🌐 | Соцсети (геоблок) | Соцсети, сами блокируют РФ | ⬜ |
| `ai` | AI-сервисы (РКН) | Заблокированные AI | ✅ |
| `ai_GB` 🌐 | AI-сервисы (геоблок) | ChatGPT, Claude, Gemini — блокируют РФ | ✅ |
| `gaming` | Игры (РКН) | Заблокированные игры | ⬜ |
| `gaming_GB` 🌐 | Игры (геоблок) | Игры, сами блокируют РФ | ⬜ |
| `news` | СМИ и новости (РКН) | Заблокированные СМИ | ⬜ |
| `news_GB` 🌐 | СМИ (геоблок) | Зарубежные СМИ, сами блокируют РФ | ⬜ |
| `dev` | Dev-инструменты (РКН) | Заблокированные dev-сервисы | ⬜ |
| `dev_GB` 🌐 | Dev-инструменты (геоблок) | Notion, JetBrains и др. — блокируют РФ | ✅ |
| `adult` | Контент 18+ (РКН) | 18+, казино, ставки | ⬜ |
| `adult_GB` 🌐 | Контент 18+ (геоблок) | 18+, сами блокируют РФ | ⬜ |
| `media` | Аниме/манга (РКН) | Заблокированные аниме | ⬜ |
| `media_GB` 🌐 | Медиа (геоблок) | Spotify и др. — блокируют РФ | ⬜ |
| `rkn_other` | Прочее РКН | Казино-зеркала, фишинг, прочее (без точной категории)¹ | ✅ |

🌐 — категория геоблока (сервис сам ограничивает доступ из РФ). Пары `X` / `X_GB`: первая — заблокировано в РФ по реестру РКН, вторая — сервис сам режет РФ.

¹ `rkn_other` наполняется из готового сводного CIDR-списка (вендорный снапшот Re-filter `ipsum.lst`), а не резолвом ~71k мёртвых доменов — это держит сборку быстрой. Остальные категории резолвятся на 6 DNS (включая Яндекс) с быстрым отсевом мёртвых доменов (pre-check).

### Агрегаты

| Файл | Описание |
|---|---|
| `ipsum.lst` | Все категории, включённые по умолчанию (для одного списка splify) |
| `rkn_all.lst` | Все РКН-категории (без геоблока) |
| `geoblock_all.lst` | Все категории геоблока |

## Использование

### Индекс категорий
`lists/categories.json` — канонический манифест: `id`, `name_ru`, `description_ru`, `file`, `default_on`, `is_geoblock`, `count`. splify тянет его по raw-URL и строит переключатели в UI; включённые категории мержатся в один nft-сет.

```bash
curl -fsSL https://raw.githubusercontent.com/xyzmean/ru-bypass-ipsets/main/lists/categories.json
```

### Прямые ссылки на списки
```
https://raw.githubusercontent.com/xyzmean/ru-bypass-ipsets/main/lists/<category>.lst
```
Например: `.../lists/telegram.lst`, `.../lists/ipsum.lst`.

### Локальный запуск генератора
```bash
pip install -r generator/requirements.txt
python generator/aggregate.py            # полный прогон
SAMPLE=200 python generator/aggregate.py # проверка на 200 РКН-доменах (без gate)
```

## Структура

```
sources/     вендорные снапшоты (источник правды): services/, thematic/, rkn/, asn/
generator/   Python-пайплайн: lib, fetch_sources, resolve, asn_pull, categorize, aggregate
lists/       сгенерированные .lst + categories.json  (коммитится в main)
.github/     workflows: resolve.yml, validate.yml
```

## Лицензия
MIT. Источники доменов — из публичных списков РКН/antifilter и сообщества (itdoginfo/allow-domains, 1andrevich/Re-filter-lists), вендорены в `sources/`.
