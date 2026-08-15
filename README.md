# ru-bypass-ipsets

Категоризованные IPv4 ipset-списки для обхода блокировок (РФ). Резолвит домены в CIDR по категориям и публикует готовые `.lst` для маршрутизации трафика в VPN/прокси.

Основной потребитель — [splify](https://github.com/xyzmean/splify) (OpenWrt). Формат совместим с `clean_ip_list`: строго `A.B.C.D/N`, без голых IP.

## Принцип

1. **Источники** — вендорные снапшоты в репо + надёжные онлайн-API (`antifilter.download`, RIPEstat, Cloudflare/AWS CDN). Единственное обращение к чужому репозиторию — готовый ipset Discord (`1andrevich/Re-filter-lists`), и у него есть снапшот в `sources/discord/`: недоступный источник не обнуляет список, а откатывает его к последней удачной загрузке.
2. **Резолв** — `dnspython` по 6 nameservers (включая Яндекс 77.88.8.8), объединение A-записей от всех резолверов для максимального покрытия CDN.
3. **ASN-pull** — для крупных сервисов (Telegram, Meta, …) CIDR берутся напрямую по ASN (RIPEstat → ip.guide → bgpview) и из CDN-фидов (Cloudflare, CloudFront).
4. **Склейка** — `collapse_addresses()` схлопывает перекрытия и смежные сети в максимально крупные подсети; дедуп + сортировка.
5. **Обновление** — GitHub Actions раз в 3 дня + по push + вручную.

## Категории

| Категория | Русское название | Описание | Префиксов | По умолч. |
|---|---|---|---:|:--:|
| `telegram` | Telegram | Мессенджер Telegram: домены и подсети по ASN. | 8 | ✅ |
| `whatsapp` | WhatsApp | Мессенджер WhatsApp (Meta). | 33 | ✅ |
| `discord` | Discord | Голосовой чат Discord: готовый ipset внешнего списка, без вычитаний. | 460 | ✅ |
| `meta` | Meta (Facebook/Instagram) | Соцсети Facebook и Instagram (без WhatsApp). | 33 | ✅ |
| `twitter_x` | Twitter / X | Микроблоги Twitter и X. | 13 | ✅ |
| `youtube` | YouTube | Видеохостинг YouTube и CDN (Google Video). | 58 | ✅ |
| `google` | Google (Meet/Play/AI) | Google Meet, Play и AI-сервисы (Bard/Gemini). | 58 | ✅ |
| `tiktok` | TikTok | Короткие видео TikTok (ByteDance). | 8 | ✅ |
| `roblox` | Roblox | Игровая платформа Roblox. | 4 | ⬜ |
| `netflix` 🌐 | Netflix | Видеостриминг Netflix (геоблокирует РФ). | 30 | ⬜ |
| `cloudflare` | Cloudflare CDN | Все подсети Cloudflare: официальный фид ips-v4 плюс анонсы AS13335. | 340 | ⬜ |
| `cloudfront` | AWS CloudFront | CDN Amazon CloudFront (официальный фид ip-ranges). | 180 | ⬜ |
| `akamai` | Akamai CDN | Подсети Akamai по ASN 20940. | 119 | ⬜ |
| `fastly` | Fastly CDN | Подсети Fastly по ASN 54113. Обратный прокси: за адресом тысячи сайтов. | 111 | ⬜ |
| `ddos_guard` | DDoS-Guard | Подсети DDoS-Guard по ASN 57724. Обратный прокси, много российских сайтов. | 18 | ⬜ |
| `qrator` | Qrator | Подсети Qrator по ASN 197068. Обратный прокси. | 6 | ⬜ |
| `gcore` | Gcore CDN | Подсети Gcore по ASN 199524. | 326 | ⬜ |
| `bunny` | Bunny CDN | Подсети Bunny по ASN 200325. | 11 | ⬜ |
| `sucuri` | Sucuri | Подсети Sucuri по ASN 30148. Обратный прокси с защитой сайтов. | 11 | ⬜ |
| `imperva` | Imperva | Подсети Imperva (Incapsula) по ASN 19551. Обратный прокси. | 202 | ⬜ |
| `hetzner` | Hetzner | Хостинг Hetzner по ASN 24940. | 80 | ⬜ |
| `ovh` | OVH | Хостинг OVH по ASN 16276. | 619 | ⬜ |
| `digitalocean` | DigitalOcean | Хостинг DigitalOcean по ASN 14061. | 167 | ⬜ |
| `aws` | Amazon AWS | Подсети Amazon AWS по ASN 16509 (без CloudFront — он отдельно). | 5691 | ⬜ |
| `rkn` | Заблокированное в РФ | Единый реестр заблокированного в РФ: тематика РКН и прочие ресурсы из снапшота. | 11923 | ✅ |
| `geoblock` 🌐 | Геоблок (сервисы, режущие РФ) | Зарубежные сервисы, сами закрывающие доступ из РФ: AI, СМИ, стриминг, dev-инструменты. | 494 | ⬜ |

🌐 — геоблок: сервис сам ограничивает доступ из РФ, а не заблокирован в РФ. Это разные решения человека, поэтому и списка два: `rkn` обходит блокировку, `geoblock` прячет страну.

Раньше признак геоблока задваивал КАЖДУЮ тематику: рядом со `streaming` стоял `streaming_GB`, рядом с `adult` — `adult_GB`, и так восемь пар. Данных за этим не было — `adult_GB` не имел ни одного уникального префикса из 126, `social_GB` — ни одного из 22. Все старые имена ведут на новые через `aliases` в манифесте, см. «Переименование списков» ниже.

`rkn` наполняется из двух источников сразу: готовый сводный CIDR-список (вендорный снапшот Re-filter `ipsum.lst`) плюс резолв доменов, подошедших под тематические правила. Домены реестра без правила не резолвятся — они уже покрыты снапшотом по адресам, и гонять по ним DNS значило бы платить за то, что есть. Остальные категории резолвятся на 6 DNS (включая Яндекс) с быстрым отсевом мёртвых доменов (pre-check).

`discord` — исключение из всего конвейера: это готовый ipset [Re-filter-lists](https://github.com/1andrevich/Re-filter-lists), взятый как есть. По нему НЕ гоняются ни вычитание инфраструктуры, ни вычитание общих обратных прокси, поэтому в нём остаётся то, что в остальных списках вырезается, — в частности `104.16.0.0/12` (1 048 576 адресов Cloudflare).

### Переименование списков

Семнадцать категорий свёрнуты в две (`rkn`, `geoblock`), файлы старых имён из публикации убраны. Чтобы уже настроенные роутеры не остались с замершими списками, манифест несёт карту `aliases` вида `{"from": "rkn_other.lst", "to": "rkn.lst"}` — 18 записей. Потребитель (splify2) по ней качает новый список по прежнему пути и говорит об этом в журнале. Без карты переименование выглядело бы как «нет в манифесте, пропущен»: файл остаётся последней скачанной копией и перестаёт обновляться навсегда, без признака ошибки.

### Агрегаты

| Файл | Описание | Префиксов |
|---|---|---:|
| `rkn_all.lst` | Объединение всех категорий, заблокированных в РФ, без геоблока и без инфраструктуры. | 11883 |
| `ipsum.lst` | Все категории, включённые по умолчанию (для совместимости с одним списком splify). | 11883 |
| `all.lst` | Полный объединяющий список: все категории РКН и геоблока вместе (без инфраструктуры — она в hodca). | 12172 |
| `hodca.lst` | Объединение всех провайдеров: Cloudflare, CloudFront, Akamai, Hetzner, OVH, DigitalOcean, AWS. | 6501 |

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
