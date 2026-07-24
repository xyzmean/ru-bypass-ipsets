# lists/

Сгенерированные ipset-списки. Эта директория наполняется автоматически
GitHub Actions (`.github/workflows/resolve.yml`) — раз в 3 дня, по push в
`sources/`/`generator/` или вручную (`workflow_dispatch`).

Первый прогон создаёт:
- `<category>.lst` — по одному файлу на категорию (см. `categories.json`)
- `categories.json` — индекс с русскими названиями/описаниями
- `ipsum.lst` / `rkn_all.lst` / `geoblock_all.lst` — агрегаты

Каждая строка `.lst` — `A.B.C.D/N` (IPv4 CIDR, префикс обязателен).
