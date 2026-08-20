# SafeNet UZ 🇺🇿

> Open-source cybersecurity ecosystem protecting Uzbekistan's digital space from phishing attacks, fake bots, and malicious Android applications (malware APK).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Aiogram 3.x](https://img.shields.io/badge/Aiogram-3.x-blueviolet.svg)](https://docs.aiogram.dev)
[![Open Source](https://img.shields.io/badge/Open%20Source-%E2%9D%A4-red.svg)](README.md#contributing)

## Mission

"SafeNet UZ" is a **crowdsourced** cyber-security initiative. Users forward suspicious links to a Telegram bot; the system analyzes them **asynchronously**, cross-checks DNS/WHOIS/GEO data, and automatically sends **Abuse Reports** to the relevant hosting providers — while publishing verified threats to global blacklists.

### How it works

```
1. Foydalanuvchi shubhali havolani botga yuboradi
        │
        ▼
2. URL normalizatsiya va parslanadi (url_parser)
        │
        ▼
3. DNS + WHOIS + GEO ma'lumotlari asinxron yig'iladi (httpx, dnspython, python-whois)
        │
        ▼
4. Reputatsiya bali hisoblanadi → verdict (XAVFLI / SHUBHALI / XAVFSIZ)
        │
        ▼
5. XAVFLI deb tasdiqlanganlar: hosting provayderga Abuse Report + global qora ro'yxat
```

### Core capabilities

| Capability | Description |
|---|---|
| 🕵️ Link analysis | Async URL phishing detection pipeline |
| 🌐 DNS & WHOIS checks | `dnspython` + `python-whois` enrichment |
| 🚨 Automatic Abuse Reports | Verified threats reported to hosting/abuse contacts |
| 📚 Global blacklists | Crowdsourced denial-of-service for phishing networks |
| 🤖 Telegram-first UX | Zero-install reporting via [Aiogram 3.x](https://docs.aiogram.dev) |
| ⚡ Async by design | Non-blocking analysis with `httpx` + `asyncio` |
| 🗄️ Fast lookups | Redis kesh (TTL) + SQLAlchemy 2.x ORM (SQLite/PostgreSQL) |
| 🔁 Mirror bots | Community Telegram bots join the network via `/addbot` and share the same analyzers + database |

## Architecture

```mermaid
flowchart LR
    U[User] -->|sends suspicious link| B[Telegram Bot<br/>Aiogram 3.x]
    B --> H[Handlers & Middlewares<br/>bot/]
    H --> A[Analyzer<br/>analyzer/]
    A --> DNS[(DNS Lookup<br/>dnspython)]
    A --> WHOIS[(WHOIS Registry<br/>python-whois)]
    A --> HP[HTTP Probing<br/>httpx]
    A -->|verdict| B
    B -->|report| UA[Hosting Provider<br/>Abuse Report]
    A -->|verified threat| BL[(Global Blacklist)]
    C[core/ Settings<br/>pydantic-settings] -.-> B
    C -.-> A
```

### Folder structure

```
safenetuz/
├── .github/workflows/ci.yml   # CI pipeline
├── assets/logo.jpg             # Bot profile logo (png/jpg/jpeg qabul qilinadi, kvadratga aylantiriladi)
├── bot/
│   ├── handlers/              # Telegram message handlers (+ /addbot mirror flow)
│   ├── middlewares/           # Bot middlewares
│   └── main.py                # Async entry point
├── analyzer/
│   ├── analysis.py          # Shared analysis orchestration + verdict logic
│   ├── external_apis.py     # VirusTotal / URLhaus / Google Safe Browsing
│   ├── pipeline.py          # Kesh → DB → External → saqlash konveyeri
│   ├── url_parser.py        # URL normalization & parsing
│   └── whois_checker.py     # WHOIS enrichment
├── core/
│   ├── config.py              # Typed, validated settings
│   └── mirror_manager.py      # Mirror bot validation, branding & runtime
├── database/
│   ├── models.py              # SQLAlchemy 2.x ORM: ThreatURL, ThreatAPK, MirrorBot, Analysis
│   ├── session.py             # Async engine/session (SQLite yoki PostgreSQL)
│   └── cache.py               # Redis kesh (TTL: clean 24h, malicious 30d)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

## Tech stack

- **Python 3.11+**
- **Aiogram 3.x** — Telegram Bot API
- **httpx** — async HTTP probing
- **dnspython** & **python-whois** — DNS/WHOIS enrichment
- **SQLAlchemy 2.x** — async ORM (SQLite via `aiosqlite`, PostgreSQL via `asyncpg`)
- **Redis** — kesh (natsangi natijalar uchun TTL)
- **pydantic** & **pydantic-settings** — safe, validated configuration
- **Docker & Docker Compose** — containerized deployment

## Getting started

### 1. Clone & configure

```bash
git clone git@github.com:<your-username>/SafeNet-UZ.git
cd SafeNet-UZ

python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
```

Then fill `.env` with your bot token (from [@BotFather](https://t.me/BotFather)):

```
BOT_TOKEN=1234567890:AAE...
LOG_LEVEL=INFO
VIRUSTOTAL_API_KEY=
URLHAUS_API_KEY=
GOOGLE_SAFEBROWSING_API_KEY=

# Ma'lumotlar bazasi (SQLite default; Postgres uchun boshqa DSN)
DATABASE_URL=sqlite+aiosqlite:///data/safenetuz.db
# DATABASE_URL=postgresql+asyncpg://safenetuz:safenetuz@localhost:5432/safenetuz

# Redis kesh (TTL: clean 24 soat, malicious 30 kun)
REDIS_URL=redis://localhost:6379/0
CACHE_TTL_CLEAN=86400
CACHE_TTL_MALICIOUS=2592000
```

> `bot_token` is required and stored as a `SecretStr` — it is never logged or exposed.
> All threat-intelligence keys are **optional**: without them the bot gracefully skips those checks (`status: skipped`) instead of failing.

### Data layer & analysis pipeline

Every URL goes through a fast, layered pipeline in `analyzer/pipeline.py`, precisely in this order:

```
1. Redis kesh (url_hash={sha256}) → bir xil natija tez qaytariladi (TTL: clean 24h / malicious 30d)
        │ (miss)
        ▼
2. SQLAlchemy DB (threat_urls jadvali) → avvalgi tahlil bor bo'lsa qaytariladi (kesh yangilanadi)
        │ (miss)
        ▼
3. Tashqi API'lar (VirusTotal, URLhaus, Google Safe Browsing) + static parser (url_parser)
        │
        ▼
4. Natija DB + Redis ga saqlanadi va qaytariladi
```

`ThreatURL` modeli: `url_hash` (SHA-256, indexed), `original_url`, `domain`, `status` (`malicious`/`clean`), `threat_type` (`phishing`/`malware`/`bot`), `source` (`user_report`/`external_api`). APK fayllari uchun `ThreatAPK` (`file_hash`, `file_name`, `package_name`, `status`, `malicious_score`) mavjud. Kesh/DB andozilari halokatli emas — tashqi xizmatlar ishlamasa ham tahlil davom etadi.

### Mirror bots (`/addbot`)

Any Telegram bot owner can expand the SafeNet UZ network. From the main bot, send `/addbot` and paste a token from [@BotFather](https://t.me/BotFather). `MirrorManager` will:

1. Validate the token via `get_me()`.
2. Set SafeNet UZ branding: commands, description, short description and `assets/logo.{png,jpg,jpeg}` as profile photo (any format is auto-cropped to a square 640×640 via Pillow).
3. Register the bot for **dynamic polling** (default) or a **webhook** when `MIRROR_WEBHOOK_DOMAIN` is configured (`https://<domain>/webhook/mirror/<token>`).
4. Persist an entry in the shared SQLAlchemy database (`token` is stored **hashed** only).

Every message received by a mirror bot is routed through the same `start` / `mirror` / `analyze` routers, so reports are analyzed identically and recorded in the **single shared database** with the main bot.

### Group auto-moderation (`group_guard`)

In groups and supergroups the bot stays **silent on clean traffic** but watches every message for URL links, `.apk` documents, or Telegram bot/channel mentions (`@user`, `t.me/...`). Suspicious content is analyzed **in a background task** (never blocking the group):

1. A URL is checked against VirusTotal, URLhaus and Google Safe Browsing.
2. If the verdict is **dangerous** (`malicious` / blacklisted / flagged):
   - the message is deleted immediately,
   - a phishing warning is posted with the sender's name,
   - the warning is auto-deleted after `GROUP_GUARD_WARNING_TTL` seconds (default `15`).
3. `.apk` files are moderated by policy (`GROUP_GUARD_BLOCK_APK`, default `true`) since executable drops in open groups are a primary malware vector.

Requires the bot to be a group **administrator** with *Delete messages* permission.

### Threat intelligence sources

| Service | Key | Detects |
|---|---|---|
| [VirusTotal v3](https://docs.virustotal.com) | Free (VT account) | Malicious / suspicious / harmless engine votes |
| [URLhaus](https://urlhaus-api.abuse.ch/) | Free ([auth.abuse.ch](https://auth.abuse.ch/), `Auth-Key` header) | Active malware distribution URLs |
| [Google Safe Browsing v4](https://developers.google.com/safe-browsing/v4) | Free (Google Cloud Console) | `MALWARE`, `SOCIAL_ENGINEERING`, `UNWANTED_SOFTWARE` |

### 2. Run locally

```bash
python -m bot.main
```

> `bot_token` is required and stored as a `SecretStr` — it is never logged or exposed.

### 3. Run with Docker

```bash
docker compose up -d --build
docker compose logs -f bot
```

Redis compose servisi bilan birga ishga tushadi. PostgreSQL faqat `full` profilda:

```bash
docker compose --profile full up -d
```

Keyin `.env` da:

```
DATABASE_URL=postgresql+asyncpg://safenetuz:safenetuz@db:5432/safenetuz
REDIS_URL=redis://redis:6379/0
```

### 4. Verify the pipeline

Start the bot, open your chat, and send `/start` followed by a test URL. The reporting flow returns a structured analysis verdict.

## Contributing

We welcome contributors of all levels.

1. **Fork** the repository and create a feature branch:
   ```bash
   git checkout -b feat/your-feature
   ```
2. **Keep it clean**: follow the existing module layout; all package imports must be import-safe (see CI).
3. **Commit** with a descriptive message and open a **Pull Request** against `main`.

### Development guidelines

- Python 3.11+, type hints required for all public functions.
- Secrets must never reach code, logs, or commits.
- Add a test case for every new analyzer rule.
- Run `python -m compileall -q bot analyzer core database` before pushing.

### Testing

The test-suite uses `pytest` + `pytest-asyncio` and runs **without any network or real API keys** (httpx `MockTransport` + fakes):

```bash
pip install -r requirements-dev.txt
python -m pytest -v
```

Coverage: config loading, URL parsing, WHOIS (mocked), all `ExternalAPIService` branches (skipped / done / http / network / parse errors), report formatting, verdict logic, Telegram handlers, SQLAlchemy models (`ThreatURL`/`ThreatAPK`), the analysis pipeline (kesh → DB → external → save order) and the Redis cache (via `fakeredis`).

## Security policy

### Reporting a vulnerability

Found a security issue? **Do not open a public issue.**

- Email: `security@safenet.uz`
- Scope: bot source code, analyzer logic, abuse-report pipeline, CI/CD.

We commit to acknowledging reports within **48 hours** and releasing fixes as part of the next patch release. Cheerful disclosure is part of the culture here. 🙏

### Threat intelligence safety

- All source URLs are **sanitized** before any outbound request.
- Abuse Reports are only sent for **verified** threats.
- Crowdsourced blacklist entries are reviewed before publication.

## License

Distributed under the **MIT License**. See [LICENSE](LICENSE).

---

**SafeNet UZ** — protecting Uzbekistan's digital space, together. 🇺🇿