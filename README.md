# rymory-gateway

> **Author:** Onur Yaşar ([@onxorg](https://github.com/onxorg))
> **Part of:** [Rymory](https://rymory.org) — Open Identity Infrastructure
> © 2017–2026 Onur Yaşar. All rights reserved.

---

## What is rymory-gateway?

rymory-gateway is the edge layer of the Rymory identity infrastructure. It sits between your applications and the identity backend, handling:

- **Token management** — secure HMAC-signed cookie wrapping, token validation and renewal
- **Authentication intercept** — transparently captures login responses, wraps JWT into secure HttpOnly cookies
- **Rate limiting** — per-IP and per-token fixed-window rate limiting via Cloudflare KV
- **CORS enforcement** — origin validation against allowed application domains
- **Reverse proxy** — routes requests to the correct backend service (security, system, file)
- **Logout** — cookie invalidation across all subdomains

Two implementations are provided:

| File | Runtime | Description |
|---|---|---|
| `main.go` | Go / Docker | Self-hosted reverse proxy |
| `cloudflare-worker.js` | Cloudflare Workers | Edge-deployed proxy |

---

## Architecture

```
Browser
  │
  ▼
rymory-gateway  (this repo)
  ├── /security/*   → identity backend (authenticate, account, role)
  ├── /system/*     → system backend (project, member)
  ├── /file/*       → file storage backend
  └── /api/logout   → cookie invalidation
```

The gateway never exposes raw JWT tokens to the browser. All tokens are wrapped in HMAC-signed, HttpOnly, Secure cookies scoped to the root domain.

---

## Configuration

Copy `.env.example` to `.env` and fill in:

```env
MAIN_DOMAIN=yourdomain.com
RATE_SECRET_KEY=your-hmac-secret
SERVICE_TARGET_URL=https://your-service-backend
SECURITY_TARGET_URL=https://your-security-backend
SYSTEM_TARGET_URL=https://your-system-backend
FILE_TARGET_URL=https://your-file-backend
```

For Cloudflare Workers, set these as Worker secrets via `wrangler secret put`.

---

## Running (Go / Docker)

```bash
git clone https://github.com/rymory/rymory-gateway.git
cd rymory-gateway
cp .env.example .env
# edit .env
docker-compose up -d
```

---

## Cloudflare Workers Deployment

```bash
npm install -g wrangler
wrangler login
wrangler secret put RATE_SECRET_KEY
wrangler secret put MAIN_DOMAIN
wrangler deploy cloudflare-worker.js
```

---

## Security Model

- JWT tokens are **never stored in localStorage** — HttpOnly cookies only
- Tokens are **HMAC-SHA256 wrapped** before being set as cookies
- Raw JWT is replaced with a **non-sensitive fake token** in API responses to prevent client-side token theft
- Rate limiting is enforced at the edge before requests reach the backend
- All cookies are `Secure`, `HttpOnly`, `SameSite=Lax`

---

## License

Licensed under **GNU AGPL v3** with Commercial Exception.
See [LICENSE.txt](./LICENSE.txt) for full terms.

Commercial licensing: onxorg@proton.me

---

## Part of Rymory

```
rymory-gateway    ← you are here (edge proxy)
rymory-core       ← identity backend (Go)
rymory-spec       ← protocol specification
```

→ [rymory.org](https://rymory.org)
