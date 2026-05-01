# Jan Kaam Backend (Node + Express + MongoDB Atlas)

Minimal auth + login-event logging API.

## Endpoints

| Method | Path                  | Auth | Purpose                                  |
|--------|-----------------------|------|------------------------------------------|
| POST   | `/api/auth/signup`    | —    | Create user (phone + password)           |
| POST   | `/api/auth/login`     | —    | Login, returns JWT, logs a login event   |
| GET    | `/api/auth/me`        | JWT  | Current user                             |
| GET    | `/api/login-events`   | JWT  | List your login events (admin: all)      |
| GET    | `/healthz`            | —    | Health check                             |

## Login event fields captured

`userId, phone, success, reason, ip, userAgent, browser, os, device, country, region, city, language, referrer, createdAt`

(Geo fields are placeholders — wire MaxMind/ipinfo if you want city/country.)

## Run locally

```bash
cp .env.example .env   # then edit .env
npm install
npm run dev
```

## Deploy

Works on Render, Railway, Fly.io, or any Node host.
1. Push this folder to a Git repo.
2. Create a new Web Service, point it at the repo.
3. Set env vars from `.env.example` in the host's dashboard (NOT in code).
4. Build cmd: `npm install`  · Start cmd: `npm start`.
5. Whitelist the host's outbound IPs in MongoDB Atlas (Network Access).

## Wire your Lovable frontend

Set `VITE_API_BASE_URL=https://your-backend.example.com` and call:

```ts
await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/auth/login`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ phone, password }),
});
```

## Security notes

- Passwords hashed with bcrypt (cost 12).
- JWT in `Authorization: Bearer <token>`. Consider httpOnly cookies for production.
- Rate-limited: 10 login attempts / 15 min / IP.
- Helmet + strict CORS allowlist.
- Never log password values. Failed logins record `reason` only.
