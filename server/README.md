# IPAScope share backend

Optional. The frontend is 100% client-side by default — nothing leaves the
tab unless you deploy this and someone clicks **Share Report**. This exists
for exactly one job: turn a scan result into a link someone else can open.

Zero npm dependencies. Just Node's built-in `http` and `fs` modules — no
`npm install`, no `node_modules`, no build step. Consistent with the rest of
this project: a static analyzer shouldn't need a framework to serve JSON.

## Run it locally

```bash
cd server
node index.js
# IPAScope share backend listening on :8787
```

That's it. Reports are stored as flat JSON files under `server/data/`.

## Configure the frontend to use it

Edit `src/core/config.js`:

```js
export const API_BASE = 'http://localhost:8787'; // or your deployed URL
```

Leave it as `''` (the default) to keep Share disabled and the app fully offline.

## Environment variables

| Variable              | Default              | Meaning                                          |
|------------------------|----------------------|---------------------------------------------------|
| `PORT`                 | `8787`                | Port to listen on                                  |
| `DATA_DIR`             | `server/data`         | Where report JSON files are stored                 |
| `TTL_DAYS`             | `30`                  | Auto-delete reports after this many days           |
| `ALLOWED_ORIGIN`       | `*`                   | CORS origin allowed to call this API               |
| `MAX_BODY_BYTES`       | `2097152` (2MB)       | Max size of a shared report                        |
| `RATE_LIMIT_MAX`       | `20`                  | Max POSTs per IP per window                        |
| `RATE_LIMIT_WINDOW_MS` | `3600000` (1h)        | Rate limit window                                  |

Set `ALLOWED_ORIGIN` to your actual frontend origin (e.g. `https://ipascope.com`)
before deploying publicly — the `*` default is fine for local testing only.

## API

- `POST /api/reports` — body: the report JSON. Returns `{ id, deleteToken, expiresAt }`.
  `deleteToken` is shown once, at creation — save it if you want to delete the
  share later. The server only stores a hash of it, not the token itself.
- `GET /api/reports/:id` — returns `{ report, createdAt, expiresAt }`, or `404`
  if missing/expired.
- `DELETE /api/reports/:id` — body: `{ deleteToken }`. Returns `403` on a bad
  token, `404` if already gone.
- `GET /health` — `{ status: "ok" }`.

## Deploying

Any host that runs a Node process works — this deliberately avoids anything
platform-specific. A few common options:

- **A small VPS**: `node server/index.js` behind a process manager (`pm2`,
  a systemd unit, or just `nohup`) and a reverse proxy (nginx/Caddy) for TLS.
- **Render / Railway / Fly.io**: point them at the `server/` folder, start
  command `node index.js`. Set `DATA_DIR` to a persistent volume if the
  platform's filesystem isn't durable across deploys (most free tiers aren't —
  check before relying on it for anything you care about keeping).
- **Anything with a persistent disk + a way to run `node`.** There's nothing
  here that requires a specific provider.

Since you're still deciding on hosting for the static site, this can live on
a completely different host than `ipascope.com` — it only needs to be
reachable over HTTPS from wherever the frontend is served, and to have
`ALLOWED_ORIGIN` set to match.

## What this does NOT do

- No accounts, no auth beyond the per-report delete token.
- No database — flat files. Fine for shared scan reports (small, write-once,
  read-occasionally); revisit if you add features that need querying/indexing.
- No analytics on who viewed a shared report.
- Does not change how scanning works — the `.ipa` itself is never uploaded,
  only the JSON *result* of a scan you already ran locally, and only when you
  click Share.
