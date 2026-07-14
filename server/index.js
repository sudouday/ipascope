'use strict';

/**
 * IPAScope share-report backend.
 *
 * Deliberately zero npm dependencies — just Node's http module — so it can be
 * dropped onto any host that runs Node with no `npm install` step, matching
 * the "don't need 1,200 packages to render a button" ethos of the frontend.
 *
 * What it does, and only this:
 *   - accepts a scan report (JSON) a user explicitly chooses to share
 *   - stores it under a random, unguessable id
 *   - serves it back at GET /api/reports/:id so a link can be shared
 *   - auto-expires it after TTL_DAYS (default 30)
 *   - lets the creator delete it early with the one-time delete token
 *
 * The frontend remains 100% client-side by default. This server is only
 * contacted if the user explicitly clicks "Share Report" and API_BASE is
 * configured in src/core/config.js. Nothing is sent here otherwise.
 */

const http = require('http');
const store = require('./store');

const PORT = parseInt(process.env.PORT || '8787', 10);
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const MAX_BODY_BYTES = parseInt(process.env.MAX_BODY_BYTES || String(2 * 1024 * 1024), 10); // 2MB
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || '20', 10); // requests
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || String(60 * 60 * 1000), 10); // 1h

// --- tiny in-memory rate limiter (per-IP, POST only) ---------------------
const hits = new Map(); // ip -> [timestamps]
function isRateLimited(ip) {
    const now = Date.now();
    const arr = (hits.get(ip) || []).filter(t => now - t < RATE_LIMIT_WINDOW_MS);
    arr.push(now);
    hits.set(ip, arr);
    return arr.length > RATE_LIMIT_MAX;
}
setInterval(() => {
    const now = Date.now();
    for (const [ip, arr] of hits) {
        const fresh = arr.filter(t => now - t < RATE_LIMIT_WINDOW_MS);
        if (fresh.length === 0) hits.delete(ip); else hits.set(ip, fresh);
    }
}, 10 * 60 * 1000).unref();

// --- periodic cleanup of expired reports ---------------------------------
store.cleanupExpired().catch(err => console.error('cleanup failed:', err.message));
setInterval(() => {
    store.cleanupExpired().catch(err => console.error('cleanup failed:', err.message));
}, 60 * 60 * 1000).unref();

function send(res, status, body, extraHeaders) {
    const payload = typeof body === 'string' ? body : JSON.stringify(body);
    res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': Buffer.byteLength(payload),
        'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
        'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        ...extraHeaders,
    });
    res.end(payload);
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        const declaredLen = parseInt(req.headers['content-length'] || '0', 10);
        if (declaredLen > MAX_BODY_BYTES) {
            // Reject before reading anything — cheapest way to bail on a body
            // that's already too large per its own Content-Length header.
            reject(Object.assign(new Error('payload too large'), { code: 'TOO_LARGE' }));
            req.resume(); // drain so the socket doesn't hang
            return;
        }
        let size = 0;
        let tooLarge = false;
        const chunks = [];
        req.on('data', (chunk) => {
            if (tooLarge) return;
            size += chunk.length;
            if (size > MAX_BODY_BYTES) {
                // Don't destroy the socket here — that would tear down the
                // response side too, and the client would only ever see a
                // dangling "100 Continue" with no final status. Just stop
                // buffering and let the stream drain to 'end' below.
                tooLarge = true;
                return;
            }
            chunks.push(chunk);
        });
        req.on('end', () => {
            if (tooLarge) {
                reject(Object.assign(new Error('payload too large'), { code: 'TOO_LARGE' }));
            } else {
                resolve(Buffer.concat(chunks).toString('utf8'));
            }
        });
        req.on('error', reject);
    });
}

function clientIp(req) {
    const fwd = req.headers['x-forwarded-for'];
    if (fwd) return fwd.split(',')[0].trim();
    return req.socket.remoteAddress || 'unknown';
}

const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const parts = url.pathname.split('/').filter(Boolean);

    if (req.method === 'OPTIONS') {
        return send(res, 204, '');
    }

    if (req.method === 'GET' && parts.length === 1 && parts[0] === 'health') {
        return send(res, 200, { status: 'ok' });
    }

    if (parts[0] === 'api' && parts[1] === 'reports') {
        // POST /api/reports
        if (req.method === 'POST' && parts.length === 2) {
            const ip = clientIp(req);
            if (isRateLimited(ip)) {
                return send(res, 429, { error: 'rate_limited', message: 'Too many reports shared from this address recently. Try again later.' });
            }
            let raw;
            try {
                raw = await readBody(req);
            } catch (e) {
                if (e.code === 'TOO_LARGE') return send(res, 413, { error: 'payload_too_large' });
                return send(res, 400, { error: 'bad_request' });
            }
            let report;
            try {
                report = JSON.parse(raw);
            } catch (_) {
                return send(res, 400, { error: 'invalid_json' });
            }
            const { id, deleteToken, expiresAt } = await store.create(report);
            return send(res, 201, { id, deleteToken, expiresAt });
        }

        // GET /api/reports/:id
        if (req.method === 'GET' && parts.length === 3) {
            let record;
            try {
                record = await store.get(parts[2]);
            } catch (_) {
                return send(res, 400, { error: 'invalid_id' });
            }
            if (!record) return send(res, 404, { error: 'not_found' });
            return send(res, 200, { report: record.report, createdAt: record.createdAt, expiresAt: record.expiresAt });
        }

        // DELETE /api/reports/:id  (body: { deleteToken })
        if (req.method === 'DELETE' && parts.length === 3) {
            let raw;
            try {
                raw = await readBody(req);
            } catch (_) {
                return send(res, 400, { error: 'bad_request' });
            }
            let body = {};
            try { body = raw ? JSON.parse(raw) : {}; } catch (_) { /* ignore, treat as no token */ }
            let result;
            try {
                result = await store.remove(parts[2], body.deleteToken);
            } catch (_) {
                return send(res, 400, { error: 'invalid_id' });
            }
            if (!result.ok) {
                const status = result.reason === 'not_found' ? 404 : 403;
                return send(res, status, { error: result.reason });
            }
            return send(res, 200, { deleted: true });
        }
    }

    send(res, 404, { error: 'not_found' });
});

server.listen(PORT, () => {
    console.log(`IPAScope share backend listening on :${PORT}`);
    console.log(`Data dir: ${store.DATA_DIR}  |  TTL: ${store.TTL_DAYS} days  |  Allowed origin: ${ALLOWED_ORIGIN}`);
});
