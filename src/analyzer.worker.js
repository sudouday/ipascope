self.IPAS = self.IPAS || {};

let workerReady = false;
let workerLoadError = null;

try {
    importScripts(
        '../lib/jszip.min.js?v=20260530',
        'core/macho.js?v=20260530',
        'core/plist.js?v=20260530',
        'core/provisioning.js?v=20260530',
        'core/entropy.js?v=20260530',
        'core/rules.js?v=20260530',
        'core/ats.js?v=20260530',
        'core/analyzer.js?v=20260530'
    );
    if (self.IPAS && self.IPAS.Analyzer && typeof self.IPAS.Analyzer.analyzeIPA === 'function') {
        workerReady = true;
    } else {
        workerLoadError = 'IPAS.Analyzer.analyzeIPA not registered after importScripts';
    }
} catch (e) {
    workerLoadError = 'Worker importScripts failed: ' + (e && e.message || e);
}

if (!workerReady) {
    self.postMessage({ type: 'fatal', data: { error: workerLoadError || 'Worker did not initialize' } });
}

function post(type, data) {
    self.postMessage({ type, data });
}

self.onmessage = async (e) => {
    const msg = e.data;
    if (!msg || !msg.type) return;
    if (!workerReady) {
        post('fatal', { error: workerLoadError || 'Worker did not initialize' });
        return;
    }
    if (msg.type === 'analyze') {
        try {
            const result = await self.IPAS.Analyzer.analyzeIPA(msg.buffer, msg.fileMeta, {
                progress: (kind, payload) => post(kind, payload),
                dedupeOpts: msg.dedupeOpts || {},
            });
            const safe = sanitizeForTransfer(result);
            post('result', safe);
        } catch (err) {
            post('error', { message: err && err.message || String(err), stack: err && err.stack });
        }
    } else if (msg.type === 'ping') {
        post('pong', { ok: true });
    }
};

function sanitizeForTransfer(obj) {
    const seen = new WeakSet();
    function walk(v) {
        if (v == null || typeof v !== 'object') return v;
        if (seen.has(v)) return undefined;
        if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) return undefined;
        seen.add(v);
        if (Array.isArray(v)) return v.map(walk);
        const out = {};
        for (const k of Object.keys(v)) {
            out[k] = walk(v[k]);
        }
        return out;
    }
    return walk(obj);
}
