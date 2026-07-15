(function () {
'use strict';

const IPAS = window.IPAS = window.IPAS || {};
const $  = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => Array.from(el.querySelectorAll(sel));

const State = {
    currentResults: null,
    currentFile: null,
    viewerZip: null,
    activeSeverityFilter: new Set(['high', 'warning', 'info', 'secure']),
    findingsSearch: '',
    findingsSort: 'severity',
    findingsMinConfidence: 0,
    findingsPage: 0,
    findingsPerPage: 50,
    worker: null,
    workerFailed: false,
    explorerFiles: [],
    explorerTree: null,
    currentOpenFile: null,
    binaryView: null,
};

function esc(text) {
    if (text == null) return '';
    const d = document.createElement('div');
    d.textContent = String(text);
    return d.innerHTML;
}
function escAttr(t) {
    return String(t ?? '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function html(strings, ...values) {
    let out = '';
    strings.forEach((s, i) => {
        out += s;
        if (i < values.length) {
            const v = values[i];
            if (v == null) out += '';
            else if (typeof v === 'object' && v.__raw) out += v.html;
            else if (Array.isArray(v)) out += v.map(x => (x && x.__raw) ? x.html : esc(x)).join('');
            else out += esc(v);
        }
    });
    return { __raw: true, html: out, toString() { return out; } };
}
const raw = (s) => ({ __raw: true, html: typeof s === 'string' ? s : String(s) });

// Display labels for the internal severity keys (high/warning/info/secure).
// Only the shown text changes; the underlying keys stay the same so filtering,
// grouping, scoring and exports are unaffected.
const SEV_LABEL = { high: 'High', warning: 'Medium', info: 'Low', secure: 'Info' };

function fmtSize(b) {
    if (b == null) return '?';
    const u = ['B','KB','MB','GB'];
    let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return b.toFixed(b < 10 && i > 0 ? 2 : 1) + ' ' + u[i];
}
function toast(message, type, duration) {
    const c = document.getElementById('toastContainer') || (() => {
        const d = document.createElement('div');
        d.id = 'toastContainer'; d.className = 'toast-container';
        document.body.appendChild(d);
        return d;
    })();
    const t = document.createElement('div');
    t.className = 'toast ' + (type || 'info');
    t.setAttribute('role', 'status');
    t.textContent = message;
    c.appendChild(t);
    setTimeout(() => t.remove(), duration || 4500);
}

function showCenterPopup(message, duration) {
    const existing = document.getElementById('centerPopup');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.className = 'center-popup-overlay';
    overlay.id = 'centerPopup';
    overlay.setAttribute('role', 'alertdialog');
    overlay.setAttribute('aria-live', 'assertive');
    overlay.innerHTML =
        '<div class="center-popup">' +
            '<div class="center-popup-head">' +
                '<span class="scan-console-dot"></span>' +
                '<span class="scan-console-dot"></span>' +
                '<span class="scan-console-dot"></span>' +
                '<span class="center-popup-title">ipascope</span>' +
            '</div>' +
            '<div class="center-popup-body">' +
                '<div class="center-popup-icon" aria-hidden="true">' +
                    '<svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">' +
                        '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>' +
                        '<line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>' +
                    '</svg>' +
                '</div>' +
                '<div class="center-popup-msg"></div>' +
                '<div class="center-popup-hint">tap anywhere to dismiss</div>' +
            '</div>' +
        '</div>';
    overlay.querySelector('.center-popup-msg').textContent = message;
    document.body.appendChild(overlay);

    let closed = false;
    const dismiss = () => {
        if (closed) return;
        closed = true;
        overlay.classList.add('closing');
        setTimeout(() => overlay.remove(), 200);
    };
    overlay.addEventListener('click', dismiss);
    setTimeout(dismiss, duration || 5500);
}

function setupWorker() {
    try {
        const w = new Worker('src/analyzer.worker.js?v=20260530');
        w.addEventListener('error', (e) => {
            console.warn('Worker error:', e.message);
            State.workerFailed = true;
        });
        w.postMessage({ type: 'ping' });
        return w;
    } catch (e) {
        console.warn('Worker spawn failed - falling back to main thread:', e.message);
        State.workerFailed = true;
        return null;
    }
}

async function analyzeFile(file) {
    document.body.classList.add('analyzing');
    resetProgressLog();
    showProgress(0, 'Initializing…');
    State.currentFile = file;
    State.viewerZip = null;
    const arrayBuffer = await file.arrayBuffer();
    const fileMeta = { name: file.name, size: file.size, lastModified: file.lastModified };

    if (!State.worker) State.worker = setupWorker();

    let workerBuffer = arrayBuffer;
    if (State.worker && !State.workerFailed) {
        workerBuffer = arrayBuffer.slice(0);
    }

    return new Promise((resolve, reject) => {
        const useWorker = State.worker && !State.workerFailed;
        if (!useWorker) {
            runOnMainThread(arrayBuffer, fileMeta).then(resolve, reject);
            return;
        }
        const w = State.worker;
        const onMsg = (e) => {
            const payload = e.data || {};
            const type = payload.type;
            const data = payload.data || {};
            const topErr = payload.error || data.error;
            if (type === 'progress') {
                showProgress(data.percent || 0, data.text || '…', data);
            } else if (type === 'result') {
                w.removeEventListener('message', onMsg);
                resolve(data);
            } else if (type === 'error') {
                w.removeEventListener('message', onMsg);
                reject(new Error((data && data.message) || topErr || 'Worker error'));
            } else if (type === 'fatal') {
                console.warn('Worker fatal, falling back to main thread:', topErr);
                w.removeEventListener('message', onMsg);
                State.workerFailed = true;
                runOnMainThread(arrayBuffer, fileMeta).then(resolve, reject);
            }
        };
        w.addEventListener('message', onMsg);
        try {
            w.postMessage({ type: 'analyze', buffer: workerBuffer, fileMeta }, [workerBuffer]);
        } catch (e) {
            w.removeEventListener('message', onMsg);
            State.workerFailed = true;
            runOnMainThread(arrayBuffer, fileMeta).then(resolve, reject);
        }
    });
}

async function runOnMainThread(arrayBuffer, fileMeta) {
    return IPAS.Analyzer.analyzeIPA(arrayBuffer, fileMeta, {
        progress: (kind, payload) => {
            if (kind === 'progress') showProgress(payload.percent || 0, payload.text || '…', payload);
        },
    });
}

async function getViewerZip() {
    if (State.viewerZip) return State.viewerZip;
    if (!State.currentFile) return null;
    if (typeof JSZip === 'undefined') return null;
    const buf = await State.currentFile.arrayBuffer();
    State.viewerZip = await JSZip.loadAsync(buf);
    return State.viewerZip;
}

function nowMs() { return (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now(); }

function resetProgressLog() {
    const log = $('#progressLog');
    if (log) log.innerHTML = '';
    State._lastStage = null;
    State._logStart = nowMs();
    const pctEl = $('#progressPct');
    if (pctEl) pctEl.textContent = '0%';
    const fill = $('#progressFill');
    if (fill) fill.style.width = '0%';
}

function showProgress(pct, text, payload) {
    const overlay = $('#loadingOverlay');
    const fill = $('#progressFill');
    const pctEl = $('#progressPct');
    const log = $('#progressLog');
    if (overlay) overlay.classList.add('active');
    if (fill) fill.style.width = (pct || 0) + '%';
    if (pctEl) pctEl.textContent = Math.round(pct || 0) + '%';
    if (!log) return;

    if (State._logStart == null) State._logStart = nowMs();
    const stage = (payload && payload.stage) ? payload.stage : (text || '');
    const secs = ((nowMs() - State._logStart) / 1000).toFixed(1);
    const fileName = (payload && payload.file) ? payload.file.split('/').pop() : '';

    let active = log.querySelector('.log-line.active');

    if (stage !== State._lastStage) {
        // finalize the previous stage line
        if (active) {
            active.classList.remove('active');
            active.classList.add('done');
            const ic = active.querySelector('.log-icon');
            if (ic) ic.textContent = '✓'; // ✓
        }
        // append the new stage line
        const line = document.createElement('div');
        line.className = 'log-line active';
        line.innerHTML = '<span class="log-time"></span><span class="log-icon">▸</span>' + // ▸
                         '<span class="log-msg"></span><span class="log-file"></span>';
        line.querySelector('.log-time').textContent = secs + 's';
        line.querySelector('.log-msg').textContent = text || '…';
        log.appendChild(line);
        State._lastStage = stage;
        active = line;
        log.scrollTop = log.scrollHeight;
    } else if (active) {
        // same stage repeating (e.g. per-file scan) — update in place
        const msgEl = active.querySelector('.log-msg');
        if (msgEl) msgEl.textContent = text || '…';
    }

    if (active) {
        const fEl = active.querySelector('.log-file');
        if (fEl) fEl.textContent = fileName;
    }

    // finalize the last line on completion
    if ((pct || 0) >= 100 && active) {
        active.classList.remove('active');
        active.classList.add('done');
        const ic = active.querySelector('.log-icon');
        if (ic) ic.textContent = '✓';
    }
}
function hideProgress() {
    const o = $('#loadingOverlay');
    if (o) o.classList.remove('active');
    document.body.classList.remove('analyzing');
}

async function startAnalysis(file) {
    if (!file) return;
    if (!/\.ipa$/i.test(file.name) && !/\.zip$/i.test(file.name)) {
        showCenterPopup('That doesn’t look like a valid .ipa. Please upload an iOS .ipa file and try again.', 5500); return;
    }
    try {
        const _t0 = nowMs();
        const results = await analyzeFile(file);
        const _elapsed = nowMs() - _t0;
        // Keep the verbose console visible long enough to be seen on fast scans
        if (_elapsed < 900) await new Promise(r => setTimeout(r, 900 - _elapsed));
        hideProgress();
        State.currentResults = results;
        renderAll(results);
        showApp();
        toast('Analysis complete · Score ' + results.securityScore, 'success');
    } catch (e) {
        hideProgress();
        console.error(e);
        showCenterPopup('That doesn’t look like a valid .ipa. Please upload an iOS .ipa file and try again.', 5500);
    }
}

function showApp() {
    $('#landingContent') && ($('#landingContent').style.display = 'none');
    $('#appContainer')?.classList.add('active');
}

function showLanding() {
    $('#landingContent') && ($('#landingContent').style.display = '');
    $('#appContainer')?.classList.remove('active');
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function switchTab(name) {
    $$('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
    $$('.tab').forEach(t => t.setAttribute('aria-selected', t.dataset.tab === name ? 'true' : 'false'));
    $$('.panel').forEach(p => {
        const active = p.id === 'panel-' + name;
        p.classList.toggle('active', active);
        p.hidden = !active;
    });
}

function renderAll(r) {
    renderHeader(r);
    renderOverview(r);
    renderFindings(r);
    renderBinary(r);
    renderEntitlements(r);
    renderATS(r);
    renderExplorer(r);
    renderTrackers(r);
    updateBadges(r);
}

function renderHeader(r) {
    $('#appName').textContent = r.appInfo?.appName || 'Unknown';
    $('#bundleId').textContent = r.appInfo?.bundleId || '';
    const ic = $('#appIcon');
    if (r.appIcon) ic.innerHTML = '<img src="' + escAttr(r.appIcon) + '" alt="">';
    else ic.innerHTML = '<span aria-hidden="true" style="font-size:24px;font-weight:700;color:#fff;">' + esc((r.appInfo?.appName || '?').charAt(0).toUpperCase()) + '</span>';

    const badgesEl = $('#appBadges');
    if (badgesEl) {
        const archs = (r.machoSummary?.slices?.length
            ? r.machoSummary.slices.map(s => s.arch)
            : [r.machoSummary?.arch]).filter(Boolean);
        const ICON = {
            lang:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
            ios:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="7" y="2" width="10" height="20" rx="2"/><line x1="11" y1="18" x2="13" y2="18"/></svg>',
            cpu:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/></svg>',
            size:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>',
            xcode: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>',
            check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
        };
        const chips = [];
        if (r.binType)            chips.push(['lang', r.binType]);
        if (r.appInfo?.minOS)     chips.push(['ios', 'iOS ' + r.appInfo.minOS + '+']);
        if (archs.length)         chips.push(['cpu', archs.join(' · ')]);
        if (r.appInfo?.fileSize)  chips.push(['size', r.appInfo.fileSize]);
        if (r.appInfo?.dtXcode)   chips.push(['xcode', 'Xcode ' + r.appInfo.dtXcode]);
        let bh = chips.map(([k, label]) => html`<span class="app-badge">${raw(ICON[k])}${label}</span>`.toString()).join('');
        bh += html`<span class="app-badge status">${raw(ICON.check)}Analyzed</span>`.toString();
        badgesEl.innerHTML = bh;
    }
}
function updateBadges(r) {
    const total = r.summary.high + r.summary.warning + r.summary.info + r.summary.secure;
    const badge = $('#findingsCount');
    if (badge) {
        badge.textContent = total;
        badge.classList.toggle('zero', r.summary.high === 0 && r.summary.warning === 0);
    }
}

function renderOverview(r) {
    const high = r.summary.high, warn = r.summary.warning, info = r.summary.info, secure = r.summary.secure;
    const score = r.securityScore ?? 0;
    const scoreClass = score >= 80 ? 'good' : score >= 60 ? 'ok' : score >= 40 ? 'meh' : 'bad';

    const scoreLabel = score >= 85 ? 'Excellent' : score >= 70 ? 'Good' : score >= 50 ? 'Fair' : score >= 30 ? 'Poor' : 'Critical';
    const grade = score >= 90 ? 'A+' : score >= 80 ? 'A' : score >= 70 ? 'B' : score >= 55 ? 'C' : score >= 40 ? 'D' : 'F';
    const totalChecks = high + warn + info + secure;
    $('#overviewStats').innerHTML = html`
      <div class="score-panel score-${scoreClass}">
        <div class="score-panel-left">
          <div class="score-ring-lg" style="--score:${score}" role="img" aria-label="Security score ${score} of 100, ${scoreLabel}">
            <div class="score-ring-inner"><div class="score-num">${score}</div><div class="score-den">/ 100</div></div>
          </div>
        </div>
        <div class="score-panel-mid">
          <div class="score-grade">${grade}</div>
          <div class="score-risk">${scoreLabel} security posture</div>
          <div class="score-sub">${totalChecks} checks evaluated · trend across scans coming soon</div>
        </div>
        <div class="score-panel-right">
          <div class="risk-breakdown">
            <button class="risk-row high"    data-jumpsev="high"    aria-label="${high} high findings"><span class="risk-dot"></span><span class="risk-name">High</span><span class="risk-count">${high}</span></button>
            <button class="risk-row warning" data-jumpsev="warning" aria-label="${warn} medium findings"><span class="risk-dot"></span><span class="risk-name">Medium</span><span class="risk-count">${warn}</span></button>
            <button class="risk-row info"    data-jumpsev="info"    aria-label="${info} low findings"><span class="risk-dot"></span><span class="risk-name">Low</span><span class="risk-count">${info}</span></button>
            <button class="risk-row secure"  data-jumpsev="secure"  aria-label="${secure} informational"><span class="risk-dot"></span><span class="risk-name">Info</span><span class="risk-count">${secure}</span></button>
          </div>
        </div>
      </div>
      <div class="metric-row">
        <div class="metric-card">
          <div class="metric-ic"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg></div>
          <div class="metric-num">${(r.files || []).length}</div>
          <div class="metric-title">Files</div>
          <div class="metric-sub">inside the IPA</div>
        </div>
        <div class="metric-card">
          <div class="metric-ic"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>
          <div class="metric-num">${Object.keys(r.permissions || {}).length}</div>
          <div class="metric-title">Permissions</div>
          <div class="metric-sub">requested</div>
        </div>
        <div class="metric-card">
          <div class="metric-ic"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/></svg></div>
          <div class="metric-num">${(r.trackers || []).length}</div>
          <div class="metric-title">Trackers</div>
          <div class="metric-sub">SDKs detected</div>
        </div>
        <div class="metric-card">
          <div class="metric-ic"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg></div>
          <div class="metric-num">${(r.libraries || []).length}</div>
          <div class="metric-title">Libraries</div>
          <div class="metric-sub">linked</div>
        </div>
        <div class="metric-card">
          <div class="metric-ic"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l7 4v6c0 5-3.5 8-7 10-3.5-2-7-5-7-10V6z"/><path d="M9 12l2 2 4-4"/></svg></div>
          <div class="metric-num">${Object.keys(r.provisioning?.entitlements || {}).length}</div>
          <div class="metric-title">Entitlements</div>
          <div class="metric-sub">declared</div>
        </div>
      </div>
    `;

    $$('#overviewStats [data-jumpsev]').forEach(b => b.addEventListener('click', () => {
        State.activeSeverityFilter = new Set([b.dataset.jumpsev]);
        renderFindings(State.currentResults);
        switchTab('findings');
    }));

    const cs2 = r.machoSummary?.checksec || r.machoSummary?.slices?.[0]?.checksec || {};
    const archStr = (r.machoSummary?.slices?.length ? r.machoSummary.slices.map(s => s.arch) : [r.machoSummary?.arch]).filter(Boolean).join(' · ');
    const detailGroups = [
        ['Identity', [
            ['Bundle ID',  r.appInfo?.bundleId, true],
            ['Version',    r.appInfo?.version],
            ['Build',      r.appInfo?.build],
            ['Executable', r.appInfo?.executableName],
            ['Xcode',      r.appInfo?.dtXcode],
        ]],
        ['Platform', [
            ['Minimum iOS', r.appInfo?.minOS ? 'iOS ' + r.appInfo.minOS + '+' : null],
            ['Architecture', archStr],
            ['Language', r.binType],
            ['IPA Size', r.appInfo?.fileSize],
        ]],
    ];
    let infoHtml = '<div class="detail-groups">';
    for (const [title, rows] of detailGroups) {
        const present = rows.filter(([, v]) => v);
        if (!present.length) continue;
        infoHtml += html`<details class="detail-group" open><summary class="detail-group-head">${title}</summary><div class="detail-group-body">`;
        for (const [k, v, mono] of present) infoHtml += html`<div class="detail-row"><span class="detail-k">${k}</span><span class="detail-v ${mono ? 'mono' : ''}">${v}</span></div>`;
        infoHtml += '</div></details>';
    }
    const secChecks = [
        ['Code Signature', cs2.codeSigned, 'sec'],
        ['PIE / ASLR', cs2.pie, 'sec'],
        ['Stack Canary', cs2.stackCanary, 'sec'],
        ['ARC', cs2.arc, 'sec'],
        ['FairPlay Encryption', cs2.encryptedFairPlay, 'neutral'],
    ].filter(([, v]) => v !== undefined);
    if (secChecks.length) {
        infoHtml += html`<details class="detail-group" open><summary class="detail-group-head">Binary Security</summary><div class="detail-group-body">`;
        for (const [k, ok, kind] of secChecks) {
            const chipClass = kind === 'neutral' ? 'neutral' : (ok ? 'ok' : 'no');
            const chipText = kind === 'neutral' ? (ok ? 'Encrypted' : 'Not encrypted') : (ok ? 'Enabled' : 'Absent');
            infoHtml += html`<div class="detail-row"><span class="detail-k">${k}</span><span class="detail-chip ${chipClass}">${chipText}</span></div>`;
        }
        infoHtml += '</div></details>';
    }
    if (r.appInfo?.sha256 || r.appInfo?.fileName) {
        infoHtml += html`<details class="detail-group full" open><summary class="detail-group-head">Integrity</summary><div class="detail-group-body">`;
        if (r.appInfo?.fileName) infoHtml += html`<div class="detail-row"><span class="detail-k">File</span><span class="detail-v mono">${r.appInfo.fileName}</span></div>`;
        if (r.appInfo?.sha256) infoHtml += html`<div class="detail-row col"><span class="detail-k">SHA-256</span><span class="detail-v mono hash">${r.appInfo.sha256}</span></div>`;
        infoHtml += '</div></details>';
    }
    infoHtml += '</div>';
    $('#appInfoGrid').innerHTML = infoHtml;

    const recentEl = $('#recentFindings');
    if (recentEl) {
        const g = r.groupedFindings || {};
        const top = [...(g.high || []), ...(g.warning || []), ...(g.info || [])].slice(0, 6);
        if (!top.length) {
            recentEl.innerHTML = '<div class="no-data">No findings — nothing was flagged in this build.</div>';
        } else {
            recentEl.innerHTML = '<div class="recent-list">' + top.map(f => html`
              <button class="recent-row" data-jumpsev="${f.severity}" type="button">
                <span class="recent-dot ${f.severity}"></span>
                <span class="recent-title">${f.ruleName}</span>
                <span class="recent-sev ${f.severity}">${SEV_LABEL[f.severity] || f.severity}</span>
              </button>`.toString()).join('') + '</div>';
            $$('#recentFindings [data-jumpsev]').forEach(b => b.addEventListener('click', () => {
                State.activeSeverityFilter = new Set([b.dataset.jumpsev]);
                renderFindings(State.currentResults);
                switchTab('findings');
            }));
        }
    }

    const perms = Object.entries(r.permissions || {});
    $('#permissionsList').innerHTML = perms.length === 0
        ? '<div class="no-data">No special permissions requested</div>'
        : '<div class="permissions-grid">' + perms.map(([k, v]) => html`
            <div class="permission-item">
              <div class="permission-header"><span class="permission-name">${v.name}</span></div>
              <div class="permission-key"><code>${k}</code></div>
              <div class="permission-reason"><span class="reason-label">App's stated reason</span><span class="reason-text">"${v.reason || 'No description provided'}"</span></div>
            </div>`).join('') + '</div>';

    const schemes = r.urlSchemes || [];
    $('#urlSchemesList').innerHTML = schemes.length === 0
        ? '<div class="no-data">No custom URL schemes</div>'
        : schemes.map(s => html`<span class="scheme-tag">${s}://</span>`).join('');
}

function renderTrackers(r) {
    const trackers = r.trackers || [];
    const el = $('#trackersList');
    if (!el) return;
    if (trackers.length === 0) { el.innerHTML = '<div class="no-data">No trackers detected</div>'; return; }
    const byCat = {};
    for (const t of trackers) { (byCat[t.category || 'other'] ||= []).push(t); }
    el.innerHTML = Object.entries(byCat).map(([cat, items]) => html`
        <div class="tracker-group">
          <div class="tracker-cat">${cat}</div>
          <div class="tracker-row">${raw(items.map(t => html`<span class="tracker-tag">${t.name}</span>`).join(''))}</div>
        </div>`).join('');
}

function findingsAfterFilters(r) {
    const groups = ['high', 'warning', 'info', 'secure'];
    let all = [];
    for (const g of groups) {
        if (!State.activeSeverityFilter.has(g)) continue;
        for (const f of (r.groupedFindings?.[g] || [])) all.push(f);
    }
    const q = State.findingsSearch.trim().toLowerCase();
    if (q) {
        all = all.filter(f =>
            (f.ruleName || '').toLowerCase().includes(q)
         || (f.description || '').toLowerCase().includes(q)
         || (f.cwe || '').toLowerCase().includes(q)
         || (f.owasp || '').toLowerCase().includes(q)
         || (f.masvs || '').toLowerCase().includes(q)
         || (f.mitre || '').toLowerCase().includes(q)
         || f.instances.some(i => (i.match || '').toLowerCase().includes(q) || (i.file || '').toLowerCase().includes(q))
        );
    }
    if (State.findingsMinConfidence > 0) {
        all = all.filter(f => (f.avgConfidence ?? 50) >= State.findingsMinConfidence);
    }
    const sortKey = State.findingsSort;
    if (sortKey === 'severity') {
        const order = { high: 0, warning: 1, info: 2, secure: 3 };
        all.sort((a, b) => (order[a.severity] - order[b.severity]) || (b.avgConfidence - a.avgConfidence));
    } else if (sortKey === 'confidence') {
        all.sort((a, b) => b.avgConfidence - a.avgConfidence);
    } else if (sortKey === 'count') {
        all.sort((a, b) => b.instances.length - a.instances.length);
    } else if (sortKey === 'name') {
        all.sort((a, b) => a.ruleName.localeCompare(b.ruleName));
    }
    return all;
}

function renderFindings(r) {
    if (!r) return;
    const container = $('#findingsList');
    if (!container) return;
    const all = findingsAfterFilters(r);

    if (all.length === 0) {
        container.innerHTML = '<div class="no-data">No findings match the current filters.</div>';
        $('#findingsResultCount').textContent = '0';
        $('#findingsPager').innerHTML = '';
        return;
    }

    const start = State.findingsPage * State.findingsPerPage;
    const page = all.slice(start, start + State.findingsPerPage);
    $('#findingsResultCount').textContent = all.length + ' rules · showing ' + (start + 1) + '–' + Math.min(all.length, start + page.length);

    container.innerHTML = page.map((f, i) => {
        const idx = start + i;
        const instances = f.instances.slice(0, 200).map((inst, j) => {
            const isBin = inst.file && inst.file.startsWith('BINARY:');
            const binName = isBin ? inst.file.replace('BINARY:', '') : null;
            const fileLabel = isBin ? (binName + ' (binary)') : (inst.file || '');
            const off = inst.binaryOffset ? parseInt(inst.binaryOffset.replace('0x', ''), 16) : 0;
            const clickAttr = isBin
                ? `data-jump-bin="${escAttr(binName)}" data-jump-offset="${off}"`
                : `data-jump-file="${escAttr(inst.file)}" data-jump-line="${parseInt(inst.line) || 0}"`;
            const confBar = inst.confidence != null
                ? `<span class="confidence-badge ${inst.confidenceLabel || 'medium'}" title="Confidence ${inst.confidence}%">${inst.confidence}%</span>`
                : '';
            const entropy = inst.entropy != null ? `<span class="entropy-badge" title="Shannon entropy">H=${inst.entropy}</span>` : '';
            return html`
              <div class="instance-item">
                <div class="instance-header">
                  <span class="instance-number">#${j + 1}</span>
                  <button class="instance-file clickable" ${raw(clickAttr)} aria-label="Open ${fileLabel}">${fileLabel}${inst.line ? ':' + inst.line : ''}</button>
                  ${inst.binaryOffset ? raw('<span class="instance-offset">@ ' + esc(inst.binaryOffset) + '</span>') : ''}
                  ${raw(confBar)}
                  ${raw(entropy)}
                </div>
                <div class="instance-match"><code>${inst.match}</code><button class="copy-btn" data-copy="${escAttr(inst.match || '')}" title="Copy match" aria-label="Copy match value">⧉</button></div>
                <pre class="instance-snippet">${inst.snippet}</pre>
              </div>`;
        }).join('');
        return html`
          <article class="finding-card ${f.severity}" data-severity="${f.severity}" data-finding-id="${idx}">
            <button class="finding-header" aria-expanded="false" aria-controls="finding-body-${idx}">
              <span class="severity-badge ${f.severity}">${(SEV_LABEL[f.severity] || f.severity).toUpperCase()}</span>
              <span class="finding-title">${f.ruleName}</span>
              <span class="confidence-pill ${labelFor(f.avgConfidence)}" title="Average confidence">${f.avgConfidence}%</span>
              <span class="instance-count">${f.instances.length} instance${f.instances.length > 1 ? 's' : ''}</span>
              <span class="finding-toggle" aria-hidden="true">▾</span>
            </button>
            <div class="finding-body" id="finding-body-${idx}" hidden>
              <div class="finding-description">${f.description}</div>
              <div class="finding-meta">
                ${f.cwe   ? raw('<a class="meta-tag" target="_blank" rel="noopener" href="https://cwe.mitre.org/data/definitions/' + esc(f.cwe.replace(/^CWE-/, '')) + '.html">CWE: ' + esc(f.cwe) + '</a>') : ''}
                ${f.owasp ? raw('<span class="meta-tag">OWASP: ' + esc(f.owasp) + '</span>') : ''}
                ${f.masvs ? raw('<span class="meta-tag">MASVS: ' + esc(f.masvs) + '</span>') : ''}
                ${f.mitre ? raw(mitreTag(f.mitre)) : ''}
                ${f.category ? raw('<span class="meta-tag category">' + esc(f.category) + '</span>') : ''}
              </div>
              <div class="instances-section">
                <div class="instances-header">Found in ${f.instances.length} location${f.instances.length > 1 ? 's' : ''}</div>
                <div class="instances-list">${raw(instances)}</div>
              </div>
            </div>
          </article>`;
    }).join('');

    $$('#findingsList .finding-header').forEach(h => h.addEventListener('click', () => {
        const expanded = h.getAttribute('aria-expanded') === 'true';
        h.setAttribute('aria-expanded', expanded ? 'false' : 'true');
        const body = h.parentElement.querySelector('.finding-body');
        if (body) body.hidden = expanded;
    }));
    $$('#findingsList [data-jump-file]').forEach(b => b.addEventListener('click', () => {
        const file = b.getAttribute('data-jump-file');
        const line = parseInt(b.getAttribute('data-jump-line') || '0', 10);
        navigateToFile(file, line);
    }));
    $$('#findingsList [data-jump-bin]').forEach(b => b.addEventListener('click', () => {
        const name = b.getAttribute('data-jump-bin');
        const off = parseInt(b.getAttribute('data-jump-offset') || '0', 10);
        navigateToBinary(name, off);
    }));
    $$('#findingsList [data-copy]').forEach(b => b.addEventListener('click', async (e) => {
        e.stopPropagation();
        const text = b.getAttribute('data-copy');
        try {
            await navigator.clipboard.writeText(text);
            b.classList.add('copied');
            const orig = b.textContent;
            b.textContent = '✓';
            setTimeout(() => { b.classList.remove('copied'); b.textContent = orig; }, 1200);
        } catch (_) {
            toast('Copy failed - select text manually', 'error');
        }
    }));

    renderPager(all.length);
}

function mitreTag(mitre) {
    // mitre may be "T1409", "T1636.003", "T1512, T1429", or "T1521.003 (mitigates)"
    const isMitigation = /\(mitigates\)/i.test(mitre);
    const clean = mitre.replace(/\s*\(mitigates\)\s*/i, '');
    const ids = clean.split(',').map(s => s.trim()).filter(Boolean);
    const links = ids.map(id => {
        const m = id.match(/^T(\d+)(?:\.(\d+))?$/);
        if (!m) return esc(id);
        const url = m[2]
            ? `https://attack.mitre.org/techniques/T${m[1]}/${m[2]}/`
            : `https://attack.mitre.org/techniques/T${m[1]}/`;
        return `<a target="_blank" rel="noopener" href="${escAttr(url)}">${esc(id)}</a>`;
    }).join(', ');
    const label = isMitigation ? 'ATT&CK (mitigates): ' : 'ATT&CK: ';
    return `<span class="meta-tag mitre${isMitigation ? ' mitigates' : ''}">${label}${links}</span>`;
}

function labelFor(conf) {
    if (conf >= 85) return 'high';
    if (conf >= 60) return 'medium';
    if (conf >= 30) return 'low';
    return 'noise';
}

function renderPager(total) {
    const pages = Math.max(1, Math.ceil(total / State.findingsPerPage));
    const cur = State.findingsPage;
    const wrap = $('#findingsPager');
    if (!wrap) return;
    if (pages <= 1) { wrap.innerHTML = ''; return; }
    wrap.innerHTML = `
      <button class="pager-btn" data-pager="first" ${cur === 0 ? 'disabled' : ''}>⏮ First</button>
      <button class="pager-btn" data-pager="prev"  ${cur === 0 ? 'disabled' : ''}>◀ Prev</button>
      <span class="pager-info">Page ${cur + 1} of ${pages}</span>
      <button class="pager-btn" data-pager="next" ${cur >= pages - 1 ? 'disabled' : ''}>Next ▶</button>
      <button class="pager-btn" data-pager="last" ${cur >= pages - 1 ? 'disabled' : ''}>Last ⏭</button>`;
    $$('#findingsPager [data-pager]').forEach(b => b.addEventListener('click', () => {
        const a = b.dataset.pager;
        if (a === 'first') State.findingsPage = 0;
        else if (a === 'prev')  State.findingsPage = Math.max(0, cur - 1);
        else if (a === 'next')  State.findingsPage = Math.min(pages - 1, cur + 1);
        else if (a === 'last')  State.findingsPage = pages - 1;
        renderFindings(State.currentResults);
    }));
}

function renderBinary(r) {
    const grid = $('#checksecGrid');
    if (!grid) return;

    const summary = r.machoSummary;
    if (!summary) { grid.innerHTML = '<div class="no-data">No Mach-O executable parsed</div>'; return; }

    const cs = summary.checksec || (summary.slices && summary.slices[0] && summary.slices[0].checksec) || {};

    const checks = [
        ['PIE / ASLR',          cs.pie,         'MH_PIE flag in Mach-O header'],
        ['Stack Canary',        cs.stackCanary, '___stack_chk_guard / ___stack_chk_fail imported'],
        ['ARC',                 cs.arc,         '_objc_release / _swift_release imported'],
        ['Code Signed',         cs.codeSigned,  'LC_CODE_SIGNATURE present'],
        ['NX Heap',             cs.nx_heap,     'MH_NO_HEAP_EXECUTION flag'],
        ['NX Stack',            cs.nx_stack,    'MH_ALLOW_STACK_EXECUTION not set'],
        ['Two-Level NS',        cs.twoLevelNamespace, 'MH_TWOLEVEL flag'],
        ['FairPlay Encrypted',  cs.encryptedFairPlay, 'LC_ENCRYPTION_INFO_64 cryptid != 0'],
    ];
    grid.innerHTML = '<div class="checksec-grid">' + checks.map(([name, ok, desc]) => html`
      <div class="checksec-item ${ok ? 'pass' : 'fail'}">
        <div class="checksec-status" aria-hidden="true">${ok ? '✓' : '✗'}</div>
        <div class="checksec-info"><div class="checksec-name">${name}</div><div class="checksec-desc">${desc}</div></div>
      </div>`).join('') + '</div>';

    const machoMeta = $('#machoMeta');
    if (machoMeta) {
        const slices = summary.type === 'fat' ? (summary.slices || []) : [summary];
        machoMeta.innerHTML = slices.map(s => html`
          <div class="macho-slice">
            <div class="macho-header">
              <span class="info-badge format">${s.arch}</span>
              ${s.bits ? raw('<span class="info-badge">' + esc(s.bits) + '-bit</span>') : ''}
              ${s.platform ? raw('<span class="info-badge">' + esc(s.platform) + '</span>') : ''}
              ${s.minOS ? raw('<span class="info-badge">min ' + esc(s.minOS) + '</span>') : ''}
              ${s.sdk ? raw('<span class="info-badge">SDK ' + esc(s.sdk) + '</span>') : ''}
              ${s.uuid ? raw('<span class="info-badge mono">UUID ' + esc(s.uuid) + '</span>') : ''}
            </div>
            ${s.segments && s.segments.length ? raw(html`
              <div class="macho-section">
                <h4>Segments (${s.segments.length})</h4>
                <table class="segments-table"><thead><tr><th>Name</th><th>VM Addr</th><th>VM Size</th><th>Sections</th><th>initprot</th></tr></thead><tbody>
                  ${raw(s.segments.map(seg => html`
                    <tr><td class="mono">${seg.name}</td><td class="mono">${seg.vmaddr}</td><td>${fmtSize(seg.vmsize)}</td><td>${seg.sections.length}</td><td>${seg.initprot}</td></tr>`).join(''))}
                </tbody></table>
              </div>`) : ''}
            ${s.dylibs && s.dylibs.length ? raw(html`
              <div class="macho-section">
                <h4>Linked Libraries (${s.dylibs.length})</h4>
                <div class="libraries-list">${raw(s.dylibs.map(d => html`<div class="library-item mono">${typeof d === 'string' ? d : d.name}</div>`).join(''))}</div>
              </div>`) : ''}
            ${s.rpaths && s.rpaths.length ? raw(html`
              <div class="macho-section">
                <h4>RPATHs (${s.rpaths.length})</h4>
                <div class="libraries-list">${raw(s.rpaths.map(p => html`<div class="library-item mono">${p}</div>`).join(''))}</div>
              </div>`) : ''}
            ${s.codeSignature && s.codeSignature.codeDirectory ? raw(html`
              <div class="macho-section">
                <h4>Code Directory</h4>
                <div class="info-grid">
                  <div class="info-item"><label>Identifier</label><div class="value mono">${s.codeSignature.codeDirectory.identifier || ''}</div></div>
                  <div class="info-item"><label>Team ID</label><div class="value mono">${s.codeSignature.codeDirectory.teamId || '(none)'}</div></div>
                  <div class="info-item"><label>Hash</label><div class="value">${s.codeSignature.codeDirectory.hashAlgorithm}</div></div>
                  <div class="info-item"><label>Page Size</label><div class="value">${fmtSize(s.codeSignature.codeDirectory.pageSize || 4096)}</div></div>
                  <div class="info-item"><label>Slots</label><div class="value">${s.codeSignature.codeDirectory.nCodeSlots} code, ${s.codeSignature.codeDirectory.nSpecialSlots} special</div></div>
                  <div class="info-item"><label>Flags</label><div class="value mono">${(s.codeSignature.codeDirectory.flagNames || []).join(', ') || '(none)'}</div></div>
                </div>
              </div>`) : ''}
          </div>`).join('');
    }
}

function entCategory(key) {
    const k = String(key).toLowerCase();
    if (k.includes('vpn')) return 'VPN';
    if (k.includes('aps-environment') || k.includes('usernotifications') || k.includes('push')) return 'Push';
    if (k.includes('icloud') || k.includes('ubiquity') || k.includes('cloudkit')) return 'iCloud';
    if (k.includes('networking') || k.includes('associated-domains') || k.includes('wifi') || k.includes('hotspot')) return 'Networking';
    if (k.includes('background') || k.includes('fetch')) return 'Background';
    if (k.includes('get-task-allow') || k.includes('debug')) return 'Debug';
    if (k.includes('keychain') || k.includes('security') || k.includes('data-protection') || k.includes('sandbox')) return 'Security';
    if (k.includes('team-identifier') || k.includes('application-identifier') || k.includes('developer')) return 'Developer';
    return 'Other';
}

function renderEntitlements(r) {
    const ent = r.provisioning?.entitlements || null;
    const provMeta = r.provisioning?.meta || null;
    const certs = r.provisioning?.certificates || [];

    const provCard = $('#provisioningCard');
    if (provCard) {
        if (!provMeta) {
            provCard.innerHTML = '<div class="no-data">No embedded.mobileprovision in this IPA</div>';
        } else {
            const dist = provMeta.distribution || 'unknown';
            const distLabel = { 'app-store': 'App Store', 'enterprise': 'Enterprise', 'development': 'Development', 'ad-hoc': 'Ad-Hoc' }[dist] || dist;
            const expClass = provMeta.expired ? 'bad' : (provMeta.daysUntilExpiry != null && provMeta.daysUntilExpiry < 30 ? 'warn' : 'good');
            provCard.innerHTML = html`
              <div class="prov-summary">
                <div class="prov-headline">
                  <span class="prov-name">${provMeta.name || provMeta.appIDName || 'Provisioning Profile'}</span>
                  <span class="prov-dist badge-${dist}">${distLabel}</span>
                </div>
                <div class="info-grid">
                  <div class="info-item"><label>App ID</label><div class="value mono">${provMeta.applicationIdentifier || ''}</div></div>
                  <div class="info-item"><label>Team</label><div class="value">${provMeta.teamName || ''}</div></div>
                  <div class="info-item"><label>Team IDs</label><div class="value mono">${(provMeta.teamIdentifier || []).join(', ')}</div></div>
                  <div class="info-item"><label>UUID</label><div class="value mono">${provMeta.uuid || ''}</div></div>
                  <div class="info-item"><label>Created</label><div class="value">${provMeta.creationDate || ''}</div></div>
                  <div class="info-item"><label>Expires</label><div class="value ${expClass}">${provMeta.expirationDate || ''}${provMeta.daysUntilExpiry != null ? ' (' + (provMeta.expired ? 'expired' : provMeta.daysUntilExpiry + 'd left') + ')' : ''}</div></div>
                  <div class="info-item"><label>Devices</label><div class="value">${provMeta.deviceCount || 0}${provMeta.provisionsAllDevices ? ' (all devices)' : ''}</div></div>
                  <div class="info-item"><label>APS</label><div class="value">${provMeta.apsEnvironment || '(none)'}</div></div>
                  <div class="info-item"><label>get-task-allow</label><div class="value ${provMeta.getTaskAllow ? 'bad' : 'good'}">${provMeta.getTaskAllow ? 'YES (debug)' : 'no'}</div></div>
                </div>
              </div>
              ${certs.length ? raw(html`
                <div class="cert-list">
                  <h4>Developer Certificates (${certs.length})</h4>
                  ${raw(certs.map(c => html`
                    <div class="cert-item">
                      <div class="cert-cn">${c.subjectCN || '(unknown)'}</div>
                      <div class="cert-meta">
                        ${c.issuerCN ? raw('<span>Issuer: ' + esc(c.issuerCN) + '</span>') : ''}
                        ${c.validity && c.validity.notAfter ? raw('<span>Until ' + esc(c.validity.notAfter) + '</span>') : ''}
                        ${c.serial ? raw('<span class="mono">SN ' + esc((c.serial || '').slice(0,40)) + '</span>') : ''}
                      </div>
                    </div>`).join(''))}
                </div>`) : ''}
            `;
        }
    }

    const entCard = $('#entitlementsCard');
    if (entCard) {
        const entSource = ent || (r.entitlementsXml ? tryParseXMLPlist(r.entitlementsXml) : null);
        if (!entSource || Object.keys(entSource).length === 0) {
            entCard.innerHTML = '<div class="no-data">No entitlements detected (neither in code signature nor provisioning).</div>';
        } else {
            const flagged = flagDangerousEntitlements(entSource);
            const keys = Object.keys(entSource).sort();
            const cats = {};
            for (const k of keys) { (cats[entCategory(k)] ||= []).push(k); }
            const catOrder = ['Security', 'Networking', 'iCloud', 'Push', 'Background', 'VPN', 'Debug', 'Developer', 'Other'];
            let entHtml = '<div class="ent-head"><h4>Entitlements (' + keys.length + ')</h4></div><div class="ent-groups">';
            for (const cat of catOrder) {
                if (!cats[cat]) continue;
                entHtml += '<div class="ent-group"><div class="ent-group-title">' + esc(cat) + '<span class="ent-group-count">' + cats[cat].length + '</span></div><div class="ent-group-body">';
                for (const k of cats[cat]) {
                    const flag = flagged.find(x => x.key === k);
                    entHtml += '<div class="ent-row' + (flag ? ' risk-' + flag.level : '') + '">'
                        + '<div class="ent-row-key mono">' + esc(k) + '</div>'
                        + '<div class="ent-row-val">' + renderEntValue(entSource[k]) + '</div>'
                        + (flag ? '<span class="risk-badge ' + esc(flag.level) + '">' + esc(flag.reason) + '</span>' : '')
                        + '</div>';
                }
                entHtml += '</div></div>';
            }
            entHtml += '</div>';
            if (r.entitlementsXml) entHtml += '<details class="ent-xml"><summary>Raw Entitlements XML</summary><pre class="mono">' + esc(r.entitlementsXml) + '</pre></details>';
            entCard.innerHTML = entHtml;
        }
    }
}

function renderEntValue(v) {
    if (Array.isArray(v)) return v.map(x => '<span class="ent-val mono">' + esc(x) + '</span>').join(' ');
    if (typeof v === 'boolean') return '<span class="ent-bool ' + (v ? 'yes' : 'no') + '">' + (v ? 'YES' : 'NO') + '</span>';
    if (typeof v === 'object' && v != null) return '<code class="mono">' + esc(JSON.stringify(v)) + '</code>';
    return '<span class="mono">' + esc(v) + '</span>';
}

function flagDangerousEntitlements(ent) {
    const flags = [];
    if (ent['get-task-allow']) flags.push({ key: 'get-task-allow', level: 'high', reason: 'debug build' });
    if (ent['com.apple.security.get-task-allow']) flags.push({ key: 'com.apple.security.get-task-allow', level: 'high', reason: 'debug build' });
    if (ent['com.apple.private.security.no-sandbox']) flags.push({ key: 'com.apple.private.security.no-sandbox', level: 'high', reason: 'no sandbox' });
    if (Array.isArray(ent['com.apple.developer.associated-domains'])) flags.push({ key: 'com.apple.developer.associated-domains', level: 'info', reason: String(ent['com.apple.developer.associated-domains'].length) + ' domains' });
    if (Array.isArray(ent['keychain-access-groups']) && ent['keychain-access-groups'].length > 5) flags.push({ key: 'keychain-access-groups', level: 'info', reason: ent['keychain-access-groups'].length + ' groups' });
    if (ent['com.apple.developer.networking.networkextension']) flags.push({ key: 'com.apple.developer.networking.networkextension', level: 'warn', reason: 'network extension' });
    if (ent['com.apple.developer.networking.vpn.api']) flags.push({ key: 'com.apple.developer.networking.vpn.api', level: 'warn', reason: 'VPN' });
    return flags;
}

function tryParseXMLPlist(xml) {
    try {
        const doc = new DOMParser().parseFromString(xml, 'text/xml');
        const dict = doc.querySelector('plist > dict');
        if (!dict) return null;
        return walkPlist(dict);
    } catch (_) { return null; }
}
function walkPlist(node) {
    if (!node) return null;
    switch (node.tagName) {
        case 'string':  return node.textContent;
        case 'integer': return parseInt(node.textContent, 10);
        case 'real':    return parseFloat(node.textContent);
        case 'true':    return true;
        case 'false':   return false;
        case 'array':   return Array.from(node.children).map(walkPlist);
        case 'dict': {
            const o = {};
            const ch = Array.from(node.children);
            for (let i = 0; i < ch.length; i += 2) {
                if (ch[i].tagName === 'key') o[ch[i].textContent] = walkPlist(ch[i + 1]);
            }
            return o;
        }
        default: return node.textContent;
    }
}

function renderATS(r) {
    const wrap = $('#atsPanel');
    if (!wrap) return;
    const a = r.ats;
    if (!a) { wrap.innerHTML = '<div class="no-data">No ATS data</div>'; return; }
    const verdictLabel = {
        'default-strict': 'Default (strict)',
        'strict': 'Strict - no exceptions',
        'strict-with-exceptions': 'Strict with explicit exceptions',
        'mixed': 'Mixed - some exceptions are risky',
        'mostly-disabled': 'Mostly disabled (per-domain re-enabled)',
        'globally-disabled': 'Globally disabled',
    }[a.verdict] || a.verdict;
    const verdictClass = (a.verdict === 'strict' || a.verdict === 'default-strict' || a.verdict === 'strict-with-exceptions') ? 'good'
                       : (a.verdict === 'mixed') ? 'warn' : 'bad';

    wrap.innerHTML = html`
      <div class="ats-overview">
        <div class="ats-verdict ${verdictClass}"><span class="ats-verdict-icon">${verdictClass === 'good' ? '✓' : verdictClass === 'warn' ? '!' : '✕'}</span>${verdictLabel}</div>
        <div class="ats-flags">
          <span class="ats-flag ${a.allowsArbitraryLoads ? 'bad' : 'good'}">Arbitrary Loads: ${a.allowsArbitraryLoads ? 'YES' : 'no'}</span>
          <span class="ats-flag ${a.allowsArbitraryLoadsInWebContent ? 'bad' : 'good'}">In WebContent: ${a.allowsArbitraryLoadsInWebContent ? 'YES' : 'no'}</span>
          <span class="ats-flag ${a.allowsArbitraryLoadsForMedia ? 'warn' : 'good'}">For Media: ${a.allowsArbitraryLoadsForMedia ? 'YES' : 'no'}</span>
          <span class="ats-flag ${a.allowsLocalNetworking ? 'warn' : 'good'}">Local Network: ${a.allowsLocalNetworking ? 'YES' : 'no'}</span>
        </div>
      </div>
      ${a.domains.length === 0
        ? '<div class="no-data">No NSExceptionDomains defined.</div>'
        : raw('<div class="ats-domains">' + a.domains.map(d => html`
            <div class="ats-domain-card ${d.issues.length ? 'has-issues' : ''}">
              <div class="ats-domain-head">
                <span class="ats-domain-name mono">${d.domain}</span>
                ${d.includesSubdomains ? raw('<span class="ats-domain-sub">+ subdomains</span>') : ''}
              </div>
              <div class="ats-domain-attrs">
                <span class="ats-attr ${d.allowsInsecureHTTPLoads ? 'bad' : 'good'}">HTTP ${d.allowsInsecureHTTPLoads ? 'insecure' : 'secure'}</span>
                <span class="ats-attr">TLS ${d.minimumTLSVersion}</span>
                <span class="ats-attr ${d.requiresForwardSecrecy ? 'good' : 'bad'}">PFS ${d.requiresForwardSecrecy ? 'on' : 'off'}</span>
                <span class="ats-attr ${d.requiresCertificateTransparency ? 'good' : 'neutral'}">CT ${d.requiresCertificateTransparency ? 'on' : 'off'}</span>
                <span class="ats-attr ${(d.pinnedLeafIdentities || d.pinnedCAIdentities) ? 'good' : 'neutral'}">Pin ${d.pinnedLeafIdentities ? 'leaf' : d.pinnedCAIdentities ? 'CA' : 'none'}</span>
              </div>
              ${d.issues.length ? raw('<div class="ats-domain-issues">' + d.issues.map(i => '<span class="ats-issue">' + esc(i) + '</span>').join('') + '</div>') : ''}
            </div>`.toString()).join('') + '</div>')}
    `;
}


function renderExplorer(r) {
    State.explorerFiles = r.files || [];
    State.explorerTree = r.fileTree || {};
    const treeContainer = $('#fileTree');
    treeContainer.innerHTML = buildTree(State.explorerTree, '');
    $('#totalFileCount') && ($('#totalFileCount').textContent = State.explorerFiles.length + ' files');
    populateQuickAccess(r);
    setupExplorerSearch();
    treeContainer.onclick = onTreeClick;
}

function onTreeClick(e) {
    const folderHeader = e.target.closest('.tree-folder-header');
    if (folderHeader) {
        const folder = folderHeader.parentElement;
        folder.classList.toggle('open');
        const ic = folderHeader.querySelector('.folder-icon');
        if (ic) ic.textContent = folder.classList.contains('open') ? '📂' : '📁';
        return;
    }
    const file = e.target.closest('.tree-file');
    if (file) openFile(file.dataset.path);
}

function buildTree(tree, prefix) {
    let out = '';
    const entries = Object.entries(tree).filter(([k]) => !k.startsWith('_')).sort((a, b) => {
        const aDir = a[1]._type === 'dir', bDir = b[1]._type === 'dir';
        if (aDir !== bDir) return aDir ? -1 : 1;
        return a[0].localeCompare(b[0]);
    });
    for (const [name, node] of entries) {
        if (node._type === 'dir') {
            const count = countFiles(node);
            out += '<div class="tree-folder" role="treeitem" aria-expanded="false">' +
                    '<button class="tree-folder-header" title="' + escAttr(prefix + name) + '">' +
                    '<span class="folder-chevron" aria-hidden="true">▶</span>' +
                    '<span class="folder-icon" aria-hidden="true">📁</span>' +
                    '<span class="folder-name">' + esc(name) + '</span>' +
                    '<span class="folder-count">' + count + '</span>' +
                    '</button>' +
                    '<div class="tree-folder-content">' + buildTree(node, prefix + name + '/') + '</div></div>';
        } else {
            const ext = name.split('.').pop().toLowerCase();
            const ic = fileIcon(ext);
            const lower = name.toLowerCase();
            const important = lower === 'info.plist' || lower.includes('entitlements')
                            || lower === 'embedded.mobileprovision' || ext === 'sqlite' || ext === 'db' || ext === 'realm';
            out += '<button class="tree-file' + (important ? ' important' : '') + '" data-path="' + escAttr(node._path) + '" data-ext="' + ext + '" title="' + escAttr(node._path) + '" role="treeitem">' +
                    '<span class="file-icon" aria-hidden="true">' + ic + '</span>' +
                    '<span class="file-name">' + esc(name) + '</span></button>';
        }
    }
    return out;
}

function countFiles(node) {
    let n = 0;
    for (const [k, v] of Object.entries(node)) {
        if (k.startsWith('_')) continue;
        if (v._type === 'dir') n += countFiles(v);
        else n++;
    }
    return n;
}

function fileIcon(ext) {
    const m = {
        swift: '🔶', m: '📘', mm: '📘', h: '📄', c: '📄', cpp: '📄',
        plist: '📋', json: '📜', xml: '📰', yaml: '📜', yml: '📜',
        db: '🗄️', sqlite: '🗄️', sqlite3: '🗄️', realm: '🗄️',
        png: '🖼️', jpg: '🖼️', jpeg: '🖼️', gif: '🖼️', svg: '🖼️', webp: '🖼️',
        js: '📒', html: '🌐', css: '🎨', strings: '🔤', stringsdict: '🔤',
        cer: '🔐', pem: '🔐', p12: '🔐', mobileprovision: '📜', entitlements: '🔐',
        dylib: '⚙️', framework: '📦',
    };
    return m[ext] || '📄';
}

function populateQuickAccess(r) {
    const list = $('#quickAccessList');
    if (!list) return;
    const found = { info: null, ent: null, prov: null, bin: null };
    const extras = [];
    for (const p of [...State.explorerFiles].sort((a, b) => a.length - b.length)) {
        const fn = p.split('/').pop().toLowerCase();
        const lower = p.toLowerCase();
        const inFw = lower.includes('.framework/') || lower.includes('.appex/');
        if (fn === 'info.plist' && !found.info && !inFw) found.info = { path: p, name: 'Info.plist', icon: '📋', desc: 'Bundle config' };
        else if (fn.includes('entitlements') && !found.ent && !inFw) found.ent = { path: p, name: 'Entitlements', icon: '🔐', desc: 'Capabilities' };
        else if (fn === 'embedded.mobileprovision' && !found.prov) found.prov = { path: p, name: 'Provisioning', icon: '📜', desc: 'Code signing' };
        else if ((fn.endsWith('.sqlite') || fn.endsWith('.db')) && extras.length < 3) extras.push({ path: p, name: fn.slice(0, 18), icon: '🗄️', desc: 'Database' });
    }
    if (r.appInfo?.executableName) {
        const bp = State.explorerFiles.find(f => f.endsWith('/' + r.appInfo.executableName) || f === r.appInfo.executableName);
        if (bp) found.bin = { path: bp, name: 'Binary', icon: '⚙️', desc: r.appInfo.executableName };
    }
    const items = [found.bin, found.info, found.ent, found.prov, ...extras].filter(Boolean);
    list.innerHTML = items.length === 0
        ? '<span class="qa-empty">No key files found</span>'
        : items.map(f => html`
            <button class="quick-access-item" data-path="${f.path}" title="${f.path}">
              <span class="qa-icon" aria-hidden="true">${f.icon}</span>
              <div class="qa-text"><span class="qa-name">${f.name}</span><span class="qa-desc">${f.desc}</span></div>
            </button>`).join('');
    list.querySelectorAll('.quick-access-item').forEach(b => b.addEventListener('click', () => openFile(b.dataset.path)));
}

function setupExplorerSearch() {
    const input = $('#fileSearchInput');
    const results = $('#fileSearchResults');
    if (!input || !results) return;
    input.oninput = () => {
        const q = input.value.toLowerCase().trim();
        if (q.length < 2) { results.innerHTML = ''; return; }
        const matches = State.explorerFiles.filter(f => f.toLowerCase().includes(q)).slice(0, 50);
        if (matches.length === 0) {
            results.innerHTML = '<div class="search-result-item" style="color: var(--text-muted)">No matches</div>';
            return;
        }
        results.innerHTML = matches.map(f => html`<button class="search-result-item" data-path="${f}"><span class="match-name">${f.split('/').pop()}</span><span class="match-path">${f}</span></button>`).join('');
        results.querySelectorAll('[data-path]').forEach(b => b.addEventListener('click', () => openFile(b.dataset.path)));
    };
}


function updateExplorerMeta(path, size) {
    const el = $('#explorerMeta');
    if (!el) return;
    const name = path.split('/').pop();
    const ext = name.includes('.') ? name.split('.').pop().toUpperCase() : '—';
    const dir = path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '/';
    el.innerHTML =
        '<div class="explorer-meta-title">File Details</div>' +
        '<div class="meta-icon">📄</div>' +
        '<div class="meta-row"><div class="meta-k">Name</div><div class="meta-v mono">' + esc(name) + '</div></div>' +
        '<div class="meta-row"><div class="meta-k">Type</div><div class="meta-v">' + esc(ext) + '</div></div>' +
        '<div class="meta-row"><div class="meta-k">Size</div><div class="meta-v">' + esc(fmtSize(size)) + '</div></div>' +
        '<div class="meta-row"><div class="meta-k">Folder</div><div class="meta-v mono">' + esc(dir) + '</div></div>' +
        '<div class="meta-row"><div class="meta-k">Full path</div><div class="meta-v mono">' + esc(path) + '</div></div>';
}

async function openFile(path) {
    if (!path) return;
    State.currentOpenFile = path;
    State.currentOpenBytes = null;
    $('#currentFilePath').textContent = path;
    const dl = $('#downloadFileBtn'); if (dl) dl.disabled = true;
    const viewer = $('#fileViewer');
    viewer.innerHTML = '<div class="loading-file">Loading…</div>';
    try {
        const zip = await getViewerZip();
        if (!zip) {
            viewer.innerHTML = '<div class="no-data">Drop the IPA again to enable the inline viewer (analysis results remain loaded).</div>';
            return;
        }
        const r = State.currentResults;
        const entry = zip.file(r.appPath + path) || zip.file(path);
        if (!entry) {
            viewer.innerHTML = '<div class="no-data">File not found in archive: ' + esc(path) + '</div>';
            return;
        }
        const data = await entry.async('arraybuffer');
        State.currentOpenBytes = new Uint8Array(data);
        if (dl) dl.disabled = false;
        renderFile(viewer, path, data);
        updateExplorerMeta(path, data.byteLength);
    } catch (e) {
        viewer.innerHTML = '<div class="no-data">' + esc(e.message || 'Unable to read file') + '</div>';
    }
}

function downloadCurrentFile() {
    if (!State.currentOpenBytes || !State.currentOpenFile) return;
    const blob = new Blob([State.currentOpenBytes]);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = State.currentOpenFile.split('/').pop();
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(a.href); }, 800);
}

function isCrushedPNG(bytes) {
    if (!bytes || bytes.length < 16) return false;
    if (bytes[0] !== 0x89 || bytes[1] !== 0x50 || bytes[2] !== 0x4E || bytes[3] !== 0x47) return false;
    for (let i = 8; i < Math.min(bytes.length, 128); i++) {
        if (bytes[i] === 0x43 && bytes[i+1] === 0x67 && bytes[i+2] === 0x42 && bytes[i+3] === 0x49) return true;
    }
    return false;
}

function renderFile(viewer, path, arrayBuffer) {
    const bytes = new Uint8Array(arrayBuffer);
    const ext = path.split('.').pop().toLowerCase();
    let header = ''; for (let i = 0; i < 6 && i < bytes.length; i++) header += String.fromCharCode(bytes[i]);

    if (header.startsWith('bplist')) {
        const parsed = IPAS.Plist.parse(bytes);
        const json = parsed ? JSON.stringify(parsed, null, 2) : '(unable to parse binary plist)';
        viewer.innerHTML = '<pre class="code-viewer mono">' + esc(json) + '</pre>';
        return;
    }
    if (ext === 'mobileprovision') {
        const prov = IPAS.Provisioning.parse(bytes);
        viewer.innerHTML = '<pre class="code-viewer mono">' + esc(prov?.xml || '(parse failed)') + '</pre>';
        return;
    }
    if (['png','jpg','jpeg','gif','webp','svg','ico','icns'].includes(ext)) {
        if (ext === 'png' && isCrushedPNG(bytes)) {
            viewer.innerHTML = '<div class="image-viewer">' +
                '<div class="image-info">' +
                '<span class="info-badge">PNG (Apple CgBI)</span>' +
                '<span class="info-badge">' + fmtSize(bytes.length) + '</span>' +
                '</div>' +
                '<div class="no-data" style="padding:24px 16px;">' +
                'This is an iOS optimized PNG (CgBI). Browsers cannot decode it directly. ' +
                'Use the Download button and convert with <code>pngdefry</code> or similar.' +
                '</div></div>';
            return;
        }
        const mime = ext === 'jpg' ? 'image/jpeg' : (ext === 'svg' ? 'image/svg+xml' : ext === 'icns' ? 'application/octet-stream' : ('image/' + ext));
        const blob = new Blob([bytes], { type: mime });
        const url = URL.createObjectURL(blob);
        viewer.innerHTML = '<div class="image-viewer">' +
            '<div class="image-info">' +
            '<span class="info-badge">' + ext.toUpperCase() + '</span>' +
            '<span class="info-badge">' + fmtSize(bytes.length) + '</span>' +
            '</div>' +
            '<div class="image-container"><img src="' + url + '" alt="' + escAttr(path) + '" loading="lazy"></div>' +
            '</div>';
        return;
    }

    const isText = looksText(bytes);
    if (isText && IPAS.MachO.detectMagic(bytes).kind === 'unknown') {
        const text = new TextDecoder('utf-8').decode(bytes);
        viewer.innerHTML = '<pre class="code-viewer mono">' + esc(text) + '</pre>';
        return;
    }
    openBinaryViewer(viewer, path, bytes);
}

function looksText(bytes) {
    const sample = Math.min(bytes.length, 1000);
    let printable = 0;
    for (let i = 0; i < sample; i++) {
        const b = bytes[i];
        if (b === 9 || b === 10 || b === 13) { printable++; continue; }
        if (b >= 32 && b <= 126) { printable++; continue; }
        if (b === 0) return false;
    }
    return printable / sample > 0.95;
}

const HEX_PAGE_BYTES = 4096;
const STRINGS_PAGE = 200;

function openBinaryViewer(viewer, path, bytes) {
    const machoInfo = IPAS.MachO.detectMagic(bytes);
    const isMachO = machoInfo.kind !== 'unknown';
    State.binaryView = {
        path, bytes,
        mode: 'hex',
        offset: 0,
        searchQuery: '',
        searchResults: [],
        currentMatch: -1,
        stringsMinLen: 5,
        stringsCache: null,
        stringsFilter: '',
        stringsPage: 0,
        isMachO,
        machoFormat: isMachO ? machoFormatLabel(machoInfo, bytes) : '',
    };
    renderBinaryViewer();
}

function machoFormatLabel(info, bytes) {
    if (info.kind === 'fat') return 'Mach-O FAT';
    if (info.kind === 'mach-o') return 'Mach-O ' + (info.bits64 ? '64-bit' : '32-bit') + ' (' + (info.le ? 'LE' : 'BE') + ')';
    return '';
}

function renderBinaryViewer() {
    const v = State.binaryView;
    if (!v) return;
    const viewer = $('#fileViewer');
    const totalPages = Math.max(1, Math.ceil(v.bytes.length / HEX_PAGE_BYTES));
    const curPage = Math.floor(v.offset / HEX_PAGE_BYTES);

    const header = html`
      <div class="binary-viewer">
        <div class="binary-toolbar">
          <div class="binary-info">
            ${v.isMachO ? raw('<span class="info-badge format">' + esc(v.machoFormat) + '</span>') : raw('<span class="info-badge">Binary</span>')}
            <span class="info-badge">${fmtSize(v.bytes.length)}</span>
          </div>
          <div class="binary-mode-tabs" role="tablist">
            <button class="view-tab ${v.mode === 'hex' ? 'active' : ''}" data-mode="hex" role="tab" aria-selected="${v.mode === 'hex'}">Hex</button>
            <button class="view-tab ${v.mode === 'strings' ? 'active' : ''}" data-mode="strings" role="tab" aria-selected="${v.mode === 'strings'}">Strings</button>
          </div>
        </div>
        ${v.mode === 'hex' ? raw(renderHexControls(curPage, totalPages)) : raw(renderStringsControls())}
        <div class="binary-body">${v.mode === 'hex' ? raw(renderHexLines()) : raw(renderStringsList())}</div>
      </div>`;
    viewer.innerHTML = header.toString();
    wireBinaryControls();

    if (v.mode === 'hex' && v.currentMatch >= 0) {
        const el = viewer.querySelector('.hex-line.match');
        if (el) el.scrollIntoView({ block: 'center' });
    }
}

function renderHexControls(curPage, totalPages) {
    const v = State.binaryView;
    const matchInfo = v.searchResults.length > 0
        ? '<span class="hex-search-info">' + (v.currentMatch + 1) + ' / ' + v.searchResults.length + ' matches</span>'
        : (v.searchQuery ? '<span class="hex-search-info muted">no matches</span>' : '');
    return `
      <div class="hex-controls">
        <button class="hex-nav" data-action="first" ${curPage === 0 ? 'disabled' : ''}>⏮</button>
        <button class="hex-nav" data-action="prev"  ${curPage === 0 ? 'disabled' : ''}>◀</button>
        <span class="hex-page-info">Page ${curPage + 1} / ${totalPages} · offset 0x${v.offset.toString(16)}</span>
        <button class="hex-nav" data-action="next" ${curPage >= totalPages - 1 ? 'disabled' : ''}>▶</button>
        <button class="hex-nav" data-action="last" ${curPage >= totalPages - 1 ? 'disabled' : ''}>⏭</button>
        <input type="text" class="hex-goto" placeholder="Go to offset (hex or dec)…" aria-label="Go to offset">
      </div>
      <div class="hex-search-bar">
        <input type="text" class="hex-search" placeholder="Search string or hex (e.g. 'AKIA' or 'de ad be ef')" value="${escAttr(v.searchQuery)}" aria-label="Search binary">
        <button class="hex-search-btn" type="button">Find</button>
        <button class="hex-search-prev" ${v.searchResults.length === 0 ? 'disabled' : ''}>◀ Prev</button>
        <button class="hex-search-next" ${v.searchResults.length === 0 ? 'disabled' : ''}>Next ▶</button>
        ${matchInfo}
      </div>`;
}

function renderStringsControls() {
    const v = State.binaryView;
    if (!v.stringsCache) v.stringsCache = IPAS.Analyzer.extractStrings(v.bytes, v.stringsMinLen);
    const filter = (v.stringsFilter || '').toLowerCase();
    const filtered = filter ? v.stringsCache.filter(s => s.str.toLowerCase().includes(filter)) : v.stringsCache;
    const totalPages = Math.max(1, Math.ceil(filtered.length / STRINGS_PAGE));
    const page = Math.min(v.stringsPage, totalPages - 1);
    return `
      <div class="strings-controls">
        <input type="search" class="strings-filter" placeholder="Filter strings…" value="${escAttr(v.stringsFilter)}" aria-label="Filter strings">
        <label class="strings-minlen">Min len <input type="number" min="3" max="32" value="${v.stringsMinLen}" class="strings-minlen-input" aria-label="Minimum string length"></label>
        <span class="strings-count">${filtered.length.toLocaleString()} strings${filter ? ' (filtered)' : ''}</span>
      </div>
      <div class="strings-nav">
        <button class="strings-nav-btn" data-action="first" ${page === 0 ? 'disabled' : ''}>⏮</button>
        <button class="strings-nav-btn" data-action="prev"  ${page === 0 ? 'disabled' : ''}>◀</button>
        <span class="strings-page-info">Page ${page + 1} / ${totalPages}</span>
        <button class="strings-nav-btn" data-action="next" ${page >= totalPages - 1 ? 'disabled' : ''}>▶</button>
        <button class="strings-nav-btn" data-action="last" ${page >= totalPages - 1 ? 'disabled' : ''}>⏭</button>
      </div>`;
}

function renderHexLines() {
    const v = State.binaryView;
    const start = v.offset;
    const end = Math.min(v.bytes.length, start + HEX_PAGE_BYTES);
    const matchStart = v.searchResults[v.currentMatch] ?? -1;
    const matchLen = v.searchQuery.length;

    let out = '<div class="hex-table-header"><span>Offset</span><span>Hex</span><span>ASCII</span></div><div class="hex-dump">';
    for (let i = start; i < end; i += 16) {
        let hexCol = '';
        let asciiCol = '';
        let lineHasMatch = false;
        for (let j = 0; j < 16; j++) {
            const off = i + j;
            const b = v.bytes[off];
            if (b === undefined) {
                hexCol += '   ';
                asciiCol += ' ';
                continue;
            }
            const isMatch = matchStart >= 0 && off >= matchStart && off < matchStart + matchLen;
            if (isMatch) lineHasMatch = true;
            const hex = b.toString(16).padStart(2, '0');
            const ch = (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
            hexCol += isMatch ? `<span class="hex-hit">${hex}</span> ` : (hex + ' ');
            asciiCol += isMatch ? `<span class="hex-hit">${esc(ch)}</span>` : esc(ch);
        }
        out += '<div class="hex-line' + (lineHasMatch ? ' match' : '') + '" data-off="' + i + '"><span class="hex-offset mono">' + i.toString(16).padStart(8, '0') + '</span><span class="hex-bytes mono">' + hexCol + '</span><span class="hex-ascii mono">' + asciiCol + '</span></div>';
    }
    out += '</div>';
    return out;
}

function renderStringsList() {
    const v = State.binaryView;
    if (!v.stringsCache) return '<div class="no-data">Extracting…</div>';
    const filter = (v.stringsFilter || '').toLowerCase();
    const filtered = filter ? v.stringsCache.filter(s => s.str.toLowerCase().includes(filter)) : v.stringsCache;
    const totalPages = Math.max(1, Math.ceil(filtered.length / STRINGS_PAGE));
    const page = Math.min(v.stringsPage, totalPages - 1);
    const startIdx = page * STRINGS_PAGE;
    const slice = filtered.slice(startIdx, startIdx + STRINGS_PAGE);
    if (slice.length === 0) return '<div class="no-data">No strings.</div>';
    return '<div class="strings-list">' + slice.map((s, i) => {
        const off = '0x' + s.offset.toString(16).padStart(8, '0');
        return '<button class="string-entry" data-offset="' + s.offset + '"><span class="string-index">' + (startIdx + i + 1) + '</span><span class="string-offset mono">' + off + '</span><span class="string-value mono">' + esc(s.str) + '</span></button>';
    }).join('') + '</div>';
}

function wireBinaryControls() {
    const v = State.binaryView;
    const viewer = $('#fileViewer');

    viewer.querySelectorAll('[data-mode]').forEach(b => b.addEventListener('click', () => {
        v.mode = b.dataset.mode;
        renderBinaryViewer();
    }));

    viewer.querySelectorAll('.hex-nav').forEach(b => b.addEventListener('click', () => {
        const action = b.dataset.action;
        const totalPages = Math.ceil(v.bytes.length / HEX_PAGE_BYTES);
        const cur = Math.floor(v.offset / HEX_PAGE_BYTES);
        if (action === 'first') v.offset = 0;
        else if (action === 'prev')  v.offset = Math.max(0, (cur - 1) * HEX_PAGE_BYTES);
        else if (action === 'next')  v.offset = Math.min((totalPages - 1) * HEX_PAGE_BYTES, (cur + 1) * HEX_PAGE_BYTES);
        else if (action === 'last')  v.offset = (totalPages - 1) * HEX_PAGE_BYTES;
        v.currentMatch = -1;
        renderBinaryViewer();
    }));

    const goto = viewer.querySelector('.hex-goto');
    if (goto) goto.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter') return;
        const txt = goto.value.trim();
        let off = txt.startsWith('0x') || /[a-f]/i.test(txt) ? parseInt(txt.replace(/^0x/, ''), 16) : parseInt(txt, 10);
        if (Number.isFinite(off)) {
            v.offset = Math.max(0, Math.min(v.bytes.length - 1, off)) & ~15;
            renderBinaryViewer();
        }
    });

    const searchInput = viewer.querySelector('.hex-search');
    const doSearch = () => {
        const q = searchInput.value;
        v.searchQuery = q;
        v.searchResults = searchBytes(v.bytes, q);
        v.currentMatch = v.searchResults.length > 0 ? 0 : -1;
        if (v.currentMatch >= 0) v.offset = Math.floor(v.searchResults[0] / HEX_PAGE_BYTES) * HEX_PAGE_BYTES;
        renderBinaryViewer();
    };
    if (searchInput) {
        viewer.querySelector('.hex-search-btn').addEventListener('click', doSearch);
        searchInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') doSearch(); });
    }
    const prevBtn = viewer.querySelector('.hex-search-prev');
    const nextBtn = viewer.querySelector('.hex-search-next');
    if (prevBtn) prevBtn.addEventListener('click', () => {
        if (!v.searchResults.length) return;
        v.currentMatch = (v.currentMatch - 1 + v.searchResults.length) % v.searchResults.length;
        v.offset = Math.floor(v.searchResults[v.currentMatch] / HEX_PAGE_BYTES) * HEX_PAGE_BYTES;
        renderBinaryViewer();
    });
    if (nextBtn) nextBtn.addEventListener('click', () => {
        if (!v.searchResults.length) return;
        v.currentMatch = (v.currentMatch + 1) % v.searchResults.length;
        v.offset = Math.floor(v.searchResults[v.currentMatch] / HEX_PAGE_BYTES) * HEX_PAGE_BYTES;
        renderBinaryViewer();
    });

    const sFilter = viewer.querySelector('.strings-filter');
    if (sFilter) {
        let t;
        sFilter.addEventListener('input', () => {
            clearTimeout(t);
            t = setTimeout(() => {
                v.stringsFilter = sFilter.value;
                v.stringsPage = 0;
                renderBinaryViewer();
                const newInput = $('.strings-filter');
                if (newInput) { newInput.focus(); newInput.setSelectionRange(newInput.value.length, newInput.value.length); }
            }, 200);
        });
    }
    const minLenInput = viewer.querySelector('.strings-minlen-input');
    if (minLenInput) minLenInput.addEventListener('change', () => {
        const n = parseInt(minLenInput.value, 10);
        if (Number.isFinite(n) && n >= 3 && n <= 32) {
            v.stringsMinLen = n;
            v.stringsCache = null;
            renderBinaryViewer();
        }
    });
    viewer.querySelectorAll('.strings-nav-btn').forEach(b => b.addEventListener('click', () => {
        const filtered = v.stringsFilter ? v.stringsCache.filter(s => s.str.toLowerCase().includes(v.stringsFilter.toLowerCase())) : v.stringsCache;
        const totalPages = Math.max(1, Math.ceil(filtered.length / STRINGS_PAGE));
        const a = b.dataset.action;
        if (a === 'first') v.stringsPage = 0;
        else if (a === 'prev')  v.stringsPage = Math.max(0, v.stringsPage - 1);
        else if (a === 'next')  v.stringsPage = Math.min(totalPages - 1, v.stringsPage + 1);
        else if (a === 'last')  v.stringsPage = totalPages - 1;
        renderBinaryViewer();
    }));
    viewer.querySelectorAll('.string-entry').forEach(e => e.addEventListener('click', () => {
        const off = parseInt(e.dataset.offset, 10);
        v.mode = 'hex';
        v.offset = Math.floor(off / HEX_PAGE_BYTES) * HEX_PAGE_BYTES;
        v.searchQuery = '';
        v.searchResults = [off];
        v.currentMatch = 0;
        renderBinaryViewer();
    }));
}

function searchBytes(bytes, query) {
    if (!query) return [];
    let needle;
    const hexOnly = /^[0-9a-fA-F\s]+$/.test(query) && query.replace(/\s+/g, '').length >= 4 && query.replace(/\s+/g, '').length % 2 === 0;
    if (hexOnly) {
        const cleaned = query.replace(/\s+/g, '');
        needle = new Uint8Array(cleaned.length / 2);
        for (let i = 0; i < cleaned.length; i += 2) needle[i / 2] = parseInt(cleaned.substr(i, 2), 16);
    } else {
        needle = new TextEncoder().encode(query);
    }
    const results = [];
    if (needle.length === 0) return results;
    const last = bytes.length - needle.length;
    outer:
    for (let i = 0; i <= last && results.length < 5000; i++) {
        for (let j = 0; j < needle.length; j++) {
            if (bytes[i + j] !== needle[j]) continue outer;
        }
        results.push(i);
    }
    return results;
}

function navigateToFile(file, line) {
    switchTab('explorer');
    openFile(file).then(() => {
        if (line > 0) setTimeout(() => {
            const target = $('.code-viewer');
            if (target) {
                const els = target.querySelectorAll('div');
                if (els[line - 1]) els[line - 1].scrollIntoView({ block: 'center' });
            }
        }, 200);
    });
}
function navigateToBinary(name, offset) {
    switchTab('explorer');
    const path = State.explorerFiles.find(f => f.endsWith('/' + name) || f === name);
    if (!path) return;
    openFile(path).then(() => {
        setTimeout(() => {
            if (State.binaryView && offset >= 0) {
                State.binaryView.mode = 'hex';
                State.binaryView.offset = Math.floor(offset / HEX_PAGE_BYTES) * HEX_PAGE_BYTES;
                State.binaryView.searchResults = [offset];
                State.binaryView.currentMatch = 0;
                State.binaryView.searchQuery = '';
                renderBinaryViewer();
            }
        }, 200);
    });
}


function setupTabs() {
    const TAB_NAMES = ['overview', 'findings', 'binary', 'entitlements', 'ats', 'explorer'];
    $$('.tab').forEach((t, i) => {
        t.addEventListener('click', () => switchTab(t.dataset.tab));
        t.addEventListener('keydown', (e) => {
            const tabs = $$('.tab');
            const idx = tabs.indexOf(t);
            let next = -1;
            if (e.key === 'ArrowRight') next = (idx + 1) % tabs.length;
            else if (e.key === 'ArrowLeft')  next = (idx - 1 + tabs.length) % tabs.length;
            else if (e.key === 'Home')       next = 0;
            else if (e.key === 'End')        next = tabs.length - 1;
            if (next >= 0) {
                e.preventDefault();
                tabs[next].focus();
                switchTab(tabs[next].dataset.tab);
            }
        });
    });
    document.addEventListener('keydown', (e) => {
        const ae = document.activeElement;
        const inField = ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA' || ae.tagName === 'SELECT' || ae.isContentEditable);
        if (e.key === '/' && !inField) {
            const search = $('#findingsSearchInput');
            if ($('#panel-findings')?.classList.contains('active') && search) {
                e.preventDefault(); search.focus();
            }
        }
        if (e.key === 'Escape') {
            const dd = $('#exportDropdown');
            if (dd && !dd.hidden) { dd.hidden = true; $('#exportMenuBtn').setAttribute('aria-expanded', 'false'); return; }
            $$('#findingsList .finding-body').forEach(b => b.hidden = true);
            $$('#findingsList .finding-header').forEach(h => h.setAttribute('aria-expanded', 'false'));
        }
        if (e.key >= '1' && e.key <= '6' && (e.altKey || e.metaKey)) {
            e.preventDefault();
            switchTab(TAB_NAMES[parseInt(e.key, 10) - 1]);
        }
    });

    // Quick Actions tiles + "View all" section links (Overview)
    document.addEventListener('click', (e) => {
        const el = e.target.closest('[data-qa]');
        if (!el) return;
        const a = el.dataset.qa;
        if (a === 'export') $('#exportMenuBtn')?.click();
        else if (a === 'newscan') $('#fileInput')?.click();
        else switchTab(a);
    });
}

function setupFindingsFilters() {
    $$('.filter-btn[data-filter]').forEach(b => b.addEventListener('click', () => {
        $$('.filter-btn[data-filter]').forEach(x => x.classList.remove('active'));
        b.classList.add('active');
        const f = b.dataset.filter;
        State.activeSeverityFilter = f === 'all' ? new Set(['high', 'warning', 'info', 'secure']) : new Set([f]);
        State.findingsPage = 0;
        renderFindings(State.currentResults);
    }));
    $('#findingsSearchInput')?.addEventListener('input', (e) => {
        State.findingsSearch = e.target.value;
        State.findingsPage = 0;
        renderFindings(State.currentResults);
    });
    $('#expandAllBtn')?.addEventListener('click', () => {
        $$('#findingsList .finding-header').forEach(h => h.setAttribute('aria-expanded', 'true'));
        $$('#findingsList .finding-body').forEach(b => b.hidden = false);
    });
    $('#collapseAllBtn')?.addEventListener('click', () => {
        $$('#findingsList .finding-header').forEach(h => h.setAttribute('aria-expanded', 'false'));
        $$('#findingsList .finding-body').forEach(b => b.hidden = true);
    });
}

function setupExport() {
    const btn = $('#exportMenuBtn');
    const dd  = $('#exportDropdown');
    if (!btn || !dd) return;
    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const open = !dd.hidden;
        dd.hidden = open;
        btn.setAttribute('aria-expanded', String(!open));
    });
    document.addEventListener('click', () => {
        dd.hidden = true;
        btn.setAttribute('aria-expanded', 'false');
    });
    dd.addEventListener('click', (e) => e.stopPropagation());
    dd.querySelectorAll('[data-export]').forEach(b => b.addEventListener('click', async () => {
        const kind = b.dataset.export;
        if (!State.currentResults) return;
        dd.hidden = true;
        btn.setAttribute('aria-expanded', 'false');
        if (kind === 'share') {
            await shareCurrentReport();
            return;
        }
        try {
            if (kind === 'pdf') {
                if (!IPAS.PDF) throw new Error('PDF module not loaded');
                IPAS.PDF.exportPDF(State.currentResults);
                toast('PDF report generated', 'success');
            } else {
                IPAS.Export.exportFile(kind, State.currentResults);
                toast('Exported ' + kind.toUpperCase(), 'success');
            }
        }
        catch (e) { toast('Export failed: ' + e.message, 'error'); }
    }));
}

function setupTheme() {
    const THEMES = ['dark', 'light'];
    const stored = localStorage.getItem('theme');
    const queryTheme = new URLSearchParams(location.search).get('theme');
    document.documentElement.dataset.theme = (queryTheme && THEMES.includes(queryTheme)) ? queryTheme
        : stored || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    $('#themeToggle')?.addEventListener('click', () => {
        const cur = document.documentElement.dataset.theme || 'dark';
        const idx = THEMES.indexOf(cur);
        const next = THEMES[(idx + 1) % THEMES.length];
        document.documentElement.dataset.theme = next;
        localStorage.setItem('theme', next);
    });
}

function setupDragDrop() {
    const dropZone = $('#dropZone');
    const input    = $('#fileInput');
    if (dropZone) {
        dropZone.addEventListener('click', () => input.click());
        dropZone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
        dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); });
        dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault(); dropZone.classList.remove('drag-over');
            const f = e.dataTransfer.files[0];
            if (f) startAnalysis(f);
        });
    }
    if (input) input.addEventListener('change', () => {
        const f = input.files[0];
        if (f) startAnalysis(f);
        input.value = '';
    });
    window.addEventListener('dragover', (e) => e.preventDefault());
    window.addEventListener('drop', (e) => {
        e.preventDefault();
        const f = e.dataTransfer.files[0];
        if (f && !document.body.classList.contains('analyzing')) startAnalysis(f);
    });
}

function setupGlobalErrors() {
    window.addEventListener('error', (e) => {
        if (e.error && e.error.message) {
            console.error('[IPAScope] error:', e.error);
            if (document.body.classList.contains('analyzing')) {
                hideProgress();
                toast('Analysis failed - ' + (e.error.message || 'unknown error'), 'error');
            }
        }
    });
    window.addEventListener('unhandledrejection', (e) => {
        console.error('[IPAScope] unhandled promise:', e.reason);
        if (document.body.classList.contains('analyzing')) {
            hideProgress();
            toast('Analysis failed - ' + (e.reason?.message || 'unknown error'), 'error');
        }
    });
}

async function shareCurrentReport() {
    const base = (IPAS.Config && IPAS.Config.API_BASE || '').trim();
    if (!base) {
        toast('Share backend not configured — see server/README.md', 'error');
        return;
    }
    if (!State.currentResults) return;
    try {
        const payload = IPAS.Export.buildShareable(State.currentResults);
        const res = await fetch(base.replace(/\/$/, '') + '/api/reports', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.message || err.error || ('HTTP ' + res.status));
        }
        const { id, deleteToken } = await res.json();
        const url = new URL(location.href);
        url.search = '?report=' + encodeURIComponent(id);
        url.hash = '';
        openShareModal(url.toString(), deleteToken);
        toast('Share link created', 'success');
    } catch (e) {
        toast('Share failed: ' + e.message, 'error');
    }
}

function openShareModal(link, deleteToken) {
    const overlay = $('#shareModalOverlay');
    if (!overlay) return;
    const linkInput = $('#shareLinkInput');
    const tokenInput = $('#shareDeleteTokenInput');
    if (linkInput) linkInput.value = link;
    if (tokenInput) tokenInput.value = deleteToken || '';
    overlay.hidden = false;
}

function copyField(selector, message) {
    const el = $(selector);
    if (!el || !el.value) return;
    const done = () => toast(message, 'success');
    const fail = () => toast('Copy failed — select the field and copy manually', 'error');
    if (navigator.clipboard?.writeText) {
        navigator.clipboard.writeText(el.value).then(done).catch(fail);
    } else {
        el.select();
        try { document.execCommand('copy'); done(); } catch (_) { fail(); }
    }
}

function setupShareModal() {
    const overlay = $('#shareModalOverlay');
    if (!overlay) return;
    const close = () => { overlay.hidden = true; };
    $('#shareModalClose')?.addEventListener('click', close);
    overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !overlay.hidden) close(); });
    $('#shareLinkCopyBtn')?.addEventListener('click', () => copyField('#shareLinkInput', 'Link copied'));
    $('#shareTokenCopyBtn')?.addEventListener('click', () => copyField('#shareDeleteTokenInput', 'Delete token copied'));
}

async function loadSharedReportFromURL() {
    const params = new URLSearchParams(location.search);
    const id = params.get('report');
    if (!id) return;
    const base = (IPAS.Config && IPAS.Config.API_BASE || '').trim();
    if (!base) {
        toast('This link needs a share backend configured on this deployment — see server/README.md', 'error');
        return;
    }
    try {
        const res = await fetch(base.replace(/\/$/, '') + '/api/reports/' + encodeURIComponent(id));
        if (!res.ok) {
            if (res.status === 404) throw new Error('This shared report was not found or has expired.');
            throw new Error('HTTP ' + res.status);
        }
        const { report } = await res.json();
        State.currentResults = report;
        renderAll(report);
        showApp();
        const banner = $('#sharedReportBanner');
        if (banner) banner.hidden = false;
        toast('Loaded shared report · Score ' + (report.securityScore ?? '?'), 'success');
    } catch (e) {
        toast('Could not load shared report: ' + e.message, 'error');
    }
}

function setupSharedReportBanner() {
    $('#sharedReportDismiss')?.addEventListener('click', () => {
        const banner = $('#sharedReportBanner');
        if (banner) banner.hidden = true;
    });
}

function init() {
    setupGlobalErrors();
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.getRegistrations().then(regs => regs.forEach(r => r.unregister())).catch(() => {});
        if (window.caches) caches.keys().then(ks => ks.forEach(k => caches.delete(k))).catch(() => {});
    }
    setupTheme();
    setupTabs();
    setupFindingsFilters();
    setupExport();
    setupShareModal();
    setupSharedReportBanner();
    setupDragDrop();
    $('#newScanBtn')?.addEventListener('click', () => $('#fileInput').click());
    $('#heroCta')?.addEventListener('click', () => $('#fileInput').click());
    $('#downloadFileBtn')?.addEventListener('click', downloadCurrentFile);
    document.querySelectorAll('a.logo, .logo[href]').forEach(el => {
        el.addEventListener('click', (e) => {
            e.preventDefault();
            showLanding();
        });
    });
    loadSharedReportFromURL();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();

})();
