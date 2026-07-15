/* IPAScope — Analysis Pipeline visualization (original).
 * SVG connectors + HTML glass nodes + rAF particle flow + staged activation.
 * GPU-friendly (transform-only particle motion), pauses off-screen, honors reduced-motion.
 */
(function () {
    'use strict';

    var stage = document.getElementById('pipelineStage');
    if (!stage) return;
    var svg = document.getElementById('pipelineSvg');
    var nodesEl = document.getElementById('pipelineNodes');
    if (!svg || !nodesEl) return;

    var mq = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)');
    var reduce = mq ? mq.matches : false;

    var VB_W = 1000, VB_H = 560;
    var SVG_NS = 'http://www.w3.org/2000/svg';

    // Node centers, in viewBox coordinates.
    var nodes = [
        { id: 'ipa',    label: 'IPA Package',        x: 92,  y: 280, kind: 'io' },
        { id: 'ext',    label: 'Package Extraction', x: 252, y: 280 },
        { id: 'macho',  label: 'Mach-O Parser',      x: 412, y: 280 },
        { id: 'ats',    label: 'ATS',                x: 600, y: 66 },
        { id: 'ent',    label: 'Entitlements',       x: 600, y: 152 },
        { id: 'sec',    label: 'Secrets',            x: 600, y: 238 },
        { id: 'swift',  label: 'SwiftUI',            x: 600, y: 324 },
        { id: 'bin',    label: 'Binary',             x: 600, y: 410 },
        { id: 'lib',    label: 'Libraries',          x: 600, y: 496 },
        { id: 'mitre',  label: 'MITRE Mapping',      x: 786, y: 280 },
        { id: 'report', label: 'Security Report',    x: 918, y: 280, kind: 'io' }
    ];
    var modules = ['ats', 'ent', 'sec', 'swift', 'bin', 'lib'];

    var edges = [['ipa', 'ext'], ['ext', 'macho']];
    modules.forEach(function (m) { edges.push(['macho', m]); });
    modules.forEach(function (m) { edges.push([m, 'mitre']); });
    edges.push(['mitre', 'report']);

    var byId = {};
    nodes.forEach(function (n) { byId[n.id] = n; });

    // Build nodes
    nodes.forEach(function (n) {
        var el = document.createElement('div');
        el.className = 'pnode' + (n.kind === 'io' ? ' pnode-io' : '');
        el.style.left = (n.x / VB_W * 100) + '%';
        el.style.top = (n.y / VB_H * 100) + '%';
        el.innerHTML = '<span class="pnode-dot"></span><span class="pnode-label"></span>';
        el.querySelector('.pnode-label').textContent = n.label;
        nodesEl.appendChild(el);
        n.el = el;
    });

    // Build curved edges
    edges.forEach(function (e) {
        var a = byId[e[0]], b = byId[e[1]];
        var dx = (b.x - a.x) * 0.5;
        var d = 'M ' + a.x + ' ' + a.y +
                ' C ' + (a.x + dx) + ' ' + a.y + ', ' + (b.x - dx) + ' ' + b.y + ', ' + b.x + ' ' + b.y;
        var path = document.createElementNS(SVG_NS, 'path');
        path.setAttribute('d', d);
        path.setAttribute('class', 'pedge');
        path.setAttribute('fill', 'none');
        svg.appendChild(path);
        e.path = path;
        e.len = path.getTotalLength();
    });

    // Particles (skipped entirely under reduced-motion)
    var particles = [];
    if (!reduce) {
        edges.forEach(function (e) {
            var count = e.len > 220 ? 2 : 1;
            for (var i = 0; i < count; i++) {
                var p = document.createElement('div');
                p.className = 'pparticle';
                nodesEl.appendChild(p);
                particles.push({ el: p, edge: e, t: i / count, speed: 0.11 + (Math.min(e.len, 500) / 5200) });
            }
        });
    }

    var raf = 0, last = 0, running = false;

    function frame(ts) {
        if (!last) last = ts;
        var dt = Math.min((ts - last) / 1000, 0.05);
        last = ts;
        var rect = stage.getBoundingClientRect();
        var sx = rect.width / VB_W, sy = rect.height / VB_H;
        for (var i = 0; i < particles.length; i++) {
            var pt = particles[i];
            pt.t += pt.speed * dt;
            if (pt.t > 1) pt.t -= 1;
            var pos = pt.edge.path.getPointAtLength(pt.t * pt.edge.len);
            var x = pos.x * sx - 3, y = pos.y * sy - 3;
            pt.el.style.transform = 'translate(' + x + 'px,' + y + 'px)';
            var fade = Math.min(pt.t, 1 - pt.t) * 10;
            pt.el.style.opacity = fade < 1 ? (fade < 0 ? 0 : fade) : 1;
        }
        raf = requestAnimationFrame(frame);
    }

    // Staged activation: light nodes one by one, complete them, loop.
    var seq = ['ipa', 'ext', 'macho', 'ats', 'ent', 'sec', 'swift', 'bin', 'lib', 'mitre', 'report'];
    var seqIdx = 0, seqTimer = 0;

    function resetSeq() {
        nodes.forEach(function (n) { n.el.classList.remove('active', 'done'); });
        seqIdx = 0;
    }

    function step() {
        if (seqIdx > 0) {
            var prev = byId[seq[seqIdx - 1]].el;
            prev.classList.remove('active');
            prev.classList.add('done');
        }
        if (seqIdx >= seq.length) {
            seqTimer = setTimeout(function () { resetSeq(); step(); }, 1500);
            return;
        }
        byId[seq[seqIdx]].el.classList.add('active');
        seqIdx++;
        seqTimer = setTimeout(step, 640);
    }

    function start() {
        if (running || reduce) return;
        running = true;
        last = 0;
        if (particles.length) raf = requestAnimationFrame(frame);
        step();
    }
    function stop() {
        running = false;
        if (raf) { cancelAnimationFrame(raf); raf = 0; }
        if (seqTimer) { clearTimeout(seqTimer); seqTimer = 0; }
    }

    if (reduce) {
        // Static, calm end-state so the diagram still reads.
        nodes.forEach(function (n) { n.el.classList.add('done'); });
        return;
    }

    // Only animate while on-screen.
    if ('IntersectionObserver' in window) {
        var io = new IntersectionObserver(function (entries) {
            entries.forEach(function (en) { en.isIntersecting ? start() : stop(); });
        }, { threshold: 0.15 });
        io.observe(stage);
    } else {
        start();
    }
})();

/* IPA Loaded demo card — looping "live analysis" reveal */
(function () {
    'use strict';
    var card = document.querySelector('.ipa-summary');
    if (!card) return;
    var rows = Array.prototype.slice.call(card.querySelectorAll('.ipa-summary-row'));
    var label = card.querySelector('.ipa-summary-label');
    var scoreEl = card.querySelector('.ipa-summary-score');
    var dot = card.querySelector('.ipa-summary-dot');
    if (!rows.length || !label || !scoreEl) return;

    var mq = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)');
    if (mq && mq.matches) return; // keep the static final state

    var TARGET = 92, STEP = 300;
    var timers = [], running = false;
    function clearTimers() { timers.forEach(clearTimeout); timers = []; }

    function settle() {
        card.classList.remove('scanning');
        if (dot) dot.classList.remove('scanning');
        label.textContent = 'IPA Loaded';
        scoreEl.textContent = TARGET;
        rows.forEach(function (r) { r.classList.add('shown'); r.classList.remove('flash'); });
    }

    function cycle() {
        clearTimers();
        card.classList.add('scanning');
        if (dot) dot.classList.add('scanning');
        label.textContent = 'Analyzing…';
        scoreEl.textContent = '—';
        rows.forEach(function (r) { r.classList.remove('shown', 'flash'); });

        rows.forEach(function (r, i) {
            timers.push(setTimeout(function () {
                r.classList.add('shown', 'flash');
                timers.push(setTimeout(function () { r.classList.remove('flash'); }, 480));
                scoreEl.textContent = Math.round(TARGET * (i + 1) / rows.length);
            }, STEP * (i + 1)));
        });

        timers.push(setTimeout(settle, STEP * (rows.length + 1)));
        timers.push(setTimeout(cycle, STEP * (rows.length + 1) + 2600));
    }

    function begin() { if (running) return; running = true; cycle(); }
    function halt() { running = false; clearTimers(); settle(); }

    if ('IntersectionObserver' in window) {
        var io = new IntersectionObserver(function (entries) {
            entries.forEach(function (en) { en.isIntersecting ? begin() : halt(); });
        }, { threshold: 0.3 });
        io.observe(card);
    } else {
        begin();
    }
})();
