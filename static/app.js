/* ================================================================
   CyberStrike Suite — Enterprise Controller (app.js v20)
   ThreeUI Spatial WebGL • Bklit UI Charts • Aceternity Spotlights
   ================================================================ */

'use strict';

// ── State ─────────────────────────────────────────────────────────
let BACKEND_HOST = '';
let ws = null;
let currentAttackId = null;
let vulnCount = 0;
let historyCount = 0;
let hasLiveVelocity = false;
let recentReqSamples = [];
let lastSampleTotalReqs = 0;
let liveRps = 0;
let peakRps = 0;
let sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };

let metricsData = {
    total_requests: 0,
    successful_requests: 0,
    failed_requests: 0,
    rps_history: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    findings_history: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
};

// ── Helper: get backend URLs ───────────────────────────────────────
function getBackendUrls() {
    const secure = BACKEND_HOST.includes('.hf.space') || location.protocol === 'https:';
    return {
        http: `${secure ? 'https' : 'http'}://${BACKEND_HOST}`,
        ws:   `${secure ? 'wss'   : 'ws'  }://${BACKEND_HOST}/ws`
    };
}

// ── Helper: sanitize host input ────────────────────────────────────
function sanitizeHost(raw) {
    if (!raw) return '';
    try {
        const s = raw.trim();
        const hf = s.match(/huggingface\.co\/spaces\/([^\/\s]+)\/([^\/\s?#]+)/i);
        if (hf) return `${hf[1]}-${hf[2].toLowerCase().replace(/_/g, '-')}.hf.space`;
        if (s.includes('://')) return new URL(s).hostname;
        return s.split('/')[0].trim();
    } catch {
        return raw.split('/')[0].trim();
    }
}

// ── Helper: safe getElementById ────────────────────────────────────
const el = (id) => document.getElementById(id);

// ── Navigation ─────────────────────────────────────────────────────
function switchToPage(pageId) {
    const links = document.querySelectorAll('.slink[data-page]');
    const pages = document.querySelectorAll('.page[id]');
    if (history.replaceState) history.replaceState(null, '', location.pathname);
    links.forEach(l => l.classList.toggle('active', l.dataset.page === pageId));
    pages.forEach(p => p.classList.toggle('active', p.id === `${pageId}-page`));
}

function initNav() {
    const links = document.querySelectorAll('.slink[data-page]');
    links.forEach(link => {
        link.addEventListener('click', e => {
            e.preventDefault();
            switchToPage(link.dataset.page);
        });
    });
}

// ── Attack type selector ───────────────────────────────────────────
function initAttackSelector() {
    const items = document.querySelectorAll('.atk-item[data-attack]');
    const typeInput   = el('attack-type-input');
    const activeBadge = el('active-module-badge');
    const bruteBox    = el('brute-fields');
    const portBox     = el('port-fields');
    const intGrp      = el('intensity-group');
    const thrdGrp     = el('threads-group');

    items.forEach(item => {
        item.addEventListener('click', () => {
            items.forEach(i => i.classList.remove('selected'));
            item.classList.add('selected');

            const t = item.dataset.attack;
            if (typeInput)   typeInput.value = t;
            if (activeBadge) activeBadge.textContent = t.toUpperCase();

            if (bruteBox) bruteBox.style.display = t === 'brute' ? 'block' : 'none';
            if (portBox)  portBox.style.display  = t === 'port'  ? 'block' : 'none';

            const showBoth     = ['ddos', 'cache_bust', 'heavy_post', 'ws_flood', 'api_flood', 'slowloris', 'brute', 'ip_stress', 'ssti', 'nosql', 'jwt_audit', 'graphql_audit', 'cors_audit', 'host_header'].includes(t);
            const hideDuration = ['sql', 'xss', 'stored_xss', 'csrf', 'idor', 'redirect', 'header_inj', 'cmd', 'ssrf', 'xxe', 'traversal', 'port'].includes(t);

            if (intGrp)  intGrp.style.display  = showBoth ? 'block' : 'none';
            if (thrdGrp) thrdGrp.style.display = showBoth ? 'block' : 'none';

            const durGrp = el('duration-input')?.closest('.field');
            if (durGrp) durGrp.style.display = hideDuration ? 'none' : 'block';

            const sqlFields    = el('sql-fields');
            const xssFields    = el('xss-fields');
            const cmdFields    = el('cmd-fields');
            const ssrfFields   = el('ssrf-fields');
            const xxeFields    = el('xxe-fields');
            const travFields   = el('traversal-fields');
            const headerFields = el('header_inj-fields');
            const ipFields     = el('ip-stress-fields');
            const phoneFields  = el('phone-probe-fields');

            if (sqlFields)    sqlFields.style.display    = (t === 'sql') ? 'block' : 'none';
            if (xssFields)    xssFields.style.display    = (t === 'xss' || t === 'stored_xss') ? 'block' : 'none';
            if (cmdFields)    cmdFields.style.display    = (t === 'cmd') ? 'block' : 'none';
            if (ssrfFields)   ssrfFields.style.display   = (t === 'ssrf') ? 'block' : 'none';
            if (xxeFields)    xxeFields.style.display    = (t === 'xxe') ? 'block' : 'none';
            if (travFields)   travFields.style.display   = (t === 'traversal') ? 'block' : 'none';
            if (headerFields) headerFields.style.display = (t === 'header_inj') ? 'block' : 'none';
            if (ipFields)     ipFields.style.display     = (t === 'ip_stress') ? 'block' : 'none';
            if (phoneFields)  phoneFields.style.display  = (t === 'phone_probe') ? 'block' : 'none';

            const urlInput = el('url-input');
            if (t === 'ip_stress' && urlInput) {
                const ipTarget = el('ip-stress-target');
                if (ipTarget) {
                    ipTarget.oninput = () => { urlInput.value = ipTarget.value; };
                    if (ipTarget.value) urlInput.value = ipTarget.value;
                }
            }
            if (t === 'phone_probe' && urlInput) {
                const phoneTarget = el('phone-probe-target');
                if (phoneTarget) {
                    phoneTarget.oninput = () => { urlInput.value = phoneTarget.value; };
                    if (phoneTarget.value) urlInput.value = phoneTarget.value;
                }
            }
        });
    });
}

// ── Log helpers ────────────────────────────────────────────────────
function addLog(msg, level = 'info') {
    const box = el('log-container');
    if (!box) return;
    const d = document.createElement('div');
    d.className = `log-line log-${level}`;
    d.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    box.appendChild(d);
    box.scrollTop = box.scrollHeight;
    while (box.children.length > 150) box.removeChild(box.firstChild);
}

// ── Metrics update ─────────────────────────────────────────────────
function updateStats(data) {
    if (data.total_requests      != null) metricsData.total_requests      = data.total_requests;
    if (data.successful_requests != null) metricsData.successful_requests = data.successful_requests;
    if (data.failed_requests     != null) metricsData.failed_requests     = data.failed_requests;

    const tr = el('total-requests');
    const sr = el('successful-requests');
    const fr = el('failed-requests');
    if (tr) tr.textContent = metricsData.total_requests.toLocaleString();
    if (sr) sr.textContent = metricsData.successful_requests.toLocaleString();
    if (fr) fr.textContent = metricsData.failed_requests.toLocaleString();

    // Update KPI progress bars & percentage badges
    const total = Math.max(metricsData.total_requests, 1);
    const sPct  = metricsData.total_requests > 0 ? Math.round((metricsData.successful_requests / total) * 100) : 100;
    const fPct  = metricsData.total_requests > 0 ? Math.round((metricsData.failed_requests / total) * 100) : 0;

    const sBadge = el('success-rate-badge');
    const eBadge = el('error-rate-badge');
    const bSucc  = el('bar-success');
    const bFail  = el('bar-failed');
    if (sBadge) sBadge.textContent = `${sPct}%`;
    if (eBadge) eBadge.textContent = `${fPct}%`;
    if (bSucc)  bSucc.style.width  = `${sPct}%`;
    if (bFail)  bFail.style.width  = `${fPct}%`;

    // Record cumulative request total with timestamp for smooth rolling window velocity
    const nowMs = Date.now();
    recentReqSamples.push({ t: nowMs, total: metricsData.total_requests });
    while (recentReqSamples.length > 1 && nowMs - recentReqSamples[0].t > 2500) {
        recentReqSamples.shift();
    }
    if (recentReqSamples.length >= 2) {
        const oldest = recentReqSamples[0];
        const newest = recentReqSamples[recentReqSamples.length - 1];
        const dtSec  = Math.max((newest.t - oldest.t) / 1000, 0.4);
        const dReq   = Math.max(0, newest.total - oldest.total);
        const rawRps = dReq / dtSec;
        liveRps = Math.round((liveRps * 0.35 + rawRps * 0.65) * 10) / 10;
        if (liveRps < 0.15 && dReq === 0) liveRps = 0;
        if (liveRps > peakRps) peakRps = liveRps;
    }

    const avgB  = el('avg-latency-badge');
    const peakB = el('peak-latency-badge');
    const topL  = el('top-avg-latency');
    if (avgB)  avgB.textContent  = `Live: ${liveRps.toFixed(1)} req/s`;
    if (peakB) peakB.textContent = `Peak: ${peakRps.toFixed(1)} req/s`;
    if (topL)  topL.textContent  = `${sPct}%`;

    if (window.bklitLiveChart) {
        window.bklitLiveChart.setTargetValue(liveRps);
    }

    updateCharts();
}

// ── Status dot ─────────────────────────────────────────────────────
function setStatus(state, label) {
    const dot      = el('status-indicator');
    const text     = el('status-text');
    const cardDot  = el('card-status-dot');
    const cardText = el('card-status-text');
    if (dot)      dot.className       = `status-dot ${state}`;
    if (text)     text.textContent    = label;
    if (cardDot)  cardDot.className   = `status-dot ${state}`;
    if (cardText) cardText.textContent = label;
}

// ── Theme toggle (Light / Dark Mode) ───────────────────────────────
function applyTheme(theme) {
    const isLight = theme === 'light';
    if (isLight) {
        document.documentElement.setAttribute('data-theme', 'light');
    } else {
        document.documentElement.removeAttribute('data-theme');
    }
    localStorage.setItem('cyberstrike_theme', isLight ? 'light' : 'dark');
    const icon  = el('theme-icon');
    const label = el('theme-label');
    if (icon)  icon.className    = isLight ? 'fas fa-moon' : 'fas fa-sun';
    if (label) label.textContent = isLight ? 'Dark' : 'Light';

    const gridColor  = isLight ? 'rgba(15, 23, 42, 0.07)' : 'rgba(255, 255, 255, 0.05)';
    const tickColor  = isLight ? '#64748b' : '#71717a';

    if (window.bklitLiveChart) {
        window.bklitLiveChart.setTheme(isLight);
    }
    if (window.requestRateChart) {
        const rr = window.requestRateChart;
        rr.options.scales.y.grid.color  = gridColor;
        rr.options.scales.y.ticks.color = tickColor;
        rr.options.scales.x.ticks.color = tickColor;
        rr.update('none');
    }
}

// ── Attack status ──────────────────────────────────────────────────
function handleAttackStatus(s) {
    const startBtn = el('start-attack');
    const stopBtn  = el('stop-attack');

    if (s.running) {
        setStatus('running', s.attack_type ? `Running: ${s.attack_type.toUpperCase()}` : 'Running...');
        if (startBtn) startBtn.disabled = true;
        if (stopBtn)  stopBtn.disabled  = false;
    } else {
        setStatus('ready', 'Ready');
        if (startBtn) startBtn.disabled = false;
        if (stopBtn)  stopBtn.disabled  = true;
        if (s.completed) {
            addLog(`Completed: ${(s.attack_type || '').toUpperCase()} — ${s.total_requests || 0} requests`, 'success');
            addHistoryEntry(s);
        }
    }
}

// ── Vulnerability card ─────────────────────────────────────────────
function updateVulnBadges() {
    const navV = el('nav-vuln-count');
    const topV = el('top-findings-count');
    const hdrV = el('findings-header-badge');
    const hudV = el('hud-vuln-total');
    if (navV) navV.textContent = String(vulnCount);
    if (topV) topV.textContent = String(vulnCount);
    if (hdrV) hdrV.textContent = `${vulnCount} Finding${vulnCount === 1 ? '' : 's'}`;
    if (hudV) hudV.textContent = String(vulnCount);
}

function addVuln(v) {
    const box = el('vulnerabilities-container');
    if (!box) return;
    const empty = box.querySelector('.empty-state');
    if (empty) empty.remove();

    vulnCount += 1;
    const sev = String(v.severity || 'Medium');
    if (/critical/i.test(sev)) sevCounts.Critical += 1;
    else if (/high/i.test(sev)) sevCounts.High += 1;
    else if (/low/i.test(sev)) sevCounts.Low += 1;
    else sevCounts.Medium += 1;

    updateVulnBadges();
    updateCharts();

    const d = document.createElement('div');
    d.className = 'vuln-item glass-card spotlight-card';
    d.style.marginBottom = '14px';

    let detailHTML = '';
    if (v.detail) {
        detailHTML = `<p style="margin-top:10px;font-size:0.84rem;color:var(--t2)"><strong>Analysis:</strong> ${v.detail}</p>`;
    }

    let evidenceHTML = '';
    if (v.evidence) {
        const ev = String(v.evidence).replace(/</g, '&lt;').replace(/>/g, '&gt;');
        evidenceHTML = `<div style="margin-top:12px;padding:10px 12px;background:var(--bg-surface);border-radius:6px;border-left:3px solid var(--danger);font-family:var(--mono);font-size:0.75rem;color:var(--t1);overflow-x:auto;"><strong>Proof / Telemetry Evidence:</strong><br><br>${ev}</div>`;
    }

    d.innerHTML = `
        <div class="card-body" style="padding:16px;">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">
                <h5 style="margin:0;font-size:1.02rem;color:var(--danger);font-weight:700"><i class="fas fa-bug" style="margin-right:8px"></i>${v.type || 'Security Finding'}</h5>
                ${v.severity ? `<span class="bklit-badge danger" style="text-transform:uppercase;letter-spacing:0.06em">${v.severity}</span>` : ''}
            </div>
            <p style="margin:0 0 6px 0;font-size:0.84rem;color:var(--t1)">
                <i class="fas fa-crosshairs" style="color:var(--t3);margin-right:6px"></i>
                <strong>Endpoint:</strong> <span style="font-family:var(--mono);color:var(--primary)">${v.url || '-'}</span>
            </p>
            ${v.payload ? `<p style="margin:0;font-size:0.84rem;color:var(--t2)"><i class="fas fa-code" style="color:var(--t3);margin-right:6px"></i><strong>Vector:</strong> <code style="margin-left:4px;color:var(--primary);font-family:var(--mono)">${String(v.payload).replace(/</g, '&lt;').replace(/>/g, '&gt;')}</code></p>` : ''}
            ${detailHTML}
            ${evidenceHTML}
            <div style="margin-top:12px;text-align:right;font-size:0.72rem;color:var(--t3);border-top:1px solid var(--gb);padding-top:8px;">
                <i class="fas fa-clock"></i> Verified: ${v.timestamp ? new Date(v.timestamp).toLocaleString() : new Date().toLocaleString()}
            </div>
        </div>
    `;
    box.insertBefore(d, box.firstChild);
}

// ── History entry ──────────────────────────────────────────────────
function addHistoryEntry(a) {
    const box = el('attack-history-container');
    if (!box) return;
    const empCard = box.querySelector('.glass-card');
    if (empCard && empCard.querySelector('.empty-state')) empCard.remove();

    historyCount += 1;
    const navH = el('nav-history-count');
    if (navH) navH.textContent = String(historyCount);

    const d = document.createElement('div');
    d.className = 'glass-card spotlight-card';
    d.style.marginBottom = '10px';
    d.innerHTML = `
        <div class="card-body" style="display:flex;justify-content:space-between;align-items:center">
            <div>
                <div style="display:flex;align-items:center;gap:8px">
                    <span class="bklit-pill">${(a.attack_type || 'AUDIT').toUpperCase()}</span>
                    <span style="font-family:var(--mono);font-size:0.82rem;color:var(--t1)">${a.url || ''}</span>
                </div>
                <div style="font-size:.73rem;color:var(--t3);margin-top:6px">${a.timestamp ? new Date(a.timestamp).toLocaleString() : ''}</div>
            </div>
            <div style="text-align:right">
                <div style="font-family:var(--mono);font-size:1.35rem;font-weight:700;color:var(--t1)">${(a.total_requests || 0).toLocaleString()}</div>
                <div style="font-size:.7rem;color:var(--t3)">requests dispatched</div>
            </div>
        </div>
    `;
    box.insertBefore(d, box.firstChild);
}

// ── Official @bklit/live-line-chart Component Engine ───────────────
// Direct port of https://ui.bklit.com/r/live-line-chart.json
// (LiveLineChart + LiveLine + LiveXAxis + LiveYAxis + curveMonotoneX)
function createBklitLiveLineChart(container) {
    const LERP_SPEED      = 0.08;
    const WINDOW_SECS     = 30;
    const WINDOW_MS       = WINDOW_SECS * 1000;
    const NUM_X_TICKS     = 5;
    const NOW_OFFSET_UNIT = 0.65;
    const X_TICK_UNIT_MS  = WINDOW_MS / (NUM_X_TICKS - 1);
    const LEADING_MS      = NOW_OFFSET_UNIT * X_TICK_UNIT_MS;
    const MARGIN          = { top: 20, right: 14, bottom: 30, left: 42 };
    const EDGE_FADE_PX    = 26;
    const TICKER_HALF_W   = 50;
    const FADE_BUFFER     = 20;

    // Seed 30s of initial data points so the live curve spans the full window immediately
    const nowInitSec = Date.now() / 1000;
    let points = [];
    for (let i = 60; i >= 0; i--) {
        points.push({ time: nowInitSec - i * 0.5, value: 0 });
    }

    let targetValue = 0;
    let frame = {
        now: Date.now(),
        yMin: 0,
        yMax: 10,
        displayValue: 0
    };
    let prevInterval = 0;
    let cursorX = null;
    let isLight = document.documentElement.getAttribute('data-theme') === 'light';

    // Format HH:MM:SS
    const hmsFmt = new Intl.DateTimeFormat(undefined, {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });
    const formatTime = (ms) => hmsFmt.format(new Date(ms));
    const formatBadgeValue = (v) => `${Math.max(0, v).toFixed(1)} req/s`;
    const formatYValue = (v) => (v < 0 ? '' : v >= 10 ? String(Math.round(v)) : v.toFixed(1));

    // Build DOM & SVG matching @bklit/live-line-chart
    container.innerHTML = `
        <svg aria-hidden="true" style="display:block;width:100%;height:100%;overflow:visible;">
            <defs>
                <linearGradient id="bklit-live-line-grad" x1="0" x2="0" y1="0" y2="1">
                    <stop id="bklit-grad-stop-1" offset="0%" stop-color="#f59e0b" stop-opacity="1" />
                    <stop id="bklit-grad-stop-2" offset="100%" stop-color="#f59e0b" stop-opacity="0.65" />
                </linearGradient>
                <linearGradient id="bklit-live-area-grad" x1="0" x2="0" y1="0" y2="1">
                    <stop id="bklit-area-stop-1" offset="0%" stop-color="#f59e0b" stop-opacity="0.14" />
                    <stop id="bklit-area-stop-2" offset="100%" stop-color="#f59e0b" stop-opacity="0" />
                </linearGradient>
                <linearGradient id="bklit-live-fade" x1="0" x2="1" y1="0" y2="0">
                    <stop offset="0%" stop-color="white" stop-opacity="0" />
                    <stop offset="4%" stop-color="white" stop-opacity="1" />
                    <stop id="bklit-fade-dot-stop" offset="84%" stop-color="white" stop-opacity="1" />
                    <stop offset="100%" stop-color="white" stop-opacity="0" />
                </linearGradient>
                <mask id="bklit-live-fade-mask">
                    <rect id="bklit-fade-mask-rect" x="0" y="-20" width="600" height="260" fill="url(#bklit-live-fade)" />
                </mask>
            </defs>
            <g id="bklit-chart-g" transform="translate(${MARGIN.left},${MARGIN.top})" style="cursor:crosshair;">
                <rect id="bklit-hit-rect" x="0" y="0" width="600" height="190" fill="transparent" />
                <g id="bklit-grid-g"></g>
                <g mask="url(#bklit-live-fade-mask)">
                    <path id="bklit-area-path" fill="url(#bklit-live-area-grad)" stroke-width="0" />
                    <path id="bklit-line-path" fill="none" stroke="url(#bklit-live-line-grad)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
                </g>
                <line id="bklit-live-guide" x1="0" x2="600" y1="190" y2="190" stroke="#f59e0b" stroke-width="1" stroke-dasharray="4,4" opacity="0.25" />
                <g id="bklit-scrub-g" style="opacity:0;transition:opacity 0.15s ease;pointer-events:none;">
                    <line id="bklit-scrub-line" x1="0" x2="0" y1="0" y2="190" stroke="#a1a1aa" stroke-width="1" stroke-dasharray="3,3" opacity="0.55" />
                    <circle id="bklit-scrub-dot" cx="0" cy="0" r="4" fill="#f59e0b" stroke="var(--bg-card)" stroke-width="2" />
                </g>
                <g id="bklit-live-tip-g" style="transition:opacity 0.25s ease;pointer-events:none;">
                    <circle id="bklit-live-halo" cx="0" cy="0" r="7" fill="#f59e0b" opacity="0.14" />
                    <circle id="bklit-live-dot" cx="0" cy="0" r="4" fill="#f59e0b" stroke="var(--bg-card)" stroke-width="2" />
                    <g id="bklit-live-badge" transform="translate(0,0)">
                        <rect id="bklit-live-badge-rect" x="0" y="-11" height="22" rx="6" fill="var(--bg-elevated)" stroke="var(--gb-bright)" stroke-width="1" opacity="0.96" />
                        <text id="bklit-live-badge-text" x="7" y="4" fill="var(--t1)" font-family="'JetBrains Mono', monospace" font-size="10.5" font-weight="600">0.0 req/s</text>
                    </g>
                </g>
            </g>
        </svg>
        <div id="bklit-y-axis" style="position:absolute;top:${MARGIN.top}px;left:0;width:${MARGIN.left}px;overflow:hidden;pointer-events:none;"></div>
        <div id="bklit-x-axis" style="position:absolute;inset:0;pointer-events:none;"></div>
        <div id="bklit-hover-pill" style="position:absolute;bottom:2px;left:0;transform:translateX(-50%);opacity:0;transition:opacity 0.15s ease;pointer-events:none;z-index:20;">
            <div style="border-radius:9999px;background:var(--t1);color:var(--bg-base);padding:2px 10px;font-family:'JetBrains Mono',monospace;font-size:10.5px;font-weight:600;white-space:nowrap;box-shadow:0 4px 12px rgba(0,0,0,0.22);">
                <span id="bklit-hover-pill-text"></span>
            </div>
        </div>
    `;

    const svgEl        = container.querySelector('svg');
    const chartG       = container.querySelector('#bklit-chart-g');
    const hitRect      = container.querySelector('#bklit-hit-rect');
    const gridG        = container.querySelector('#bklit-grid-g');
    const fadeDotStop  = container.querySelector('#bklit-fade-dot-stop');
    const fadeMaskRect = container.querySelector('#bklit-fade-mask-rect');
    const areaPathEl   = container.querySelector('#bklit-area-path');
    const linePathEl   = container.querySelector('#bklit-line-path');
    const liveGuideEl  = container.querySelector('#bklit-live-guide');
    const scrubG       = container.querySelector('#bklit-scrub-g');
    const scrubLine    = container.querySelector('#bklit-scrub-line');
    const scrubDot     = container.querySelector('#bklit-scrub-dot');
    const liveTipG     = container.querySelector('#bklit-live-tip-g');
    const liveHalo     = container.querySelector('#bklit-live-halo');
    const liveDot      = container.querySelector('#bklit-live-dot');
    const liveBadge    = container.querySelector('#bklit-live-badge');
    const liveBadgeRect= container.querySelector('#bklit-live-badge-rect');
    const liveBadgeText= container.querySelector('#bklit-live-badge-text');
    const yAxisEl      = container.querySelector('#bklit-y-axis');
    const xAxisEl      = container.querySelector('#bklit-x-axis');
    const hoverPillEl  = container.querySelector('#bklit-hover-pill');
    const hoverPillTxt = container.querySelector('#bklit-hover-pill-text');

    // Create 5 reusable X-axis tick DOM nodes
    const xTickNodes = [];
    for (let i = 0; i < NUM_X_TICKS; i++) {
        const wrap = document.createElement('div');
        wrap.style.cssText = 'position:absolute;bottom:6px;width:0;display:flex;justify-content:center;';
        const span = document.createElement('span');
        span.style.cssText = 'white-space:nowrap;font-family:"JetBrains Mono",monospace;font-size:10px;color:var(--t3);transition:opacity 0.15s ease;';
        wrap.appendChild(span);
        xAxisEl.appendChild(wrap);
        xTickNodes.push({ wrap, span });
    }

    // Mouse / pointer scrubbing interactions
    chartG.addEventListener('mousemove', (e) => {
        const rect = svgEl.getBoundingClientRect();
        const x = e.clientX - rect.left - MARGIN.left;
        const innerW = Math.max(1, rect.width - MARGIN.left - MARGIN.right);
        cursorX = (x >= 0 && x <= innerW) ? x : null;
    });
    chartG.addEventListener('mouseleave', () => {
        cursorX = null;
    });

    // Compute target Y range from visible points + latest value (computeTargetRange from live-line-chart.tsx)
    function computeTargetRange(visiblePts, val) {
        let min = 0;
        let max = val;
        for (let i = 0; i < visiblePts.length; i++) {
            const v = visiblePts[i].value;
            if (v > max) max = v;
        }
        const rawRange = Math.max(max - min, 5);
        const pad = rawRange * 0.18;
        return { yMin: 0, yMax: max + pad };
    }

    // pickNiceInterval with hysteresis (from live-y-axis.tsx)
    function pickNiceInterval(valRange, chartHeight, minGap) {
        if (valRange <= 0 || chartHeight <= 0) return 1;
        const pxPerUnit = chartHeight / valRange;
        if (prevInterval > 0) {
            const px = prevInterval * pxPerUnit;
            if (px >= minGap * 0.55 && px <= minGap * 2.8) return prevInterval;
        }
        const divisorSets = [[2, 2.5, 2], [2, 2, 2.5], [2.5, 2, 2]];
        let best = Number.POSITIVE_INFINITY;
        for (const divs of divisorSets) {
            let span = Math.pow(10, Math.ceil(Math.log10(valRange)));
            let i = 0;
            let d = divs[i % 3];
            while ((span / d) * pxPerUnit >= minGap) {
                span /= d;
                i++;
                d = divs[i % 3];
            }
            if (span < best) best = span;
        }
        prevInterval = best === Number.POSITIVE_INFINITY ? valRange / 4 : best;
        return prevInterval;
    }

    // Monotone cubic Hermite spline path generator (@visx/curve curveMonotoneX)
    function buildMonotoneCubicPaths(coords, baselineY) {
        const n = coords.length;
        if (n === 0) return { line: '', area: '' };
        if (n === 1) {
            const p = coords[0];
            return {
                line: `M ${p.x.toFixed(2)},${p.y.toFixed(2)}`,
                area: `M ${p.x.toFixed(2)},${baselineY.toFixed(2)} L ${p.x.toFixed(2)},${p.y.toFixed(2)} Z`
            };
        }
        const dx = new Array(n - 1);
        const dy = new Array(n - 1);
        const m  = new Array(n - 1);
        for (let i = 0; i < n - 1; i++) {
            dx[i] = Math.max(coords[i + 1].x - coords[i].x, 1e-4);
            dy[i] = coords[i + 1].y - coords[i].y;
            m[i]  = dy[i] / dx[i];
        }
        const tangents = new Array(n);
        tangents[0]     = m[0];
        tangents[n - 1] = m[n - 2];
        for (let i = 1; i < n - 1; i++) {
            const m0 = m[i - 1];
            const m1 = m[i];
            if (m0 * m1 <= 0) {
                tangents[i] = 0;
            } else {
                const dx0 = dx[i - 1];
                const dx1 = dx[i];
                const common = dx0 + dx1;
                tangents[i] = (3 * common) / ((common + dx1) / m0 + (common + dx0) / m1);
            }
        }
        let d = `M ${coords[0].x.toFixed(2)},${coords[0].y.toFixed(2)}`;
        for (let i = 0; i < n - 1; i++) {
            const p0 = coords[i];
            const p1 = coords[i + 1];
            const step = dx[i] / 3;
            const cp1x = p0.x + step;
            const cp1y = p0.y + tangents[i] * step;
            const cp2x = p1.x - step;
            const cp2y = p1.y - tangents[i + 1] * step;
            d += ` C ${cp1x.toFixed(2)},${cp1y.toFixed(2)} ${cp2x.toFixed(2)},${cp2y.toFixed(2)} ${p1.x.toFixed(2)},${p1.y.toFixed(2)}`;
        }
        const area = `${d} L ${coords[n - 1].x.toFixed(2)},${baselineY.toFixed(2)} L ${coords[0].x.toFixed(2)},${baselineY.toFixed(2)} Z`;
        return { line: d, area };
    }

    // Binary search interpolation at timeSec (interpolateAtTime from live-line-chart.tsx)
    function interpolateAtTime(pts, timeSec) {
        if (!pts.length) return 0;
        if (timeSec <= pts[0].time) return pts[0].value;
        if (timeSec >= pts[pts.length - 1].time) return pts[pts.length - 1].value;
        let lo = 0;
        let hi = pts.length - 1;
        while (hi - lo > 1) {
            const mid = (lo + hi) >> 1;
            if (pts[mid].time <= timeSec) lo = mid;
            else hi = mid;
        }
        const p1 = pts[lo];
        const p2 = pts[hi];
        const dt = p2.time - p1.time;
        if (dt <= 0) return p1.value;
        return p1.value + ((timeSec - p1.time) / dt) * (p2.value - p1.value);
    }

    // Stream sample every 450ms so the chart advances smoothly even when idle
    setInterval(() => {
        const nowMs = Date.now();
        // Decay liveRps gently if no new requests arrived in the last 1.6s
        if (recentReqSamples.length > 0) {
            const lastSampleAge = nowMs - recentReqSamples[recentReqSamples.length - 1].t;
            if (lastSampleAge > 1600 && liveRps > 0) {
                liveRps = Math.max(0, Math.round(liveRps * 0.72 * 10) / 10);
                if (liveRps < 0.2) liveRps = 0;
                targetValue = liveRps;
                const avgB = el('avg-latency-badge');
                if (avgB) avgB.textContent = `Live: ${liveRps.toFixed(1)} req/s`;
            }
        }
        points.push({ time: nowMs / 1000, value: targetValue });
        const cutoff = (nowMs - 90000) / 1000;
        while (points.length > 2 && points[0].time < cutoff) {
            points.shift();
        }
    }, 450);

    // 60fps animation loop (nextAnimFrame from live-line-chart.tsx)
    function renderTick() {
        const rect = container.getBoundingClientRect();
        const width  = Math.max(260, rect.width  || 560);
        const height = Math.max(180, rect.height || 240);
        const innerW = Math.max(100, width - MARGIN.left - MARGIN.right);
        const innerH = Math.max(80,  height - MARGIN.top - MARGIN.bottom);

        hitRect.setAttribute('width', String(innerW));
        hitRect.setAttribute('height', String(innerH));
        fadeMaskRect.setAttribute('width', String(innerW));
        fadeMaskRect.setAttribute('height', String(innerH + 40));
        yAxisEl.style.height = `${innerH}px`;

        const nowMs = Date.now();
        const domainEndMs   = nowMs + LEADING_MS;
        const domainStartMs = domainEndMs - WINDOW_MS;
        const windowStartSec = domainStartMs / 1000;

        // Slice points visible in [windowStartSec, now]
        let startIdx = 0;
        while (startIdx < points.length && points[startIdx].time < windowStartSec) {
            startIdx++;
        }
        if (startIdx > 0) startIdx--;
        const visible = points.slice(startIdx);

        // Compute target range & lerp frame
        const targetRange = computeTargetRange(visible, targetValue);
        frame.now = nowMs;
        frame.yMin = 0;
        frame.yMax = targetRange.yMax > frame.yMax
            ? targetRange.yMax
            : frame.yMax + (targetRange.yMax - frame.yMax) * LERP_SPEED;
        frame.displayValue = frame.displayValue + (targetValue - frame.displayValue) * LERP_SPEED;
        if (Math.abs(frame.displayValue) < 0.02 && targetValue === 0) {
            frame.displayValue = 0;
        }

        const xScale = (ms) => ((ms - domainStartMs) / WINDOW_MS) * innerW;
        const yRange = Math.max(frame.yMax - frame.yMin, 1);
        const yScale = (val) => innerH - ((val - frame.yMin) / yRange) * innerH;

        // Build contextData with 2 virtual points (at "now" and "now + 1 unit")
        const renderPts = visible.map(p => ({ time: p.time, value: p.value }));
        renderPts.push({ time: nowMs / 1000, value: frame.displayValue });
        renderPts.push({ time: (nowMs + X_TICK_UNIT_MS) / 1000, value: frame.displayValue });

        const coords = renderPts.map(p => ({
            x: xScale(p.time * 1000),
            y: Math.min(innerH, Math.max(0, yScale(p.value)))
        }));

        const { line, area } = buildMonotoneCubicPaths(coords, innerH);
        linePathEl.setAttribute('d', line);
        areaPathEl.setAttribute('d', area);

        // Live tip position (second-to-last point is "now")
        const liveDotX = Math.max(0, Math.min(innerW, xScale(nowMs)));
        const liveDotY = Math.min(innerH, Math.max(0, yScale(frame.displayValue)));

        const dotStopPct = Math.min(98, Math.max(10, (liveDotX / innerW) * 100));
        fadeDotStop.setAttribute('offset', `${dotStopPct.toFixed(1)}%`);

        liveGuideEl.setAttribute('x2', String(innerW));
        liveGuideEl.setAttribute('y1', liveDotY.toFixed(2));
        liveGuideEl.setAttribute('y2', liveDotY.toFixed(2));

        liveHalo.setAttribute('cx', liveDotX.toFixed(2));
        liveHalo.setAttribute('cy', liveDotY.toFixed(2));
        liveDot.setAttribute('cx', liveDotX.toFixed(2));
        liveDot.setAttribute('cy', liveDotY.toFixed(2));

        // Badge pill at live tip (clamped so it never clips outside the card)
        const badgeLabel = formatBadgeValue(frame.displayValue);
        const badgeW = Math.round(badgeLabel.length * 6.6 + 14);
        const badgeX = (liveDotX + 10 + badgeW <= innerW + MARGIN.right - 2)
            ? (liveDotX + 10)
            : (liveDotX - badgeW - 10);
        const badgeY = Math.max(12, Math.min(innerH - 12, liveDotY));
        liveBadge.setAttribute('transform', `translate(${badgeX.toFixed(1)},${badgeY.toFixed(1)})`);
        liveBadgeRect.setAttribute('width', String(badgeW));
        liveBadgeText.textContent = badgeLabel;

        // LiveYAxis & horizontal grid lines
        const interval = pickNiceInterval(yRange, innerH, 38);
        const firstTick = Math.ceil(frame.yMin / interval) * interval;
        const gridColor = isLight ? 'rgba(15, 23, 42, 0.06)' : 'rgba(255, 255, 255, 0.05)';
        let yHtml = '';
        let gHtml = '';
        for (let v = firstTick; v <= frame.yMax + interval * 0.25; v += interval) {
            const rounded = Math.round(v * 100) / 100;
            const y = yScale(rounded);
            if (y < -4 || y > innerH + 4) continue;
            const fromEdge = Math.min(y, innerH - y);
            const alpha = fromEdge >= EDGE_FADE_PX ? 1 : Math.max(0, fromEdge / EDGE_FADE_PX);
            const lbl = formatYValue(rounded);
            if (lbl) {
                yHtml += `<div style="position:absolute;right:0;top:${(y - 7).toFixed(1)}px;padding-right:8px;text-align:right;opacity:${alpha.toFixed(2)};font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--t3);white-space:nowrap;">${lbl}</div>`;
                gHtml += `<line x1="0" x2="${innerW}" y1="${y.toFixed(1)}" y2="${y.toFixed(1)}" stroke="${gridColor}" stroke-width="1" stroke-dasharray="4,4" />`;
            }
        }
        yAxisEl.innerHTML = yHtml;
        gridG.innerHTML   = gHtml;

        // LiveXAxis & interactive crosshair scrubbing
        const isHovering = cursorX !== null && cursorX >= 0 && cursorX <= innerW;
        const crosshairScreenX = isHovering ? (cursorX + MARGIN.left) : null;
        const stepMs = WINDOW_MS / (NUM_X_TICKS - 1);

        for (let i = 0; i < NUM_X_TICKS; i++) {
            const tMs = domainStartMs + i * stepMs;
            const xPx = xScale(tMs) + MARGIN.left;
            let op = 1;
            if (isHovering && crosshairScreenX !== null) {
                const dist = Math.abs(xPx - crosshairScreenX);
                if (dist < TICKER_HALF_W) op = 0;
                else if (dist < TICKER_HALF_W + FADE_BUFFER) op = (dist - TICKER_HALF_W) / FADE_BUFFER;
            }
            xTickNodes[i].wrap.style.left = `${xPx.toFixed(1)}px`;
            xTickNodes[i].span.style.opacity = op.toFixed(2);
            xTickNodes[i].span.textContent = formatTime(tMs);
        }

        if (isHovering) {
            const hoverTimeMs = domainStartMs + (cursorX / innerW) * WINDOW_MS;
            const hoverVal = interpolateAtTime(renderPts, hoverTimeMs / 1000);
            const hoverY = Math.min(innerH, Math.max(0, yScale(hoverVal)));

            liveTipG.style.opacity = '0.25';
            scrubG.style.opacity   = '1';
            scrubLine.setAttribute('x1', cursorX.toFixed(1));
            scrubLine.setAttribute('x2', cursorX.toFixed(1));
            scrubLine.setAttribute('y2', String(innerH));
            scrubDot.setAttribute('cx', cursorX.toFixed(1));
            scrubDot.setAttribute('cy', hoverY.toFixed(1));

            hoverPillEl.style.opacity = '1';
            hoverPillEl.style.left    = `${(cursorX + MARGIN.left).toFixed(1)}px`;
            hoverPillTxt.textContent  = `${formatTime(hoverTimeMs)} • ${hoverVal.toFixed(1)} req/s`;
        } else {
            liveTipG.style.opacity    = '1';
            scrubG.style.opacity      = '0';
            hoverPillEl.style.opacity = '0';
        }

        requestAnimationFrame(renderTick);
    }

    requestAnimationFrame(renderTick);

    return {
        setTargetValue(val) {
            targetValue = Math.max(0, Number(val) || 0);
            points.push({ time: Date.now() / 1000, value: targetValue });
        },
        setTheme(lightMode) {
            isLight = Boolean(lightMode);
        },
        reset() {
            targetValue = 0;
            frame.displayValue = 0;
            frame.yMax = 10;
            const tSec = Date.now() / 1000;
            points = [];
            for (let i = 60; i >= 0; i--) {
                points.push({ time: tSec - i * 0.5, value: 0 });
            }
        }
    };
}

// ── Bklit UI Charts ────────────────────────────────────────────────
function initCharts() {
    const liveContainer = el('bklit-live-line-chart');
    if (liveContainer && !window.bklitLiveChart) {
        window.bklitLiveChart = createBklitLiveLineChart(liveContainer);
    }

    const rrCanvas = el('request-rate-chart');
    if (!rrCanvas || typeof Chart === 'undefined') return;

    const baseOpts = {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 240 },
        scales: {
            y: {
                beginAtZero: true,
                grid:  { color: 'rgba(255, 255, 255, 0.05)', borderDash: [4, 4] },
                ticks: { color: '#71717a', font: { family: 'JetBrains Mono', size: 10 }, precision: 0 }
            },
            x: {
                grid:  { display: false },
                ticks: { color: '#71717a', font: { family: 'JetBrains Mono', size: 10 } }
            }
        },
        plugins: {
            legend: { display: false },
            tooltip: {
                backgroundColor: 'rgba(18, 18, 22, 0.94)',
                titleColor: '#f4f4f5',
                bodyColor: '#f59e0b',
                borderColor: 'rgba(255, 255, 255, 0.12)',
                borderWidth: 1,
                padding: 10,
                titleFont: { family: 'Inter', size: 11, weight: '600' },
                bodyFont:  { family: 'JetBrains Mono', size: 11 }
            }
        }
    };

    window.requestRateChart = new Chart(rrCanvas.getContext('2d'), {
        type: 'bar',
        data: {
            labels: ['2xx/3xx OK', 'Blocked/5xx', 'Critical', 'High', 'Med/Low'],
            datasets: [{
                label: 'Telemetry Count',
                data: [0, 0, 0, 0, 0],
                backgroundColor: [
                    'rgba(148, 163, 184, 0.25)',
                    'rgba(248, 113, 113, 0.22)',
                    'rgba(220, 38, 38, 0.30)',
                    'rgba(245, 158, 11, 0.28)',
                    'rgba(113, 113, 122, 0.24)'
                ],
                borderColor: [
                    '#94a3b8',
                    '#f87171',
                    '#dc2626',
                    '#f59e0b',
                    '#71717a'
                ],
                borderWidth: 1.5,
                borderRadius: 6,
                barThickness: 32
            }]
        },
        options: JSON.parse(JSON.stringify(baseOpts))
    });
}

function updateCharts() {
    if (window.requestRateChart) {
        const rr = window.requestRateChart;
        rr.data.datasets[0].data = [
            metricsData.successful_requests,
            metricsData.failed_requests,
            sevCounts.Critical,
            sevCounts.High,
            sevCounts.Medium + sevCounts.Low
        ];
        rr.update('none');
    }
}

// ── WebSocket ──────────────────────────────────────────────────────
let wsRetryDelay = 2000;
let wsRetryTimer = null;

function connectWS() {
    if (!BACKEND_HOST) return;
    if (wsRetryTimer) { clearTimeout(wsRetryTimer); wsRetryTimer = null; }
    const { ws: wsUrl } = getBackendUrls();
    ws = new WebSocket(wsUrl);

    ws.onopen = function() {
        wsRetryDelay = 2000;
        addLog('Connected to telemetry stream.', 'success');
        setStatus('ready', 'Ready');
    };
    ws.onclose = function() {
        addLog('WebSocket stream disconnected — retrying in ' + (wsRetryDelay / 1000) + 's...', 'warning');
        setStatus('error', 'Offline');
        wsRetryTimer = setTimeout(connectWS, wsRetryDelay);
        wsRetryDelay = Math.min(wsRetryDelay * 1.5, 30000);
    };
    ws.onerror = function() { addLog('WebSocket transport error.', 'error'); };

    ws.onmessage = function(evt) {
        try {
            var msg = JSON.parse(evt.data);
            switch (msg.type) {
                case 'metrics':       updateStats(msg.data);         break;
                case 'vulnerability': addVuln(msg.data);             break;
                case 'attack_status': handleAttackStatus(msg.data);  break;
                case 'log':           addLog(msg.message, msg.level || 'info'); break;
            }
        } catch (e) { /* ignore malformed */ }
    };
}

// ── API: fetch status ──────────────────────────────────────────────
async function fetchStatus() {
    if (!BACKEND_HOST) return;
    try {
        const res  = await fetch(`${getBackendUrls().http}/api/status`);
        const data = await res.json();

        handleAttackStatus({ running: data.attacks_running, attack_type: data.current_attacks?.[0] });

        if (data.vulnerabilities && data.vulnerabilities.length) {
            const vc = el('vulnerabilities-container');
            if (vc) vc.innerHTML = '';
            vulnCount = 0;
            sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
            data.vulnerabilities.forEach(addVuln);
        }
        updateStats({
            total_requests:      data.stats?.total_requests      || 0,
            successful_requests: data.stats?.successful_requests || 0,
            failed_requests:     data.stats?.failed_requests     || 0
        });
        if (data.history && data.history.length) {
            const hc = el('attack-history-container');
            if (hc) hc.innerHTML = '';
            historyCount = 0;
            data.history.forEach(addHistoryEntry);
        }
    } catch (e) { /* backend not ready yet */ }
}

// ── API: start attack ──────────────────────────────────────────────
async function startAttack() {
    const urlVal = el('url-input') ? el('url-input').value.trim() : '';
    if (!urlVal)       { alert('Enter a target URL first.'); return; }
    if (!BACKEND_HOST) { alert('No backend configured - go to Settings.'); return; }

    let selectedType = el('attack-type-input') ? el('attack-type-input').value : 'ddos';
    const xssVec = el('xss-vector-select');
    if ((selectedType === 'xss' || selectedType === 'stored_xss') && xssVec && xssVec.value === 'stored_xss') {
        selectedType = 'stored_xss';
    }

    const payload = {
        url:         urlVal,
        attack_type: selectedType,
        duration:    parseInt(el('duration-input')  ? el('duration-input').value  : 30),
        intensity:   parseInt(el('intensity-input') ? el('intensity-input').value : 5),
        threads:     parseInt(el('threads-input')   ? el('threads-input').value   : 10),
        target_port: el('port-input') && el('port-input').value ? parseInt(el('port-input').value) : null,
        username:    el('username-input') ? el('username-input').value.trim() || null : null,
        wordlist:    el('wordlist-input') ? el('wordlist-input').value.trim() || null : null,
        custom_header_payload: el('header-payload-input') ? el('header-payload-input').value.trim() || null : null,
        custom_xss_payload: el('xss-payload-input') ? el('xss-payload-input').value.trim() || null : null
    };

    const startBtn = el('start-attack');
    if (startBtn) startBtn.disabled = true;

    try {
        const res = await fetch(`${getBackendUrls().http}/api/attack/start`, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(payload)
        });
        const result = await res.json();

        if (res.ok && result.success) {
            currentAttackId = result.attack_id;
            addLog(`Verification module [${selectedType.toUpperCase()}] launched — ID: ${currentAttackId}`, 'info');
            switchToPage('dashboard');
        } else {
            alert(result.detail || result.message || 'Failed to start.');
            if (startBtn) startBtn.disabled = false;
        }
    } catch (err) {
        addLog('API error: ' + err.message, 'error');
        if (startBtn) startBtn.disabled = false;
    }
}

// ── API: stop attack ───────────────────────────────────────────────
async function stopAttack() {
    if (!BACKEND_HOST) return;
    try {
        const res = await fetch(`${getBackendUrls().http}/api/attack/stop`, { method: 'POST' });
        const r   = await res.json();
        if (r.success) addLog('Stop command dispatched to engine.', 'info');
    } catch (err) { addLog('Stop error: ' + err.message, 'error'); }
}

// ── API: reset all ─────────────────────────────────────────────────
async function resetAll() {
    if (!confirm('Reset all stats, logs and findings?')) return;
    try {
        if (BACKEND_HOST) await fetch(`${getBackendUrls().http}/api/logs/clear`, { method: 'POST' });
        hasLiveVelocity = false;
        recentReqSamples = [];
        lastSampleTotalReqs = 0;
        liveRps = 0;
        peakRps = 0;
        vulnCount = 0;
        historyCount = 0;
        sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        updateVulnBadges();
        const navH = el('nav-history-count');
        if (navH) navH.textContent = '0';
        if (window.bklitLiveChart) {
            window.bklitLiveChart.reset();
        }

        metricsData = {
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            rps_history: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            findings_history: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        };
        updateStats(metricsData);

        const vc = el('vulnerabilities-container');
        if (vc) vc.innerHTML = '<div class="empty-state"><i class="fas fa-shield-halved empty-ico"></i><p>No vulnerabilities detected yet</p><small>Launch a test module against an authorized target to populate verified findings</small></div>';

        const hc = el('attack-history-container');
        if (hc) hc.innerHTML = '<div class="glass-card spotlight-card"><div class="card-body"><div class="empty-state"><i class="fas fa-clock-rotate-left empty-ico"></i><p>No audit runs recorded yet</p><small>Completed module executions will be archived here automatically</small></div></div></div>';

        addLog('All telemetry counters and findings cleared.', 'info');
    } catch (err) { addLog('Reset error: ' + err.message, 'error'); }
}

// ── Recon helpers ──────────────────────────────────────────────────
async function callRecon(endpoint, extra) {
    extra = extra || {};
    const outBox = el('recon-output');
    if (!BACKEND_HOST) {
        if (outBox) outBox.innerHTML = '<div class="log-line log-error">No backend configured - go to Settings.</div>';
        return null;
    }
    let target = el('recon-target') ? el('recon-target').value.trim() : '';
    if (!target && endpoint === 'wifi-audit') {
        target = 'wlan0';
    }
    if (!target) {
        if (outBox) outBox.innerHTML = '<div class="log-line log-warning">Enter a target domain or IP first.</div>';
        return null;
    }
    if (outBox) outBox.innerHTML = '<div class="log-line log-info">Executing passive recon module [' + endpoint.toUpperCase() + ']... please wait.</div>';

    try {
        const res = await fetch(`${getBackendUrls().http}/api/recon/${endpoint}`, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(Object.assign({ target }, extra))
        });
        return await res.json();
    } catch (e) {
        if (outBox) outBox.innerHTML = '<div class="log-line log-error">Error: ' + e.message + '</div>';
        return null;
    }
}

function showRecon(data, label) {
    const active = el('recon-active-tool');
    if (active) active.textContent = '— ' + label;
    const box = el('recon-output');
    if (!box || !data) return;
    box.innerHTML = '<pre class="recon-pre">' + JSON.stringify(data, null, 2) + '</pre>';
}

// ── Red Team helpers ───────────────────────────────────────────────
async function callRedTeam(endpoint, body) {
    if (!BACKEND_HOST) return { error: 'No backend configured.' };
    try {
        const res = await fetch(`${getBackendUrls().http}/api/redteam/${endpoint}`, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(body)
        });
        return await res.json();
    } catch (e) { return { error: e.message }; }
}

function showRT(data, resultId) {
    const box = el(resultId);
    if (!box || !data) return;
    box.innerHTML = '<pre class="recon-pre">' + JSON.stringify(data, null, 2) + '</pre>';
}

// ── Aceternity UI Cursor-Tracking Spotlights ───────────────────────
function initSpotlights() {
    const cards = document.querySelectorAll('.glass-card, .stat-card, .spotlight-card');
    cards.forEach(function(card) {
        card.classList.add('spotlight-card');
        card.addEventListener('mousemove', function(e) {
            const rect = card.getBoundingClientRect();
            card.style.setProperty('--mouse-x', (e.clientX - rect.left) + 'px');
            card.style.setProperty('--mouse-y', (e.clientY - rect.top) + 'px');
        });
    });
}

// ── Wire all buttons ───────────────────────────────────────────────
function wireButtons() {
    // Theme toggle
    var themeBtn = el('theme-toggle');
    if (themeBtn) {
        themeBtn.onclick = function() {
            var cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
            applyTheme(cur === 'light' ? 'dark' : 'light');
        };
    }

    // Copy Recon JSON button
    var copyReconBtn = el('copy-recon-btn');
    if (copyReconBtn) {
        copyReconBtn.onclick = function() {
            var out = el('recon-output');
            if (out && navigator.clipboard) {
                navigator.clipboard.writeText(out.innerText || '');
                addLog('Recon JSON copied to clipboard.', 'info');
            }
        };
    }

    // Attack controls
    var startBtn = el('start-attack');
    var stopBtn  = el('stop-attack');
    var resetBtn = el('btn-reset-all');
    var clearBtn = el('clear-log');
    var saveBtn  = el('btn-save-backend');

    if (startBtn) startBtn.onclick = startAttack;
    if (stopBtn)  stopBtn.onclick  = stopAttack;
    if (resetBtn) resetBtn.onclick = resetAll;
    if (clearBtn) clearBtn.onclick = function() { var b = el('log-container'); if (b) b.innerHTML = ''; };

    if (saveBtn) {
        saveBtn.onclick = function() {
            var inp = el('backend-url-input');
            var val = inp ? inp.value.trim() : '';
            if (val) {
                localStorage.setItem('cyberstrike_custom_backend', val);
                BACKEND_HOST = sanitizeHost(val);
            } else {
                localStorage.removeItem('cyberstrike_custom_backend');
                BACKEND_HOST = location.host;
            }
            addLog('Backend endpoint updated. Reconnecting...', 'info');
            if (ws) ws.close();
            connectWS();
            fetchStatus();
        };
    }

    // Recon buttons — endpoint : label
    var reconMap = [
        ['run-dns',           'dns',            'DNS Records'],
        ['run-whois',         'whois',          'WHOIS / RDAP'],
        ['run-ssl',           'ssl',            'SSL/TLS Certificate'],
        ['run-ip',            'ip',             'IP Geolocation'],
        ['run-phone',         'phone',          'Phone OSINT'],
        ['run-headers',       'headers',        'HTTP Security Headers'],
        ['run-fingerprint',   'fingerprint',    'Tech Fingerprint'],
        ['run-subdomains',    'subdomains',     'Subdomain Discovery'],
        ['run-dorks',         'dorks',          'Search Engine Dorks'],
        ['run-zonetransfer',  'zonetransfer',   'DNS Zone Transfer'],
        ['run-waf',           'waf',            'WAF Fingerprinting'],
        ['run-ratelimit',     'ratelimit',      'Rate Limit Probe'],
        ['run-breaches',      'breaches',       'Breach Exposure'],
        ['run-ioc',           'ioc',            'IOC Threat Intel'],
        ['run-wifi-audit',    'wifi-audit',     'Wi-Fi 802.11w Posture Audit'],
        ['run-email-sec',     'email-security', 'Email Security (DMARC/SPF/DKIM)'],
        ['run-cors-matrix',   'cors-matrix',    'CORS Trust Matrix'],
        ['run-api-discovery', 'api-discovery',  'API Surface Discovery']
    ];
    reconMap.forEach(function(row) {
        var btn = el(row[0]);
        if (!btn) return;
        (function(ep, lbl) {
            btn.onclick = function() {
                callRecon(ep).then(function(d) { showRecon(d, lbl); });
            };
        })(row[1], row[2]);
    });

    // Red Team buttons
    var phishBtn   = el('run-phishing');
    var persistBtn = el('run-persistence');
    var privBtn    = el('run-privesc');
    var latBtn     = el('run-lateral');

    if (phishBtn) phishBtn.onclick = function() {
        callRedTeam('phishing', {
            target:  el('phish-target') ? el('phish-target').value : '',
            options: { brand: el('phish-brand') ? el('phish-brand').value : '', lure: el('phish-lure') ? el('phish-lure').value : '' }
        }).then(function(d) { showRT(d, 'phishing-result'); });
    };
    if (persistBtn) persistBtn.onclick = function() {
        callRedTeam('persistence', {
            os_type: el('persist-os') ? el('persist-os').value : 'windows',
            options: { lhost: el('persist-lhost') ? el('persist-lhost').value : '', lport: el('persist-lport') ? el('persist-lport').value : '4444' }
        }).then(function(d) { showRT(d, 'persistence-result'); });
    };
    if (privBtn) privBtn.onclick = function() {
        callRedTeam('privesc', { os_type: el('privesc-os') ? el('privesc-os').value : 'windows' })
            .then(function(d) { showRT(d, 'privesc-result'); });
    };
    if (latBtn) latBtn.onclick = function() {
        callRedTeam('lateral', { options: {
            target_ip: el('lat-ip')     ? el('lat-ip').value     : '',
            domain:    el('lat-domain') ? el('lat-domain').value : '',
            username:  el('lat-user')   ? el('lat-user').value   : '',
            lhost:     el('lat-lhost')  ? el('lat-lhost').value  : ''
        }}).then(function(d) { showRT(d, 'lateral-result'); });
    };

    // ── Self-Test Buttons ───────────────────────────────────────────
    var selfStart = el('btn-selftest-start');
    var selfStop  = el('btn-selftest-stop');

    if (selfStart) selfStart.onclick = async function() {
        var ipInput = el('selftest-ip-input');
        var targetIp = ipInput ? ipInput.value.trim() : '';
        if (!targetIp) {
            alert('Please enter an IP address to test.');
            return;
        }

        selfStart.disabled = true;
        if (selfStop) selfStop.disabled = false;
        addLog(`[Diagnostic] Launching reachability stress test against ${targetIp}...`, 'warning');
        try {
            var urls = getBackendUrls();
            var r = await fetch(urls.http + '/api/selftest/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_ip: targetIp })
            });
            var d = await r.json();
            addLog('[Diagnostic] ' + (d.message || 'Started'), d.success ? 'success' : 'error');
        } catch (e) {
            addLog('[Diagnostic] Error: ' + e.message, 'error');
            selfStart.disabled = false;
            if (selfStop) selfStop.disabled = true;
        }
    };

    if (selfStop) selfStop.onclick = async function() {
        selfStop.disabled = true;
        try {
            var urls = getBackendUrls();
            await fetch(urls.http + '/api/attack/stop', { method: 'POST' });
            addLog('[Diagnostic] Stop command sent.', 'warning');
        } catch (e) {
            addLog('[Diagnostic] Stop error: ' + e.message, 'error');
        }
        if (selfStart) selfStart.disabled = false;
    };
}

// ── Boot ───────────────────────────────────────────────────────────
async function boot() {
    // Clear legacy cached backend host so no stale link is pre-filled
    localStorage.removeItem('testing_backend_host');

    // 1. Try Vercel /api/config
    try {
        var res = await fetch('/api/config');
        var cfg = await res.json();
        if (cfg.backendHost) BACKEND_HOST = sanitizeHost(cfg.backendHost);
    } catch (e) { /* no config endpoint */ }

    // 2. Custom user-saved override
    var saved = localStorage.getItem('cyberstrike_custom_backend');
    if (saved) BACKEND_HOST = sanitizeHost(saved);

    // 3. Local dev fallback
    if (!BACKEND_HOST) {
        var h = location.host;
        if (h.indexOf('localhost') !== -1 || h.indexOf('127.0.0.1') !== -1) BACKEND_HOST = h;
    }

    // Init UI & Creative UI Components
    if (typeof lucide !== 'undefined' && lucide.createIcons) {
        lucide.createIcons();
    }
    initNav();
    initAttackSelector();
    initCharts();
    var savedTheme = localStorage.getItem('cyberstrike_theme') || 'dark';
    applyTheme(savedTheme);
    initSpotlights();
    wireButtons();

    var bInp = el('backend-url-input');
    if (bInp && saved) bInp.value = saved;

    if (BACKEND_HOST) {
        connectWS();
        fetchStatus();
    } else {
        addLog('No backend configured - go to Settings to set one.', 'warning');
    }
}

// Run after DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
} else {
    boot();
}
