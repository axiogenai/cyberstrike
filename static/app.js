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
let recentReqTimestamps = [];
let lastVelocitySampleTime = 0;
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

    // Update Severity & Delivery badges
    const avgB  = el('avg-latency-badge');
    const peakB = el('peak-latency-badge');
    const topL  = el('top-avg-latency');
    if (avgB)  avgB.textContent  = `Critical: ${sevCounts.Critical}`;
    if (peakB) peakB.textContent = `High: ${sevCounts.High}`;
    if (topL)  topL.textContent  = `${sPct}%`;

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

    if (window.responseTimeChart) {
        const rt = window.responseTimeChart;
        rt.options.scales.y.grid.color  = gridColor;
        rt.options.scales.y.ticks.color = tickColor;
        rt.options.scales.x.ticks.color = tickColor;
        rt.update('none');
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

    const avgB  = el('avg-latency-badge');
    const peakB = el('peak-latency-badge');
    if (avgB)  avgB.textContent  = `Critical: ${sevCounts.Critical}`;
    if (peakB) peakB.textContent = `High: ${sevCounts.High}`;
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

// ── Bklit UI Charts ────────────────────────────────────────────────
function initCharts() {
    const rtCanvas = el('response-time-chart');
    const rrCanvas = el('request-rate-chart');
    if (!rtCanvas || !rrCanvas || typeof Chart === 'undefined') return;

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

    window.responseTimeChart = new Chart(rtCanvas.getContext('2d'), {
        type: 'bar',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low / Info'],
            datasets: [{
                label: 'Findings',
                data: [0, 0, 0, 0],
                backgroundColor: [
                    'rgba(220, 38, 38, 0.28)',
                    'rgba(245, 158, 11, 0.28)',
                    'rgba(148, 163, 184, 0.24)',
                    'rgba(113, 113, 122, 0.22)'
                ],
                borderColor: [
                    '#dc2626',
                    '#f59e0b',
                    '#94a3b8',
                    '#71717a'
                ],
                borderWidth: 1.5,
                borderRadius: 6,
                barThickness: 38
            }]
        },
        options: JSON.parse(JSON.stringify(baseOpts))
    });

    window.requestRateChart = new Chart(rrCanvas.getContext('2d'), {
        type: 'bar',
        data: {
            labels: ['Successful (2xx/3xx)', 'Blocked / Errors'],
            datasets: [{
                label: 'Requests',
                data: [0, 0],
                backgroundColor: ['rgba(148, 163, 184, 0.25)', 'rgba(248, 113, 113, 0.22)'],
                borderColor:     ['#94a3b8', '#f87171'],
                borderWidth: 1.5,
                borderRadius: 6,
                barThickness: 44
            }]
        },
        options: JSON.parse(JSON.stringify(baseOpts))
    });
}

function updateCharts() {
    if (window.responseTimeChart) {
        const rt = window.responseTimeChart;
        rt.data.datasets[0].data = [
            sevCounts.Critical,
            sevCounts.High,
            sevCounts.Medium,
            sevCounts.Low
        ];
        rt.update('none');
    }
    if (window.requestRateChart) {
        const rr = window.requestRateChart;
        rr.data.datasets[0].data = [metricsData.successful_requests, metricsData.failed_requests];
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
        recentReqTimestamps = [];
        lastVelocitySampleTime = 0;
        peakRps = 0;
        vulnCount = 0;
        historyCount = 0;
        sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        updateVulnBadges();
        const navH = el('nav-history-count');
        if (navH) navH.textContent = '0';

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
