/* ================================================================
   CyberStrike Suite — app.js
   Clean rewrite matched exactly to index.html DOM structure.
   ================================================================ */

'use strict';

// ── State ─────────────────────────────────────────────────────────
let BACKEND_HOST = '';
let ws = null;
let currentAttackId = null;
let metricsData = {
    total_requests: 0,
    successful_requests: 0,
    failed_requests: 0,
    response_times: []
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
        if (hf) return `${hf[1]}-${hf[2].toLowerCase().replace(/_/g,'-')}.hf.space`;
        if (s.includes('://')) return new URL(s).hostname;
        return s.split('/')[0].trim();
    } catch { return raw.split('/')[0].trim(); }
}

// ── Helper: safe getElementById ────────────────────────────────────
const el = (id) => document.getElementById(id);

// ── Navigation ─────────────────────────────────────────────────────
function initNav() {
    const links = document.querySelectorAll('.slink[data-page]');
    const pages = document.querySelectorAll('.page[id]');

    links.forEach(link => {
        link.addEventListener('click', e => {
            e.preventDefault();
            const pageId = link.dataset.page;

            // Clean URL — no hash
            if (history.replaceState) history.replaceState(null, '', location.pathname);

            // Toggle active link
            links.forEach(l => l.classList.toggle('active', l.dataset.page === pageId));

            // Toggle active page
            pages.forEach(p => p.classList.toggle('active', p.id === `${pageId}-page`));
        });
    });
}

// ── Attack type selector ───────────────────────────────────────────
function initAttackSelector() {
    const items = document.querySelectorAll('.atk-item[data-attack]');
    const typeInput  = el('attack-type-input');
    const bruteBox   = el('brute-fields');
    const portBox    = el('port-fields');
    const intGrp     = el('intensity-group');
    const thrdGrp    = el('threads-group');

    items.forEach(item => {
        item.addEventListener('click', () => {
            items.forEach(i => i.classList.remove('selected'));
            item.classList.add('selected');

            const t = item.dataset.attack;
            if (typeInput) typeInput.value = t;

            
            if (bruteBox)  bruteBox.style.display  = t === 'brute' ? 'block' : 'none';
            if (portBox)   portBox.style.display    = t === 'port'  ? 'block' : 'none';
            
            // For DDoS, Slowloris, Brute: Show both Intensity and Threads
            // For other vulnerabilities (SQL, XSS, CSRF, IDOR, etc.): Hide Intensity and Threads
            // For Port scan: Hide Intensity and Threads
            
            
            const showBoth = ['ddos', 'slowloris', 'brute'].includes(t);
            const hideDuration = ['sql', 'xss', 'csrf', 'idor', 'redirect', 'header_inj', 'cmd', 'ssrf', 'xxe', 'traversal', 'port'].includes(t);

            if (intGrp)    intGrp.style.display     = showBoth ? 'block'  : 'none';
            if (thrdGrp)   thrdGrp.style.display    = showBoth ? 'block'  : 'none';
            
            const durGrp = el('duration-input')?.closest('.field');
            if (durGrp) durGrp.style.display = hideDuration ? 'none' : 'block';

             const sqlFields = el('sql-fields');
             const xssFields = el('xss-fields');
             const cmdFields = el('cmd-fields');
             const ssrfFields = el('ssrf-fields');
             const xxeFields = el('xxe-fields');
             const travFields = el('traversal-fields');
             const headerFields = el('header_inj-fields');
 
             if (sqlFields) sqlFields.style.display = (t === 'sql') ? 'block' : 'none';
             if (xssFields) xssFields.style.display = (t === 'xss') ? 'block' : 'none';
             if (cmdFields) cmdFields.style.display = (t === 'cmd') ? 'block' : 'none';
             if (ssrfFields) ssrfFields.style.display = (t === 'ssrf') ? 'block' : 'none';
             if (xxeFields) xxeFields.style.display = (t === 'xxe') ? 'block' : 'none';
             if (travFields) travFields.style.display = (t === 'traversal') ? 'block' : 'none';
             if (headerFields) headerFields.style.display = (t === 'header_inj') ? 'block' : 'none';


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

    if (data.response_time != null) {
        metricsData.response_times.push(data.response_time * 1000);
        if (metricsData.response_times.length > 60) metricsData.response_times.shift();
    }

    const tr = el('total-requests');
    const sr = el('successful-requests');
    const fr = el('failed-requests');
    if (tr) tr.textContent = metricsData.total_requests;
    if (sr) sr.textContent = metricsData.successful_requests;
    if (fr) fr.textContent = metricsData.failed_requests;

    updateCharts();
}

// ── Status dot ─────────────────────────────────────────────────────
function setStatus(state, label) {
    const dot  = el('status-indicator');
    const text = el('status-text');
    if (dot)  dot.className  = `status-dot ${state}`;
    if (text) text.textContent = label;
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
            addLog(`Completed: ${(s.attack_type||'').toUpperCase()} - ${s.total_requests||0} requests`, 'success');
            addHistoryEntry(s);
        }
    }
}

// ── Vulnerability card ─────────────────────────────────────────────
function addVuln(v) {
    const box = el('vulnerabilities-container');
    if (!box) return;
    const empty = box.querySelector('.empty-state');
    if (empty) empty.remove();

    const d = document.createElement('div');
    d.className = 'vuln-item glass-card'; 
    d.style.marginBottom = '15px';
    
    let detailHTML = '';
    if (v.detail) detailHTML = `<p style="margin-top:10px;font-size:0.85rem;color:var(--t2)"><strong>Detail:</strong> ${v.detail}</p>`;
    
    let evidenceHTML = '';
    if (v.evidence) {
        const ev = String(v.evidence).replace(/</g, '&lt;').replace(/>/g, '&gt;');
        evidenceHTML = `<div style="margin-top:12px;padding:10px;background:rgba(0,0,0,0.3);border-radius:4px;border-left:3px solid var(--danger);font-family:var(--mono);font-size:0.75rem;color:#f0a3a3;overflow-x:auto;"><strong>Proof / Evidence:</strong><br><br>${ev}</div>`;
    }

    d.innerHTML = `
        <div class="card-body" style="padding:15px;">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">
                <h5 style="margin:0;font-size:1.1rem;color:var(--danger)"><i class="fas fa-spider" style="margin-right:8px"></i>${v.type || 'Unknown'}</h5>
                ${v.severity ? `<span style="font-size:0.7rem;padding:3px 10px;border-radius:12px;background:var(--danger);color:white;font-weight:700;text-transform:uppercase;letter-spacing:1px">${v.severity}</span>` : ''}
            </div>
            
            <p style="margin:0 0 6px 0;font-size:0.85rem;color:var(--t1)">
                <i class="fas fa-crosshairs" style="color:var(--t3);margin-right:6px"></i> 
                <strong>Target:</strong> <span style="font-family:var(--mono);color:var(--primary)">${v.url || '-'}</span>
            </p>
            
            ${v.payload ? `<p style="margin:0;font-size:0.85rem;color:var(--t2)"><i class="fas fa-biohazard" style="color:var(--t3);margin-right:6px"></i><strong>Payload:</strong> <code style="margin-left:4px;color:#c97a7e">${String(v.payload).replace(/</g, '&lt;').replace(/>/g, '&gt;')}</code></p>` : ''}
            
            ${detailHTML}
            ${evidenceHTML}
            
            <div style="margin-top:12px;text-align:right;font-size:0.7rem;color:var(--t3);border-top:1px solid rgba(255,255,255,0.05);padding-top:8px;">
                <i class="fas fa-clock"></i> Discovered: ${v.timestamp ? new Date(v.timestamp).toLocaleString() : new Date().toLocaleString()}
            </div>
        </div>
    `;
    box.insertBefore(d, box.firstChild);
}

// ── History entry ──────────────────────────────────────────────────
function addHistoryEntry(a) {
    const box = el('attack-history-container');
    if (!box) return;
    // Remove empty placeholder
    const empCard = box.querySelector('.glass-card');
    if (empCard && empCard.querySelector('.empty-state')) empCard.remove();

    const d = document.createElement('div');
    d.className = 'glass-card';
    d.style.marginBottom = '10px';
    d.innerHTML = `
        <div class="card-body" style="display:flex;justify-content:space-between;align-items:center">
            <div>
                <div style="font-weight:700;font-size:.9rem">${(a.attack_type||'test').toUpperCase()}</div>
                <div style="font-size:.75rem;color:var(--t2);margin-top:2px">${a.url||''}</div>
                <div style="font-size:.7rem;color:var(--t3);margin-top:2px">${a.timestamp ? new Date(a.timestamp).toLocaleString() : ''}</div>
            </div>
            <div style="text-align:right">
                <div style="font-family:var(--mono);font-size:1.4rem;font-weight:700">${a.total_requests||0}</div>
                <div style="font-size:.7rem;color:var(--t3)">requests</div>
            </div>
        </div>
    `;
    box.insertBefore(d, box.firstChild);
}

// ── Charts ─────────────────────────────────────────────────────────
const CHART_OPTS = {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 250 },
    scales: {
        y: {
            beginAtZero: true,
            grid:  { color: 'rgba(255,255,255,0.05)' },
            ticks: { color: 'rgba(255,255,255,0.35)', font: { family: 'JetBrains Mono', size: 10 } }
        },
        x: {
            grid:  { display: false },
            ticks: { color: 'rgba(255,255,255,0.25)', font: { family: 'JetBrains Mono', size: 9 } }
        }
    },
    plugins: { legend: { display: false } }
};

function initCharts() {
    const rtCanvas = el('response-time-chart');
    const rrCanvas = el('request-rate-chart');
    if (!rtCanvas || !rrCanvas || typeof Chart === 'undefined') return;

    Chart.defaults.color       = 'rgba(255,255,255,0.35)';
    Chart.defaults.borderColor = 'rgba(255,255,255,0.06)';

    window.responseTimeChart = new Chart(rtCanvas.getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: 'rgba(255,255,255,0.05)',
                borderColor:     'rgba(255,255,255,0.65)',
                borderWidth: 1.5,
                tension: 0.4,
                fill: true,
                pointRadius: 2
            }]
        },
        options: { ...CHART_OPTS }
    });

    window.requestRateChart = new Chart(rrCanvas.getContext('2d'), {
        type: 'bar',
        data: {
            labels: ['Successful', 'Errors/Blocks'],
            datasets: [{
                data: [0, 0],
                backgroundColor: ['rgba(255,255,255,0.18)', 'rgba(255,255,255,0.06)'],
                borderColor:     ['rgba(255,255,255,0.55)', 'rgba(255,255,255,0.2)'],
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: { ...CHART_OPTS }
    });
}

function updateCharts() {
    if (window.responseTimeChart) {
        const rt = window.responseTimeChart;
        rt.data.labels            = metricsData.response_times.map((_, i) => i);
        rt.data.datasets[0].data  = metricsData.response_times;
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
        addLog('Connected to backend.', 'success');
        setStatus('ready', 'Ready');
    };
    ws.onclose = function() {
        addLog('Disconnected — retrying in ' + (wsRetryDelay/1000) + 's...', 'warning');
        setStatus('error', 'Offline');
        wsRetryTimer = setTimeout(connectWS, wsRetryDelay);
        wsRetryDelay = Math.min(wsRetryDelay * 1.5, 30000);
    };
    ws.onerror = function() { addLog('WebSocket error.', 'error'); };

    ws.onmessage = function(evt) {
        try {
            var msg = JSON.parse(evt.data);
            switch (msg.type) {
                case 'metrics':       updateStats(msg.data);         break;
                case 'vulnerability': addVuln(msg.data);             break;
                case 'attack_status': handleAttackStatus(msg.data);  break;
                case 'log':           addLog(msg.message, msg.level || 'info'); break;
            }
        } catch(e) { /* ignore malformed */ }
    };
}

// ── API: fetch status ──────────────────────────────────────────────
async function fetchStatus() {
    if (!BACKEND_HOST) return;
    try {
        const res  = await fetch(`${getBackendUrls().http}/api/status`);
        const data = await res.json();

        handleAttackStatus({ running: data.attacks_running, attack_type: data.current_attacks?.[0] });
        updateStats({
            total_requests:      data.stats?.total_requests      || 0,
            successful_requests: data.stats?.successful_requests || 0,
            failed_requests:     data.stats?.failed_requests     || 0
        });

        if (data.vulnerabilities && data.vulnerabilities.length) data.vulnerabilities.forEach(addVuln);
        if (data.history && data.history.length) data.history.forEach(addHistoryEntry);
    } catch (e) { /* backend not ready yet */ }
}

// ── API: start attack ──────────────────────────────────────────────
async function startAttack() {
    const urlVal = el('url-input') ? el('url-input').value.trim() : '';
    if (!urlVal)        { alert('Enter a target URL first.'); return; }
    if (!BACKEND_HOST)  { alert('No backend configured - go to Settings.'); return; }

    const payload = {
        url:         urlVal,
        attack_type: el('attack-type-input') ? el('attack-type-input').value : 'ddos',
        duration:    parseInt(el('duration-input')  ? el('duration-input').value  : 30),
        intensity:   parseInt(el('intensity-input') ? el('intensity-input').value : 5),
        threads:     parseInt(el('threads-input')   ? el('threads-input').value   : 10),
        target_port: el('port-input') && el('port-input').value ? parseInt(el('port-input').value) : null,
        username:    el('username-input') ? el('username-input').value.trim() || null : null,
        wordlist:    el('wordlist-input') ? el('wordlist-input').value.trim() || null : null,
        custom_header_payload: el('header-payload-input') ? el('header-payload-input').value.trim() || null : null
    };

    const startBtn = el('start-attack');
    if (startBtn) startBtn.disabled = true;

    try {
        const res    = await fetch(`${getBackendUrls().http}/api/attack/start`, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(payload)
        });
        const result = await res.json();

        if (res.ok && result.success) {
            currentAttackId = result.attack_id;
            addLog(`Attack launched - ID: ${currentAttackId}`, 'info');
            document.querySelector('.slink[data-page="dashboard"]').click();
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
        if (r.success) addLog('Stop command sent.', 'info');
    } catch (err) { addLog('Stop error: ' + err.message, 'error'); }
}

// ── API: reset all ─────────────────────────────────────────────────
async function resetAll() {
    if (!confirm('Reset all stats, logs and findings?')) return;
    try {
        if (BACKEND_HOST) await fetch(`${getBackendUrls().http}/api/logs/clear`, { method: 'POST' });
        metricsData = { total_requests: 0, successful_requests: 0, failed_requests: 0, response_times: [] };
        updateStats(metricsData);

        const vc = el('vulnerabilities-container');
        if (vc) vc.innerHTML = '<div class="empty-state"><i class="fas fa-shield-check empty-ico"></i><p>No findings yet</p><small>Run a test to discover vulnerabilities</small></div>';

        const hc = el('attack-history-container');
        if (hc) hc.innerHTML = '<div class="glass-card"><div class="card-body"><div class="empty-state"><i class="fas fa-clock-rotate-left empty-ico"></i><p>No history yet</p><small>Completed tests appear here</small></div></div></div>';

        addLog('All data reset.', 'info');
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
    const target = el('recon-target') ? el('recon-target').value.trim() : '';
    if (!target) {
        if (outBox) outBox.innerHTML = '<div class="log-line log-warning">Enter a target domain first.</div>';
        return null;
    }
    if (outBox) outBox.innerHTML = '<div class="log-line log-info">Running... please wait.</div>';

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
    if (active) active.textContent = '- ' + label;
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

// ── Wire all buttons ───────────────────────────────────────────────
function wireButtons() {
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
                localStorage.setItem('testing_backend_host', val);
                BACKEND_HOST = sanitizeHost(val);
            } else {
                localStorage.removeItem('testing_backend_host');
                BACKEND_HOST = '';
            }
            addLog('Backend saved. Reconnecting...', 'info');
            if (ws) ws.close();
            connectWS();
            fetchStatus();
        };
    }

    // Recon buttons — endpoint : label
    var reconMap = [
        ['run-dns',          'dns',          'DNS Lookup'],
        ['run-whois',        'whois',        'WHOIS'],
        ['run-ssl',          'ssl',          'SSL/TLS'],
        ['run-headers',      'headers',      'HTTP Headers'],
        ['run-fingerprint',  'fingerprint',  'Fingerprint'],
        ['run-subdomains',   'subdomains',   'Subdomains'],
        ['run-dorks',        'dorks',        'Google Dorks'],
        ['run-zonetransfer', 'zonetransfer', 'Zone Transfer'],
        ['run-waf',          'waf',          'WAF Detection'],
        ['run-ratelimit',    'ratelimit',    'Rate Limit'],
        ['run-breaches',     'breaches',     'Breach Check'],
        ['run-ioc',          'ioc',          'IOC / Threat Intel']
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
}

// ── Boot ───────────────────────────────────────────────────────────
async function boot() {
    // 1. Try Vercel /api/config
    try {
        var res = await fetch('/api/config');
        var cfg = await res.json();
        if (cfg.backendHost) BACKEND_HOST = sanitizeHost(cfg.backendHost);
    } catch (e) { /* no config endpoint */ }

    // 2. localStorage override
    var saved = localStorage.getItem('testing_backend_host');
    if (saved) BACKEND_HOST = sanitizeHost(saved);

    // 3. Local dev fallback
    if (!BACKEND_HOST) {
        var h = location.host;
        if (h.indexOf('localhost') !== -1 || h.indexOf('127.0.0.1') !== -1) BACKEND_HOST = h;
    }

    // Init
    initNav();
    initAttackSelector();
    initCharts();
    wireButtons();

    // Pre-fill Settings input
    var bInp = el('backend-url-input');
    if (bInp && saved) bInp.value = saved;

    if (BACKEND_HOST) {
        addLog('Backend: ' + BACKEND_HOST, 'info');
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
