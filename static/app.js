// Global variables
const DEFAULT_BACKEND_HOST = 'adityax26-cyberstrike-backend.hf.space';
let ws = null;
let currentAttackId = null;
let attackHistory = [];
let metricsData = {
    total_requests: 0,
    successful_requests: 0,
    failed_requests: 0,
    response_times: [],
    vulnerabilities_found: []
};

// DOM elements
const attackForm = document.getElementById('attack-form');
const attackOptions = document.querySelectorAll('.attack-option');
const startAttackBtn = document.getElementById('start-attack');
const stopAttackBtn = document.getElementById('stop-attack');
const statusIndicator = document.getElementById('status-indicator');
const statusText = document.getElementById('status-text');
const logContainer = document.getElementById('log-container');
const totalRequestsEl = document.getElementById('total-requests');
const successfulRequestsEl = document.getElementById('successful-requests');
const failedRequestsEl = document.getElementById('failed-requests');
const vulnerabilitiesContainer = document.getElementById('vulnerabilities-container');
const attackHistoryContainer = document.getElementById('attack-history-container');
const responseTimeChartEl = document.getElementById('response-time-chart');
const requestRateChartEl = document.getElementById('request-rate-chart');

// Navigation links
const navLinks = document.querySelectorAll('.nav-link, .sidebar .nav-link');
const pages = document.querySelectorAll('.page-content');

// Form dynamic fields
const attackTypeInput = document.getElementById('attack-type-input');
const bruteFields = document.getElementById('brute-fields');
const portFields = document.getElementById('port-fields');
const intensityGroup = document.getElementById('intensity-group');
const threadsGroup = document.getElementById('threads-group');

// Backend Host URL Settings elements
const backendUrlInput = document.getElementById('backend-url-input');
const saveBackendBtn = document.getElementById('btn-save-backend');

// Initialize settings input from localStorage
if (backendUrlInput) {
    backendUrlInput.value = localStorage.getItem('testing_backend_host') || '';
}

// Get Dynamic Backend URLs (supporting local & Hugging Face remote)
function getBackendUrls() {
    const savedHost = localStorage.getItem('testing_backend_host');
    const host = window.location.host || '';
    const isLocal = host.includes('localhost') || host.includes('127.0.0.1');

    // Priority: 1) localStorage override, 2) same-origin if local, 3) default HF backend
    let backendHost;
    if (savedHost) {
        backendHost = savedHost.replace(/^(https?:\/\/|wss?:\/\/)/i, '').replace(/\/$/, '');
    } else if (isLocal) {
        backendHost = host;
    } else if (window.location.protocol === 'file:') {
        backendHost = '127.0.0.1:8000';
    } else {
        // Deployed remotely (e.g. Vercel) — auto-connect to HF Space backend
        backendHost = DEFAULT_BACKEND_HOST;
    }

    const isSecure = backendHost.includes('.hf.space') || window.location.protocol === 'https:';
    return {
        ws: `${isSecure ? 'wss:' : 'ws:'}//${backendHost}/ws`,
        http: `${isSecure ? 'https:' : 'http:'}//${backendHost}`
    };
}

// Navigation management
navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const pageId = link.getAttribute('data-page');
        
        // Update active class on nav links
        navLinks.forEach(l => {
            if (l.getAttribute('data-page') === pageId) {
                l.classList.add('active');
            } else {
                l.classList.remove('active');
            }
        });
        
        // Show correct page
        pages.forEach(page => {
            if (page.id === `${pageId}-page`) {
                page.classList.add('active');
            } else {
                page.classList.remove('active');
            }
        });
    });
});

// Select Attack Type configuration
attackOptions.forEach(option => {
    option.addEventListener('click', () => {
        attackOptions.forEach(opt => opt.classList.remove('selected'));
        option.classList.add('selected');
        
        const attackType = option.getAttribute('data-attack');
        attackTypeInput.value = attackType;
        
        // Toggle parameter fields depending on selection
        bruteFields.style.display = 'none';
        portFields.style.display = 'none';
        intensityGroup.style.display = 'block';
        threadsGroup.style.display = 'block';
        
        if (attackType === 'brute') {
            bruteFields.style.display = 'block';
        } else if (attackType === 'port') {
            portFields.style.display = 'block';
            intensityGroup.style.display = 'block';
            threadsGroup.style.display = 'none';
        }
    });
});

// Initialize WebSocket connection
function initWebSocket() {
    const urls = getBackendUrls();
    ws = new WebSocket(urls.ws);
    
    ws.onopen = () => {
        console.log('WebSocket connection established');
        addLogEntry('Connected to testing suite server.', 'info');
    };
    
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
    };
    
    ws.onclose = () => {
        console.log('WebSocket connection closed');
        addLogEntry('Disconnected from testing server. Reconnecting...', 'warning');
        setTimeout(initWebSocket, 3000);
    };
    
    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        addLogEntry('Connection error encountered.', 'error');
    };
}

// Handle WebSocket messages
function handleWebSocketMessage(data) {
    switch (data.type) {
        case 'metrics':
            updateMetrics(data.data);
            break;
        case 'vulnerability':
            addVulnerability(data.data);
            break;
        case 'attack_status':
            updateAttackStatus(data.data);
            break;
        case 'log':
            addLogEntry(data.message, data.level);
            break;
    }
}

// Update metrics
function updateMetrics(data) {
    metricsData.total_requests = data.total_requests;
    metricsData.successful_requests = data.successful_requests;
    metricsData.failed_requests = data.failed_requests;
    
    if (data.response_time !== undefined) {
        metricsData.response_times.push(data.response_time * 1000); // convert to ms
        if (metricsData.response_times.length > 50) {
            metricsData.response_times.shift();
        }
    }
    
    // Update UI numbers
    totalRequestsEl.textContent = metricsData.total_requests;
    successfulRequestsEl.textContent = metricsData.successful_requests;
    failedRequestsEl.textContent = metricsData.failed_requests;
    
    updateCharts();
}

// Add vulnerability to layout
function addVulnerability(vulnerability) {
    // Check if placeholder is present and remove it
    if (vulnerabilitiesContainer.querySelector('p.text-center')) {
        vulnerabilitiesContainer.innerHTML = '';
    }

    metricsData.vulnerabilities_found.push(vulnerability);
    
    const vulnEl = document.createElement('div');
    vulnEl.className = 'vulnerability-item';
    vulnEl.innerHTML = `
        <h5><i class="fas fa-triangle-exclamation"></i> ${vulnerability.type}</h5>
        <p><strong>URL/Target:</strong> ${vulnerability.url}</p>
        <p><strong>Payload:</strong> <code>${vulnerability.payload}</code></p>
        <p><strong>Time:</strong> ${new Date(vulnerability.timestamp).toLocaleString()}</p>
    `;
    
    vulnerabilitiesContainer.insertBefore(vulnEl, vulnerabilitiesContainer.firstChild);
    addLogEntry(`Vulnerability recorded: ${vulnerability.type} at ${vulnerability.url}`, 'error');
}

// Update attack running states
function updateAttackStatus(status) {
    if (status.running) {
        statusIndicator.className = 'status-indicator status-running';
        statusText.textContent = `Testing (${status.attack_type.toUpperCase()})`;
        startAttackBtn.disabled = true;
        stopAttackBtn.disabled = false;
    } else {
        statusIndicator.className = 'status-indicator status-ready';
        statusText.textContent = 'Ready';
        startAttackBtn.disabled = false;
        stopAttackBtn.disabled = true;
        
        if (status.completed) {
            addLogEntry(`Attack completed: ${status.attack_type.toUpperCase()}. Total: ${status.total_requests} requests.`, 'success');
            addToAttackHistory(status);
        }
    }
}

// Add logs to scroll container
function addLogEntry(message, level = 'info') {
    const logEntry = document.createElement('div');
    logEntry.className = `log-entry log-${level}`;
    
    const timestamp = new Date().toLocaleTimeString();
    logEntry.textContent = `[${timestamp}] ${message}`;
    
    logContainer.appendChild(logEntry);
    logContainer.scrollTop = logContainer.scrollHeight;
    
    while (logContainer.children.length > 100) {
        logContainer.removeChild(logContainer.firstChild);
    }
}

// Render history card
function addToAttackHistory(attack) {
    if (attackHistoryContainer.querySelector('p.text-center')) {
        attackHistoryContainer.innerHTML = '';
    }

    attackHistory.push(attack);
    
    const historyItem = document.createElement('div');
    historyItem.className = 'card';
    historyItem.innerHTML = `
        <div class="card-body">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h5 class="mb-1 text-primary">${attack.attack_type.toUpperCase()} Attack</h5>
                    <p class="text-secondary mb-1"><strong>Target:</strong> ${attack.url}</p>
                    <p class="text-secondary mb-0"><strong>Time:</strong> ${new Date(attack.timestamp).toLocaleString()}</p>
                </div>
                <div class="text-right" style="text-align: right;">
                    <div style="font-size: 1.5rem; font-weight:700;">${attack.total_requests}</div>
                    <div class="text-secondary">Requests sent</div>
                </div>
            </div>
        </div>
    `;
    
    attackHistoryContainer.insertBefore(historyItem, attackHistoryContainer.firstChild);
}

// Initialize ChartJS
function initCharts() {
    const responseTimeCtx = responseTimeChartEl.getContext('2d');
    window.responseTimeChart = new Chart(responseTimeCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Response Time (ms)',
                data: [],
                backgroundColor: 'rgba(59, 130, 246, 0.2)',
                borderColor: 'rgba(59, 130, 246, 1)',
                borderWidth: 2,
                tension: 0.3,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: 'rgba(255, 255, 255, 0.6)' }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: 'rgba(255, 255, 255, 0.6)' }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
    
    const requestRateCtx = requestRateChartEl.getContext('2d');
    window.requestRateChart = new Chart(requestRateCtx, {
        type: 'bar',
        data: {
            labels: ['Successful', 'Failed'],
            datasets: [{
                label: 'Requests',
                data: [0, 0],
                backgroundColor: [
                    'rgba(16, 185, 129, 0.6)',
                    'rgba(239, 68, 68, 0.6)'
                ],
                borderColor: [
                    'rgba(16, 185, 129, 1)',
                    'rgba(239, 68, 68, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: 'rgba(255, 255, 255, 0.6)' }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: 'rgba(255, 255, 255, 0.6)' }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

// Update ChartJS data dynamically
function updateCharts() {
    if (window.responseTimeChart) {
        const labels = metricsData.response_times.map((_, i) => i.toString());
        window.responseTimeChart.data.labels = labels;
        window.responseTimeChart.data.datasets[0].data = metricsData.response_times;
        window.responseTimeChart.update('none');
    }
    
    if (window.requestRateChart) {
        window.requestRateChart.data.datasets[0].data = [
            metricsData.successful_requests,
            metricsData.failed_requests
        ];
        window.requestRateChart.update('none');
    }
}

// Trigger start attack API
async function startAttack() {
    const urlInput = document.getElementById('url-input');
    if (!urlInput.value) {
        alert('Please specify a target URL/Host.');
        return;
    }
    
    const payload = {
        url: urlInput.value.trim(),
        attack_type: attackTypeInput.value,
        duration: parseInt(document.getElementById('duration-input').value),
        intensity: parseInt(document.getElementById('intensity-input').value),
        threads: parseInt(document.getElementById('threads-input').value),
        target_port: document.getElementById('port-input').value ? parseInt(document.getElementById('port-input').value) : null,
        username: document.getElementById('username-input').value.trim() || null,
        wordlist: document.getElementById('wordlist-input').value.trim() || null
    };

    startAttackBtn.disabled = true;
    
    try {
        const urls = getBackendUrls();
        const response = await fetch(`${urls.http}/api/attack/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const result = await response.json();
        
        if (response.ok && result.success) {
            currentAttackId = result.attack_id;
            addLogEntry(`Attack request authorized. Test ID: ${currentAttackId}`, 'info');
            // Navigate to Dashboard to watch stats
            document.querySelector('[data-page="dashboard"]').click();
        } else {
            alert(result.detail || result.message || 'Failed to start attack.');
            startAttackBtn.disabled = false;
        }
    } catch (err) {
        console.error('Error starting attack:', err);
        addLogEntry('Connection to API failed.', 'error');
        startAttackBtn.disabled = false;
    }
}

// Trigger stop attack API
async function stopAttack() {
    try {
        const urls = getBackendUrls();
        const response = await fetch(`${urls.http}/api/attack/stop`, { method: 'POST' });
        const result = await response.json();
        if (result.success) {
            addLogEntry('Termination command sent successfully.', 'info');
        }
    } catch (err) {
        console.error('Error stopping attack:', err);
    }
}

// Clear UI logs
document.getElementById('clear-log').addEventListener('click', () => {
    logContainer.innerHTML = '';
});

// Full state reset
async function resetAllData() {
    if (!confirm('Are you sure you want to reset all test statistics, history logs, and graphs?')) {
        return;
    }
    try {
        const urls = getBackendUrls();
        const response = await fetch(`${urls.http}/api/logs/clear`, { method: 'POST' });
        if (response.ok) {
            metricsData = {
                total_requests: 0,
                successful_requests: 0,
                failed_requests: 0,
                response_times: [],
                vulnerabilities_found: []
            };
            attackHistory = [];
            totalRequestsEl.textContent = '0';
            successfulRequestsEl.textContent = '0';
            failedRequestsEl.textContent = '0';
            vulnerabilitiesContainer.innerHTML = '<p class="text-secondary text-center py-4">No vulnerabilities discovered yet.</p>';
            attackHistoryContainer.innerHTML = '<p class="text-secondary text-center py-4">No previous test runs.</p>';
            updateCharts();
            alert('Suite statistics reset successfully.');
        }
    } catch (err) {
        console.error('Error resetting database:', err);
    }
}

// Save backend host and trigger reconnect
if (saveBackendBtn) {
    saveBackendBtn.addEventListener('click', () => {
        const val = backendUrlInput.value.trim();
        if (val) {
            localStorage.setItem('testing_backend_host', val);
        } else {
            localStorage.removeItem('testing_backend_host');
        }
        addLogEntry('Backend host saved. Reconnecting...', 'info');
        if (ws) {
            ws.close(); // Triggers auto-reconnect with new URLs
        }
        fetchStatus();
    });
}

// Attach control event listeners
startAttackBtn.addEventListener('click', startAttack);
stopAttackBtn.addEventListener('click', stopAttack);
document.getElementById('btn-reset-all').addEventListener('click', resetAllData);

// Fetch initial status on load
async function fetchStatus() {
    try {
        const urls = getBackendUrls();
        const response = await fetch(`${urls.http}/api/status`);
        const data = await response.json();
        
        // Sync active state
        updateAttackStatus({ running: data.attacks_running, attack_type: data.current_attacks[0], completed: false });
        
        // Sync UI counts
        metricsData.total_requests = data.stats.total_requests;
        metricsData.successful_requests = data.stats.successful_requests;
        metricsData.failed_requests = data.stats.failed_requests;
        totalRequestsEl.textContent = metricsData.total_requests;
        successfulRequestsEl.textContent = metricsData.successful_requests;
        failedRequestsEl.textContent = metricsData.failed_requests;
        
        // Render vulnerabilities
        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            vulnerabilitiesContainer.innerHTML = '';
            data.vulnerabilities.reverse().forEach(v => addVulnerability(v));
        }
        
        // Render history
        if (data.history && data.history.length > 0) {
            attackHistoryContainer.innerHTML = '';
            data.history.forEach(h => addToAttackHistory(h));
        }
        
        updateCharts();
    } catch (err) {
        console.error('Error syncing status:', err);
    }
}

// Boot UI
initCharts();
initWebSocket();
fetchStatus();
