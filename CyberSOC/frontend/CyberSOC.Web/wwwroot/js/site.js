/**
 * CyberSOC Command Center — site.js
 *
 * Connects to CyberSOC.WebApi /hubs/alerts via SignalR.
 * Hub URL is injected server-side → window.ALERTS_HUB_URL (_Layout.cshtml).
 *
 * Panels driven by this file:
 *  - Stats bar          (statTotal, statCritical, statHigh, statMedium, statLow, statInfo)
 *  - Severity chart     (Chart.js horizontal bar — #severityChart)
 *  - Severity breakdown (#severityBreakdown — count + % + mini-bar)
 *  - Connection info    (#infoHubUrl, #infoState, #infoConnectedAt, #infoReconnects)
 *  - Last alert panel   (#lastAlertPanel)
 *  - Alert table        (#alertTableBody) with severity filter + detail modal
 */

'use strict';

// ── Constants ──────────────────────────────────────────────────
const MAX_ALERTS_RETAINED = 200;

const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Informational'];

const SEVERITY_COLORS = {
    Critical: '#c0392b',
    High: '#e74c3c',
    Medium: '#f39c12',
    Low: '#3498db',
    Informational: '#95a5a6',
};

const STATE_CONFIG = {
    connecting: { text: 'Connecting…', colorClass: 'bg-secondary' },
    connected: { text: 'Live', colorClass: 'bg-success' },
    reconnecting: { text: 'Reconnecting…', colorClass: 'bg-warning' },
    disconnected: { text: 'Disconnected', colorClass: 'bg-danger' },
    error: { text: 'Connection error', colorClass: 'bg-danger' },
};

// ── State ───────────────────────────────────────────────────────
const alerts = [];
const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
let reconnectCount = 0;
let connectedAt = null;
let activeFilter = '';

// ── DOM refs ────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const statusDot = $('statusDot');
const statusText = $('statusText');
const alertCount = $('alertCount');
const emptyState = $('emptyState');
const tableWrapper = $('alertTableWrapper');
const tableBody = $('alertTableBody');
const severityBreakdown = $('severityBreakdown');
const lastAlertPanel = $('lastAlertPanel');
const infoHubUrl = $('infoHubUrl');
const infoState = $('infoState');
const infoConnectedAt = $('infoConnectedAt');
const infoReconnects = $('infoReconnects');
const chartUpdated = $('chartUpdated');
const severityFilter = $('severityFilter');

// Stat bar refs
const statRefs = {
    Total: $('statTotal'),
    Critical: $('statCritical'),
    High: $('statHigh'),
    Medium: $('statMedium'),
    Low: $('statLow'),
    Informational: $('statInfo'),
};

// ── Connection status ───────────────────────────────────────────
function updateConnectionStatus(state) {
    const cfg = STATE_CONFIG[state] ?? STATE_CONFIG.disconnected;
    statusDot.className = 'status-dot ' + cfg.colorClass;
    statusText.textContent = cfg.text;
    statusText.className = state === 'connected' ? 'text-success small' : 'text-secondary small';
    infoState.textContent = cfg.text;
    infoState.className = state === 'connected' ? 'text-success' : 'text-secondary';
}

// ── Severity badge HTML ─────────────────────────────────────────
function severityBadgeHtml(severity) {
    const key = (severity ?? 'informational').toLowerCase();
    return `<span class="badge badge-${key} px-2">${escapeHtml(severity ?? '—')}</span>`;
}

// ── Stats bar ───────────────────────────────────────────────────
function updateStats() {
    const total = alerts.length;
    statRefs.Total.textContent = total;
    statRefs.Critical.textContent = counts.Critical;
    statRefs.High.textContent = counts.High;
    statRefs.Medium.textContent = counts.Medium;
    statRefs.Low.textContent = counts.Low;
    statRefs.Informational.textContent = counts.Informational;
    alertCount.textContent = Math.min(total, MAX_ALERTS_RETAINED);
}

// ── Chart ───────────────────────────────────────────────────────
let severityChart = null;

function initChart() {
    const ctx = $('severityChart').getContext('2d');
    severityChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: SEVERITY_ORDER,
            datasets: [{
                label: 'Alerts',
                data: SEVERITY_ORDER.map(s => counts[s]),
                backgroundColor: SEVERITY_ORDER.map(s => SEVERITY_COLORS[s]),
                borderRadius: 5,
                borderSkipped: false,
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#1c2130',
                    borderColor: '#2a2f3a',
                    borderWidth: 1,
                    titleColor: '#c9d1d9',
                    bodyColor: '#8b949e',
                    callbacks: {
                        label: ctx => {
                            const count = ctx.parsed.x;
                            const total = alerts.length;
                            const pct = total > 0 ? ((count / total) * 100).toFixed(1) : '0.0';
                            return `  ${count} alert${count !== 1 ? 's' : ''} (${pct}%)`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    ticks: { color: '#8b949e', precision: 0 },
                    grid: { color: '#2a2f3a' },
                    border: { color: '#2a2f3a' },
                },
                y: {
                    ticks: { color: '#c9d1d9', font: { weight: '500' } },
                    grid: { display: false },
                    border: { color: '#2a2f3a' },
                }
            },
            animation: { duration: 300 }
        }
    });
}

function updateChart() {
    if (!severityChart) return;
    severityChart.data.datasets[0].data = SEVERITY_ORDER.map(s => counts[s]);
    severityChart.update();
    chartUpdated.textContent = new Date().toLocaleTimeString();
}

// ── Severity breakdown table ────────────────────────────────────
function updateBreakdown() {
    const total = alerts.length;
    severityBreakdown.innerHTML = SEVERITY_ORDER.map(s => {
        const c = counts[s];
        const pct = total > 0 ? ((c / total) * 100) : 0;
        return `
        <tr>
            <td>${severityBadgeHtml(s)}</td>
            <td class="text-end fw-semibold">${c}</td>
            <td class="text-end">
                <div class="d-flex align-items-center justify-content-end gap-2">
                    <span class="text-secondary" style="min-width:34px">${pct.toFixed(0)}%</span>
                    <span class="pct-bar-track">
                        <span class="pct-bar-fill" style="width:${pct.toFixed(1)}%;background-color:${SEVERITY_COLORS[s]}"></span>
                    </span>
                </div>
            </td>
        </tr>`;
    }).join('');
}

// ── Last alert panel ────────────────────────────────────────────
function updateLastAlert(alert) {
    lastAlertPanel.innerHTML = `
        <li class="list-group-item d-flex justify-content-between">
            <span class="text-secondary">Severity</span>
            ${severityBadgeHtml(alert.severity)}
        </li>
        <li class="list-group-item d-flex justify-content-between">
            <span class="text-secondary">Type</span>
            <span>${escapeHtml(alert.alertType)}</span>
        </li>
        <li class="list-group-item">
            <div class="text-secondary mb-1">Title</div>
            <div class="small">${escapeHtml(alert.title)}</div>
        </li>
        <li class="list-group-item d-flex justify-content-between">
            <span class="text-secondary">Source IP</span>
            <code>${escapeHtml(alert.sourceIp)}</code>
        </li>
        <li class="list-group-item d-flex justify-content-between">
            <span class="text-secondary">Raised At</span>
            <span class="small">${new Date(alert.raisedAt).toLocaleTimeString()}</span>
        </li>`;
}

// ── Alert table row ─────────────────────────────────────────────
function prependAlertRow(alert) {
    // Visibility filter
    const hidden = activeFilter && alert.severity !== activeFilter;

    const tr = document.createElement('tr');
    tr.dataset.severity = alert.severity;
    tr.dataset.alertId = alert.alertId;
    if (hidden) tr.classList.add('d-none');
    tr.classList.add('row-new');

    tr.innerHTML = `
        <td>${severityBadgeHtml(alert.severity)}</td>
        <td class="text-secondary">${escapeHtml(alert.alertType)}</td>
        <td>${escapeHtml(alert.title)}</td>
        <td><code>${escapeHtml(alert.sourceIp)}</code></td>
        <td class="text-secondary">${new Date(alert.raisedAt).toLocaleTimeString()}</td>
        <td><button class="btn-detail" title="View detail" onclick="showDetail('${escapeHtml(alert.alertId)}')">
            <i class="bi bi-eye"></i>
        </button></td>`;

    tableBody.insertBefore(tr, tableBody.firstChild);

    // Trim to cap
    while (tableBody.rows.length > MAX_ALERTS_RETAINED) {
        tableBody.deleteRow(tableBody.rows.length - 1);
    }

    // Show table, hide empty state
    if (!emptyState.classList.contains('d-none')) {
        emptyState.classList.add('d-none');
        tableWrapper.classList.remove('d-none');
    }
}

// ── Detail modal ────────────────────────────────────────────────
function showDetail(alertId) {
    const alert = alerts.find(a => a.alertId === alertId);
    if (!alert) return;

    const body = $('alertDetailBody');
    body.innerHTML = `
        <div class="detail-row">
            <span class="detail-label">Alert ID</span>
            <code class="detail-value">${escapeHtml(alert.alertId)}</code>
        </div>
        <div class="detail-row">
            <span class="detail-label">Severity</span>
            <span class="detail-value">${severityBadgeHtml(alert.severity)}</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Type</span>
            <span class="detail-value">${escapeHtml(alert.alertType)}</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Title</span>
            <span class="detail-value">${escapeHtml(alert.title)}</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Source IP</span>
            <code class="detail-value">${escapeHtml(alert.sourceIp)}</code>
        </div>
        <div class="detail-row">
            <span class="detail-label">Raised At</span>
            <span class="detail-value">${new Date(alert.raisedAt).toLocaleString()}</span>
        </div>
        <div class="detail-row" style="flex-direction:column">
            <span class="detail-label mb-2">Reason / Detail</span>
            <div class="reason-box">${escapeHtml(alert.reason ?? 'No reason provided.')}</div>
        </div>`;

    const modal = new bootstrap.Modal($('alertDetailModal'));
    modal.show();
}

// ── Severity filter ─────────────────────────────────────────────
function applyFilter(severity) {
    activeFilter = severity;
    const rows = tableBody.querySelectorAll('tr[data-severity]');
    rows.forEach(tr => {
        if (!severity || tr.dataset.severity === severity) {
            tr.classList.remove('d-none');
        } else {
            tr.classList.add('d-none');
        }
    });
}

// ── SignalR feed ────────────────────────────────────────────────
function startAlertsFeed() {
    const hubUrl = window.ALERTS_HUB_URL;

    if (!hubUrl) {
        console.error('[CyberSOC] window.ALERTS_HUB_URL is not set. Check appsettings.json → SignalR:HubUrl');
        updateConnectionStatus('error');
        return;
    }

    infoHubUrl.textContent = hubUrl;
    infoHubUrl.title = hubUrl;

    const connection = new signalR.HubConnectionBuilder()
        .withUrl(hubUrl, {
            withCredentials: true,
            transport: signalR.HttpTransportType.WebSockets | signalR.HttpTransportType.LongPolling,
        })
        .withAutomaticReconnect([0, 2000, 5000, 10000, 30000])
        .configureLogging(signalR.LogLevel.Information)
        .build();

    connection.on('AlertRaised', (notification) => {
        // Buffer
        alerts.unshift(notification);
        if (alerts.length > MAX_ALERTS_RETAINED) alerts.pop();

        // Counts
        const sev = notification.severity;
        if (sev in counts) counts[sev]++;

        // Refresh all panels
        prependAlertRow(notification);
        updateStats();
        updateChart();
        updateBreakdown();
        updateLastAlert(notification);
    });

    connection.onreconnecting(() => {
        updateConnectionStatus('reconnecting');
    });

    connection.onreconnected(() => {
        reconnectCount++;
        infoReconnects.textContent = reconnectCount;
        updateConnectionStatus('connected');
    });

    connection.onclose(() => {
        updateConnectionStatus('disconnected');
        infoConnectedAt.textContent = '—';
    });

    updateConnectionStatus('connecting');

    connection.start()
        .then(() => {
            connectedAt = new Date();
            infoConnectedAt.textContent = connectedAt.toLocaleTimeString();
            updateConnectionStatus('connected');
        })
        .catch(err => {
            console.error('[CyberSOC] SignalR connection failed:', err);
            updateConnectionStatus('error');
        });
}

// ── XSS helper ──────────────────────────────────────────────────
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ── Boot ────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initChart();
    updateStats();
    updateBreakdown();

    severityFilter.addEventListener('change', () => applyFilter(severityFilter.value));

    startAlertsFeed();
});
