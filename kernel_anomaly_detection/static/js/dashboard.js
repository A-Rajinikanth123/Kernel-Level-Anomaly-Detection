/**
 * AI-Based Kernel-Level Anomaly Detection System
 * Real-Time Dashboard Client Controller
 */

document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    initPolling();
    initSimulatorButtons();
    initMitigationHandlers();
    initProbeToggle();
});

let velocityChart = null;
let threatChart = null;

// Initialize Chart.js
function initCharts() {
    const velocityCtx = document.getElementById('velocityChart');
    if (velocityCtx) {
        velocityChart = new Chart(velocityCtx, {
            type: 'line',
            data: {
                labels: ['-20s', '-16s', '-12s', '-8s', '-4s', 'Now'],
                datasets: [
                    {
                        label: 'Kernel Syscalls / sec',
                        data: [120, 145, 130, 180, 160, 195],
                        borderColor: '#06b6d4',
                        backgroundColor: 'rgba(6, 182, 212, 0.1)',
                        fill: true,
                        tension: 0.35,
                        borderWidth: 2,
                        pointRadius: 3
                    },
                    {
                        label: 'CPU Usage %',
                        data: [12, 14, 18, 15, 22, 19],
                        borderColor: '#8b5cf6',
                        backgroundColor: 'transparent',
                        tension: 0.35,
                        borderWidth: 2,
                        pointRadius: 2
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#94a3b8', font: { size: 11 } }
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#64748b', font: { size: 10 } }
                    },
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#64748b', font: { size: 10 } }
                    }
                }
            }
        });
    }

    const threatCtx = document.getElementById('threatChart');
    if (threatCtx) {
        // Read data attributes if available
        const normalCount = parseInt(threatCtx.dataset.normal || 20);
        const lowCount = parseInt(threatCtx.dataset.low || 5);
        const medCount = parseInt(threatCtx.dataset.med || 4);
        const highCount = parseInt(threatCtx.dataset.high || 3);
        const critCount = parseInt(threatCtx.dataset.crit || 2);

        threatChart = new Chart(threatCtx, {
            type: 'doughnut',
            data: {
                labels: ['Normal', 'Low Risk', 'Medium Risk', 'High Risk', 'Critical'],
                datasets: [{
                    data: [normalCount, lowCount, medCount, highCount, critCount],
                    backgroundColor: [
                        '#10b981', // Emerald
                        '#3b82f6', // Blue
                        '#f59e0b', // Amber
                        '#f97316', // Orange
                        '#ef4444'  // Crimson
                    ],
                    borderColor: '#111827',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#94a3b8', boxWidth: 12, font: { size: 10 } }
                    }
                },
                cutout: '68%'
            }
        });
    }
}

// Live Polling every 4 seconds
function initPolling() {
    setInterval(() => {
        fetch('/api/stats/')
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success') {
                    updateDashboardCounters(data);
                    updateCharts(data);
                }
            })
            .catch(err => console.debug('Polling background stats...', err));

        fetch('/api/events/live/')
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success' && data.events) {
                    updateLiveEventsTable(data.events);
                }
            })
            .catch(err => console.debug('Polling live events...', err));
    }, 4000);
}

function updateDashboardCounters(data) {
    const elEvents = document.getElementById('stat-total-events');
    const elAnomalies = document.getElementById('stat-total-anomalies');
    const elActive = document.getElementById('stat-active-alerts');
    const elCritical = document.getElementById('stat-critical-alerts');

    if (elEvents) elEvents.innerText = data.total_events;
    if (elAnomalies) elAnomalies.innerText = data.total_anomalies;
    if (elActive) elActive.innerText = data.active_alerts;
    if (elCritical) elCritical.innerText = data.critical_alerts;
}

function updateCharts(data) {
    if (velocityChart && data.chart_labels && data.chart_labels.length > 0) {
        velocityChart.data.labels = data.chart_labels;
        velocityChart.data.datasets[0].data = data.syscall_data;
        velocityChart.data.datasets[1].data = data.cpu_data;
        velocityChart.update('none');
    }

    if (threatChart && data.threat_distribution) {
        const td = data.threat_distribution;
        threatChart.data.datasets[0].data = [
            td.NORMAL || 0,
            td.LOW || 0,
            td.MEDIUM || 0,
            td.HIGH || 0,
            td.CRITICAL || 0
        ];
        threatChart.update('none');
    }
}

function updateLiveEventsTable(events) {
    const tbody = document.getElementById('live-events-tbody');
    if (!tbody || events.length === 0) return;

    let html = '';
    events.forEach(ev => {
        html += `
            <tr>
                <td class="font-mono text-cyan">${ev.timestamp}</td>
                <td><span class="badge-type">${ev.event_type}</span></td>
                <td class="font-mono"><strong>${ev.process_name}</strong> <span class="text-dim">(${ev.pid})</span></td>
                <td>${ev.user}</td>
                <td class="font-mono text-dim">${ev.syscall_name}</td>
                <td><span class="badge-threat badge-${ev.threat_level}">${ev.threat_level}</span></td>
                <td class="font-mono">${ev.anomaly_score.toFixed(2)}</td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
}

// Quick Attack Simulation Handlers
function initSimulatorButtons() {
    const simButtons = document.querySelectorAll('.btn-sim-attack');
    simButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const scenario = btn.dataset.scenario;
            btn.disabled = true;
            btn.innerHTML = `<i class="fa fa-spinner fa-spin"></i> Injecting...`;

            fetch('/api/simulate/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scenario: scenario })
            })
            .then(res => res.json())
            .then(data => {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa fa-crosshairs"></i> ${btn.dataset.label || 'Inject'}`;

                if (data.status === 'success') {
                    showToast(
                        `<strong>🚨 Attack Injected!</strong><br>
                        ${data.data.scenario} (PID ${data.data.pid})<br>
                        AI Score: <strong>${data.data.anomaly_score}</strong> (${data.data.threat_level})`,
                        'danger'
                    );
                    // Refresh counters immediately
                    fetch('/api/stats/').then(r => r.json()).then(updateDashboardCounters);
                } else {
                    showToast(`Error: ${data.message}`, 'danger');
                }
            })
            .catch(err => {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa fa-crosshairs"></i> ${btn.dataset.label || 'Inject'}`;
                showToast(`Simulation failed: ${err}`, 'danger');
            });
        });
    });
}

// 1-Click Threat Mitigation Handlers
function initMitigationHandlers() {
    document.addEventListener('click', (e) => {
        const btn = e.target.closest('.btn-quick-mitigate');
        if (!btn) return;

        const alertId = btn.dataset.alertId;
        const action = btn.dataset.action;

        if (!confirm(`Are you sure you want to execute ${action} for alert ${alertId}?`)) {
            return;
        }

        btn.disabled = true;
        btn.innerHTML = `<i class="fa fa-spinner fa-spin"></i>`;

        fetch(`/api/alerts/${alertId}/mitigate/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: action })
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                showToast(`<strong>Action Executed:</strong> ${data.message}`, 'success');
                const row = document.getElementById(`alert-row-${alertId}`);
                if (row) {
                    row.style.opacity = '0.5';
                    row.querySelector('.badge-threat').innerText = 'RESOLVED';
                    row.querySelector('.badge-threat').className = 'badge-threat badge-NORMAL';
                }
            } else {
                showToast(`Mitigation failed: ${data.message}`, 'danger');
                btn.disabled = false;
                btn.innerHTML = `Mitigate`;
            }
        })
        .catch(err => {
            showToast(`Mitigation error: ${err}`, 'danger');
            btn.disabled = false;
        });
    });
}

// Probe Live Toggle Button
function initProbeToggle() {
    const probeBtn = document.getElementById('btn-toggle-probe');
    if (!probeBtn) return;

    probeBtn.addEventListener('click', () => {
        fetch('/api/collector/toggle/', { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success') {
                    showToast(data.message, data.is_running ? 'success' : 'danger');
                    location.reload();
                }
            });
    });
}

// Toast notification helper
function showToast(htmlMessage, type = 'info') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `soc-toast ${type}`;
    toast.innerHTML = htmlMessage;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 0.4s ease';
        setTimeout(() => toast.remove(), 400);
    }, 4500);
}
