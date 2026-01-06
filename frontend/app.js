/**
 * Adaptive Intrusion Detection System (AIDS) - Dashboard JavaScript
 * Enhanced with WebSocket real-time updates, UEBA viewer, and response controls
 */

// API Base URL
const API_BASE = '/api';

// WebSocket connection
let alertsWebSocket = null;
let wsConnected = false;

// Global state
let allAlerts = [];
let uebaProfiles = [];
let trafficChart = null;
let networkGraph = null;
let audioEnabled = false;

// Critical alert sound
const alertSound = new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2telegsXUMnq6pJDAxNfqNrzoFsIDUKN0f+4eBsoYqbc+LZ0Gxkhaqvj/b15LCQMebnv/sF+MSghfrz0/8WAOCEVR5/L+8x8PDkhRJjC9MZ4QTYZe7Ll98V2Px');

// ============================================
// Initialization
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    console.log('AIDS Dashboard initialized');
    initTrafficChart();
    initWebSocket();
    loadInitialData();

    // Auto-refresh every 10 seconds
    setInterval(() => {
        if (!wsConnected) {
            refreshData();
        }
    }, 10000);
});

// ============================================
// WebSocket Real-Time Updates
// ============================================

function initWebSocket() {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.host}/ws/alerts`;

    try {
        alertsWebSocket = new WebSocket(wsUrl);

        alertsWebSocket.onopen = () => {
            console.log('WebSocket connected for real-time alerts');
            wsConnected = true;
            updateConnectionStatus(true);
        };

        alertsWebSocket.onmessage = (event) => {
            const message = JSON.parse(event.data);
            handleWebSocketMessage(message);
        };

        alertsWebSocket.onclose = () => {
            console.log('WebSocket disconnected');
            wsConnected = false;
            updateConnectionStatus(false);
            // Try to reconnect after 5 seconds
            setTimeout(initWebSocket, 5000);
        };

        alertsWebSocket.onerror = (error) => {
            console.error('WebSocket error:', error);
            wsConnected = false;
        };
    } catch (error) {
        console.error('Failed to initialize WebSocket:', error);
    }
}

function handleWebSocketMessage(message) {
    if (message.type === 'alert') {
        // New alert received
        const alert = message.data;
        console.log('Real-time alert received:', alert);

        // Add to alerts array
        allAlerts.unshift(alert);
        renderAlerts(allAlerts);

        // Play sound for critical alerts
        if (audioEnabled && (alert.severity === 'critical' || alert.severity === 'high')) {
            playAlertSound();
        }

        // Update stats
        fetchAlertStats();

        // Show notification
        showNotification(`New ${alert.severity} alert: ${alert.title || 'Security Event'}`, alert.severity);
    } else if (message.type === 'status') {
        console.log('System status update:', message.data);
    }
}

function updateConnectionStatus(connected) {
    const statusIndicator = document.getElementById('wsStatus');
    if (statusIndicator) {
        statusIndicator.className = connected ? 'ws-status connected' : 'ws-status disconnected';
        statusIndicator.title = connected ? 'Real-time updates active' : 'Disconnected - polling';
    }
}

function playAlertSound() {
    try {
        alertSound.play();
    } catch (e) {
        console.log('Could not play alert sound');
    }
}

function toggleAudio() {
    audioEnabled = !audioEnabled;
    const btn = document.getElementById('audioToggle');
    if (btn) {
        btn.innerHTML = audioEnabled ? '🔔' : '🔕';
        btn.title = audioEnabled ? 'Sound alerts enabled' : 'Sound alerts disabled';
    }
}

function showNotification(message, severity) {
    const notification = document.createElement('div');
    notification.className = `toast-notification ${severity}`;
    notification.innerHTML = `
        <span class="toast-icon">${severity === 'critical' ? '🚨' : severity === 'high' ? '⚠️' : 'ℹ️'}</span>
        <span class="toast-message">${message}</span>
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.classList.add('show');
    }, 100);

    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

// ============================================
// API Calls
// ============================================

async function loadInitialData() {
    try {
        await Promise.all([
            fetchAlertStats(),
            fetchFinalAlerts(),
            fetchNetworkGraph(),
            fetchTrafficStats(),
            fetchMitreStats()
        ]);
        fetchThreatTimeline(); // Run after alerts loaded
        updateLastUpdate();
    } catch (error) {
        console.error('Error loading initial data:', error);
    }
}

async function fetchAlertStats() {
    try {
        const response = await fetch(`${API_BASE}/alerts/stats`);
        const stats = await response.json();
        updateStatCards(stats);
    } catch (error) {
        console.error('Error fetching alert stats:', error);
    }
}

async function fetchFinalAlerts() {
    try {
        const response = await fetch(`${API_BASE}/alerts/final`);
        allAlerts = await response.json();
        renderAlerts(allAlerts);
    } catch (error) {
        console.error('Error fetching alerts:', error);
    }
}

async function fetchNetworkGraph() {
    try {
        const response = await fetch(`${API_BASE}/graph`);
        const graphData = await response.json();
        if (graphData.nodes && graphData.nodes.length > 0) {
            renderNetworkGraph(graphData);
        }
    } catch (error) {
        console.error('Error fetching network graph:', error);
    }
}

async function fetchTrafficStats() {
    try {
        const response = await fetch(`${API_BASE}/stats`);
        const stats = await response.json();
        updateTrafficChart(stats);
        document.getElementById('deviceCount').textContent = stats.total_devices || 0;
        document.getElementById('flowCount').textContent = stats.total_flows || 0;
    } catch (error) {
        console.error('Error fetching traffic stats:', error);
    }
}

async function fetchUEBAProfiles() {
    try {
        const response = await fetch(`${API_BASE}/ueba/profiles`);
        uebaProfiles = await response.json();
        renderUEBAProfiles(uebaProfiles);
    } catch (error) {
        console.error('Error fetching UEBA profiles:', error);
    }
}

async function fetchMitreStats() {
    try {
        const response = await fetch(`${API_BASE}/intel/mitre/coverage`);
        const stats = await response.json();
        renderMitreHeatmap(stats);
    } catch (error) {
        console.error('Error fetching MITRE stats:', error);
    }
}

async function fetchThreatTimeline() {
    // Simulated timeline data for now, eventually API
    const timelineData = allAlerts.map(a => ({
        id: a.alert_id,
        timestamp: a.timestamp,
        title: a.title,
        severity: a.severity,
        details: `${a.source_ip} → ${a.target_ips.length} targets`
    })).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    renderInvestigationTimeline(timelineData);
}

function renderMitreHeatmap(data) {
    const container = document.getElementById('mitreHeatmap');
    if (!container) return;

    container.innerHTML = '';

    // Group by tactic
    const tactics = {};
    if (data.techniques) {
        data.techniques.forEach(tech => {
            tech.tactics.forEach(tactic => {
                if (!tactics[tactic]) tactics[tactic] = [];
                tactics[tactic].push(tech);
            });
        });
    } else {
        // Fallback demo data
        const demoTactics = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration', 'Command and Control'];
        demoTactics.forEach(t => tactics[t] = []);
    }

    Object.entries(tactics).forEach(([tactic, techniques]) => {
        const col = document.createElement('div');
        col.className = 'mitre-column';

        col.innerHTML = `
            <div class="mitre-tactic">${tactic.replace(/-/g, ' ')}</div>
            ${techniques.length > 0 ? techniques.map(t => `
                <div class="mitre-technique ${t.detection_count > 0 ? 'active' : ''}" title="${t.name}: ${t.detection_count} detections">
                    ${t.technique_id}
                </div>
            `).join('') : '<div class="mitre-technique" style="opacity:0.3">No coverage</div>'}
        `;
        container.appendChild(col);
    });
}

function renderInvestigationTimeline(events) {
    const container = document.getElementById('threatTimeline');
    if (!container) return;

    if (events.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No timeline events</p></div>';
        return;
    }

    container.innerHTML = events.map((e, i) => `
        <div class="timeline-event" style="border-left: 3px solid var(--${e.severity})">
            <span class="event-time">${new Date(e.timestamp).toLocaleTimeString()}</span>
            <span class="event-title">${e.title}</span>
            <span class="event-details">${e.details}</span>
        </div>
    `).join('');
}



// ============================================
// Threat Hunting
// ============================================
async function executeHunt() {
    const timeRange = document.getElementById('huntTimeRange').value;
    const ip = document.getElementById('huntIP').value;
    const protocol = document.getElementById('huntProtocol').value;

    // Calculate start time based on range
    const now = new Date();
    let startTime = new Date();
    if (timeRange === '1h') startTime.setHours(now.getHours() - 1);
    if (timeRange === '24h') startTime.setHours(now.getHours() - 24);
    if (timeRange === '7d') startTime.setDate(now.getDate() - 7);

    const query = {
        start_time: startTime.toISOString(),
        end_time: now.toISOString(),
        source_ip: ip || undefined,
        protocol: protocol || undefined
    };

    const btn = document.querySelector('.query-builder .btn-primary');
    const originalText = btn.innerText;
    btn.innerText = 'Searching...';
    btn.disabled = true;

    try {
        const response = await fetch(`${API_BASE}/hunting/search`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(query)
        });
        const data = await response.json();
        renderHuntResults(data.flows);
    } catch (error) {
        console.error('Hunting error:', error);
        alert('Search failed. See console for details.');
    } finally {
        btn.innerText = originalText;
        btn.disabled = false;
    }
}

function renderHuntResults(flows) {
    const tbody = document.querySelector('#huntResults tbody');
    if (!tbody) return;

    if (!flows || flows.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; py-4">No matching flows found</td></tr>';
        return;
    }

    tbody.innerHTML = flows.map(flow => `
        <tr>
            <td>${new Date(flow.timestamp).toLocaleTimeString()}</td>
            <td>${flow.source_ip}${flow.source_port ? ':' + flow.source_port : ''}</td>
            <td>${flow.dest_ip}${flow.dest_port ? ':' + flow.dest_port : ''}</td>
            <td><span class="detail-tag">${flow.protocol}</span></td>
            <td>${((flow.bytes_sent || 0) + (flow.bytes_received || 0)).toLocaleString()} B</td>
            <td>
                <span class="severity-badge ${getRiskClass(flow.risk_score || 0)}">
                    ${flow.risk_score !== undefined ? flow.risk_score + '/100' : 'Low'}
                </span>
            </td>
        </tr>
    `).join('');
}

function getRiskClass(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
}

async function exportSearchResults() {
    try {
        const response = await fetch(`${API_BASE} /hunting/export`);
        const data = await response.json();

        // Trigger download
        const blob = new Blob([JSON.stringify(data.data, null, 2)], { type: 'application/json' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `hunting_export_${new Date().toISOString().slice(0, 10)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Export error:', error);
    }
}

// ============================================
// Demo Controls
// ============================================

async function generateDemo() {
    const btn = event.target.closest('button');
    btn.disabled = true;
    btn.innerHTML = '<svg class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg> Generating...';

    try {
        const response = await fetch(`${API_BASE}/demo/generate`, { method: 'POST' });
        const result = await response.json();
        console.log('Demo generated:', result);

        // Reload all data
        await loadInitialData();

        // Show success
        btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg> Done!';
        setTimeout(() => {
            btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Generate Demo';
            btn.disabled = false;
        }, 2000);
    } catch (error) {
        console.error('Error generating demo:', error);
        btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg> Error';
        setTimeout(() => {
            btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Generate Demo';
            btn.disabled = false;
        }, 2000);
    }
}

async function refreshData() {
    try {
        await fetch(`${API_BASE}/demo/refresh`, { method: 'POST' });
        await loadInitialData();
        updateLastUpdate();
    } catch (error) {
        console.error('Error refreshing data:', error);
    }
}

// ============================================
// Automated Response Actions
// ============================================

async function executeResponse(playbook, alertId, sourceIp) {
    try {
        const response = await fetch(
            `${API_BASE}/response/execute/${playbook}?alert_id=${alertId}&source_ip=${sourceIp}`,
            { method: 'POST' }
        );
        const result = await response.json();

        if (result.status === 'success') {
            showNotification(`Response executed: ${playbook} `, 'medium');
            console.log('Response result:', result);
        }
        return result;
    } catch (error) {
        console.error('Error executing response:', error);
        showNotification('Failed to execute response', 'critical');
    }
}

async function blockIP(ip) {
    return executeResponse('brute_force', 'manual-block', ip);
}

async function isolateIP(ip) {
    return executeResponse('lateral_movement', 'manual-isolate', ip);
}

async function unblockIP(ip) {
    try {
        const response = await fetch(`${API_BASE}/response/unblock/${ip}`, { method: 'POST' });
        const result = await response.json();
        showNotification(`IP ${ip} unblocked`, 'low');
        return result;
    } catch (error) {
        console.error('Error unblocking IP:', error);
    }
}

// ============================================
// Export Functions
// ============================================

async function exportAlertsCSV() {
    try {
        const response = await fetch(`${API_BASE}/export/alerts/csv`);
        const result = await response.json();

        const blob = new Blob([result.data], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = result.filename;
        a.click();
        window.URL.revokeObjectURL(url);

        showNotification('Alerts exported to CSV', 'low');
    } catch (error) {
        console.error('Error exporting alerts:', error);
    }
}

async function exportProfilesCSV() {
    try {
        const response = await fetch(`${API_BASE} /export/profiles / csv`);
        const result = await response.json();

        const blob = new Blob([result.data], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = result.filename;
        a.click();
        window.URL.revokeObjectURL(url);

        showNotification('Profiles exported to CSV', 'low');
    } catch (error) {
        console.error('Error exporting profiles:', error);
    }
}

// ============================================
// UI Updates
// ============================================

function updateStatCards(stats) {
    document.getElementById('criticalCount').textContent = stats.critical || 0;
    document.getElementById('highCount').textContent = stats.high || 0;
    document.getElementById('mediumCount').textContent = stats.medium || 0;
    document.getElementById('lowCount').textContent = stats.low || 0;
}

function renderAlerts(alerts) {
    const container = document.getElementById('alertsContainer');

    if (!alerts || alerts.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <path d="M9 12l2 2 4-4"/>
                </svg>
                <p>No alerts detected</p>
                <span>Click "Generate Demo" to simulate network traffic</span>
            </div>
        `;
        return;
    }

    // Sort by risk score (highest first)
    const sortedAlerts = [...alerts].sort((a, b) => b.risk_score - a.risk_score);

    container.innerHTML = sortedAlerts.map((alert, index) => `
        <div class="alert-item ${alert.severity}" onclick="showAlertDetails(${index})" style="animation-delay: ${index * 0.05}s">
            <div class="alert-severity">
                <span class="severity-badge ${alert.severity}">${alert.severity}</span>
                <span class="risk-score">${alert.risk_score}</span>
            </div>
            <div class="alert-content">
                <div class="alert-title">
                    ${alert.is_incident ? '<span class="incident-tag">INCIDENT</span>' : ''}
                    ${alert.title}
                </div>
                <div class="alert-source">
                    Source: <code>${alert.source_ip}</code>
                    ${alert.source_role ? `(${alert.source_role})` : ''}
                    ${alert.target_ips.length > 0 ? `→ ${alert.target_ips.length} target(s)` : ''}
                </div>
                <div class="alert-layers">
                    ${alert.triggered_layers.map(layer => `<span class="layer-tag">${formatLayerName(layer)}</span>`).join('')}
                </div>
                ${alert.what_happened ? `
                <div class="alert-explanation">
                    <span class="explanation-label">🤖 AI Analysis:</span>
                    <p class="explanation-text">${alert.what_happened}</p>
                </div>
                ` : ''}
            </div>
            <div class="alert-actions">
                <button onclick="event.stopPropagation(); blockIP('${alert.source_ip}')" title="Block IP" class="action-btn block">
                    🚫
                </button>
                <button onclick="event.stopPropagation(); isolateIP('${alert.source_ip}')" title="Isolate" class="action-btn isolate">
                    🔒
                </button>
            </div>
        </div>
    `).join('');
}

function renderUEBAProfiles(profiles) {
    const container = document.getElementById('uebaContainer');
    if (!container) return;

    if (!profiles || profiles.length === 0) {
        container.innerHTML = '<p class="empty-state">No behavioral profiles available</p>';
        return;
    }

    // Sort by risk score
    const sortedProfiles = [...profiles].sort((a, b) => b.risk_score - a.risk_score);

    container.innerHTML = sortedProfiles.slice(0, 20).map(profile => `
        <div class="ueba-profile ${profile.risk_score > 0.5 ? 'high-risk' : profile.risk_score > 0.2 ? 'medium-risk' : ''}">
            <div class="profile-header">
                <span class="profile-id">${profile.entity_id}</span>
                <span class="profile-risk" style="color: ${getRiskColor(profile.risk_score)}">${(profile.risk_score * 100).toFixed(0)}%</span>
            </div>
            <div class="profile-details">
                <span class="profile-tag">${profile.role}</span>
                <span class="profile-tag">${profile.zone}</span>
                <span class="profile-stat">${profile.observation_count} flows</span>
                <span class="profile-stat">${profile.destinations_count} destinations</span>
            </div>
            ${profile.risk_factors.length > 0 ? `
                <div class="profile-risks">
                    ${profile.risk_factors.map(f => `<span class="risk-factor">${f}</span>`).join('')}
                </div>
            ` : ''}
        </div>
    `).join('');
}

function getRiskColor(score) {
    if (score >= 0.7) return '#ef4444';
    if (score >= 0.5) return '#f97316';
    if (score >= 0.3) return '#eab308';
    return '#22c55e';
}

function formatLayerName(layer) {
    const names = {
        'rule_based': '📋 Rules',
        'anomaly': '🔍 Anomaly',
        'identity': '🪪 Identity',
        'ueba': '👤 UEBA'
    };
    return names[layer] || layer;
}

function filterAlerts() {
    const filter = document.getElementById('severityFilter').value;
    let filtered = allAlerts;

    if (filter !== 'all') {
        filtered = allAlerts.filter(a => a.severity === filter);
    }

    renderAlerts(filtered);
}

function showAlertDetails(index) {
    const alert = allAlerts.sort((a, b) => b.risk_score - a.risk_score)[index];
    const panel = document.getElementById('detailsPanel');
    const content = document.getElementById('detailsContent');

    panel.classList.add('active');

    content.innerHTML = `
        <div class="detail-section">
            <h3>What Happened</h3>
            <p>${alert.what_happened}</p>
        </div>
        
        <div class="detail-section">
            <h3>Why It Matters</h3>
            <p>${alert.why_it_matters}</p>
        </div>
        
        <div class="detail-section">
            <h3>Source Details</h3>
            <div class="detail-tags">
                <span class="detail-tag">IP: ${alert.source_ip}</span>
                ${alert.source_role ? `<span class="detail-tag">Role: ${alert.source_role}</span>` : ''}
                ${alert.source_zone ? `<span class="detail-tag">Zone: ${alert.source_zone}</span>` : ''}
            </div>
        </div>
        
        ${alert.target_ips.length > 0 ? `
        <div class="detail-section">
            <h3>Target IPs</h3>
            <div class="targets-list">
                ${alert.target_ips.slice(0, 10).map(ip => `<span class="target-ip">${ip}</span>`).join('')}
                ${alert.target_ips.length > 10 ? `<span class="target-ip">... and ${alert.target_ips.length - 10} more</span>` : ''}
            </div>
        </div>
        ` : ''
        }

<div class="detail-section">
    <h3>Detection Layers</h3>
    <div class="detail-tags">
        ${alert.triggered_layers.map(layer => `<span class="detail-tag">${formatLayerName(layer)}</span>`).join('')}
    </div>
</div>
        
        ${alert.contributing_rules.length > 0 ? `
        <div class="detail-section">
            <h3>Triggered Rules</h3>
            <div class="detail-tags">
                ${alert.contributing_rules.map(rule => `<span class="detail-tag">${rule}</span>`).join('')}
            </div>
        </div>
        ` : ''
        }
        
        <div class="detail-section">
            <h3>Response Actions</h3>
            <div class="response-actions">
                <button onclick="blockIP('${alert.source_ip}')" class="response-btn danger">
                    🚫 Block IP
                </button>
                <button onclick="isolateIP('${alert.source_ip}')" class="response-btn warning">
                    🔒 Isolate Device
                </button>
                <button onclick="fetchExplanation('${alert.alert_id}')" class="response-btn info">
                    📊 Explain
                </button>
            </div>
        </div>
        
        <div class="detail-section">
            <h3>Timestamp</h3>
            <p>${new Date(alert.timestamp).toLocaleString()}</p>
        </div>
`;
}

async function fetchExplanation(alertId) {
    try {
        const response = await fetch(`${API_BASE} /explain/${alertId} `);
        const explanation = await response.json();

        if (explanation) {
            showExplanationModal(explanation);
        }
    } catch (error) {
        console.error('Error fetching explanation:', error);
        showNotification('Could not fetch explanation', 'medium');
    }
}

function showExplanationModal(explanation) {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.innerHTML = `
    < div class="modal-content explanation-modal" >
            <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
            <h2>🔍 AI Explanation</h2>
            
            <div class="explanation-section">
                <h3>Summary</h3>
                <p>${explanation.summary || 'N/A'}</p>
            </div>
            
            <div class="explanation-section">
                <h3>What Happened</h3>
                <p>${explanation.what_happened || 'N/A'}</p>
            </div>
            
            <div class="explanation-section">
                <h3>Why Detected</h3>
                <pre>${explanation.why_detected || 'N/A'}</pre>
            </div>
            
            <div class="explanation-section">
                <h3>Why It Matters</h3>
                <p>${explanation.why_matters || 'N/A'}</p>
            </div>
            
            ${explanation.top_features && explanation.top_features.length > 0 ? `
            <div class="explanation-section">
                <h3>Top Contributing Features</h3>
                <div class="feature-list">
                    ${explanation.top_features.map(f => `
                        <div class="feature-item">
                            <span class="feature-name">${f.name}</span>
                            <span class="feature-value">${f.value}</span>
                            <div class="feature-bar" style="width: ${f.contribution * 100}%"></div>
                            <span class="feature-desc">${f.description}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
            ` : ''
        }
            
            ${explanation.recommended_actions && explanation.recommended_actions.length > 0 ? `
            <div class="explanation-section">
                <h3>Recommended Actions</h3>
                <ul class="action-list">
                    ${explanation.recommended_actions.map(a => `<li>${a}</li>`).join('')}
                </ul>
            </div>
            ` : ''
        }

<div class="explanation-meta">
    <span>Detection Type: ${explanation.detection_type}</span>
    <span>Confidence: ${(explanation.confidence * 100).toFixed(0)}%</span>
    <span>Risk Score: ${explanation.risk_score}</span>
</div>
        </div >
    `;

    document.body.appendChild(modal);

    modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.remove();
    });
}

function closeDetails() {
    document.getElementById('detailsPanel').classList.remove('active');
}

function updateLastUpdate() {
    document.getElementById('lastUpdate').textContent = `Last update: ${new Date().toLocaleTimeString()} `;
}

// ============================================
// Tab Navigation
// ============================================

function switchTab(tabName) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });

    // Remove active from all tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });

    // Show selected tab
    document.getElementById(`${tabName} Tab`)?.classList.add('active');
    event.target.classList.add('active');

    // Load data for specific tabs
    if (tabName === 'ueba') {
        fetchUEBAProfiles();
    }
}

// ============================================
// Network Graph (D3.js)
// ============================================

// Graph State
let currentGraphMode = 'force'; // 'force' or 'tree'
let graphDataCache = null;

function renderNetworkGraph(data) {
    graphDataCache = data;
    const container = document.getElementById('networkGraph');

    // Clean up previous radar animation intervals
    if (container._radarCleanup) {
        container._radarCleanup();
    }

    container.innerHTML = '';

    // Add Toggle Button
    const controls = document.createElement('div');
    controls.className = 'graph-controls';
    controls.style.cssText = 'position: absolute; top: 10px; right: 10px; z-index: 10;';
    controls.innerHTML = `
        <button id="viewToggle" class="btn-xs" style="background: rgba(0,0,0,0.6); border: 1px solid rgba(99,102,241,0.4); color: white; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px;">
            ${currentGraphMode === 'force' ? '🌳 Tree View' : '🕸️ Force View'}
        </button>
    `;
    container.appendChild(controls);

    document.getElementById('viewToggle').onclick = () => {
        currentGraphMode = currentGraphMode === 'force' ? 'tree' : 'force';
        renderNetworkGraph(graphDataCache);
    };

    const width = container.clientWidth || 600;
    const height = container.clientHeight || 350;

    // Create SVG with gradient definitions
    const svg = d3.select('#networkGraph')
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .style('background', 'transparent');

    // Add defs for gradients and glow effects
    const defs = svg.append('defs');

    // Glow filter for nodes
    const glow = defs.append('filter').attr('id', 'glow');
    glow.append('feGaussianBlur').attr('stdDeviation', '3').attr('result', 'coloredBlur');
    const glowMerge = glow.append('feMerge');
    glowMerge.append('feMergeNode').attr('in', 'coloredBlur');
    glowMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Radar gradient for sweep effect
    const radarGradient = defs.append('linearGradient')
        .attr('id', 'radarSweep')
        .attr('gradientUnits', 'userSpaceOnUse');
    radarGradient.append('stop').attr('offset', '0%').attr('stop-color', 'rgba(99, 102, 241, 0)');
    radarGradient.append('stop').attr('offset', '50%').attr('stop-color', 'rgba(99, 102, 241, 0.3)');
    radarGradient.append('stop').attr('offset', '100%').attr('stop-color', 'rgba(99, 102, 241, 0)');

    // Add radar animation background
    const radarGroup = svg.append('g').attr('class', 'radar-animation');
    const centerX = width / 2;
    const centerY = height / 2;
    const maxRadius = Math.min(width, height) * 0.45;

    // Radar grid circles (static)
    [0.25, 0.5, 0.75, 1].forEach(scale => {
        radarGroup.append('circle')
            .attr('cx', centerX)
            .attr('cy', centerY)
            .attr('r', maxRadius * scale)
            .attr('fill', 'none')
            .attr('stroke', 'rgba(99, 102, 241, 0.1)')
            .attr('stroke-width', 1);
    });

    // Radar crosshairs
    radarGroup.append('line')
        .attr('x1', centerX - maxRadius).attr('y1', centerY)
        .attr('x2', centerX + maxRadius).attr('y2', centerY)
        .attr('stroke', 'rgba(99, 102, 241, 0.08)').attr('stroke-width', 1);
    radarGroup.append('line')
        .attr('x1', centerX).attr('y1', centerY - maxRadius)
        .attr('x2', centerX).attr('y2', centerY + maxRadius)
        .attr('stroke', 'rgba(99, 102, 241, 0.08)').attr('stroke-width', 1);

    // Animated expanding pulse circles
    function createPulse() {
        const pulse = radarGroup.append('circle')
            .attr('cx', centerX)
            .attr('cy', centerY)
            .attr('r', 10)
            .attr('fill', 'none')
            .attr('stroke', 'rgba(99, 102, 241, 0.4)')
            .attr('stroke-width', 2);

        pulse.transition()
            .duration(3000)
            .ease(d3.easeLinear)
            .attr('r', maxRadius)
            .attr('stroke-opacity', 0)
            .attr('stroke-width', 0.5)
            .remove();
    }

    // Create pulse every 2 seconds
    createPulse();
    const pulseInterval = setInterval(createPulse, 2000);

    // Radar sweep line (rotating)
    const sweepLine = radarGroup.append('line')
        .attr('x1', centerX)
        .attr('y1', centerY)
        .attr('x2', centerX + maxRadius)
        .attr('y2', centerY)
        .attr('stroke', 'rgba(99, 102, 241, 0.5)')
        .attr('stroke-width', 2)
        .style('filter', 'url(#glow)');

    // Sweep trail (arc behind the line)
    const sweepArc = radarGroup.append('path')
        .attr('fill', 'url(#radarSweep)')
        .attr('opacity', 0.3);

    let sweepAngle = 0;
    function animateSweep() {
        sweepAngle = (sweepAngle + 2) % 360;
        const radians = (sweepAngle * Math.PI) / 180;
        const endX = centerX + maxRadius * Math.cos(radians);
        const endY = centerY + maxRadius * Math.sin(radians);

        sweepLine
            .attr('x2', endX)
            .attr('y2', endY);

        // Update arc path (30 degree trail)
        const trailAngle = 30;
        const startRad = ((sweepAngle - trailAngle) * Math.PI) / 180;
        const arcPath = d3.arc()({
            innerRadius: 0,
            outerRadius: maxRadius,
            startAngle: startRad,
            endAngle: radians
        });
        sweepArc.attr('d', arcPath).attr('transform', `translate(${centerX},${centerY})`);
    }

    const sweepInterval = setInterval(animateSweep, 30);

    // Clean up intervals when graph is re-rendered
    container._radarCleanup = () => {
        clearInterval(pulseInterval);
        clearInterval(sweepInterval);
    };

    // Zone colors (matching reference image)
    const zoneColors = {
        'hostel': '#06b6d4',    // Cyan
        'lab': '#8b5cf6',       // Purple
        'server': '#22c55e',    // Green
        'admin': '#f97316',     // Orange
        'external': '#ef4444',  // Red
        'unknown': '#6b7280'    // Gray
    };

    // Device icons (Unicode/Emoji) - descriptive symbols
    const deviceIcons = {
        'server': '🖥️',
        'admin': '👤',
        'student': '🎓',
        'lab': '🔬',
        'mobile': '📱',
        'iot': '📡',
        'database': '🗄️',
        'router': '🌐',
        'firewall': '🛡️',
        'printer': '🖨️',
        'camera': '📹',
        'workstation': '💻',
        'laptop': '💻',
        'gateway': '🚪',
        'external': '🌍',
        'unknown': '🔌'  // Generic network device plug icon
    };

    // Protocol detection based on port
    function getProtocol(link) {
        if (link.protocol) return link.protocol.toUpperCase();
        const port = link.dest_port || link.port || 0;
        if (port === 443 || port === 8443) return 'HTTPS';
        if (port === 80 || port === 8080) return 'HTTP';
        if (port === 22) return 'SSH';
        if (port === 3306 || port === 5432) return 'SQL';
        if (port === 53) return 'DNS';
        if (port === 21) return 'FTP';
        if (port === 3389) return 'RDP';
        return '';
    }

    // ---------------------------------------------------------
    // RENDER: FORCE-DIRECTED GRAPH (Enhanced)
    // ---------------------------------------------------------
    if (currentGraphMode === 'force') {
        const simulation = d3.forceSimulation(data.nodes)
            .force('link', d3.forceLink(data.links).id(d => d.id).distance(120))
            .force('charge', d3.forceManyBody().strength(-300))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(50));

        // Draw links with protocol labels
        const linkGroup = svg.append('g').attr('class', 'links');

        const link = linkGroup.selectAll('line')
            .data(data.links)
            .enter()
            .append('line')
            .attr('stroke', d => d.suspicious ? '#ef4444' : 'rgba(99, 102, 241, 0.5)')
            .attr('stroke-width', d => d.suspicious ? 2.5 : 1.5)
            .attr('stroke-dasharray', d => d.suspicious ? '8,4' : 'none')
            .style('filter', d => d.suspicious ? 'drop-shadow(0 0 4px #ef4444)' : 'none');

        // Protocol labels on links
        const linkLabels = svg.append('g').attr('class', 'link-labels')
            .selectAll('text')
            .data(data.links.filter(d => getProtocol(d)))
            .enter()
            .append('text')
            .text(d => getProtocol(d))
            .attr('font-size', '9px')
            .attr('fill', 'rgba(255,255,255,0.6)')
            .attr('text-anchor', 'middle')
            .style('pointer-events', 'none');

        // Draw nodes as groups (ring + icon + label)
        const nodeGroup = svg.append('g').attr('class', 'nodes');

        const node = nodeGroup.selectAll('g.node')
            .data(data.nodes)
            .enter()
            .append('g')
            .attr('class', 'node')
            .style('cursor', 'pointer')
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended));

        // Outer glow ring
        node.append('circle')
            .attr('r', d => d.role === 'server' ? 28 : d.role === 'admin' ? 24 : 20)
            .attr('fill', 'transparent')
            .attr('stroke', d => zoneColors[d.zone] || zoneColors.unknown)
            .attr('stroke-width', 3)
            .attr('stroke-opacity', 0.8)
            .style('filter', 'url(#glow)');

        // Inner filled circle
        node.append('circle')
            .attr('r', d => d.role === 'server' ? 22 : d.role === 'admin' ? 18 : 15)
            .attr('fill', 'rgba(20, 20, 30, 0.9)')
            .attr('stroke', d => d.is_known === false ? '#ef4444' : zoneColors[d.zone] || zoneColors.unknown)
            .attr('stroke-width', d => d.is_known === false ? 2 : 1);

        // Device icon
        node.append('text')
            .attr('text-anchor', 'middle')
            .attr('dominant-baseline', 'central')
            .attr('font-size', d => d.role === 'server' ? '16px' : '12px')
            .text(d => deviceIcons[d.role] || deviceIcons.unknown);

        // Device name label (below node)
        node.append('text')
            .attr('class', 'node-label')
            .attr('text-anchor', 'middle')
            .attr('y', d => (d.role === 'server' ? 38 : d.role === 'admin' ? 32 : 28))
            .attr('fill', '#ffffff')
            .attr('font-size', '11px')
            .attr('font-weight', '500')
            .text(d => d.label || d.id.split('.').pop() || d.id);

        // Role/Zone subtitle
        node.append('text')
            .attr('class', 'node-subtitle')
            .attr('text-anchor', 'middle')
            .attr('y', d => (d.role === 'server' ? 50 : d.role === 'admin' ? 44 : 40))
            .attr('fill', d => zoneColors[d.zone] || zoneColors.unknown)
            .attr('font-size', '9px')
            .text(d => d.zone ? d.zone.charAt(0).toUpperCase() + d.zone.slice(1) : '');

        // Tooltip on hover
        node.append('title').text(d =>
            `IP: ${d.id}\nRole: ${d.role}\nZone: ${d.zone}\nKnown: ${d.is_known !== false ? 'Yes' : 'No (Suspicious!)'}`
        );

        // Simulation tick
        simulation.on('tick', () => {
            link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x).attr('y2', d => d.target.y);

            linkLabels
                .attr('x', d => (d.source.x + d.target.x) / 2)
                .attr('y', d => (d.source.y + d.target.y) / 2 - 5);

            node.attr('transform', d => {
                d.x = Math.max(40, Math.min(width - 40, d.x));
                d.y = Math.max(40, Math.min(height - 50, d.y));
                return `translate(${d.x},${d.y})`;
            });
        });

        function dragstarted(event) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            event.subject.fx = event.subject.x;
            event.subject.fy = event.subject.y;
        }
        function dragged(event) { event.subject.fx = event.x; event.subject.fy = event.y; }
        function dragended(event) {
            if (!event.active) simulation.alphaTarget(0);
            event.subject.fx = null; event.subject.fy = null;
        }

        // ---------------------------------------------------------
        // RENDER: HIERARCHICAL TREE VIEW (Enhanced)
        // ---------------------------------------------------------
    } else {
        const rootNode = data.nodes.find(n => n.role === 'server') || data.nodes[0];
        if (!rootNode) return;

        let root;
        try {
            const treeData = data.nodes.map(n => ({
                id: n.id,
                role: n.role,
                zone: n.zone,
                label: n.label || n.id,
                parentId: n.id === rootNode.id ? null : rootNode.id
            }));

            const treeRoot = d3.stratify()(treeData);
            const treeLayout = d3.tree().size([height - 80, width - 150]);
            root = treeLayout(treeRoot);
        } catch (e) {
            console.error("Tree layout error:", e);
            currentGraphMode = 'force';
            renderNetworkGraph(data);
            return;
        }

        // Links
        svg.selectAll('path.link')
            .data(root.links())
            .enter().append('path')
            .attr('class', 'link')
            .attr('fill', 'none')
            .attr('stroke', 'rgba(99, 102, 241, 0.4)')
            .attr('stroke-width', 2)
            .attr('d', d3.linkHorizontal().x(d => d.y).y(d => d.x))
            .attr('transform', 'translate(70, 40)');

        // Nodes
        const node = svg.selectAll('g.node')
            .data(root.descendants())
            .enter().append('g')
            .attr('class', 'node')
            .attr('transform', d => `translate(${d.y + 70},${d.x + 40})`);

        // Ring
        node.append('circle')
            .attr('r', 18)
            .attr('fill', 'rgba(20, 20, 30, 0.9)')
            .attr('stroke', d => zoneColors[d.data.zone] || zoneColors.unknown)
            .attr('stroke-width', 2.5)
            .style('filter', 'url(#glow)');

        // Icon
        node.append('text')
            .attr('text-anchor', 'middle')
            .attr('dominant-baseline', 'central')
            .attr('font-size', '12px')
            .text(d => deviceIcons[d.data.role] || deviceIcons.unknown);

        // Label
        node.append('text')
            .attr('dy', 32)
            .attr('text-anchor', 'middle')
            .text(d => d.data.label || d.id)
            .attr('fill', '#fff')
            .attr('font-size', '10px');

        // Subtitle
        node.append('text')
            .attr('dy', 44)
            .attr('text-anchor', 'middle')
            .text(d => d.data.zone || '')
            .attr('fill', d => zoneColors[d.data.zone] || '#888')
            .attr('font-size', '8px');
    }
}

// ============================================
// Traffic Chart (Chart.js)
// ============================================

function initTrafficChart() {
    const ctx = document.getElementById('trafficChart').getContext('2d');

    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Total Traffic (KB)',
                    data: [],
                    borderColor: '#6366f1',
                    backgroundColor: 'rgba(99, 102, 241, 0.1)',
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Suspicious Flows',
                    data: [],
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    fill: true,
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        color: 'rgba(255, 255, 255, 0.7)',
                        boxWidth: 12
                    }
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    },
                    ticks: {
                        color: 'rgba(255, 255, 255, 0.5)',
                        maxRotation: 0
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    },
                    ticks: {
                        color: 'rgba(255, 255, 255, 0.5)'
                    }
                }
            },
            interaction: {
                intersect: false,
                mode: 'index'
            }
        }
    });
}

function updateTrafficChart(stats) {
    if (!stats.time_series || stats.time_series.length === 0) return;

    const timeSeries = stats.time_series.slice(-20); // Last 20 data points

    trafficChart.data.labels = timeSeries.map(d => {
        const date = new Date(d.timestamp);
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    });

    trafficChart.data.datasets[0].data = timeSeries.map(d => Math.round(d.bytes / 1024));
    trafficChart.data.datasets[1].data = timeSeries.map(d => d.suspicious);

    trafficChart.update('none');
}

// ============================================
// Demo Scenario Handlers for Judges
// ============================================

async function runScenario(scenarioType) {
    var statusId = 'status-' + scenarioType.replace('_', '-');
    var btnId = 'btn-' + scenarioType.replace('_', '-');
    var statusEl = document.getElementById(statusId);
    var resultEl = document.getElementById('resultContent');
    var btn = document.getElementById(btnId);

    if (statusEl) statusEl.className = 'scenario-status running';
    if (btn) btn.classList.add('running');
    if (resultEl) resultEl.innerHTML = 'Running ' + scenarioType + ' scenario...';

    var result = '';

    try {
        if (scenarioType === 'port_scan') {
            result = await simulatePortScan();
        } else if (scenarioType === 'brute_force') {
            result = await simulateBruteForce();
        } else if (scenarioType === 'dns_tunnel') {
            result = await simulateDNSTunnel();
        } else if (scenarioType === 'data_exfil') {
            result = await simulateDataExfil();
        } else if (scenarioType === 'malware_c2') {
            result = await simulateMalwareC2();
        } else if (scenarioType === 'anomaly') {
            result = await simulateAnomaly();
        } else {
            result = 'Unknown scenario';
        }
        if (statusEl) statusEl.className = 'scenario-status success';
    } catch (error) {
        result = 'Error: ' + error.message;
        if (statusEl) statusEl.className = 'scenario-status error';
    }

    if (btn) btn.classList.remove('running');
    if (resultEl) resultEl.innerHTML = result;

    setTimeout(function () { refreshData(); }, 1000);
}

async function simulatePortScan() {
    var output = '<b>PORT SCAN DETECTION DEMO</b><br>';
    output += 'Attacker: 10.0.0.50 -> Target: 192.168.1.100<br><br>';

    var ports = [22, 80, 443, 3389, 8080];
    for (var i = 0; i < ports.length; i++) {
        await new Promise(function (r) { setTimeout(r, 200); });
        output += 'Scanning port ' + ports[i] + '... DETECTED!<br>';
    }

    try { await fetch(API_BASE + '/demo/generate', { method: 'POST' }); } catch (e) { }

    output += '<br><span style="color:#ef4444">ALERT: Port Scan Detected (T1046)</span>';
    output += '<br>MITRE Tactic: Discovery';
    output += '<br>Risk Score: 75/100';
    return output;
}

async function simulateBruteForce() {
    var output = '<b>BRUTE FORCE ATTACK DEMO</b><br>';
    output += 'Attacker: 10.0.0.99 -> SSH Server: 192.168.1.10:22<br><br>';

    for (var i = 1; i <= 5; i++) {
        await new Promise(function (r) { setTimeout(r, 300); });
        output += 'Attempt ' + i + '/5: Authentication FAILED<br>';
    }

    try { await fetch(API_BASE + '/demo/generate', { method: 'POST' }); } catch (e) { }

    output += '<br><span style="color:#ef4444">ALERT: Brute Force Detected (T1110)</span>';
    output += '<br>MITRE Tactic: Credential Access';
    output += '<br>Confidence: 92%';
    return output;
}

async function simulateDNSTunnel() {
    var output = '<b>DNS TUNNELING DETECTION</b><br><br>';

    var domains = ['aHR0cHM6Ly.evil-c2.com', 'ZXhmaWx0cmF0.badsite.net'];

    for (var i = 0; i < domains.length; i++) {
        await new Promise(function (r) { setTimeout(r, 400); });
        output += 'Query: ' + domains[i] + '<br>';
        output += 'Entropy: HIGH (Base64 detected)<br>';
        output += 'Status: <span style="color:#f97316">SUSPICIOUS</span><br><br>';
    }

    output += '<span style="color:#ef4444">ALERT: DNS Tunneling (T1071.004)</span>';
    return output;
}

async function simulateDataExfil() {
    var output = '<b>DATA EXFILTRATION DETECTION</b><br><br>';
    output += 'Source: Internal Server (192.168.1.50)<br>';
    output += 'Destination: External IP (203.0.113.99)<br>';
    output += 'Transfer Size: 500 MB<br><br>';

    await new Promise(function (r) { setTimeout(r, 500); });
    try { await fetch(API_BASE + '/demo/generate', { method: 'POST' }); } catch (e) { }

    output += 'Analysis:<br>';
    output += '- Transfer ratio: 99.8% outbound (ABNORMAL)<br>';
    output += '- Time: Outside business hours<br>';
    output += '- Destination: Unknown external<br><br>';
    output += '<span style="color:#ef4444">ALERT: Data Exfiltration (T1048)</span>';
    return output;
}

async function simulateMalwareC2() {
    var output = '<b>ENCRYPTED MALWARE C2 DETECTION</b><br><br>';
    output += 'TLS Traffic Analysis (JA3 Fingerprinting)<br><br>';

    await new Promise(function (r) { setTimeout(r, 400); });

    output += 'JA3 Hash: a3b45c67d89e12f34567890abcdef<br>';
    output += 'Match: Known Cobalt Strike beacon<br>';
    output += 'Certificate: Self-signed (SUSPICIOUS)<br><br>';

    output += '<span style="color:#ef4444">ALERT: Malware C2 Channel (T1573)</span>';
    return output;
}

async function simulateAnomaly() {
    var output = '<b>UEBA BEHAVIOR ANOMALY</b><br><br>';
    output += 'User: student_123<br>';
    output += 'Normal hours: 9 AM - 6 PM<br>';
    output += 'Current time: 3:47 AM<br><br>';

    await new Promise(function (r) { setTimeout(r, 300); });
    try { await fetch(API_BASE + '/demo/generate', { method: 'POST' }); } catch (e) { }

    output += 'Detected Anomalies:<br>';
    output += '- Login at unusual hour<br>';
    output += '- Accessing admin resources (first time)<br>';
    output += '- Download volume: 2.3 GB (200% above normal)<br><br>';
    output += '<span style="color:#eab308">ALERT: Behavior Anomaly Detected</span>';
    return output;
}

// ============================================
// Configuration Panel Functions
// ============================================

function applyConfig() {
    const config = {
        interface: document.getElementById('configInterface').value,
        environment: document.getElementById('configEnvironment').value,
        subnet: document.getElementById('configSubnet').value,
        sensitivity: document.getElementById('configSensitivity').value
    };

    // Send to backend
    fetch(API_BASE + '/config/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
    })
        .then(response => response.json())
        .then(data => {
            showNotification('✅ Configuration applied successfully!', 'low');
            console.log('Config saved:', config);
        })
        .catch(error => {
            showNotification('⚠️ Config saved locally (backend restart required)', 'medium');
            console.log('Config (local):', config);
        });

    // Store in localStorage for persistence
    localStorage.setItem('idsConfig', JSON.stringify(config));
}

function showFullGuide() {
    const guideContent = `
        <div class="guide-modal">
            <h2>🛡️ Deployment Guide</h2>
            
            <h3>🎓 Campus Network (Cisco)</h3>
            <pre>
! Enable SPAN port mirroring
monitor session 1 source vlan 10-50
monitor session 1 destination interface Gi0/24
            </pre>
            
            <h3>🏢 Enterprise (ERSPAN/NetFlow)</h3>
            <pre>
! ERSPAN configuration
monitor session 1 type erspan-source
  source interface Eth1/1-48
  destination ip 10.10.10.100
  erspan-id 100

! NetFlow export
flow exporter IDS-EXPORT
  destination 192.168.1.100
  transport udp 2055
            </pre>
            
            <h3>📶 Public WiFi (MikroTik)</h3>
            <pre>
/ip traffic-flow
set enabled=yes interfaces=all
/ip traffic-flow target
add dst-address=192.168.1.100 port=2055 version=9
            </pre>
            
            <h3>✅ Quick Checklist</h3>
            <ul>
                <li>Configure SPAN/Mirror port on switch</li>
                <li>Connect IDS server to mirrored port</li>
                <li>Set CAPTURE_INTERFACE in .env</li>
                <li>Run as Administrator/root</li>
                <li>Access dashboard at http://ids-server:8000</li>
            </ul>
            
            <p style="margin-top: 1rem; color: var(--text-muted);">
                Full documentation: <a href="/DEPLOYMENT.md" target="_blank">DEPLOYMENT.md</a>
            </p>
        </div>
    `;

    // Create modal
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.innerHTML = `
        <div class="modal-content" style="max-width: 800px;">
            <button class="modal-close" onclick="this.parentElement.parentElement.remove()">×</button>
            ${guideContent}
        </div>
    `;
    document.body.appendChild(modal);
}

// Load saved config on startup
document.addEventListener('DOMContentLoaded', () => {
    const savedConfig = localStorage.getItem('idsConfig');
    if (savedConfig) {
        const config = JSON.parse(savedConfig);
        if (document.getElementById('configInterface')) {
            document.getElementById('configInterface').value = config.interface || 'auto';
            document.getElementById('configEnvironment').value = config.environment || 'campus';
            document.getElementById('configSubnet').value = config.subnet || '192.168.137.0/24';
            document.getElementById('configSensitivity').value = config.sensitivity || 'medium';
        }
    }
});

// ============================================
// Auto-Refresh (Real-Time Updates)
// ============================================
setInterval(() => {
    // Only refresh if tab is active to save resources
    if (!document.hidden) {
        refreshData();
        // Also refresh graph if tree mode is active (to show new devices)
        fetchNetworkGraph();
    }
}, 5000);

