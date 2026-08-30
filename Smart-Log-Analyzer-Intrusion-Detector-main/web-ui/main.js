// ═══════════════════════════════════════════════════════════════════════════════
// Owl Monitor — Live Dashboard Client
// ═══════════════════════════════════════════════════════════════════════════════

(function () {
    "use strict";

    // ── State ────────────────────────────────────────────────────────────────
    const state = {
        alerts: [],
        events: [],
        blocked_ips: [],
        ti_cache: {},           // ip → threat intel object
        detection_counts: {},   // event_type → count
        auth_failed: 0,
        auth_brute: 0,
        fim_violations: [],
    };

    // ── DOM refs ─────────────────────────────────────────────────────────────
    const $ = (id) => document.getElementById(id);

    // ── WebSocket ────────────────────────────────────────────────────────────
    let ws = null;
    let reconnectTimer = null;

    function connectWebSocket() {
        const protocol = location.protocol === "https:" ? "wss:" : "ws:";
        const wsUrl = `${protocol}//${location.host}/ws/alerts`;

        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            updateWsStatus(true);
            // Fetch initial state snapshot
            fetch("/api/state")
                .then((r) => r.json())
                .then((data) => {
                    if (data.alerts) {
                        data.alerts.forEach((a) => handleNewAlert(a, true));
                    }
                    if (data.metrics) {
                        updateMetrics(data.metrics);
                    }
                })
                .catch(() => {});
        };

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === "new_alert") {
                    handleNewAlert(msg.data, false);
                } else if (msg.type === "new_event") {
                    handleNewEvent(msg.data);
                } else if (msg.type === "ip_blocked") {
                    handleIpBlocked(msg.data);
                }
                updateLastUpdated();
            } catch (e) {
                console.error("WS parse error", e);
            }
        };

        ws.onclose = () => {
            updateWsStatus(false);
            reconnectTimer = setTimeout(connectWebSocket, 3000);
        };

        ws.onerror = () => {
            ws.close();
        };
    }

    function updateWsStatus(connected) {
        const el = $("ws-status");
        const sysEl = $("sys-ws-status");
        if (connected) {
            el.innerHTML = '<span class="pulse-dot connected"></span><span>Connected</span>';
            if (sysEl) sysEl.textContent = "Connected";
        } else {
            el.innerHTML = '<span class="pulse-dot disconnected"></span><span>Disconnected</span>';
            if (sysEl) sysEl.textContent = "Disconnected";
        }
    }

    function updateLastUpdated() {
        const now = new Date();
        $("last-updated").textContent = `Updated: ${now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`;
    }

    // ── Handlers ─────────────────────────────────────────────────────────────

    function handleNewAlert(alert, isBatch) {
        state.alerts.unshift(alert);
        if (state.alerts.length > 100) state.alerts.length = 100;

        // Categorize
        const rule = (alert.rule_title || "").toLowerCase();
        if (rule.includes("file integrity")) {
            state.fim_violations.push(alert);
            updateFIMUI();
        }
        if (rule.includes("ssh") || rule.includes("brute") || rule.includes("auth")) {
            if (rule.includes("brute")) state.auth_brute++;
            state.auth_failed++;
            updateAuthUI(alert);
        }

        // Cache threat intel
        const ti = alert.threat_intel;
        if (ti && ti.matched && alert.ip && alert.ip !== "N/A") {
            state.ti_cache[alert.ip] = ti;
            updateTIPage();
        }

        // Update tables
        addAlertToMainTable(alert);
        addAlertToFullTable(alert);
        updateMetricsFromState();

        if (!isBatch) {
            flashNotification();
        }
    }

    function handleNewEvent(event) {
        state.events.unshift(event);
        if (state.events.length > 200) state.events.length = 200;

        // Track detection type counts for network page
        const type = event.event_type || "unknown";
        state.detection_counts[type] = (state.detection_counts[type] || 0) + 1;
        updateNetworkPage();
        updateMetricsFromState();
    }

    function handleIpBlocked(data) {
        if (!state.blocked_ips.includes(data.ip)) {
            state.blocked_ips.push(data.ip);
        }
        updateNetworkPage();
    }

    // ── DOM Updates ──────────────────────────────────────────────────────────

    function severityClass(level) {
        const l = (level || "low").toLowerCase();
        if (l === "critical") return "badge-critical";
        if (l === "very high" || l === "high") return "badge-high";
        if (l === "medium") return "badge-medium";
        return "badge-low";
    }

    function severityColor(level) {
        const l = (level || "low").toLowerCase();
        if (l === "critical") return "color-critical";
        if (l === "very high" || l === "high") return "color-high";
        if (l === "medium") return "color-medium";
        return "color-low";
    }

    function addAlertToMainTable(alert) {
        const tbody = $("events-tbody");
        // Remove empty state row
        const emptyRow = tbody.querySelector(".empty-row");
        if (emptyRow) emptyRow.remove();

        const tr = document.createElement("tr");
        tr.className = "event-row fade-in";
        tr.onclick = () => openAlertModal(alert);
        tr.innerHTML = `
            <td>${alert.time || "—"}</td>
            <td class="event-name">${alert.rule_title || "Unknown"}</td>
            <td class="source-ip clickable">${alert.ip || "N/A"}</td>
            <td><span class="badge ${severityClass(alert.level)}">${alert.level || "Low"}</span></td>
            <td>${alert.status || "Active"}</td>
        `;

        tbody.insertBefore(tr, tbody.firstChild);

        // Keep max 20 rows visible
        while (tbody.children.length > 20) {
            tbody.removeChild(tbody.lastChild);
        }

        $("event-counter").textContent = `${state.alerts.length} events`;
    }

    function addAlertToFullTable(alert) {
        const tbody = $("alerts-full-tbody");
        const emptyRow = tbody.querySelector(".empty-row");
        if (emptyRow) emptyRow.remove();

        const tr = document.createElement("tr");
        tr.className = "event-row fade-in";
        tr.onclick = () => openAlertModal(alert);
        const riskScore = typeof alert.risk_score === 'number' ? alert.risk_score.toFixed(1) : alert.risk_score;
        tr.innerHTML = `
            <td>${alert.time || "—"}</td>
            <td class="event-name">${alert.rule_title || "Unknown"}</td>
            <td class="source-ip clickable">${alert.ip || "N/A"}</td>
            <td><span class="badge ${severityClass(alert.level)}">${alert.level || "Low"}</span></td>
            <td>${riskScore}/100</td>
            <td>${alert.action || "alert_only"}</td>
        `;
        tbody.insertBefore(tr, tbody.firstChild);
    }

    function updateMetrics(metrics) {
        $("metric-threat-level").textContent = metrics.threat_level || "Low";
        $("metric-threat-level").className = "metric-value " + severityColor(metrics.threat_level);
        $("metric-active-alerts").textContent = metrics.active_alerts || 0;
        $("metric-network-events").textContent = (metrics.network_events || 0).toLocaleString();
        $("metric-system-status").textContent = metrics.system_status || "Healthy";
    }

    function updateMetricsFromState() {
        const highestLevel = state.alerts.length > 0 ? state.alerts[0].level : "Low";
        $("metric-threat-level").textContent = highestLevel;
        $("metric-threat-level").className = "metric-value " + severityColor(highestLevel);
        $("metric-active-alerts").textContent = state.alerts.length;
        $("metric-network-events").textContent = state.events.length.toLocaleString();
    }

    function updateFIMUI() {
        const count = state.fim_violations.length;
        const badge = $("fim-badge");
        const modified = $("fim-modified");
        const status = $("fim-status");

        if (count > 0) {
            badge.className = "badge badge-critical";
            badge.textContent = `${count} Alert${count > 1 ? "s" : ""}`;
            modified.textContent = count;
            status.textContent = "VIOLATION";
            status.className = "color-critical";
        }

        // Update FIM page table
        const tbody = $("fim-tbody");
        const emptyRow = tbody.querySelector(".empty-row");
        if (emptyRow) emptyRow.remove();

        const latest = state.fim_violations[state.fim_violations.length - 1];
        const tr = document.createElement("tr");
        tr.className = "event-row fade-in";
        tr.innerHTML = `
            <td>${latest.time || "—"}</td>
            <td><code>${latest.file || "Unknown"}</code></td>
            <td>${latest.event_desc || "Modified"}</td>
            <td class="hash-cell">${(latest.previous_hash || "—").substring(0, 16)}…</td>
            <td class="hash-cell">${(latest.current_hash || "—").substring(0, 16)}…</td>
        `;
        tbody.insertBefore(tr, tbody.firstChild);
    }

    function updateAuthUI(alert) {
        $("auth-failed").textContent = state.auth_failed;
        $("auth-brute").textContent = state.auth_brute;

        const tbody = $("auth-tbody");
        const emptyRow = tbody.querySelector(".empty-row");
        if (emptyRow) emptyRow.remove();

        const tr = document.createElement("tr");
        tr.className = "event-row fade-in";
        tr.innerHTML = `
            <td>${alert.time || "—"}</td>
            <td class="event-name">${alert.rule_title || "Unknown"}</td>
            <td class="source-ip">${alert.ip || "N/A"}</td>
            <td>${alert.username || "—"}</td>
            <td><span class="badge ${severityClass(alert.level)}">${alert.level || "Low"}</span></td>
        `;
        tbody.insertBefore(tr, tbody.firstChild);
    }

    function updateNetworkPage() {
        $("net-total").textContent = state.events.length;
        $("net-blocked").textContent = state.blocked_ips.length;
        $("net-page-total").textContent = state.events.length;
        $("net-page-blocked").textContent = state.blocked_ips.length;

        // Update detection type counts
        for (const [type, count] of Object.entries(state.detection_counts)) {
            const el = $("det-" + type);
            if (el) el.textContent = count;
        }
    }

    function updateTIPage() {
        const tbody = $("ti-tbody");
        // Rebuild entirely since it's a small set
        tbody.innerHTML = "";

        const ips = Object.keys(state.ti_cache);
        if (ips.length === 0) {
            tbody.innerHTML = '<tr class="empty-row"><td colspan="6" class="empty-state">No Threat Intelligence data yet.</td></tr>';
            return;
        }

        for (const ip of ips) {
            const ti = state.ti_cache[ip];
            const tr = document.createElement("tr");
            tr.className = "event-row";
            tr.onclick = () => openTIModal(ip, ti);
            tr.innerHTML = `
                <td class="source-ip clickable">${ip}</td>
                <td>${ti.country || "Unknown"}</td>
                <td><span class="badge ${ti.malicious_score >= 80 ? "badge-critical" : ti.malicious_score >= 50 ? "badge-high" : "badge-medium"}">${ti.malicious_score}%</span></td>
                <td>${ti.known_botnet ? '<span class="color-critical">YES</span>' : "No"}</td>
                <td>${(ti.abuse_reports || 0).toLocaleString()}</td>
                <td>${ti.isp || "Unknown"} (${ti.asn || "?"})</td>
            `;
            tbody.appendChild(tr);
        }
    }

    // ── Notification Flash ───────────────────────────────────────────────────

    function flashNotification() {
        const btn = $("notification-btn");
        const countEl = $("notif-count");
        const current = parseInt(countEl.textContent || "0", 10);
        countEl.textContent = current + 1;
        countEl.style.display = "flex";
        btn.classList.add("has-notification");
    }

    // ── Modals ───────────────────────────────────────────────────────────────

    function openAlertModal(alert) {
        const body = $("modal-body");
        const ti = alert.threat_intel || {};
        const hasTI = ti.matched;

        let tiSection = "";
        if (hasTI) {
            tiSection = `
                <div class="score-container">
                    <div class="score-ring">
                        <svg viewBox="0 0 36 36" class="circular-chart critical">
                            <path class="circle-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                            <path class="circle" stroke-dasharray="${ti.malicious_score}, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                            <text x="18" y="20.35" class="percentage">${ti.malicious_score}%</text>
                        </svg>
                    </div>
                    <div class="score-desc">
                        <strong>Malicious Score</strong>
                        <p>Source: ${ti.feed || "Threat Intelligence"}</p>
                    </div>
                </div>
                <div class="details-grid">
                    <div class="detail-item"><span class="label">Country</span><span class="value">${ti.country || "Unknown"}</span></div>
                    <div class="detail-item"><span class="label">Known Botnet</span><span class="value ${ti.known_botnet ? "color-critical" : ""}">${ti.known_botnet ? "Yes" : "No"}</span></div>
                    <div class="detail-item"><span class="label">Abuse Reports</span><span class="value">${(ti.abuse_reports || 0).toLocaleString()}</span></div>
                    <div class="detail-item"><span class="label">ISP / ASN</span><span class="value">${ti.isp || "Unknown"} (${ti.asn || "?"})</span></div>
                </div>
            `;
        }

        const riskScore = typeof alert.risk_score === 'number' ? alert.risk_score.toFixed(1) : alert.risk_score;

        body.innerHTML = `
            <div class="ip-header">
                <h1>${alert.rule_title || "Alert"}</h1>
                <span class="badge ${severityClass(alert.level)}">${alert.level}</span>
            </div>
            <div class="context-box">
                <strong>${alert.ip || "N/A"} → ${alert.logsource || "unknown"}</strong>
                <p>Risk Score: <strong>${riskScore}/100</strong></p>
                <p>${alert.raw_log || ""}</p>
            </div>
            <div class="mt-20">
                <h3>Threat Intelligence</h3>
                ${hasTI ? tiSection : '<p class="info-text" style="margin-top:12px;">No threat intelligence data for this IP.</p>'}
            </div>
            <div class="action-section mt-20">
                <h3>Recommended Action</h3>
                <p>${hasTI ? "Block IP via iptables and investigate authentication/network logs." : "Review the event details and monitor for repeated activity."}</p>
                ${alert.ip && alert.ip !== "N/A" ? '<button class="btn btn-critical btn-full mt-10" onclick="alert(\'IP block command sent to backend.\')">Block IP</button>' : ""}
            </div>
        `;

        $("ti-modal").classList.add("active");
    }

    function openTIModal(ip, ti) {
        openAlertModal({
            rule_title: "Threat Intelligence: " + ip,
            level: ti.malicious_score >= 80 ? "Critical" : ti.malicious_score >= 50 ? "High" : "Medium",
            ip: ip,
            risk_score: ti.malicious_score,
            logsource: "threat_intel",
            raw_log: "",
            threat_intel: ti,
        });
    }

    window.closeModal = function () {
        $("ti-modal").classList.remove("active");
    };

    // ── Page Navigation ──────────────────────────────────────────────────────

    const pageTitles = {
        dashboard: "Security Overview",
        alerts: "Alerts",
        network: "Network Monitoring",
        "threat-intel": "Threat Intelligence",
        fim: "File Integrity Monitoring",
        auth: "Authentication Monitoring",
        rules: "Detection Rules",
        system: "System Information",
        settings: "Settings",
    };

    function navigateTo(pageId) {
        // Hide all pages
        document.querySelectorAll(".page").forEach((p) => p.classList.add("hidden"));
        // Show target
        const target = $("page-" + pageId);
        if (target) target.classList.remove("hidden");
        // Update sidebar active
        document.querySelectorAll("nav li").forEach((li) => li.classList.remove("active"));
        const activeLi = document.querySelector(`nav li[data-page="${pageId}"]`);
        if (activeLi) activeLi.classList.add("active");
        // Update title
        $("page-title").textContent = pageTitles[pageId] || "Owl Monitor";
    }

    // ── Init ─────────────────────────────────────────────────────────────────

    document.addEventListener("DOMContentLoaded", () => {
        // Sidebar navigation
        document.querySelectorAll("nav li[data-page]").forEach((li) => {
            li.addEventListener("click", (e) => {
                e.preventDefault();
                navigateTo(li.dataset.page);
            });
        });

        // Filter buttons
        document.querySelectorAll(".filter-btn").forEach((btn) => {
            btn.addEventListener("click", (e) => {
                document.querySelectorAll(".filter-btn").forEach((b) => b.classList.remove("active"));
                e.target.classList.add("active");
            });
        });

        // Close modal on overlay click
        $("ti-modal").addEventListener("click", (e) => {
            if (e.target.id === "ti-modal") closeModal();
        });

        // Notification button clears count
        $("notification-btn").addEventListener("click", () => {
            $("notif-count").style.display = "none";
            $("notif-count").textContent = "0";
            $("notification-btn").classList.remove("has-notification");
        });

        // Connect WebSocket
        connectWebSocket();
        updateLastUpdated();
    });
})();
