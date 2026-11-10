
"use strict";

const API_URL = "/api/ids";
const REFRESH_INTERVAL = 5000;

const statusElement = document.getElementById("ids-status");
const criticalElement = document.getElementById("critical-count");
const recoveryElement = document.getElementById("recovery-count");
const totalElement = document.getElementById("total-events");
const eventsTable = document.getElementById("events-table");
const connectionElement = document.getElementById("api-connection");
const updateElement = document.getElementById("last-update");

let isFetching = false;

const notificationElement =
    document.getElementById("security-notification");

let previousEvents = null;

function getEventKey(event) {
    return JSON.stringify([
        event.timestamp,
        event.level,
        event.message
    ]);
}

function detectNewIncidents(events) {
    const currentEvents = new Set(
        events.map(getEventKey)
    );

    // Initial loading: do not notify historical incidents.
    if (previousEvents === null) {
        previousEvents = currentEvents;
        return;
    }

    const newEvents = events.filter(
        event => !previousEvents.has(getEventKey(event))
    );

    previousEvents = currentEvents;

    if (newEvents.length === 0) {
        return;
    }

    // API returns newest events first.
    const latest = newEvents[0];

    if (!["CRITICAL", "RECOVERY"].includes(latest.level)) {
        return;
    }

    notificationElement.hidden = false;
    notificationElement.className =
        `security-notification ${latest.level.toLowerCase()}`;

    if (latest.level === "CRITICAL") {
        notificationElement.textContent =
            "SECURITY ALERT: New critical IDS incident detected!";
    } else {
        notificationElement.textContent =
            "RECOVERY: IDS reported a return to NORMAL.";
    }
}

function updateDashboard(data) {
    detectNewIncidents(data.events);
    const validStatuses = ["NORMAL", "CRITICAL", "UNKNOWN"];
    const status = validStatuses.includes(data.status)
        ? data.status
        : "UNKNOWN";

    statusElement.textContent = status;
    statusElement.className = `status ${status.toLowerCase()}`;

    criticalElement.textContent = data.critical_count;
    recoveryElement.textContent = data.recovery_count;
    totalElement.textContent = data.total_events;

    eventsTable.replaceChildren();

    if (data.events.length === 0) {
        const row = eventsTable.insertRow();
        const cell = row.insertCell();

        cell.colSpan = 3;
        cell.textContent = "No security events available.";
        return;
    }

    for (const event of data.events) {
        const row = eventsTable.insertRow();

        const timestampCell = row.insertCell();
        const levelCell = row.insertCell();
        const messageCell = row.insertCell();

        timestampCell.textContent = event.timestamp;

        levelCell.textContent = event.level;
        levelCell.className =
            ["CRITICAL", "RECOVERY"].includes(event.level)
                ? event.level.toLowerCase()
                : "";

        messageCell.textContent = event.message;
    }
}

async function fetchIDSData() {
    if (isFetching) return;

    isFetching = true;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);

    try {
        const response = await fetch(API_URL, {
            cache: "no-store",
            signal: controller.signal
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        if (!data || !Array.isArray(data.events)) {
            throw new Error("Invalid IDS response");
        }

        updateDashboard(data);

        connectionElement.textContent = "CONNECTED";
        connectionElement.style.color = "#4caf50";

        updateElement.textContent =
            new Date().toLocaleString();

    } catch (error) {
        connectionElement.textContent = "DISCONNECTED";
        connectionElement.style.color = "#ff5252";

        console.error("IDS monitoring error:", error);

    } finally {
        clearTimeout(timeout);
        isFetching = false;
    }
}

fetchIDSData();
setInterval(fetchIDSData, REFRESH_INTERVAL);

const heartbeatStatusElement =
    document.getElementById("heartbeat-status");

const heartbeatAgeElement =
    document.getElementById("heartbeat-age");

const heartbeatReasonElement =
    document.getElementById("heartbeat-reason");

let heartbeatFetching = false;

async function fetchHeartbeatData() {
    if (heartbeatFetching) return;

    heartbeatFetching = true;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);

    try {
        const response = await fetch("/api/heartbeat", {
            cache: "no-store",
            signal: controller.signal
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        if (!["ONLINE", "OFFLINE"].includes(data.status)) {
            throw new Error("Invalid heartbeat status");
        }

        heartbeatStatusElement.textContent = data.status;
        heartbeatStatusElement.className =
            data.status === "ONLINE"
                ? "heartbeat-online"
                : "heartbeat-offline";

        heartbeatAgeElement.textContent =
            typeof data.age_seconds === "number"
                ? `${data.age_seconds.toFixed(2)} seconds`
                : "N/A";

        heartbeatReasonElement.textContent = data.reason;

    } catch (error) {
        heartbeatStatusElement.textContent = "UNKNOWN";
        heartbeatStatusElement.className = "heartbeat-unknown";
        heartbeatAgeElement.textContent = "N/A";
        heartbeatReasonElement.textContent =
            "Unable to reach heartbeat API";

        console.error("Heartbeat monitoring error:", error);

    } finally {
        clearTimeout(timeout);
        heartbeatFetching = false;
    }
}

fetchHeartbeatData();
setInterval(fetchHeartbeatData, 5000);

let availabilityRequestPending = false;

async function fetchAvailabilityEvents() {
    if (availabilityRequestPending) {
        return;
    }

    availabilityRequestPending = true;

    const apiStatus = document.getElementById(
        "availability-api-status"
    );

    try {
        const response = await fetch(
            "/api/availability-events",
            { cache: "no-store" }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        document.getElementById(
            "availability-offline-count"
        ).textContent = data.offline_count;

        document.getElementById(
            "availability-recovery-count"
        ).textContent = data.recovery_count;

        document.getElementById(
            "availability-total-count"
        ).textContent = data.total_events;

        const tbody = document.getElementById(
            "availability-events-body"
        );

        tbody.replaceChildren();

        if (!Array.isArray(data.events) || data.events.length === 0) {
            const row = tbody.insertRow();
            const cell = row.insertCell();
            cell.colSpan = 3;
            cell.textContent = "No availability events recorded.";
        } else {
            for (const event of data.events) {
                const row = tbody.insertRow();

                row.insertCell().textContent = event.timestamp;

                const levelCell = row.insertCell();
                levelCell.textContent = event.level;
                levelCell.className =
                    event.level === "OFFLINE"
                        ? "critical"
                        : "recovery";

                row.insertCell().textContent = event.message;
            }
        }

        apiStatus.textContent = "CONNECTED";

    } catch (error) {
        apiStatus.textContent = "DISCONNECTED";
        console.error("Availability API error:", error);
    } finally {
        availabilityRequestPending = false;
    }
}

fetchAvailabilityEvents();
setInterval(fetchAvailabilityEvents, 5000);

let incidentsRequestPending = false;

async function fetchSecurityIncidents() {
    if (incidentsRequestPending) return;

    incidentsRequestPending = true;

    const apiStatus = document.getElementById(
        "incident-api-status"
    );

    try {
        const response = await fetch("/api/incidents", {
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        document.getElementById(
            "incident-open-count"
        ).textContent = data.open_count;

        document.getElementById(
            "incident-resolved-count"
        ).textContent = data.resolved_count;

        document.getElementById(
            "incident-total-count"
        ).textContent = data.total;

        const tbody = document.getElementById(
            "incidents-body"
        );

        tbody.replaceChildren();

        if (!Array.isArray(data.incidents) ||
            data.incidents.length === 0) {

            const row = tbody.insertRow();
            const cell = row.insertCell();
            cell.colSpan = 5;
            cell.textContent = "No incidents recorded.";

        } else {
            for (const incident of data.incidents) {
                const row = tbody.insertRow();

                row.insertCell().textContent =
                    incident.incident_id ?? "-";

                const severityCell = row.insertCell();
                severityCell.textContent =
                    incident.severity ?? "-";

                const statusCell = row.insertCell();
                statusCell.textContent =
                    incident.status ?? "-";

                statusCell.className =
                    incident.status === "OPEN"
                        ? "critical"
                        : "recovery";

                row.insertCell().textContent =
                    incident.created_at ?? "-";

                row.insertCell().textContent =
                    incident.resolved_at ?? "-";
            }
        }

        apiStatus.textContent = "CONNECTED";

    } catch (error) {
        if (apiStatus) {
            apiStatus.textContent = "DISCONNECTED";
        }

        console.error("Incident API error:", error);

    } finally {
        incidentsRequestPending = false;
    }
}

fetchSecurityIncidents();
setInterval(fetchSecurityIncidents, 5000);
let recoveryRequestPending = false;

async function fetchRecoveryStatus() {
    if (recoveryRequestPending) return;

    recoveryRequestPending = true;

    const apiStatus = document.getElementById(
        "recovery-api-status"
    );

    if (!apiStatus) {
        recoveryRequestPending = false;
        return;
    }

    try {
        const response = await fetch("/api/recovery", {
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        const freshness = ["FRESH", "STALE", "UNKNOWN"].includes(
            data.status_freshness
        ) ? data.status_freshness : "UNKNOWN";

        const recordedState = data.process_state ?? "UNKNOWN";

        const processElement = document.getElementById(
            "recovery-process-state"
        );

        processElement.textContent =
            freshness === "FRESH" ? recordedState : "UNVERIFIED";

        const freshnessElement = document.getElementById(
            "recovery-freshness"
        );

        if (freshnessElement) {
            freshnessElement.textContent = freshness;
            freshnessElement.className =
                "freshness-" + freshness.toLowerCase();
        }

        const ageElement = document.getElementById(
            "recovery-status-age"
        );

        if (ageElement) {
            ageElement.textContent =
                typeof data.status_age_seconds === "number"
                    ? data.status_age_seconds.toFixed(2) + " sec."
                    : "--";
        }

        const reasonElement = document.getElementById(
            "recovery-freshness-reason"
        );

        if (reasonElement) {
            reasonElement.textContent =
                data.status_reason ?? "No freshness information";
        }

        document.getElementById(
            "recovery-attempts"
        ).textContent =
            `${data.attempts_used} / ${data.attempts_limit}`;

        document.getElementById(
            "recovery-blocked"
        ).textContent = data.restart_blocked ? "YES" : "NO";

        document.getElementById(
            "recovery-last-result"
        ).textContent = data.last_recovery?.result ?? "NONE";

        document.getElementById(
            "recovery-last-time"
        ).textContent = data.last_recovery?.timestamp ?? "-";

        document.getElementById(
            "recovery-supervisor-check"
        ).textContent = data.supervisor_last_check ?? "-";

        apiStatus.textContent = "CONNECTED";

    } catch (error) {
        apiStatus.textContent = "DISCONNECTED";
        console.error("Recovery API error:", error);

    } finally {
        recoveryRequestPending = false;
    }
}

fetchRecoveryStatus();
setInterval(fetchRecoveryStatus, 5000);

async function fetchSecurityAlerts() {
    const statusElement = document.getElementById(
        "alerts-api-status"
    );

    if (!statusElement) return;

    try {
        const response = await fetch(
            "/api/security-alerts?limit=10",
            { cache: "no-store" }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        if (data.status !== "OK") {
            throw new Error("Invalid API response");
        }

        document.getElementById("alerts-critical").textContent =
            data.summary.CRITICAL;

        document.getElementById("alerts-warning").textContent =
            data.summary.WARNING;

        document.getElementById("alerts-info").textContent =
            data.summary.INFO;

        document.getElementById("alerts-total").textContent =
            data.total_alerts;

        const table = document.getElementById(
            "security-alerts-table"
        );

        table.replaceChildren();

        for (const alert of data.alerts) {
            const row = document.createElement("tr");

            const values = [
                alert.event_timestamp,
                alert.severity,
                alert.type,
                alert.message
            ];

            for (const value of values) {
                const cell = document.createElement("td");
                cell.textContent = value ?? "";
                cell.style.padding = "8px";
                row.appendChild(cell);
            }

            table.appendChild(row);
        }

        if (data.alerts.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");
            cell.colSpan = 4;
            cell.textContent = "No security alerts found";
            row.appendChild(cell);
            table.appendChild(row);
        }

        statusElement.textContent = "CONNECTED";

    } catch (error) {
        console.error("Security Alerts API error:", error);
        statusElement.textContent = "DISCONNECTED";
    }
}

fetchSecurityAlerts();
setInterval(fetchSecurityAlerts, 5000);

async function fetchAlertManagement() {
    const apiStatus = document.getElementById(
        "management-api-status"
    );

    if (!apiStatus) return;

    try {
        const response = await fetch(
            "/api/alert-management",
            { cache: "no-store" }
        );

        if (!response.ok) {
            throw new Error("HTTP " + response.status);
        }

        const data = await response.json();

        if (data.status !== "OK") {
            throw new Error("Invalid API response");
        }

        document.getElementById(
            "management-new"
        ).textContent = data.summary.NEW;

        document.getElementById(
            "management-acknowledged"
        ).textContent = data.summary.ACKNOWLEDGED;

        document.getElementById(
            "management-resolved"
        ).textContent = data.summary.RESOLVED;

        document.getElementById(
            "management-total"
        ).textContent = data.total;

        const secondaryNew = document.getElementById("management-new-secondary");
        if (secondaryNew) secondaryNew.textContent = data.summary.NEW;

        apiStatus.textContent = "CONNECTED";

    } catch (error) {
        console.error("Alert Management:", error);
        apiStatus.textContent = "DISCONNECTED";
    }
}


async function fetchSecurityNotifications() {
    const apiStatus = document.getElementById(
        "notifications-api-status"
    );

    const table = document.getElementById(
        "notifications-table"
    );

    if (!apiStatus || !table) return;

    try {
        const response = await fetch(
            "/api/security-notifications",
            { cache: "no-store" }
        );

        if (!response.ok) {
            throw new Error("HTTP " + response.status);
        }

        const data = await response.json();

        if (data.status !== "OK") {
            throw new Error("Invalid API response");
        }

        document.getElementById(
            "notifications-total"
        ).textContent = data.total;

        table.replaceChildren();

        const notifications = data.notifications
            .slice()
            .sort((a, b) =>
                b.created_at_utc.localeCompare(a.created_at_utc)
            )
            .slice(0, 10);

        for (const notification of notifications) {
            const row = document.createElement("tr");

            const values = [
                notification.created_at_utc,
                notification.severity,
                notification.type,
                notification.message
            ];

            for (const value of values) {
                const cell = document.createElement("td");
                cell.textContent = value ?? "";
                row.appendChild(cell);
            }

            table.appendChild(row);
        }

        if (notifications.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 4;
            cell.textContent = "No notifications available.";

            row.appendChild(cell);
            table.appendChild(row);
        }

        apiStatus.textContent = "CONNECTED";

    } catch (error) {
        console.error("Security Notifications:", error);
        apiStatus.textContent = "DISCONNECTED";
    }
}


// Initial load
fetchAlertManagement();
fetchSecurityNotifications();

// Refresh every 5 seconds
setInterval(fetchAlertManagement, 5000);
setInterval(fetchSecurityNotifications, 5000);

// SOC layout enhancements; all original polling functions remain unchanged.
(function initSocUI() {
  const clock = document.getElementById("soc-clock");
  if (clock) {
    const updateClock = () => { clock.textContent = new Date().toLocaleString("ro-RO"); };
    updateClock();
    setInterval(updateClock, 1000);
  }
  const filter = document.getElementById("soc-filter");
  const alerts = document.getElementById("security-alerts-table");
  if (filter && alerts) {
    const applyFilter = () => {
      const query = filter.value.trim().toLowerCase();
      for (const row of alerts.rows) {
        row.hidden = Boolean(query) && !row.textContent.toLowerCase().includes(query);
      }
    };
    filter.addEventListener("input", applyFilter);
    const observer = new MutationObserver(applyFilter);
    observer.observe(alerts, {childList:true});
  }
})();

// ============================================================
// DAY 14 — SECURITY EVENT CORRELATION DASHBOARD
// ============================================================

let correlatedIncidents = [];
const expandedCorrelationEvidence = new Set();

function formatCorrelationDuration(seconds) {
    if (seconds === null || seconds === undefined) {
        return "--";
    }

    const total = Math.max(0, Math.floor(Number(seconds)));

    if (!Number.isFinite(total)) {
        return "--";
    }

    const hours = Math.floor(total / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    const secs = total % 60;

    if (hours > 0) {
        return `${hours}h ${minutes}m ${secs}s`;
    }

    if (minutes > 0) {
        return `${minutes}m ${secs}s`;
    }

    return `${secs}s`;
}


function renderCorrelatedIncidents() {
    const table = document.getElementById("correlated-incidents-body");
    const severityFilter = document.getElementById("correlated-severity");
    const statusFilter = document.getElementById("correlated-status");

    if (!table) return;

    const severity = severityFilter?.value || "ALL";
    const status = statusFilter?.value || "ALL";

    const filtered = correlatedIncidents.filter(incident =>
        (severity === "ALL" || incident.severity === severity) &&
        (status === "ALL" || incident.status === status)
    );

    table.replaceChildren();

    if (filtered.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 6;
        cell.textContent = "No correlated incidents match the filters.";
        row.appendChild(cell);
        table.appendChild(row);
        return;
    }

    for (const incident of filtered) {
        const row = document.createElement("tr");
        const evidence = Array.isArray(incident.evidence)
            ? incident.evidence
            : [];

        const values = [
            incident.started_at_utc || "--",
            incident.incident_type || "--",
            incident.severity || "--",
            incident.status || "--",
            formatCorrelationDuration(incident.duration_seconds)
        ];

        values.forEach((value, index) => {
            const cell = document.createElement("td");
            cell.textContent = String(value);

            if (index === 2 && incident.severity === "CRITICAL") {
                cell.classList.add("critical");
            }

            if (index === 2 && incident.severity === "WARNING") {
                cell.classList.add("amber");
            }

            if (index === 3 &&
                ["RECOVERED", "RESTORED"].includes(incident.status)) {
                cell.classList.add("recovery");
            }

            row.appendChild(cell);
        });

        if (incident.simulated) {
            row.cells[1].appendChild(
                document.createTextNode(" [SIMULATED]")
            );
        }

        const actionCell = document.createElement("td");
        const button = document.createElement("button");

        button.type = "button";
        button.className = "evidence-button";
        button.textContent = `View Evidence (${evidence.length})`;
        button.setAttribute("aria-expanded", "false");

        actionCell.appendChild(button);
        row.appendChild(actionCell);
        table.appendChild(row);

        const detailRow = document.createElement("tr");
        detailRow.hidden = !expandedCorrelationEvidence.has(
            incident.incident_id
        );
        detailRow.className = "evidence-detail-row";

        if (!detailRow.hidden) {
            button.setAttribute("aria-expanded", "true");
            button.textContent = "Hide Evidence";
        }

        const detailCell = document.createElement("td");
        detailCell.colSpan = 6;

        const heading = document.createElement("strong");
        heading.textContent =
            `Incident: ${incident.incident_id || "Unknown"}`;

        detailCell.appendChild(heading);

        const list = document.createElement("div");
        list.className = "evidence-list";

        if (evidence.length === 0) {
            const empty = document.createElement("p");
            empty.textContent = "No evidence records available.";
            list.appendChild(empty);
        }

        for (const item of evidence) {
            const card = document.createElement("div");
            card.className = "evidence-card";

            const fields = [
                ["Event", item.event_type],
                ["Timestamp (UTC)", item.timestamp_utc],
                ["Source", item.source],
                ["Source file", item.source_file],
                ["Source record ID", item.source_record_id],
                ["Source line", item.source_line],
                ["Event ID", item.event_id]
            ];

            for (const [label, value] of fields) {
                if (value === null || value === undefined) continue;

                const field = document.createElement("div");
                field.className = "evidence-field";

                const name = document.createElement("span");
                name.textContent = label;

                const content = document.createElement("strong");
                content.textContent = String(value);

                field.appendChild(name);
                field.appendChild(content);
                card.appendChild(field);
            }

            list.appendChild(card);
        }

        detailCell.appendChild(list);
        detailRow.appendChild(detailCell);
        table.appendChild(detailRow);

        button.addEventListener("click", () => {
            const expanded = detailRow.hidden;
            detailRow.hidden = !expanded;

            if (expanded) {
                expandedCorrelationEvidence.add(incident.incident_id);
            } else {
                expandedCorrelationEvidence.delete(incident.incident_id);
            }

            button.setAttribute("aria-expanded", String(expanded));
            button.textContent = expanded
                ? "Hide Evidence"
                : `View Evidence (${evidence.length})`;
        });
    }
}

async function fetchCorrelatedIncidents() {
    const apiStatus = document.getElementById("correlated-api-status");

    try {
        const response = await fetch("/api/correlated-incidents", {
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error("HTTP " + response.status);
        }

        const data = await response.json();

        if (data.status !== "OK" || !Array.isArray(data.incidents)) {
            throw new Error("Invalid correlation API response");
        }

        correlatedIncidents = data.incidents;

        document.getElementById("correlated-total").textContent =
            data.total;

        document.getElementById("correlated-critical").textContent =
            data.summary?.by_severity?.CRITICAL ?? 0;

        document.getElementById("correlated-warning").textContent =
            data.summary?.by_severity?.WARNING ?? 0;

        document.getElementById("correlated-simulated").textContent =
            data.summary?.simulated ?? 0;

        renderCorrelatedIncidents();

        if (apiStatus) {
            apiStatus.textContent = "CONNECTED";
        }

    } catch (error) {
        console.error("Correlation API:", error);

        if (apiStatus) {
            apiStatus.textContent = "DISCONNECTED";
        }
    }
}

document.getElementById("correlated-severity")
    ?.addEventListener("change", renderCorrelatedIncidents);

document.getElementById("correlated-status")
    ?.addEventListener("change", renderCorrelatedIncidents);

fetchCorrelatedIncidents();

setInterval(fetchCorrelatedIncidents, 10000);

// Day 15 — Incident Investigation Center

let investigationRecords = [];
const expandedInvestigationFindings = new Set();

function renderInvestigations() {
    const body = document.getElementById("investigation-body");
    if (!body) return;

    const priority =
        document.getElementById("investigation-priority")?.value || "ALL";

    const status =
        document.getElementById("investigation-status")?.value || "ALL";

    const filtered = investigationRecords.filter(item =>
        (priority === "ALL" || item.investigation_priority === priority) &&
        (status === "ALL" || item.investigation_status === status)
    );

    body.replaceChildren();

    if (filtered.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 6;
        cell.textContent = "No investigations match the filters.";

        row.appendChild(cell);
        body.appendChild(row);
        return;
    }

    for (const item of filtered) {
        const row = document.createElement("tr");

        const values = [
            item.incident_id || "--",
            item.investigation_priority || "--",
            item.operational_status || "--",
            `${item.evidence_status || "--"} (${item.evidence_count ?? 0})`,
            item.investigation_status || "--"
        ];

        values.forEach((value, index) => {
            const cell = document.createElement("td");
            cell.textContent = String(value);

            if (index === 1 && item.investigation_priority === "HIGH") {
                cell.classList.add("critical");
            }

            if (index === 4 && item.investigation_status === "REVIEW_REQUIRED") {
                cell.classList.add("amber");
            }

            if (index === 4 && item.investigation_status === "EVIDENCE_LINKED") {
                cell.classList.add("recovery");
            }

            row.appendChild(cell);
        });

        const findings = Array.isArray(item.findings)
            ? item.findings
            : [];

        const actionCell = document.createElement("td");
        const button = document.createElement("button");

        button.type = "button";
        button.className = "evidence-button";
        button.textContent = `View Findings (${findings.length})`;

        actionCell.appendChild(button);
        row.appendChild(actionCell);
        body.appendChild(row);

        const detailRow = document.createElement("tr");
        detailRow.className = "evidence-detail-row";
        detailRow.hidden = !expandedInvestigationFindings.has(item.incident_id);

        const detailCell = document.createElement("td");
        detailCell.colSpan = 6;

        const heading = document.createElement("strong");
        heading.textContent = `Investigation: ${item.incident_id}`;

        detailCell.appendChild(heading);

        const list = document.createElement("div");
        list.className = "evidence-list";

        const card = document.createElement("div");
        card.className = "evidence-card";

        const details = [
            ["Source", item.source],
            ["Incident type", item.incident_type],
            ["Created", item.created_at],
            ["Resolved", item.resolved_at || "Not resolved"],
            ["Evidence status", item.evidence_status],
            ["Investigation priority", item.investigation_priority]
        ];

        for (const [label, value] of details) {
            const field = document.createElement("div");
            field.className = "evidence-field";

            const name = document.createElement("span");
            name.textContent = label;

            const content = document.createElement("strong");
            content.textContent = String(value ?? "--");

            field.appendChild(name);
            field.appendChild(content);
            card.appendChild(field);
        }

        const findingsHeading = document.createElement("strong");
        findingsHeading.textContent = "Investigation Findings";
        card.appendChild(findingsHeading);

        if (findings.length === 0) {
            const empty = document.createElement("p");
            empty.textContent = "No findings recorded.";
            card.appendChild(empty);
        }

        for (const finding of findings) {
            const paragraph = document.createElement("p");
            paragraph.textContent = String(finding);
            card.appendChild(paragraph);
        }

        list.appendChild(card);
        detailCell.appendChild(list);
        detailRow.appendChild(detailCell);
        body.appendChild(detailRow);

        function updateButton() {
            const expanded = !detailRow.hidden;
            button.setAttribute("aria-expanded", String(expanded));
            button.textContent = expanded
                ? "Hide Findings"
                : `View Findings (${findings.length})`;
        }

        updateButton();

        button.addEventListener("click", () => {
            detailRow.hidden = !detailRow.hidden;

            if (!detailRow.hidden) {
                expandedInvestigationFindings.add(item.incident_id);
            } else {
                expandedInvestigationFindings.delete(item.incident_id);
            }

            updateButton();
        });
    }
}

async function fetchIncidentInvestigations() {
    const apiStatus = document.getElementById("investigation-api-status");

    try {
        const response = await fetch("/api/incident-investigations", {
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error("HTTP " + response.status);
        }

        const data = await response.json();

        if (data.status !== "OK" ||
            !Array.isArray(data.investigations)) {
            throw new Error("Invalid investigation API response");
        }

        investigationRecords = data.investigations;

        document.getElementById("investigation-total").textContent =
            data.total;

        document.getElementById("investigation-review").textContent =
            data.summary?.by_investigation_status?.REVIEW_REQUIRED ?? 0;

        document.getElementById("investigation-linked").textContent =
            data.summary?.by_investigation_status?.EVIDENCE_LINKED ?? 0;

        document.getElementById("investigation-high").textContent =
            data.summary?.by_priority?.HIGH ?? 0;

        const reportTime =
            document.getElementById("investigation-report-time");

        if (reportTime) {
            reportTime.textContent = data.generated_at_utc
                ? ` · Snapshot: ${data.generated_at_utc}`
                : "";
        }

        renderInvestigations();

        if (apiStatus) apiStatus.textContent = "CONNECTED";

    } catch (error) {
        console.error("Investigation API:", error);

        if (apiStatus) apiStatus.textContent = "DISCONNECTED";
    }
}

document.getElementById("investigation-priority")
    ?.addEventListener("change", renderInvestigations);

document.getElementById("investigation-status")
    ?.addEventListener("change", renderInvestigations);

fetchIncidentInvestigations();
setInterval(fetchIncidentInvestigations, 10000);


// DAY 16 INCIDENT FORENSICS

let forensics16Records = [];
const forensics16Expanded = new Set();

function forensics16Cell(row, value) {
    const cell = document.createElement("td");
    cell.textContent = String(value ?? "--");
    row.appendChild(cell);
    return cell;
}

function forensics16Duration(seconds) {
    if (seconds === null || seconds === undefined) {
        return "--";
    }

    if (!Number.isFinite(Number(seconds))) {
        return "--";
    }

    return `${seconds} sec`;
}

function renderForensics16() {
    const body = document.getElementById("forensics16-body");
    if (!body) return;

    const filter = document.getElementById("forensics16-filter")?.value
        || "ALL";

    const filtered = forensics16Records.filter(item => {
        const needsReview =
            item.verification_status !== "VERIFIED" ||
            item.timeline_status !== "RECONSTRUCTED";

        if (filter === "REVIEW_REQUIRED") return needsReview;
        if (filter === "VERIFIED") return !needsReview;
        return true;
    });

    body.replaceChildren();

    if (!filtered.length) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 7;
        cell.textContent = "No matching forensic incidents.";
        row.appendChild(cell);
        body.appendChild(row);
        return;
    }

    for (const item of filtered) {
        const row = document.createElement("tr");

        forensics16Cell(row, item.incident_id);
        forensics16Cell(row, item.operational_status);

        forensics16Cell(
            row,
            `${item.verified_count ?? 0}/${item.evidence_count ?? 0}`
        );

        forensics16Cell(row, item.verification_status);
        forensics16Cell(row, item.timeline_status);
        forensics16Cell(
            row,
            forensics16Duration(item.duration_seconds)
        );

        const actions = document.createElement("td");
        const button = document.createElement("button");

        button.type = "button";
        button.textContent = forensics16Expanded.has(item.incident_id)
            ? "Hide Evidence"
            : "View Evidence";

        button.addEventListener("click", () => {
            if (forensics16Expanded.has(item.incident_id)) {
                forensics16Expanded.delete(item.incident_id);
            } else {
                forensics16Expanded.add(item.incident_id);
            }
            renderForensics16();
        });

        actions.appendChild(button);
        row.appendChild(actions);
        body.appendChild(row);

        if (forensics16Expanded.has(item.incident_id)) {
            const detailsRow = document.createElement("tr");
            const detailsCell = document.createElement("td");
            detailsCell.colSpan = 7;

            const container = document.createElement("div");
            container.className = "forensics16-details";

            const heading = document.createElement("strong");
            heading.textContent = "Evidence & Timeline";
            container.appendChild(heading);

            const evidence = Array.isArray(item.evidence)
                ? item.evidence
                : [];

            for (const entry of evidence) {
                const line = document.createElement("p");
                line.textContent =
                    `[${entry.status ?? "UNKNOWN"}] ` +
                    `${entry.event_key ?? "No evidence key"}`;
                container.appendChild(line);
            }

            const events = Array.isArray(item.events)
                ? item.events
                : [];

            for (const event of events) {
                const line = document.createElement("p");
                line.textContent =
                    `${event.timestamp ?? "--"} | ` +
                    `${event.event_type ?? "--"} | ` +
                    `${event.message ?? ""}`;
                container.appendChild(line);
            }

            const findings = [
                ...(item.verification_findings || []),
                ...(item.timeline_findings || [])
            ];

            for (const finding of findings) {
                const line = document.createElement("p");
                line.textContent = `Finding: ${finding}`;
                container.appendChild(line);
            }

            if (!evidence.length && !events.length && !findings.length) {
                const line = document.createElement("p");
                line.textContent = "No forensic details available.";
                container.appendChild(line);
            }

            detailsCell.appendChild(container);
            detailsRow.appendChild(detailsCell);
            body.appendChild(detailsRow);
        }
    }
}

async function fetchForensics16() {
    const status = document.getElementById("forensics16-api-status");

    try {
        const response = await fetch(
            "/api/day16-forensics",
            { cache: "no-store" }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        if (data.status !== "OK" || !Array.isArray(data.incidents)) {
            throw new Error("Invalid forensic API response");
        }

        forensics16Records = data.incidents;

        const summary = data.summary || {};

        document.getElementById("forensics16-total").textContent =
            summary.total_incidents ?? 0;

        document.getElementById("forensics16-evidence").textContent =
            summary.verified_evidence ?? 0;

        document.getElementById("forensics16-timelines").textContent =
            summary.reconstructed_timelines ?? 0;

        document.getElementById("forensics16-review").textContent =
            summary.review_required ?? 0;

        const reportTime = document.getElementById(
            "forensics16-report-time"
        );

        if (reportTime) {
            reportTime.textContent = data.generated_at_utc
                ? ` · Snapshot: ${data.generated_at_utc}`
                : "";
        }

        renderForensics16();

        if (status) status.textContent = "CONNECTED";

    } catch (error) {
        console.error("Day 16 Forensics API:", error);
        if (status) status.textContent = "DISCONNECTED";
    }
}

document.getElementById("forensics16-filter")
    ?.addEventListener("change", renderForensics16);

fetchForensics16();
setInterval(fetchForensics16, 10000);


// DAY 17 SOC REPORTS

let soc17Records = [];

function soc17AddCell(row, value) {
    const cell = document.createElement("td");
    cell.textContent = String(value ?? "--");
    row.appendChild(cell);
    return cell;
}

function renderSoc17Reports() {
    const body = document.getElementById("soc17-body");
    if (!body) return;

    const filter =
        document.getElementById("soc17-filter")?.value || "ALL";

    const records = soc17Records.filter(item => {
        if (filter === "REVIEW") {
            return item.review_required === true;
        }

        if (filter === "VERIFIED") {
            return item.verification_status === "VERIFIED"
                && item.review_required !== true;
        }

        return true;
    });

    body.replaceChildren();

    if (!records.length) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 6;
        cell.textContent = "No matching SOC reports.";
        row.appendChild(cell);
        body.appendChild(row);
        return;
    }

    for (const item of records) {
        const row = document.createElement("tr");

        soc17AddCell(row, item.incident_id);
        soc17AddCell(row, item.severity);
        soc17AddCell(row, item.operational_status);
        soc17AddCell(row, item.verification_status);

        soc17AddCell(
            row,
            item.review_required ? "REVIEW REQUIRED" : "NO"
        );

        const actionCell = document.createElement("td");

        if (item.pdf_available) {
            const link = document.createElement("a");

            link.href =
                "/api/day17-soc-reports/" +
                encodeURIComponent(item.incident_id) +
                "/pdf";

            link.textContent = "Download PDF";
            link.className = "soc17-download";
            link.setAttribute(
                "aria-label",
                "Download SOC report " + item.incident_id
            );

            actionCell.appendChild(link);
        } else {
            actionCell.textContent = "Unavailable";
        }

        row.appendChild(actionCell);
        body.appendChild(row);
    }
}

async function fetchSoc17Reports() {
    const apiStatus =
        document.getElementById("soc17-api-status");

    try {
        const response = await fetch(
            "/api/day17-soc-reports",
            { cache: "no-store" }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        if (data.status !== "OK" ||
            !Array.isArray(data.reports)) {
            throw new Error("Invalid SOC reports response");
        }

        soc17Records = data.reports;

        const summary = data.summary || {};

        document.getElementById("soc17-total").textContent =
            summary.total_reports ?? 0;

        document.getElementById("soc17-pdf").textContent =
            summary.pdf_available ?? 0;

        document.getElementById("soc17-review").textContent =
            summary.review_required ?? 0;

        const reportTime =
            document.getElementById("soc17-report-time");

        if (reportTime) {
            reportTime.textContent = data.generated_at_utc
                ? ` · Snapshot: ${data.generated_at_utc}`
                : "";
        }

        renderSoc17Reports();

        if (apiStatus) {
            apiStatus.textContent = "CONNECTED";
        }

    } catch (error) {
        console.error("Day 17 SOC Reports API:", error);

        if (apiStatus) {
            apiStatus.textContent = "DISCONNECTED";
        }
    }
}

document.getElementById("soc17-filter")
    ?.addEventListener("change", renderSoc17Reports);

fetchSoc17Reports();
setInterval(fetchSoc17Reports, 10000);



// DAY 19 — SOC ANALYST OPERATIONS
let day19ActionBusy = false;

async function submitDay19Action(
    incidentId,
    operation,
    payload = {}
) {
    if (day19ActionBusy) return;

    if (!["assign", "status", "notes"].includes(operation)) {
        return;
    }

    if (!window.confirm(
        "Confirm " + operation + " for " + incidentId + "?"
    )) return;

    day19ActionBusy = true;
    renderDay18Cases();

    try {
        const csrfResponse = await fetch(
            "/api/soc-auth/csrf",
            {credentials: "same-origin", cache: "no-store"}
        );

        if (!csrfResponse.ok) {
            throw new Error("Authentication required");
        }

        const csrfData = await csrfResponse.json();

        if (!csrfData.csrf_token) {
            throw new Error("CSRF token unavailable");
        }

        const response = await fetch(
            "/api/day19/cases/" +
            encodeURIComponent(incidentId) +
            "/" + operation,
            {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": csrfData.csrf_token
                },
                body: JSON.stringify(payload)
            }
        );

        const result = await response.json();

        if (!response.ok) {
            throw new Error(
                result.error || "HTTP " + response.status
            );
        }

        await fetchDay18Cases();
        await fetchDay18Audit(incidentId);

    } catch (error) {
        console.error("Day 19 analyst action:", error);
        window.alert("Action failed: " + error.message);
    } finally {
        day19ActionBusy = false;
        renderDay18Cases();
    }
}

// DAY 18 — SOC ANALYST WORKFLOW (READ ONLY)
let day18Cases = [];

function day18Element(id) {
    return document.getElementById(id);
}

function day18SetText(id, value) {
    const element = day18Element(id);
    if (element) element.textContent = String(value);
}

function renderDay18Cases() {
    const body = day18Element("day18-cases-body");
    if (!body) return;

    const search = (
        day18Element("day18-search")?.value || ""
    ).trim().toUpperCase();

    const filter =
        day18Element("day18-filter")?.value || "ALL";

    const filtered = day18Cases.filter(item => {
        const matchesSearch = item.incident_id
            .toUpperCase().includes(search);

        const matchesFilter = filter === "ALL" ||
            item.workflow_status === filter;

        return matchesSearch && matchesFilter;
    });

    body.replaceChildren();

    if (!filtered.length) {
        const row = body.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 5;
        cell.textContent = "No matching analyst cases.";
        return;
    }

    filtered.forEach(item => {
        const row = body.insertRow();

        const incidentCell = row.insertCell();
        incidentCell.textContent = item.incident_id;

        const statusCell = row.insertCell();
        const status = document.createElement("span");
        status.className = "day18-status";
        status.dataset.status = item.workflow_status;
        status.textContent = item.workflow_status;
        statusCell.appendChild(status);

        const analystCell = row.insertCell();
        analystCell.textContent =
            item.assigned_to || "Unassigned";

        const updatedCell = row.insertCell();
        const parsedDate = item.updated_at
            ? new Date(item.updated_at)
            : null;

        updatedCell.textContent =
            parsedDate && !Number.isNaN(parsedDate.getTime())
                ? parsedDate.toLocaleString("ro-RO")
                : "—";

        const actionCell = row.insertCell();

        function addCaseButton(label, handler) {
            const button = document.createElement("button");
            button.type = "button";
            button.className = "day18-action";
            button.textContent = label;
            button.disabled = day19ActionBusy;
            button.addEventListener("click", handler);
            actionCell.appendChild(button);
        }

        if (item.workflow_status === "NEW") {
            addCaseButton("Assign to Me", () => {
                submitDay19Action(item.incident_id, "assign");
            });
        }

        if (item.workflow_status === "ASSIGNED") {
            addCaseButton("Start Review", () => {
                submitDay19Action(
                    item.incident_id,
                    "status",
                    {new_status: "IN_REVIEW"}
                );
            });
        }

        if (
            item.workflow_status === "ASSIGNED" ||
            item.workflow_status === "IN_REVIEW"
        ) {
            addCaseButton("Add Note", () => {
                const note = window.prompt("Investigation note:");
                if (note === null) return;

                if (!note.trim()) {
                    window.alert("A note is required.");
                    return;
                }

                submitDay19Action(
                    item.incident_id,
                    "notes",
                    {note: note.trim()}
                );
            });
        }

        if (item.workflow_status === "IN_REVIEW") {
            addCaseButton("Close Case", () => {
                const note = window.prompt(
                    "Resolution note (required):"
                );
                if (note === null) return;

                if (!note.trim()) {
                    window.alert("A resolution note is required.");
                    return;
                }

                submitDay19Action(
                    item.incident_id,
                    "status",
                    {new_status: "CLOSED", note: note.trim()}
                );
            });
        }

        addCaseButton("View Audit Trail", () => {
            fetchDay18Audit(item.incident_id);
        });
    });
}

async function fetchDay18Cases() {
    const body = day18Element("day18-cases-body");
    if (!body) return;

    try {
        const response = await fetch(
            "/api/day18-analyst-cases",
            {cache: "no-store"}
        );

        if (!response.ok) {
            throw new Error("HTTP " + response.status);
        }

        const data = await response.json();

        if (!Array.isArray(data.cases)) {
            throw new Error("Invalid API response");
        }

        day18Cases = data.cases;

        day18SetText("day18-total", day18Cases.length);

        const counts = {
            NEW: 0,
            ASSIGNED: 0,
            IN_REVIEW: 0,
            CLOSED: 0
        };

        day18Cases.forEach(item => {
            if (Object.hasOwn(counts, item.workflow_status)) {
                counts[item.workflow_status]++;
            }
        });

        day18SetText("day18-new", counts.NEW);
        day18SetText("day18-assigned", counts.ASSIGNED);
        day18SetText("day18-review", counts.IN_REVIEW);
        day18SetText("day18-closed", counts.CLOSED);

        day18SetText(
            "day18-last-update",
            " · Updated " + new Date().toLocaleTimeString()
        );

        renderDay18Cases();

    } catch (error) {
        console.error("Day 18 cases:", error);

        body.replaceChildren();

        const row = body.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 5;
        cell.textContent = "Unable to load analyst cases.";

        day18SetText("day18-last-update", " · API unavailable");
    }
}

async function fetchDay18Audit(incidentId) {
    const panel = day18Element("day18-audit-panel");
    const content = day18Element("day18-audit-content");

    if (!panel || !content) return;

    panel.hidden = false;
    content.replaceChildren();

    day18SetText(
        "day18-audit-title",
        "Audit Trail — " + incidentId
    );

    const loading = document.createElement("p");
    loading.textContent = "Loading audit history...";
    content.appendChild(loading);

    try {
        const response = await fetch(
            "/api/day18-analyst-cases/" +
            encodeURIComponent(incidentId) +
            "/audit",
            {cache: "no-store"}
        );

        if (!response.ok) {
            throw new Error("HTTP " + response.status);
        }

        const data = await response.json();
        content.replaceChildren();

        if (!Array.isArray(data.audit)) {
            throw new Error("Invalid audit response");
        }

        if (!data.audit.length) {
            const empty = document.createElement("p");
            empty.textContent =
                "No analyst actions recorded for this incident.";
            content.appendChild(empty);
            return;
        }

        const list = document.createElement("ol");
        list.className = "day18-audit-list";

        data.audit.forEach(entry => {
            const item = document.createElement("li");

            const title = document.createElement("strong");
            title.textContent =
                entry.action + " · " + entry.actor;

            const detail = document.createElement("div");
            detail.textContent =
                (entry.previous_status || "—") +
                " → " +
                (entry.new_status || "—");

            const note = document.createElement("p");
            note.textContent = entry.note || "No note";

            const time = document.createElement("small");
            time.textContent = entry.created_at || "";

            item.append(title, detail, note, time);
            list.appendChild(item);
        });

        content.appendChild(list);

    } catch (error) {
        console.error("Day 18 audit:", error);
        content.replaceChildren();

        const message = document.createElement("p");
        message.textContent = "Unable to load audit history.";
        content.appendChild(message);
    }
}

(function initDay18Workflow() {
    if (!day18Element("day18-workflow")) return;

    day18Element("day18-search")
        ?.addEventListener("input", renderDay18Cases);

    day18Element("day18-filter")
        ?.addEventListener("change", renderDay18Cases);

    day18Element("day18-close-audit")
        ?.addEventListener("click", () => {
            day18Element("day18-audit-panel").hidden = true;
        });

    fetchDay18Cases();
})();


// Day 18 - Analyst Alert Queue
let alertQueueBusy = false;

function alertActionMessage(message) {
    const element = document.getElementById(
        "management-action-message"
    );
    if (element) element.textContent = message;
}

async function submitAlertAction(alertId, action) {
    if (alertQueueBusy) return;

    const verb = action === "resolve"
        ? "resolve"
        : "acknowledge";

    if (!window.confirm(
        `Are you sure you want to ${verb} alert ${alertId}?`
    )) return;

    let note = null;

    if (action === "resolve") {
        note = window.prompt(
            "Enter a resolution note:",
            "Reviewed by SOC analyst"
        );

        if (note === null) return;

        if (!note.trim()) {
            alertActionMessage(
                "A resolution note is required."
            );
            return;
        }
    }

    alertQueueBusy = true;
    alertActionMessage("Submitting analyst action...");

    try {
        const csrfResponse = await fetch(
            "/api/soc-auth/csrf",
            {
                cache: "no-store",
                credentials: "same-origin"
            }
        );

        if (!csrfResponse.ok) {
            throw new Error(
                "Authentication required (HTTP " +
                csrfResponse.status + ")"
            );
        }

        const csrfData = await csrfResponse.json();

        if (!csrfData.csrf_token) {
            throw new Error("CSRF token unavailable");
        }

        const response = await fetch(
            "/api/alert-management/" + action,
            {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": csrfData.csrf_token
                },
                body: JSON.stringify({
                    alert_id: alertId,
                    note: note
                })
            }
        );

        const result = await response.json();

        if (!response.ok) {
            throw new Error(
                result.message ||
                "HTTP " + response.status
            );
        }

        alertActionMessage(
            "Alert " + alertId + " updated successfully."
        );

        await Promise.all([
            renderManagementAlertQueue(),
            fetchAlertManagement()
        ]);

    } catch (error) {
        console.error("Alert action failed:", error);
        alertActionMessage(
            "Action failed: " + error.message
        );
    } finally {
        alertQueueBusy = false;
    }
}

async function renderManagementAlertQueue() {
    const body = document.getElementById(
        "management-alerts-table"
    );

    if (!body || alertQueueBusy) return;

    try {
        const response = await fetch(
            "/api/alert-management",
            {
                cache: "no-store",
                credentials: "same-origin"
            }
        );

        if (!response.ok) {
            throw new Error("HTTP " + response.status);
        }

        const data = await response.json();

        if (!Array.isArray(data.alerts)) {
            throw new Error("Invalid alert list");
        }

        body.replaceChildren();

        if (!data.alerts.length) {
            const row = body.insertRow();
            const cell = row.insertCell();
            cell.colSpan = 5;
            cell.textContent = "No alerts available.";
            return;
        }

        data.alerts.forEach(alert => {
            const row = body.insertRow();

            [
                alert.alert_id,
                alert.severity,
                alert.type,
                alert.status
            ].forEach(value => {
                const cell = row.insertCell();
                cell.textContent = String(value ?? "—");
            });

            const cell = row.insertCell();

            let action = null;
            let label = null;

            if (alert.status === "NEW") {
                action = "acknowledge";
                label = "Acknowledge";
            } else if (alert.status === "ACKNOWLEDGED") {
                action = "resolve";
                label = "Resolve";
            }

            if (!action) {
                cell.textContent = "Completed";
                return;
            }

            const button = document.createElement("button");
            button.type = "button";
            button.textContent = label;
            button.className = "soc-action-button";

            button.addEventListener("click", () => {
                submitAlertAction(alert.alert_id, action);
            });

            cell.appendChild(button);
        });

    } catch (error) {
        console.error("Analyst Alert Queue:", error);

        body.replaceChildren();

        const row = body.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 5;
        cell.textContent = "Unable to load managed alerts.";
    }
}

renderManagementAlertQueue();
setInterval(renderManagementAlertQueue, 5000);


// ============================================
// DAY 20 - AUTOMATED INCIDENT PRIORITIZATION
// ============================================

async function fetchDay20Priorities() {
    const body = document.getElementById(
        "day20-priority-body"
    );

    const apiStatus = document.getElementById(
        "day20-api-status"
    );

    if (!body || !apiStatus) return;

    try {
        const response = await fetch(
            "/api/day20/incident-priorities",
            {
                credentials: "same-origin",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error("HTTP " + response.status);
        }

        const data = await response.json();

        if (!Array.isArray(data.incidents)) {
            throw new Error("Invalid incident data");
        }

        const summary = data.priority_summary;

        if (!summary || typeof summary !== "object") {
            throw new Error("Invalid priority summary");
        }

        const metrics = {
            "day20-total": data.total_incidents,
            "day20-critical": summary.CRITICAL,
            "day20-high": summary.HIGH,
            "day20-medium": summary.MEDIUM,
            "day20-low": summary.LOW
        };

        Object.entries(metrics).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = String(value ?? 0);
            }
        });

        body.replaceChildren();

        if (!data.incidents.length) {
            const row = body.insertRow();
            const cell = row.insertCell();
            cell.colSpan = 6;
            cell.textContent = "No incidents available.";
        }

        data.incidents.forEach(incident => {
            const row = body.insertRow();

            const values = [
                incident.incident_id,
                incident.severity,
                `${incident.risk_score}/100`,
                incident.priority,
                incident.type,
                Array.isArray(incident.reasons)
                    ? incident.reasons.join("; ")
                    : "No scoring explanation"
            ];

            values.forEach(value => {
                const cell = row.insertCell();
                cell.textContent = String(value ?? "—");
            });
        });

        apiStatus.textContent = "ONLINE";

        const updated = document.getElementById(
            "day20-last-update"
        );

        if (updated) {
            updated.textContent =
                "Updated: " + new Date().toLocaleTimeString();
        }

    } catch (error) {
        console.error("Day 20 prioritization:", error);

        apiStatus.textContent = "ERROR";

        body.replaceChildren();

        const row = body.insertRow();
        const cell = row.insertCell();

        cell.colSpan = 6;
        cell.textContent =
            "Unable to load incident priorities.";
    }
}

fetchDay20Priorities();
setInterval(fetchDay20Priorities, 10000);

// ==================================================
// DAY 21 - THREAT INTELLIGENCE & IOC CORRELATION
// ==================================================

async function fetchDay21IOCCorrelations() {

    const body = document.getElementById(
        "day21-ioc-body"
    );

    const apiStatus = document.getElementById(
        "day21-api-status"
    );

    if (!body || !apiStatus) return;

    try {

        const response = await fetch(
            "/api/day21/ioc-correlations",
            {
                credentials: "same-origin",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error("HTTP " + response.status);
        }

        const data = await response.json();

        if (
            data.status !== "OK" ||
            !Array.isArray(data.matches)
        ) {
            throw new Error("Invalid IOC response");
        }

        const metrics = {
            "day21-indicators": data.total_indicators,
            "day21-events": data.total_lines,
            "day21-matches": data.total_matches
        };

        Object.entries(metrics).forEach(([id, value]) => {
            const element = document.getElementById(id);

            if (element) {
                element.textContent = String(value ?? 0);
            }
        });

        body.replaceChildren();

        if (data.matches.length === 0) {

            const row = body.insertRow();
            const cell = row.insertCell();

            cell.colSpan = 7;
            cell.textContent = "No IOC matches detected.";

        } else {

            data.matches.forEach(match => {

                const row = body.insertRow();

                const values = [
                    match.ioc_id,
                    match.ioc_type,
                    match.ioc_value,
                    match.severity,
                    `${match.confidence}%`,
                    match.threat_type,
                    match.evidence
                ];

                values.forEach(value => {
                    const cell = row.insertCell();
                    cell.textContent = String(value ?? "—");
                });

            });
        }

        apiStatus.textContent = "ONLINE";

        const updated = document.getElementById(
            "day21-last-update"
        );

        if (updated) {
            updated.textContent =
                "Updated: " + new Date().toLocaleTimeString();
        }

    } catch (error) {

        console.error("Day 21 IOC correlation:", error);

        apiStatus.textContent = "ERROR";

        body.replaceChildren();

        const row = body.insertRow();
        const cell = row.insertCell();

        cell.colSpan = 7;
        cell.textContent =
            "Unable to load IOC correlation results.";
    }
}

fetchDay21IOCCorrelations();

setInterval(fetchDay21IOCCorrelations, 10000);


// DAY 22 - SOC Threat Alert Investigation Queue

async function fetchDay22ThreatAlerts() {

    const body = document.getElementById(
        "day22-alerts-body"
    );

    const apiStatus = document.getElementById(
        "day22-api-status"
    );

    if (!body || !apiStatus) return;

    const setMetric = (id, value) => {
        const element = document.getElementById(id);
        if (element) element.textContent = String(value);
    };

    try {
        const response = await fetch(
            "/api/day22/threat-alerts",
            {
                credentials: "same-origin",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(
                "Threat alert API HTTP " + response.status
            );
        }

        const data = await response.json();

        if (
            data.status !== "OK" ||
            !Array.isArray(data.alerts)
        ) {
            throw new Error("Invalid threat alert response");
        }

        const alerts = data.alerts;

        const countPriority = (priority) =>
            alerts.filter(
                alert => alert.priority === priority
            ).length;

        setMetric("day22-total-alerts", alerts.length);
        setMetric("day22-critical-alerts", countPriority("CRITICAL"));
        setMetric("day22-high-alerts", countPriority("HIGH"));
        setMetric("day22-medium-alerts", countPriority("MEDIUM"));

        body.replaceChildren();

        if (alerts.length === 0) {

            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 7;
            cell.textContent =
                "No IOC-correlated SOC alerts detected.";

            row.appendChild(cell);
            body.appendChild(row);

        } else {

            const fields = [
                "alert_id",
                "priority",
                "ioc_value",
                "confidence",
                "threat_type",
                "investigation_status",
                "evidence"
            ];

            for (const alert of alerts) {

                const row = document.createElement("tr");

                for (const field of fields) {

                    const cell = document.createElement("td");

                    const value = alert[field];

                    cell.textContent =
                        value === null || value === undefined
                            ? "--"
                            : field === "confidence"
                                ? String(value) + "%"
                                : String(value);

                    row.appendChild(cell);
                }

                body.appendChild(row);
            }
        }

        apiStatus.textContent = "ONLINE";

        const updated = document.getElementById(
            "day22-last-update"
        );

        if (updated) {
            updated.textContent =
                "Updated: " + new Date().toLocaleTimeString();
        }

    } catch (error) {

        apiStatus.textContent = "ERROR";

        console.error(
            "Day 22 threat alert fetch failed:",
            error
        );
    }
}

fetchDay22ThreatAlerts();

setInterval(fetchDay22ThreatAlerts, 10000);


// DAY 22 WORKSPACE SCROLL SYNC
(function initializeWorkspaceNavigation() {
    const nav = document.querySelector(
        '.sidebar nav[aria-label="Dashboard navigation"]'
    );

    if (!nav) return;

    const links = Array.from(
        nav.querySelectorAll('a[href^="#"]')
    );

    const targets = links
        .map(link => {
            const id = link.getAttribute("href").slice(1);
            const section = document.getElementById(id);

            return section ? { link, section } : null;
        })
        .filter(Boolean);

    if (!targets.length) return;

    function updateActiveSection() {
        let active = targets[0];

        for (const target of targets) {
            if (
                target.section.getBoundingClientRect().top
                <= 140
            ) {
                active = target;
            }
        }

        for (const target of targets) {
            const isActive = target === active;

            target.link.classList.toggle(
                "active",
                isActive
            );

            if (isActive) {
                target.link.setAttribute(
                    "aria-current",
                    "location"
                );
            } else {
                target.link.removeAttribute(
                    "aria-current"
                );
            }
        }

        const activeLink = active.link;
        const linkTop = activeLink.offsetTop;
        const linkBottom =
            linkTop + activeLink.offsetHeight;

        const visibleTop = nav.scrollTop;
        const visibleBottom =
            visibleTop + nav.clientHeight;

        if (linkTop < visibleTop) {
            nav.scrollTop = linkTop;
        } else if (linkBottom > visibleBottom) {
            nav.scrollTop =
                linkBottom - nav.clientHeight;
        }
    }

    let scheduled = false;

    window.addEventListener(
        "scroll",
        () => {
            if (scheduled) return;

            scheduled = true;

            requestAnimationFrame(() => {
                updateActiveSection();
                scheduled = false;
            });
        },
        { passive: true }
    );

    window.addEventListener(
        "resize",
        updateActiveSection
    );

    updateActiveSection();
})();
