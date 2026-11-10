(() => {
    "use strict";

    const API = "/api/day25/incidents";
    const ALERTS_API = "/api/day22/threat-alerts";

    const element = (id) => document.getElementById(id);

    let incidents = [];
    let selectedCaseId = "";
    let busy = false;

    const transitions = {
        OPEN: ["INVESTIGATING"],
        INVESTIGATING: ["RESOLVED"],
        RESOLVED: ["CLOSED", "INVESTIGATING"],
        CLOSED: []
    };

    function setText(id, value) {
        const node = element(id);
        if (node) node.textContent = String(value ?? "--");
    }

    function feedback(message) {
        setText("day25-feedback", message);
    }

    async function requestJSON(url, options = {}) {
        const response = await fetch(url, {
            credentials: "same-origin",
            cache: "no-store",
            ...options
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.error || `HTTP ${response.status}`
            );
        }

        return data;
    }

    async function securePost(url, payload) {
        const csrf = await requestJSON("/api/soc-auth/csrf");

        if (!csrf.csrf_token) {
            throw new Error("CSRF token unavailable");
        }

        return requestJSON(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": csrf.csrf_token
            },
            body: JSON.stringify(payload)
        });
    }

    function selectedIncident() {
        return incidents.find(
            (item) => item.case_id === selectedCaseId
        );
    }

    function createCell(value) {
        const cell = document.createElement("td");
        cell.textContent = String(value ?? "--");
        return cell;
    }

    function showTableMessage(message) {
        const body = element("day25-incidents-body");
        if (!body) return;

        body.replaceChildren();

        const row = document.createElement("tr");
        const cell = createCell(message);
        cell.colSpan = 6;

        row.appendChild(cell);
        body.appendChild(row);
    }

    function renderMetrics() {
        setText("day25-total", incidents.length);

        for (const status of [
            "INVESTIGATING", "RESOLVED", "CLOSED"
        ]) {
            const count = incidents.filter(
                (item) => item.status === status
            ).length;

            setText(
                `day25-${status.toLowerCase()}`,
                count
            );
        }
    }

    function renderTable() {
        const body = element("day25-incidents-body");
        if (!body) return;

        body.replaceChildren();

        if (!incidents.length) {
            showTableMessage("No incident cases recorded.");
            return;
        }

        for (const item of incidents) {
            const row = document.createElement("tr");

            for (const value of [
                item.case_id,
                item.alert_id,
                item.severity,
                item.status,
                item.verdict,
                item.assigned_analyst
            ]) {
                row.appendChild(createCell(value));
            }

            body.appendChild(row);
        }
    }

    function renderCaseSelect() {
        const select = element("day25-case-select");
        if (!select) return;

        select.replaceChildren();

        const placeholder = document.createElement("option");
        placeholder.value = "";
        placeholder.textContent = "Select an incident";
        select.appendChild(placeholder);

        for (const item of incidents) {
            const option = document.createElement("option");
            option.value = item.case_id;
            option.textContent =
                `${item.case_id} | ${item.status}`;

            select.appendChild(option);
        }

        if (!incidents.some(
            (item) => item.case_id === selectedCaseId
        )) {
            selectedCaseId = "";
        }

        select.value = selectedCaseId;
    }

    function updateActions() {
        const incident = selectedIncident();
        const active = Boolean(incident) && !busy;
        const isClosed = incident?.status === "CLOSED";

        const statusSelect = element("day25-status-select");
        const allowed = transitions[incident?.status] || [];

        if (statusSelect) {
            statusSelect.replaceChildren();

            for (const status of allowed) {
                const option = document.createElement("option");
                option.value = status;
                option.textContent = status;
                statusSelect.appendChild(option);
            }

            statusSelect.disabled = !active || !allowed.length;
        }

        const controls = {
            "day25-create": !busy,
            "day25-update-status": active && allowed.length > 0,
            "day25-update-verdict": active && !isClosed,
            "day25-add-evidence": active && !isClosed
        };

        for (const [id, enabled] of Object.entries(controls)) {
            const node = element(id);
            if (node) node.disabled = !enabled;
        }
    }

    function renderDetails() {
        const incident = selectedIncident();

        if (!incident) {
            setText("day25-case-details", "No incident selected.");
            updateActions();
            return;
        }

        setText(
            "day25-case-details",
            [
                `Case: ${incident.case_id}`,
                `Alert: ${incident.alert_id}`,
                `Status: ${incident.status}`,
                `Severity: ${incident.severity}`,
                `Verdict: ${incident.verdict}`,
                `Analyst: ${incident.assigned_analyst}`,
                `Description: ${incident.description}`
            ].join("\n")
        );

        updateActions();
    }

    function renderRecords(id, records, fields) {
        const container = element(id);
        if (!container) return;

        container.replaceChildren();

        if (!records.length) {
            container.textContent = "No records available.";
            return;
        }

        for (const record of records) {
            const block = document.createElement("div");
            block.className = "day25-record";

            for (const field of fields) {
                const line = document.createElement("p");
                line.textContent =
                    `${field}: ${record[field] ?? "--"}`;
                block.appendChild(line);
            }

            container.appendChild(block);
        }
    }

    let recordsRequestId = 0;

    async function loadCaseRecords() {
        const requestId = ++recordsRequestId;
        const caseId = selectedCaseId;

        if (!caseId) {
            renderRecords("day25-evidence-list", [], []);
            renderRecords("day25-audit-list", [], []);
            return;
        }

        const encodedId = encodeURIComponent(caseId);

        const [evidence, audit] = await Promise.all([
            requestJSON(`${API}/${encodedId}/evidence`),
            requestJSON(`${API}/${encodedId}/audit`)
        ]);

        if (
            requestId !== recordsRequestId ||
            selectedCaseId !== caseId
        ) {
            return;
        }

        renderRecords(
            "day25-evidence-list",
            evidence.evidence || [],
            ["evidence_type", "source", "reference_id",
             "description", "added_by", "created_at"]
        );

        renderRecords(
            "day25-audit-list",
            audit.audit || [],
            ["action", "analyst", "previous_status",
             "new_status", "note", "created_at"]
        );
    }

    async function loadIncidents() {
        const data = await requestJSON(API);

        incidents = data.incidents || [];

        renderMetrics();
        renderTable();
        renderCaseSelect();
        renderDetails();

        await loadCaseRecords();

        setText("day25-api-status", "ONLINE");
        setText(
            "day25-last-update",
            new Date().toLocaleTimeString()
        );
    }

    async function loadAlerts() {
        const select = element("day25-alert-select");
        if (!select) return;

        const data = await requestJSON(ALERTS_API);
        const alerts = data.alerts || [];

        select.replaceChildren();

        const placeholder = document.createElement("option");
        placeholder.value = "";
        placeholder.textContent = alerts.length
            ? "Select an IOC alert"
            : "No IOC alerts available";

        select.appendChild(placeholder);

        for (const alert of alerts) {
            const option = document.createElement("option");
            option.value = alert.alert_id;
            option.textContent =
                `${alert.alert_id} | ${alert.severity}`;

            select.appendChild(option);
        }

        select.disabled = alerts.length === 0;
    }

    async function performAction(callback) {
        if (busy) return;

        busy = true;
        updateActions();

        try {
            await callback();
            await loadIncidents();
            feedback("Operation completed successfully.");
        } catch (error) {
            feedback(error.message);
        } finally {
            busy = false;
            updateActions();
        }
    }

    function bindEvents() {
        element("day25-case-select")?.addEventListener(
            "change",
            async (event) => {
                selectedCaseId = event.target.value;
                renderDetails();

                try {
                    await loadCaseRecords();
                } catch (error) {
                    feedback(error.message);
                }
            }
        );

        element("day25-create-form")?.addEventListener(
            "submit",
            (event) => {
                event.preventDefault();

                performAction(async () => {
                    const alertId =
                        element("day25-alert-select").value;

                    const description =
                        element("day25-description").value.trim();

                    if (!alertId || !description) {
                        throw new Error(
                            "Alert and description are required"
                        );
                    }

                    const result = await securePost(API, {
                        alert_id: alertId,
                        description
                    });

                    selectedCaseId = result.incident.case_id;
                    element("day25-description").value = "";
                });
            }
        );

        element("day25-update-status")?.addEventListener(
            "click",
            () => performAction(async () => {
                const status =
                    element("day25-status-select").value;

                const note =
                    element("day25-note").value.trim();

                if (!selectedCaseId || !status || !note) {
                    throw new Error(
                        "Select a case, status and justification"
                    );
                }

                await securePost(
                    `${API}/${encodeURIComponent(selectedCaseId)}/status`,
                    {status, note}
                );
            })
        );

        element("day25-update-verdict")?.addEventListener(
            "click",
            () => performAction(async () => {
                const verdict =
                    element("day25-verdict-select").value;

                const note =
                    element("day25-note").value.trim();

                if (!selectedCaseId || !verdict || !note) {
                    throw new Error(
                        "Select a case, verdict and justification"
                    );
                }

                await securePost(
                    `${API}/${encodeURIComponent(selectedCaseId)}/verdict`,
                    {verdict, note}
                );
            })
        );

        element("day25-add-evidence")?.addEventListener(
            "click",
            () => performAction(async () => {
                const evidenceType =
                    element("day25-evidence-type").value;

                const referenceId =
                    element("day25-evidence-reference").value.trim();

                const description =
                    element("day25-evidence-description").value.trim();

                if (!selectedCaseId || !referenceId || !description) {
                    throw new Error(
                        "Case, reference and description are required"
                    );
                }

                const source = evidenceType === "IOC_ALERT"
                    ? "DAY22"
                    : "DAY24";

                await securePost(
                    `${API}/${encodeURIComponent(selectedCaseId)}/evidence`,
                    {
                        evidence_type: evidenceType,
                        source,
                        reference_id: referenceId,
                        description
                    }
                );
            })
        );
    }

    async function initialize() {
        if (!element("day25-incident-response")) return;

        bindEvents();

        try {
            await Promise.all([
                loadAlerts(),
                loadIncidents()
            ]);
        } catch (error) {
            setText("day25-api-status", "ERROR");
            feedback(error.message);
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initialize);
    } else {
        initialize();
    }
})();
