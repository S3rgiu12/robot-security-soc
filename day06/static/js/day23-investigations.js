"use strict";

(() => {
    const API = "/api/day23/investigations";

    let selectedAlertId = null;
    let investigations = [];
    let busy = false;

    const element = (id) => document.getElementById(id);

    function setText(id, value) {
        const node = element(id);
        if (node) node.textContent = String(value ?? "--");
    }

    function feedback(message) {
        setText("day23-feedback", message);
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

    function currentInvestigation() {
        return investigations.find(
            (item) => item.alert_id === selectedAlertId
        );
    }

    function updateButtons() {
        const item = currentInvestigation();
        const status = item?.investigation?.status;

        const unreviewed = status === "UNREVIEWED";
        const investigating = status === "INVESTIGATING";

        const buttons = {
            "day23-start": unreviewed,
            "day23-add-note": investigating,
            "day23-confirm": investigating,
            "day23-false-positive-action": investigating
        };

        for (const [id, enabled] of Object.entries(buttons)) {
            const button = element(id);
            if (button) button.disabled = busy || !enabled;
        }
    }

    function updateDetails() {
        const item = currentInvestigation();
        const details = element("day23-investigation-details");

        if (!details) return;

        details.hidden = !item;

        if (!item) return;

        setText("day23-selected-alert", item.alert_id);
        setText(
            "day23-selected-status",
            item.investigation.status
        );
        setText(
            "day23-selected-analyst",
            item.investigation.assigned_analyst || "Unassigned"
        );

        updateButtons();
    }

    function renderTable() {
        const body = element("day23-investigations-body");
        if (!body) return;

        body.replaceChildren();

        if (!investigations.length) {
            const row = body.insertRow();
            const cell = row.insertCell();
            cell.colSpan = 6;
            cell.textContent =
                "No IOC investigation alerts currently available.";
            return;
        }

        for (const item of investigations) {
            const row = body.insertRow();

            const values = [
                item.alert_id,
                item.priority,
                item.ioc_value,
                item.investigation.status,
                item.investigation.assigned_analyst || "Unassigned"
            ];

            for (const value of values) {
                const cell = row.insertCell();
                cell.textContent = String(value ?? "--");
            }

            const actionCell = row.insertCell();
            const button = document.createElement("button");

            button.type = "button";
            button.textContent = "Investigate";

            button.addEventListener("click", async () => {
                selectedAlertId = item.alert_id;
                element("day23-note").value = "";
                updateDetails();
                await loadAudit();
            });

            actionCell.appendChild(button);
        }
    }

    function updateMetrics() {
        const counts = {
            UNREVIEWED: 0,
            INVESTIGATING: 0,
            CONFIRMED: 0,
            FALSE_POSITIVE: 0
        };

        for (const item of investigations) {
            const status = item.investigation.status;

            if (Object.hasOwn(counts, status)) {
                counts[status]++;
            }
        }

        setText("day23-unreviewed", counts.UNREVIEWED);
        setText("day23-investigating", counts.INVESTIGATING);
        setText("day23-confirmed", counts.CONFIRMED);
        setText("day23-false-positive", counts.FALSE_POSITIVE);
    }

    async function loadInvestigations(force = false) {
        if (busy && !force) return;

        try {
            const result = await requestJSON(API);

            investigations = result.investigations || [];

            if (
                selectedAlertId &&
                !investigations.some(
                    (item) => item.alert_id === selectedAlertId
                )
            ) {
                selectedAlertId = null;
            }

            renderTable();
            updateMetrics();
            updateDetails();

            setText("day23-api-status", "ONLINE");
            setText(
                "day23-last-update",
                new Date().toLocaleTimeString()
            );
        } catch (error) {
            setText("day23-api-status", "ERROR");
            feedback(`Unable to load investigations: ${error.message}`);
        }
    }

    async function loadAudit() {
        if (!selectedAlertId) return;

        const container = element("day23-audit-trail");
        if (!container) return;

        container.replaceChildren();

        try {
            const result = await requestJSON(
                `${API}/${encodeURIComponent(selectedAlertId)}/audit`
            );

            if (!result.events.length) {
                container.textContent =
                    "No investigation actions recorded.";
                return;
            }

            for (const event of result.events) {
                const entry = document.createElement("div");
                entry.className = "day23-audit-event";

                const heading = document.createElement("strong");
                heading.textContent =
                    `${event.action} · ${event.analyst}`;

                const description = document.createElement("p");
                description.textContent =
                    `${event.previous_status || "--"} → ` +
                    `${event.new_status || "--"}`;

                const note = document.createElement("p");
                note.textContent = event.note || "No note";

                const timestamp = document.createElement("small");
                timestamp.textContent = event.created_at || "";

                entry.append(
                    heading,
                    description,
                    note,
                    timestamp
                );

                container.appendChild(entry);
            }
        } catch (error) {
            container.textContent =
                `Audit unavailable: ${error.message}`;
        }
    }

    async function performAction(action, status = null) {
        if (busy || !selectedAlertId) return;

        const noteField = element("day23-note");
        const note = noteField.value.trim();
        const item = currentInvestigation();

        if (!item) return;

        const currentStatus = item.investigation.status;

        if (
            action === "status" &&
            !(
                (currentStatus === "UNREVIEWED" &&
                 status === "INVESTIGATING") ||
                (currentStatus === "INVESTIGATING" &&
                 ["CONFIRMED", "FALSE_POSITIVE"].includes(status))
            )
        ) {
            feedback("This status transition is not permitted.");
            return;
        }

        if (action === "note" && currentStatus !== "INVESTIGATING") {
            feedback("Investigation must be active to add notes.");
            return;
        }

        if (
            (action === "note" ||
             status === "CONFIRMED" ||
             status === "FALSE_POSITIVE") &&
            !note
        ) {
            feedback("An investigation note is required.");
            return;
        }

        busy = true;
        updateButtons();

        try {
            const url = `${API}/${encodeURIComponent(selectedAlertId)}/` +
                (action === "note" ? "notes" : "status");

            const payload = action === "note"
                ? {note}
                : {status, note};

            await securePost(url, payload);

            noteField.value = "";
            feedback("Investigation action saved successfully.");

            await loadInvestigations(true);
            await loadAudit();
        } catch (error) {
            feedback(`Action failed: ${error.message}`);
        } finally {
            busy = false;
            updateButtons();
        }
    }

    function initialize() {
        if (!element("day23-investigations")) return;

        element("day23-start")?.addEventListener(
            "click",
            () => performAction("status", "INVESTIGATING")
        );

        element("day23-add-note")?.addEventListener(
            "click",
            () => performAction("note")
        );

        element("day23-confirm")?.addEventListener(
            "click",
            () => performAction("status", "CONFIRMED")
        );

        element("day23-false-positive-action")?.addEventListener(
            "click",
            () => performAction("status", "FALSE_POSITIVE")
        );

        updateButtons();
        loadInvestigations();

        window.setInterval(loadInvestigations, 10000);
    }

    if (document.readyState === "loading") {
        document.addEventListener(
            "DOMContentLoaded",
            initialize,
            {once: true}
        );
    } else {
        initialize();
    }
})();
