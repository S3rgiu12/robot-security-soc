(() => {
    "use strict";

    const API_URL = "/api/day24/timeline";
    const REFRESH_MS = 15000;

    const element = (id) => document.getElementById(id);

    function setText(id, value) {
        const node = element(id);
        if (node) {
            node.textContent = String(value);
        }
    }

    function resetMetrics() {
        setText("day24-total-events", "--");
        setText("day24-total-alerts", "--");
        setText("day24-correlated-alerts", "--");
    }

    function showMessage(message) {
        const body = element("day24-timeline-body");
        if (!body) return;

        body.replaceChildren();

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 5;
        cell.className = "day24-empty-state";
        cell.textContent = message;

        row.appendChild(cell);
        body.appendChild(row);
    }

    function createCell(value, className = "") {
        const cell = document.createElement("td");

        cell.textContent = String(value ?? "--");

        if (className) {
            cell.className = className;
        }

        return cell;
    }

    function createSeverityCell(value) {
        const cell = document.createElement("td");
        const badge = document.createElement("span");

        const severity = String(value ?? "UNKNOWN")
            .toUpperCase();

        const allowed = [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW"
        ];

        const cssSeverity = allowed.includes(severity)
            ? severity.toLowerCase()
            : "unknown";

        badge.className =
            "day24-severity day24-severity-" + cssSeverity;

        badge.textContent = severity;

        cell.appendChild(badge);

        return cell;
    }

    function renderTimeline(events) {
        const body = element("day24-timeline-body");
        if (!body) return;

        body.replaceChildren();

        if (events.length === 0) {
            showMessage(
                "No IOC-correlated alerts in the current IDS log."
            );
            return;
        }

        const fragment = document.createDocumentFragment();

        for (const event of events) {
            const row = document.createElement("tr");

            row.appendChild(
                createCell(
                    event.timestamp_available
                        ? event.timestamp
                        : "Timestamp unavailable"
                )
            );

            row.appendChild(
                createSeverityCell(event.severity)
            );

            row.appendChild(
                createCell(event.alert_id)
            );

            row.appendChild(
                createCell(
                    `${event.ioc_type ?? "IOC"}: ` +
                    `${event.ioc_value ?? "Unknown"}`
                )
            );

            row.appendChild(
                createCell(
                    event.evidence,
                    "day24-evidence"
                )
            );

            fragment.appendChild(row);
        }

        body.appendChild(fragment);
    }

    let loading = false;

    async function loadTimeline() {
        if (loading) return;

        loading = true;

        try {
            const response = await fetch(API_URL, {
                method: "GET",
                credentials: "same-origin",
                cache: "no-store",
                headers: {
                    "Accept": "application/json"
                }
            });

            if (response.status === 401 ||
                response.status === 403) {

                resetMetrics();

                setText(
                    "day24-api-status",
                    "AUTH REQUIRED"
                );

                setText(
                    "day24-feedback",
                    "Sign in as an SOC analyst to view the timeline."
                );

                showMessage(
                    "Timeline unavailable without analyst authorization."
                );

                return;
            }

            if (!response.ok) {
                throw new Error(
                    `Timeline API returned HTTP ${response.status}`
                );
            }

            const data = await response.json();

            if (
                data.status !== "OK" ||
                !Array.isArray(data.timeline) ||
                !Number.isInteger(data.total_events) ||
                !Number.isInteger(data.total_alerts) ||
                !Number.isInteger(data.correlated_alerts)
            ) {
                throw new Error(
                    "Unexpected timeline API response"
                );
            }

            setText(
                "day24-total-events",
                data.total_events
            );

            setText(
                "day24-total-alerts",
                data.total_alerts
            );

            setText(
                "day24-correlated-alerts",
                data.correlated_alerts
            );

            renderTimeline(data.timeline);

            setText("day24-api-status", "ONLINE");
            setText("day24-feedback", "");

            setText(
                "day24-last-update",
                "Updated: " + new Date().toLocaleTimeString()
            );

        } catch (error) {
            resetMetrics();

            setText("day24-api-status", "ERROR");

            setText(
                "day24-feedback",
                "Timeline data could not be loaded."
            );

            showMessage(
                "Timeline temporarily unavailable."
            );

            console.error(
                "Day24 timeline request failed:",
                error
            );

        } finally {
            loading = false;
        }
    }

    function initialize() {
        if (!element("day24-timeline-body")) {
            return;
        }

        loadTimeline();

        window.setInterval(
            loadTimeline,
            REFRESH_MS
        );
    }

    if (document.readyState === "loading") {
        document.addEventListener(
            "DOMContentLoaded",
            initialize,
            { once: true }
        );
    } else {
        initialize();
    }
})();
