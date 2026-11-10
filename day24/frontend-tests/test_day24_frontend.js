"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const SCRIPT_PATH = path.resolve(
    __dirname,
    "../../day06/static/js/day24-threat-hunting.js"
);

const script = fs.readFileSync(SCRIPT_PATH, "utf8");

const alerts = [
    {
        alert_id: "ALT-D12105D2C7303721",
        timestamp: "2026-10-29T10:00:00.000",
        timestamp_available: true,
        severity: "HIGH",
        ioc_type: "IP",
        ioc_value: "192.0.2.10",
        evidence: "Robot connection from 192.0.2.10"
    },
    {
        alert_id: "ALT-619C8DAF469BECE8",
        timestamp: "2026-10-29T10:00:01.000",
        timestamp_available: true,
        severity: "CRITICAL",
        ioc_type: "DOMAIN",
        ioc_value: "robot-control-test.example",
        evidence: "DNS request to robot-control-test.example"
    },
    {
        alert_id: "ALT-E4766345A0ABDA45",
        timestamp: "2026-10-29T10:00:02.000",
        timestamp_available: true,
        severity: "MEDIUM",
        ioc_type: "IP",
        ioc_value: "198.51.100.25",
        evidence: "Connection attempt from 198.51.100.25"
    }
];

function response(status, data = null) {
    return {
        status,
        ok: status >= 200 && status < 300,
        json: async () => data
    };
}

function successResponse(timeline = alerts) {
    return response(200, {
        status: "OK",
        total_events: 4,
        total_alerts: timeline.length,
        correlated_alerts: timeline.length,
        timeline
    });
}

async function setup(mockResponse) {
    const html = `
        <!DOCTYPE html>
        <html>
        <body>
            <section id="day24-threat-hunting">
                <strong id="day24-total-events">--</strong>
                <strong id="day24-total-alerts">--</strong>
                <strong id="day24-correlated-alerts">--</strong>

                <table>
                    <tbody id="day24-timeline-body"></tbody>
                </table>

                <strong id="day24-api-status">WAITING</strong>
                <span id="day24-last-update"></span>
                <p id="day24-feedback"></p>
            </section>
        </body>
        </html>
    `;

    const dom = new JSDOM(html, {
        url: "http://127.0.0.1:5000/",
        runScripts: "outside-only"
    });

    const { window } = dom;

    let requestedUrl = null;
    let requestedOptions = null;

    window.fetch = async (url, options) => {
        requestedUrl = url;
        requestedOptions = options;
        return mockResponse;
    };

    window.setInterval = () => 1;

    window.eval(script);

    if (window.document.readyState === "loading") {
        window.document.dispatchEvent(
            new window.Event("DOMContentLoaded")
        );
    }

    // Allow the asynchronous fetch/json/render sequence to finish.
    for (let i = 0; i < 10; i++) {
        await new Promise(resolve => setImmediate(resolve));
    }

    return {
        window,
        document: window.document,
        requestedUrl,
        requestedOptions,
        close: () => dom.window.close()
    };
}

test("01 - renders three synthetic IOC alerts", async () => {
    const env = await setup(successResponse());

    try {
        const rows = env.document.querySelectorAll(
            "#day24-timeline-body tr"
        );

        assert.equal(rows.length, 3);

        assert.equal(
            env.document.getElementById(
                "day24-total-events"
            ).textContent,
            "4"
        );

        assert.equal(
            env.document.getElementById(
                "day24-total-alerts"
            ).textContent,
            "3"
        );

        assert.equal(
            env.document.getElementById(
                "day24-correlated-alerts"
            ).textContent,
            "3"
        );

        assert.equal(
            env.document.getElementById(
                "day24-api-status"
            ).textContent,
            "ONLINE"
        );
    } finally {
        env.close();
    }
});

test("02 - preserves chronological order", async () => {
    const env = await setup(successResponse());

    try {
        const timestamps = [
            ...env.document.querySelectorAll(
                "#day24-timeline-body tr"
            )
        ].map(row => row.cells[0].textContent);

        assert.deepEqual(timestamps, [
            "2026-10-29T10:00:00.000",
            "2026-10-29T10:00:01.000",
            "2026-10-29T10:00:02.000"
        ]);
    } finally {
        env.close();
    }
});

test("03 - displays severity and original evidence", async () => {
    const env = await setup(successResponse());

    try {
        const rows = [
            ...env.document.querySelectorAll(
                "#day24-timeline-body tr"
            )
        ];

        assert.deepEqual(
            rows.map(row => row.cells[1].textContent),
            ["HIGH", "CRITICAL", "MEDIUM"]
        );

        assert.deepEqual(
            rows.map(row => row.cells[4].textContent),
            alerts.map(alert => alert.evidence)
        );

        assert.equal(
            rows[1].cells[1].querySelector("span").className,
            "day24-severity day24-severity-critical"
        );
    } finally {
        env.close();
    }
});

test("04 - renders malicious HTML as text", async () => {
    const malicious = "<img src=x onerror=alert(1)>";

    const modifiedAlerts = [
        {
            ...alerts[0],
            evidence: malicious,
            ioc_value: malicious
        }
    ];

    const env = await setup(
        successResponse(modifiedAlerts)
    );

    try {
        const row = env.document.querySelector(
            "#day24-timeline-body tr"
        );

        assert.equal(
            row.cells[4].textContent,
            malicious
        );

        assert.equal(
            row.querySelector("img"),
            null
        );

        assert.equal(
            row.cells[3].textContent.includes(malicious),
            true
        );
    } finally {
        env.close();
    }
});

test("05 - handles HTTP 401 authorization failure", async () => {
    const env = await setup(response(401));

    try {
        assert.equal(
            env.document.getElementById(
                "day24-api-status"
            ).textContent,
            "AUTH REQUIRED"
        );

        assert.equal(
            env.document.getElementById(
                "day24-total-events"
            ).textContent,
            "--"
        );

        assert.match(
            env.document.getElementById(
                "day24-timeline-body"
            ).textContent,
            /without analyst authorization/
        );
    } finally {
        env.close();
    }
});

test("06 - handles HTTP 503 API failure", async () => {
    const env = await setup(response(503));

    try {
        assert.equal(
            env.document.getElementById(
                "day24-api-status"
            ).textContent,
            "ERROR"
        );

        assert.match(
            env.document.getElementById(
                "day24-timeline-body"
            ).textContent,
            /temporarily unavailable/
        );
    } finally {
        env.close();
    }
});

test("07 - handles empty IOC timeline", async () => {
    const env = await setup(
        response(200, {
            status: "OK",
            total_events: 28,
            total_alerts: 0,
            correlated_alerts: 0,
            timeline: []
        })
    );

    try {
        assert.equal(
            env.document.getElementById(
                "day24-api-status"
            ).textContent,
            "ONLINE"
        );

        assert.match(
            env.document.getElementById(
                "day24-timeline-body"
            ).textContent,
            /No IOC-correlated alerts/
        );
    } finally {
        env.close();
    }
});

test("08 - uses authenticated read-only API request", async () => {
    const env = await setup(successResponse());

    try {
        assert.equal(
            env.requestedUrl,
            "/api/day24/timeline"
        );

        assert.equal(
            env.requestedOptions.method,
            "GET"
        );

        assert.equal(
            env.requestedOptions.credentials,
            "same-origin"
        );

        assert.equal(
            env.requestedOptions.cache,
            "no-store"
        );
    } finally {
        env.close();
    }
});
