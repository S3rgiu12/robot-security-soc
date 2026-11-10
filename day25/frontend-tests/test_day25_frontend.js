"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { JSDOM } = require(
    "../../day24/frontend-tests/node_modules/jsdom"
);

const script = fs.readFileSync(
    path.resolve(
        __dirname,
        "../../day06/static/js/day25-incident-response.js"
    ),
    "utf8"
);

const ids = [
    "day25-total",
    "day25-investigating",
    "day25-resolved",
    "day25-closed",
    "day25-incidents-body",
    "day25-case-details",
    "day25-evidence-list",
    "day25-audit-list",
    "day25-api-status",
    "day25-last-update",
    "day25-feedback"
];

const selects = [
    "day25-alert-select",
    "day25-case-select",
    "day25-status-select",
    "day25-verdict-select",
    "day25-evidence-type"
];

const inputs = [
    "day25-description",
    "day25-note",
    "day25-evidence-reference",
    "day25-evidence-description"
];

const buttons = [
    "day25-create",
    "day25-update-status",
    "day25-update-verdict",
    "day25-add-evidence"
];

const ALERT = {
    alert_id: "ALT-TEST-001",
    severity: "HIGH"
};

const INCIDENT = {
    case_id: "INC-TEST-001",
    alert_id: ALERT.alert_id,
    status: "OPEN",
    severity: "HIGH",
    verdict: "UNDETERMINED",
    assigned_analyst: "test_analyst",
    description: "Synthetic incident"
};

function response(data, status = 200) {
    return {
        ok: status >= 200 && status < 300,
        status,
        json: async () => data
    };
}

function createEnvironment(handler) {
    const html = `
      <section id="day25-incident-response">
        <form id="day25-create-form">
          <select id="day25-alert-select"></select>
          <textarea id="day25-description"></textarea>
          <button id="day25-create" type="submit"></button>
        </form>

        <table>
          <tbody id="day25-incidents-body"></tbody>
        </table>

        <select id="day25-case-select"></select>
        <select id="day25-status-select"></select>
        <select id="day25-verdict-select">
          <option value="TRUE_POSITIVE">TRUE_POSITIVE</option>
        </select>
        <select id="day25-evidence-type">
          <option value="IOC_ALERT">IOC_ALERT</option>
          <option value="LOG_EVENT">LOG_EVENT</option>
        </select>

        <textarea id="day25-note"></textarea>
        <input id="day25-evidence-reference">
        <textarea id="day25-evidence-description"></textarea>

        <button id="day25-update-status"></button>
        <button id="day25-update-verdict"></button>
        <button id="day25-add-evidence"></button>

        <div id="day25-case-details"></div>
        <div id="day25-evidence-list"></div>
        <div id="day25-audit-list"></div>

        ${ids
            .filter(id => ![
                "day25-incidents-body",
                "day25-case-details",
                "day25-evidence-list",
                "day25-audit-list"
            ].includes(id))
            .map(id => `<div id="${id}"></div>`)
            .join("")}
      </section>
    `;

    const dom = new JSDOM(html, {
        url: "http://localhost:5000/",
        runScripts: "outside-only"
    });

    const calls = [];

    dom.window.fetch = async (url, options = {}) => {
        calls.push({url, options});
        return handler(url, options);
    };

    dom.window.eval(script);

    const document = dom.window.document;

    const el = id => document.getElementById(id);

    const flush = async () => {
        for (let i = 0; i < 12; i++) {
            await new Promise(resolve => setImmediate(resolve));
        }
    };

    return {dom, document, el, calls, flush};
}

function defaultHandler(url) {
    if (url === "/api/day22/threat-alerts") {
        return response({alerts: [ALERT]});
    }

    if (url === "/api/day25/incidents") {
        return response({incidents: [INCIDENT]});
    }

    if (url.endsWith("/evidence")) {
        return response({evidence: []});
    }

    if (url.endsWith("/audit")) {
        return response({audit: []});
    }

    if (url === "/api/soc-auth/csrf") {
        return response({csrf_token: "synthetic-csrf"});
    }

    return response({error: "Unexpected request"}, 404);
}

test("Day25 loads incident metrics and table", async () => {
    const env = createEnvironment(defaultHandler);

    await env.flush();

    assert.equal(env.el("day25-total").textContent, "1");
    assert.equal(env.el("day25-api-status").textContent, "ONLINE");
    assert.match(
        env.el("day25-incidents-body").textContent,
        /INC-TEST-001/
    );

    env.dom.window.close();
});

test("Day25 loads available IOC alerts", async () => {
    const env = createEnvironment(defaultHandler);

    await env.flush();

    const options = [
        ...env.el("day25-alert-select").options
    ];

    assert.ok(
        options.some(option => option.value === ALERT.alert_id)
    );

    env.dom.window.close();
});

test("Day25 renders incident data without HTML execution", async () => {
    const malicious = {
        ...INCIDENT,
        description: '<img src=x onerror=alert(1)>',
        assigned_analyst: '<script>alert(1)</script>'
    };

    const env = createEnvironment(url => {
        if (url === "/api/day25/incidents") {
            return response({incidents: [malicious]});
        }

        return defaultHandler(url);
    });

    await env.flush();

    env.el("day25-case-select").value = malicious.case_id;
    env.el("day25-case-select").dispatchEvent(
        new env.dom.window.Event("change", {bubbles: true})
    );

    await env.flush();

    assert.equal(
        env.document.querySelectorAll(
            "#day25-case-details img, #day25-case-details script"
        ).length,
        0
    );

    assert.match(
        env.el("day25-case-details").textContent,
        /<img src=x/
    );

    env.dom.window.close();
});

test("Day25 requires CSRF for incident creation", async () => {
    const env = createEnvironment((url, options) => {
        if (url === "/api/day25/incidents" &&
            options.method === "POST") {
            return response({
                incident: INCIDENT
            }, 201);
        }

        return defaultHandler(url);
    });

    await env.flush();

    env.el("day25-alert-select").value = ALERT.alert_id;
    env.el("day25-description").value = "Synthetic case";

    env.el("day25-create-form").dispatchEvent(
        new env.dom.window.Event("submit", {
            bubbles: true,
            cancelable: true
        })
    );

    await env.flush();

    const post = env.calls.find(
        call => call.options.method === "POST"
    );

    assert.ok(post);
    assert.equal(
        post.options.headers["X-CSRF-Token"],
        "synthetic-csrf"
    );

    assert.equal(
        JSON.parse(post.options.body).alert_id,
        ALERT.alert_id
    );

    env.dom.window.close();
});

test("Day25 reports unauthorized API access", async () => {
    const env = createEnvironment(url => {
        if (url === "/api/day25/incidents") {
            return response({
                error: "Authentication required"
            }, 401);
        }

        return defaultHandler(url);
    });

    await env.flush();

    assert.equal(
        env.el("day25-api-status").textContent,
        "ERROR"
    );

    assert.match(
        env.el("day25-feedback").textContent,
        /Authentication required/
    );

    env.dom.window.close();
});

test("Day25 handles empty incident lists", async () => {
    const env = createEnvironment(url => {
        if (url === "/api/day25/incidents") {
            return response({incidents: []});
        }

        return defaultHandler(url);
    });

    await env.flush();

    assert.equal(env.el("day25-total").textContent, "0");

    assert.match(
        env.el("day25-incidents-body").textContent,
        /No incident cases recorded/
    );

    env.dom.window.close();
});

test("Day25 uses same-origin credentials", async () => {
    const env = createEnvironment(defaultHandler);

    await env.flush();

    assert.ok(env.calls.length > 0);

    for (const call of env.calls) {
        assert.equal(
            call.options.credentials,
            "same-origin"
        );
    }

    env.dom.window.close();
});

test("Day25 disables actions without a selected incident", async () => {
    const env = createEnvironment(defaultHandler);

    await env.flush();

    assert.equal(
        env.el("day25-update-status").disabled,
        true
    );

    assert.equal(
        env.el("day25-update-verdict").disabled,
        true
    );

    assert.equal(
        env.el("day25-add-evidence").disabled,
        true
    );

    env.dom.window.close();
});

test("Day25 changes incident status with CSRF", async () => {
    const env = createEnvironment((url, options) => {
        if (url.endsWith("/status") && options.method === "POST") {
            return response({
                incident: {...INCIDENT, status: "INVESTIGATING"}
            });
        }
        return defaultHandler(url);
    });

    await env.flush();

    env.el("day25-case-select").value = INCIDENT.case_id;
    env.el("day25-case-select").dispatchEvent(
        new env.dom.window.Event("change")
    );
    await env.flush();

    env.el("day25-note").value = "Starting investigation";
    env.el("day25-update-status").click();
    await env.flush();

    const post = env.calls.find(
        call => call.url.endsWith("/status") &&
                call.options.method === "POST"
    );

    assert.ok(post);
    assert.equal(
        post.options.headers["X-CSRF-Token"],
        "synthetic-csrf"
    );
    assert.deepEqual(JSON.parse(post.options.body), {
        status: "INVESTIGATING",
        note: "Starting investigation"
    });

    env.dom.window.close();
});

test("Day25 changes incident verdict with justification", async () => {
    const env = createEnvironment((url, options) => {
        if (url.endsWith("/verdict") && options.method === "POST") {
            return response({
                incident: {...INCIDENT, verdict: "TRUE_POSITIVE"}
            });
        }
        return defaultHandler(url);
    });

    await env.flush();

    env.el("day25-case-select").value = INCIDENT.case_id;
    env.el("day25-case-select").dispatchEvent(
        new env.dom.window.Event("change")
    );
    await env.flush();

    env.el("day25-note").value = "Evidence reviewed";
    env.el("day25-update-verdict").click();
    await env.flush();

    const post = env.calls.find(
        call => call.url.endsWith("/verdict") &&
                call.options.method === "POST"
    );

    assert.ok(post);
    assert.equal(
        JSON.parse(post.options.body).verdict,
        "TRUE_POSITIVE"
    );
    assert.equal(
        JSON.parse(post.options.body).note,
        "Evidence reviewed"
    );

    env.dom.window.close();
});

test("Day25 submits evidence with correct source and CSRF", async () => {
    const env = createEnvironment((url, options) => {
        if (url.endsWith("/evidence") &&
            options.method === "POST") {
            return response({
                status: "OK",
                message: "Evidence attached"
            }, 201);
        }
        return defaultHandler(url);
    });

    await env.flush();

    env.el("day25-case-select").value = INCIDENT.case_id;
    env.el("day25-case-select").dispatchEvent(
        new env.dom.window.Event("change")
    );
    await env.flush();

    env.el("day25-evidence-type").value = "IOC_ALERT";
    env.el("day25-evidence-reference").value = ALERT.alert_id;
    env.el("day25-evidence-description").value = "Verified IOC";

    env.el("day25-add-evidence").click();
    await env.flush();

    const post = env.calls.find(
        call => call.url.endsWith("/evidence") &&
                call.options.method === "POST"
    );

    assert.ok(post);

    const payload = JSON.parse(post.options.body);

    assert.equal(payload.evidence_type, "IOC_ALERT");
    assert.equal(payload.source, "DAY22");
    assert.equal(payload.reference_id, ALERT.alert_id);
    assert.equal(
        post.options.headers["X-CSRF-Token"],
        "synthetic-csrf"
    );

    env.dom.window.close();
});

test("Day25 displays evidence and audit safely", async () => {
    const env = createEnvironment(url => {
        if (url.endsWith("/evidence")) {
            return response({
                evidence: [{
                    evidence_type: "IOC_ALERT",
                    source: "DAY22",
                    reference_id: ALERT.alert_id,
                    description: "<img src=x onerror=alert(1)>",
                    added_by: "test_analyst",
                    created_at: "2026-11-03"
                }]
            });
        }

        if (url.endsWith("/audit")) {
            return response({
                audit: [{
                    action: "CASE_CREATED",
                    analyst: "test_analyst",
                    previous_status: null,
                    new_status: "OPEN",
                    note: "<script>alert(1)</script>",
                    created_at: "2026-11-03"
                }]
            });
        }

        return defaultHandler(url);
    });

    await env.flush();

    env.el("day25-case-select").value = INCIDENT.case_id;
    env.el("day25-case-select").dispatchEvent(
        new env.dom.window.Event("change")
    );
    await env.flush();

    assert.match(
        env.el("day25-evidence-list").textContent,
        /ALT-TEST-001/
    );
    assert.match(
        env.el("day25-audit-list").textContent,
        /CASE_CREATED/
    );

    assert.equal(
        env.el("day25-evidence-list").querySelector("img"),
        null
    );
    assert.equal(
        env.el("day25-audit-list").querySelector("script"),
        null
    );

    env.dom.window.close();
});

test("Day25 ignores stale evidence responses", async () => {
    const second = {
        ...INCIDENT,
        case_id: "INC-TEST-002"
    };

    let releaseFirst;
    const delayedFirst = new Promise(resolve => {
        releaseFirst = resolve;
    });

    const env = createEnvironment(url => {
        if (url === "/api/day25/incidents") {
            return response({
                incidents: [INCIDENT, second]
            });
        }

        if (url.includes("INC-TEST-001/evidence")) {
            return delayedFirst;
        }

        if (url.includes("INC-TEST-002/evidence")) {
            return response({
                evidence: [{
                    evidence_type: "IOC_ALERT",
                    source: "DAY22",
                    reference_id: "ALT-SECOND",
                    description: "Second case evidence"
                }]
            });
        }

        return defaultHandler(url);
    });

    await env.flush();

    const select = env.el("day25-case-select");

    select.value = INCIDENT.case_id;
    select.dispatchEvent(
        new env.dom.window.Event("change")
    );

    await env.flush();

    select.value = second.case_id;
    select.dispatchEvent(
        new env.dom.window.Event("change")
    );

    await env.flush();

    releaseFirst(response({
        evidence: [{
            reference_id: "ALT-FIRST",
            description: "Stale evidence"
        }]
    }));

    await env.flush();

    assert.match(
        env.el("day25-evidence-list").textContent,
        /ALT-SECOND/
    );

    assert.doesNotMatch(
        env.el("day25-evidence-list").textContent,
        /ALT-FIRST/
    );

    env.dom.window.close();
});

test("Day25 reports API service errors", async () => {
    const env = createEnvironment(url => {
        if (url === "/api/day25/incidents") {
            return response({
                error: "Incident data unavailable"
            }, 503);
        }

        return defaultHandler(url);
    });

    await env.flush();

    assert.equal(
        env.el("day25-api-status").textContent,
        "ERROR"
    );

    assert.match(
        env.el("day25-feedback").textContent,
        /Incident data unavailable/
    );

    env.dom.window.close();
});
