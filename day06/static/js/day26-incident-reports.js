"use strict";

(() => {
  const API = "/api/day26/incidents";
  const CASES_API = "/api/day25/incidents";

  const $ = (id) => document.getElementById(id);

  const selector = $("day26-case-select");
  const preview = $("day26-report-preview");
  const feedback = $("day26-feedback");
  const status = $("day26-api-status");

  if (!selector || !preview || !feedback || !status) {
    return;
  }

  function message(text, isError = false) {
    feedback.textContent = text;
    feedback.style.color = isError ? "#f87171" : "";
  }

  function selectedCase() {
    const id = selector.value.trim();

    if (!/^INC-[A-Za-z0-9_-]{1,64}$/.test(id)) {
      message("Please select a valid incident.", true);
      return null;
    }

    return id;
  }

  async function request(url) {
    const response = await fetch(url, {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
      headers: {
        "Accept": "application/json, text/csv"
      }
    });

    if (!response.ok) {
      if (response.status === 401) {
        throw new Error("Authentication required.");
      }

      if (response.status === 403) {
        throw new Error("Insufficient permissions.");
      }

      if (response.status === 404) {
        throw new Error("Incident not found.");
      }

      throw new Error(`API error: HTTP ${response.status}`);
    }

    return response;
  }

  async function loadCases() {
    status.textContent = "LOADING";

    try {
      const response = await request(CASES_API);
      const payload = await response.json();

      const cases = Array.isArray(payload)
        ? payload
        : Array.isArray(payload.incidents)
          ? payload.incidents
          : Array.isArray(payload.cases)
            ? payload.cases
            : [];

      selector.replaceChildren(
        new Option("Select an incident...", "")
      );

      for (const incident of cases) {
        const id = incident.case_id;

        if (
          typeof id !== "string" ||
          !/^INC-[A-Za-z0-9_-]{1,64}$/.test(id)
        ) {
          continue;
        }

        const label = `${id} — ${incident.status || "UNKNOWN"}`;

        selector.add(new Option(label, id));
      }

      status.textContent = "ONLINE";

      if (cases.length === 0) {
        message("No incident cases available.");
      } else {
        message("Incident cases loaded.");
      }
    } catch (error) {
      status.textContent = "ERROR";
      message(error.message, true);
    }
  }

  async function generateReport() {
    const id = selectedCase();
    if (!id) return;

    message("Generating incident report...");

    try {
      const response = await request(
        `${API}/${encodeURIComponent(id)}/report`
      );

      const report = await response.json();

      preview.textContent = JSON.stringify(report, null, 2);
      message("Incident report generated successfully.");
    } catch (error) {
      message(error.message, true);
    }
  }

  async function downloadCSV(type) {
    const id = selectedCase();
    if (!id) return;

    try {
      message(`Preparing ${type} export...`);

      const response = await request(
        `${API}/${encodeURIComponent(id)}/${type}.csv`
      );

      const blob = await response.blob();
      const url = URL.createObjectURL(blob);

      const link = document.createElement("a");
      link.href = url;
      link.download = `${id}-${type}.csv`;

      document.body.appendChild(link);
      link.click();
      link.remove();

      URL.revokeObjectURL(url);

      message(`${type} CSV exported successfully.`);
    } catch (error) {
      message(error.message, true);
    }
  }

  $("day26-report-json")?.addEventListener(
    "click",
    generateReport
  );

  $("day26-evidence-csv")?.addEventListener(
    "click",
    () => downloadCSV("evidence")
  );

  $("day26-audit-csv")?.addEventListener(
    "click",
    () => downloadCSV("audit")
  );

  loadCases();
})();
