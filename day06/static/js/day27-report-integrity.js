"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("day27-case-id");
  const button = document.getElementById("day27-verify-button");
  const status = document.getElementById("day27-integrity-status");
  const results = document.getElementById("day27-integrity-results");
  const feedback = document.getElementById("day27-feedback");
  const apiStatus = document.getElementById("day27-api-status");

  if (!input || !button || !status || !results ||
      !feedback || !apiStatus) {
    return;
  }

  function updateVisualStates() {
    const value = status.textContent.trim();

    status.dataset.state =
      value === "VALID" ? "success" :
      value === "VERIFYING..." ? "loading" :
      ["TAMPERED", "VERIFICATION FAILED",
       "INVALID CASE ID", "ERROR"].includes(value)
        ? "error" : "";

    feedback.dataset.state =
      value === "VALID" ? "success" :
      ["TAMPERED", "VERIFICATION FAILED",
       "INVALID CASE ID", "ERROR"].includes(value)
        ? "error" : "";

    results.querySelectorAll("li").forEach(item => {
      const label = item.textContent.trim();

      item.dataset.state =
        label.startsWith("PASS —") ? "success" :
        label.startsWith("FAIL —") ? "error" : "";
    });
  }

  const visualObserver = new MutationObserver(
    updateVisualStates
  );

  visualObserver.observe(status, {
    childList: true,
    characterData: true,
    subtree: true
  });

  visualObserver.observe(results, {
    childList: true,
    subtree: true
  });

  visualObserver.observe(feedback, {
    childList: true,
    characterData: true,
    subtree: true
  });

  updateVisualStates();

  function showMessage(message) {
    results.replaceChildren();
    const p = document.createElement("p");
    p.textContent = message;
    results.appendChild(p);
  }

  button.addEventListener("click", async () => {
    const caseId = input.value.trim();

    if (!/^INC-[A-Za-z0-9_-]{1,64}$/.test(caseId)) {
      status.textContent = "INVALID CASE ID";
      feedback.textContent = "Use a valid incident ID.";
      apiStatus.textContent = "NOT REQUESTED";
      showMessage("Example: INC-CAC40C42F3254074");
      return;
    }

    button.disabled = true;
    status.textContent = "VERIFYING...";
    feedback.textContent = "";
    apiStatus.textContent = "CHECKING";
    showMessage("Checking SHA-256 integrity...");

    try {
      const response = await fetch(
        `/api/day27/incidents/${encodeURIComponent(caseId)}/integrity`,
        {
          method: "GET",
          credentials: "same-origin",
          cache: "no-store",
          headers: { "Accept": "application/json" }
        }
      );

      apiStatus.textContent = `HTTP ${response.status}`;

      const data = await response.json();

      if (!response.ok) {
        status.textContent = "VERIFICATION FAILED";
        showMessage(data.error || "Unable to verify incident.");
        return;
      }

      if (data.case_id !== caseId ||
          !["VALID", "TAMPERED"].includes(data.status) ||
          !data.files || typeof data.files !== "object") {
        throw new Error("Unexpected API response.");
      }

      status.textContent = data.status;
      results.replaceChildren();

      const summary = document.createElement("p");
      summary.textContent =
        `Verified files: ${data.verified_count}/${data.total_files}`;
      results.appendChild(summary);

      const list = document.createElement("ul");

      for (const [filename, valid] of Object.entries(data.files)) {
        const item = document.createElement("li");
        item.textContent =
          `${valid === true ? "PASS" : "FAIL"} — ${filename}`;
        list.appendChild(item);
      }

      results.appendChild(list);

      feedback.textContent = data.status === "VALID"
        ? "All exported files match the SHA-256 manifest."
        : "Integrity mismatch detected. Review the incident bundle.";

    } catch (error) {
      status.textContent = "ERROR";
      apiStatus.textContent = "ERROR";
      showMessage("Unable to complete verification.");
      feedback.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  });
});
