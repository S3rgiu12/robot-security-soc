"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("day28-case-id");
  const button = document.getElementById("day28-verify-button");
  const status = document.getElementById("day28-signature-status");
  const results = document.getElementById("day28-signature-results");
  const feedback = document.getElementById("day28-feedback");
  const apiStatus = document.getElementById("day28-api-status");

  if (!input || !button || !status || !results ||
      !feedback || !apiStatus) {
    return;
  }

  function updateVisualStates() {
    const value = status.textContent.trim();

    status.dataset.state =
      value === "SIGNED & VERIFIED" ? "success" :
      value === "VERIFYING..." ? "loading" :
      ["VERIFICATION FAILED", "INVALID CASE ID", "ERROR"].includes(value)
        ? "error" : "";

    feedback.dataset.state =
      value === "SIGNED & VERIFIED" ? "success" :
      ["VERIFICATION FAILED", "INVALID CASE ID", "ERROR"].includes(value)
        ? "error" : "";

    results.querySelectorAll("li").forEach(item => {
      const label = item.textContent.trim();
      item.dataset.state =
        label.startsWith("PASS —") ? "success" :
        label.startsWith("FAIL —") ? "error" : "";
    });
  }

  const visualObserver = new MutationObserver(updateVisualStates);
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

  function addLine(text, parent = results) {
    const p = document.createElement("p");
    p.textContent = text;
    parent.appendChild(p);
  }

  function showMessage(message) {
    results.replaceChildren();
    addLine(message);
  }

  button.addEventListener("click", async () => {
    const caseId = input.value.trim();

    if (!/^INC-[A-Za-z0-9_-]{1,64}$/.test(caseId)) {
      status.textContent = "INVALID CASE ID";
      feedback.textContent = "Enter a valid incident case ID.";
      apiStatus.textContent = "NOT REQUESTED";
      showMessage("Example: INC-CAC40C42F3254074");
      return;
    }

    button.disabled = true;
    status.textContent = "VERIFYING...";
    feedback.textContent = "";
    apiStatus.textContent = "CHECKING";
    showMessage("Verifying Ed25519 signature and SHA-256 integrity...");

    try {
      const response = await fetch(
        `/api/day28/incidents/${encodeURIComponent(caseId)}/signature`,
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

        if (response.status === 401) {
          showMessage("Authentication required. Please log in.");
        } else if (response.status === 403) {
          showMessage("Insufficient permissions.");
        } else {
          showMessage(data.error || "Unable to verify signed bundle.");
        }

        return;
      }

      if (
        data.case_id !== caseId ||
        !["VALID", "INVALID"].includes(data.signature_status) ||
        !["VALID", "INVALID"].includes(data.integrity_status) ||
        !["SIGNED & VERIFIED", "VERIFICATION FAILED"].includes(data.status) ||
        !data.files ||
        typeof data.files !== "object" ||
        Array.isArray(data.files) ||
        !Number.isInteger(data.verified_count) ||
        !Number.isInteger(data.total_files) ||
        data.total_files !== 3
      ) {
        throw new Error("Unexpected API response.");
      }

      status.textContent = data.status;
      results.replaceChildren();

      addLine(`Signature algorithm: ${data.signature_algorithm}`);
      addLine(`Signature: ${data.signature_status}`);
      addLine(`Hash algorithm: ${data.hash_algorithm}`);
      addLine(`Integrity: ${data.integrity_status}`);
      addLine(
        `Verified files: ${data.verified_count}/${data.total_files}`
      );

      const list = document.createElement("ul");

      for (const [filename, valid] of Object.entries(data.files)) {
        const item = document.createElement("li");
        item.textContent =
          `${valid === true ? "PASS" : "FAIL"} — ${filename}`;
        list.appendChild(item);
      }

      results.appendChild(list);

      feedback.textContent =
        data.status === "SIGNED & VERIFIED"
          ? "Digital signature and exported files verified successfully."
          : "Signature or integrity verification failed. Review the incident.";

    } catch (error) {
      status.textContent = "ERROR";
      apiStatus.textContent = "ERROR";
      showMessage("Unable to complete digital signature verification.");
      feedback.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  });
});
