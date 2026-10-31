import { elements, setScanStatus } from "./dom.js";
import { fetchCatalog } from "./api.js";

export const FALLBACK_CWES = [
  { cwe_id: 78, label: "OS command injection", name: "Improper Neutralization of Special Elements used in an OS Command" },
  { cwe_id: 79, label: "Cross-site scripting", name: "Improper Neutralization of Input During Web Page Generation" },
  { cwe_id: 89, label: "SQL injection", name: "Improper Neutralization of Special Elements used in an SQL Command" },
  { cwe_id: 352, label: "Cross-site request forgery", name: "Cross-Site Request Forgery" },
  { cwe_id: 787, label: "Out-of-bounds write", name: "Out-of-bounds Write" },
  { cwe_id: 862, label: "Missing authorization", name: "Missing Authorization" },
  { cwe_id: 918, label: "Server-side request forgery", name: "Server-Side Request Forgery" },
];

let selectedCwes = new Set([89]);

export function getSelectedCwes() { return [...selectedCwes]; }

export function initializeCatalog(invalidateResults) {
  const refresh = () => {
    elements.selectionCount.innerHTML = `${selectedCwes.size} <span>/ 4</span>`;
    elements.cweList.querySelectorAll(".cwe-option").forEach((label) => {
      const checkbox = label.querySelector("input");
      const selected = selectedCwes.has(Number(checkbox.value));
      const disabled = !selected && selectedCwes.size >= 4;
      checkbox.disabled = disabled;
      label.classList.toggle("is-selected", selected);
      label.classList.toggle("is-disabled", disabled);
    });
    elements.scanButton.disabled = selectedCwes.size === 0;
  };
  const render = (cwes) => {
    elements.cweList.replaceChildren();
    for (const cwe of [...cwes].sort((a, b) => Number(a.cwe_id) - Number(b.cwe_id))) {
      const id = Number(cwe.cwe_id);
      const bundled = FALLBACK_CWES.find((entry) => entry.cwe_id === id);
      if (!bundled) continue;
      const label = document.createElement("label");
      label.className = "cwe-option";
      label.dataset.cweId = String(id);
      label.title = cwe.name || bundled.name;
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = String(id);
      checkbox.checked = selectedCwes.has(id);
      checkbox.setAttribute("aria-label", `CWE-${id}: ${bundled.label}`);
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) {
          if (selectedCwes.size >= 4) {
            checkbox.checked = false;
            setScanStatus("Select no more than four CWEs per scan.", "error");
            return;
          }
          selectedCwes.add(id);
        } else selectedCwes.delete(id);
        invalidateResults();
        setScanStatus(selectedCwes.size ? "Ready when you are." : "Choose at least one CWE to scan.");
        refresh();
      });
      const copy = document.createElement("span");
      copy.className = "cwe-copy";
      const idLabel = document.createElement("span");
      idLabel.className = "cwe-id";
      idLabel.textContent = `CWE-${id}`;
      const name = document.createElement("span");
      name.className = "cwe-name";
      name.textContent = bundled.label;
      copy.append(idLabel, name);
      label.append(checkbox, copy);
      elements.cweList.append(label);
    }
    refresh();
  };
  void (async () => {
    try {
      const payload = await fetchCatalog();
      const cwes = Array.isArray(payload.cwes) ? payload.cwes : [];
      const allowed = new Set(FALLBACK_CWES.map((entry) => entry.cwe_id));
      const usable = cwes.filter((entry) => allowed.has(Number(entry.cwe_id)));
      const complete = usable.length === allowed.size && allowed.size === new Set(usable.map((entry) => Number(entry.cwe_id))).size;
      if (!complete) throw new Error("CWE catalog is incomplete");
      render(usable);
      elements.catalogWarning.hidden = true;
    } catch (_error) {
      render(FALLBACK_CWES);
      elements.catalogWarning.hidden = false;
    }
  })();
}
