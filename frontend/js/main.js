import { elements, setScanStatus, readLines } from "./dom.js";
import { initializeEditor, getSource, setSource, clearDecorations, updateEditorStats, getEditor } from "./editor.js";
import { initializeCatalog, getSelectedCwes } from "./catalog.js";
import { checkHealth, submitScan } from "./api.js";
import { createEmptyResults, renderResults, renderError, invalidateResults, resetResults } from "./results.js";
import { initializeTheme } from "./theme.js";

let codeRevision = 0;

function markSourceChanged() {
  codeRevision += 1;
  clearDecorations();
  invalidateResults(setScanStatus);
}

function setScanning(scanning) {
  const selected = getSelectedCwes();
  elements.scanButton.disabled = scanning || selected.length === 0;
  elements.scanButton.setAttribute("aria-busy", String(scanning));
  elements.cweList.querySelectorAll("input").forEach((input) => { input.disabled = scanning || (!input.checked && selected.length >= 4); });
  elements.customSinks.disabled = scanning;
  elements.trackedVariables.disabled = scanning;
  elements.uploadButton.disabled = scanning;
  elements.clearButton.disabled = scanning;
  if (getEditor()) getEditor().updateOptions({ readOnly: scanning });
  else elements.sourceFallback.readOnly = scanning;
  if (scanning) {
    elements.scanButtonLabel.textContent = "Scanning source";
    const spinner = document.createElement("span");
    spinner.className = "spinner";
    spinner.setAttribute("aria-hidden", "true");
    elements.scanButton.replaceChildren(spinner, elements.scanButtonLabel);
  } else {
    elements.scanButtonLabel.textContent = "Run security scan";
    const arrow = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    arrow.setAttribute("viewBox", "0 0 20 20");
    arrow.setAttribute("fill", "none");
    arrow.setAttribute("aria-hidden", "true");
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", "M4 10h11m0 0-4-4m4 4-4 4");
    path.setAttribute("stroke", "currentColor");
    path.setAttribute("stroke-width", "1.6");
    path.setAttribute("stroke-linecap", "round");
    path.setAttribute("stroke-linejoin", "round");
    arrow.append(path);
    elements.scanButton.replaceChildren(elements.scanButtonLabel, arrow);
  }
}

async function runScan() {
  const sourceCode = getSource();
  const selectedCwes = getSelectedCwes();
  if (!sourceCode.trim()) { setScanStatus("Add Python source code before scanning.", "error"); return; }
  if (!selectedCwes.length) { setScanStatus("Choose at least one CWE to scan.", "error"); return; }
  const requestRevision = codeRevision;
  const payload = {
    source_code: sourceCode,
    cwe_ids: selectedCwes.sort((a, b) => a - b),
    custom_instructions: { sinks: readLines(elements.customSinks.value), tracked_variables: readLines(elements.trackedVariables.value) },
  };
  setScanning(true);
  setScanStatus("Parsing source and tracing selected flows…");
  clearDecorations();
  try {
    const result = await submitScan(payload);
    if (requestRevision !== codeRevision) {
      setScanStatus("Source changed during the scan. Run it again to refresh results.", "error");
      return;
    }
    renderResults(result);
    setScanStatus("Scan complete.", "success");
  } catch (error) {
    setScanStatus(error instanceof TypeError ? "Could not reach the analyzer. Check that the backend is running." : error.message, "error");
    renderError(error.message);
  } finally {
    setScanning(false);
  }
}

function initializeFileControls() {
  elements.uploadButton.addEventListener("click", () => elements.fileInput.click());
  elements.fileInput.addEventListener("change", async () => {
    const file = elements.fileInput.files?.[0];
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".py")) {
      setScanStatus("Choose a Python .py file.", "error");
      elements.fileInput.value = "";
      return;
    }
    if (file.size > 1024 * 1024) {
      setScanStatus("That file exceeds the 1 MB limit.", "error");
      elements.fileInput.value = "";
      return;
    }
    try {
      setSource(await file.text());
      elements.fileLabel.textContent = `${file.name} · local file`;
      setScanStatus(`Loaded ${file.name}.`, "success");
    } catch (_error) {
      setScanStatus("The selected file could not be read.", "error");
    } finally { elements.fileInput.value = ""; }
  });
  elements.clearButton.addEventListener("click", () => {
    setSource("");
    elements.fileLabel.textContent = "Python module · unsaved";
    clearDecorations();
    resetResults();
    setScanStatus("Editor cleared.");
  });
}

elements.scanButton.addEventListener("click", runScan);
elements.customSinks.addEventListener("input", markSourceChanged);
elements.trackedVariables.addEventListener("input", markSourceChanged);
initializeTheme();
initializeFileControls();
initializeCatalog(markSourceChanged);
initializeEditor(markSourceChanged);
updateEditorStats();
elements.resultsContent.replaceChildren(createEmptyResults());
void checkHealth(elements);
