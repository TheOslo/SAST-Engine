export async function fetchCatalog() {
  const response = await fetch("/api/cwes", { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error("CWE catalog request failed");
  return response.json();
}

export async function checkHealth(elements) {
  try {
    const response = await fetch("/health", { headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error("API unavailable");
    elements.connectionStatus.classList.add("is-online");
    elements.connectionStatus.classList.remove("is-offline");
    elements.connectionLabel.textContent = "Analyzer online";
  } catch (_error) {
    elements.connectionStatus.classList.add("is-offline");
    elements.connectionStatus.classList.remove("is-online");
    elements.connectionLabel.textContent = "Analyzer unreachable";
  }
}

export async function submitScan(payload) {
  const response = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(payload),
  });
  let result;
  try {
    result = await response.json();
  } catch (_error) {
    throw new Error(`Analyzer returned an unreadable response (${response.status}).`);
  }
  if (!response.ok) throw new Error(result?.error?.message || `Scan failed (${response.status}).`);
  return result;
}
