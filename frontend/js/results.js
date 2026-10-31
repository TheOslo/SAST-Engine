import { elements } from "./dom.js";
import { highlightLines } from "./editor.js";

let hasResults = false;

function textSpan(value, className) {
  const span = document.createElement("span");
  span.className = className;
  span.textContent = String(value ?? "");
  return span;
}

function createLocationIcon() {
  const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  icon.setAttribute("viewBox", "0 0 16 16");
  icon.setAttribute("fill", "none");
  icon.setAttribute("aria-hidden", "true");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", "M3 3h10M3 6.5h10M3 10h6M3 13h6");
  path.setAttribute("stroke", "currentColor");
  path.setAttribute("stroke-width", "1.2");
  path.setAttribute("stroke-linecap", "round");
  icon.append(path);
  return icon;
}

export function createEmptyResults() {
  const empty = document.createElement("div");
  empty.className = "empty-results";
  const art = document.createElement("div");
  art.className = "empty-art";
  art.setAttribute("aria-hidden", "true");
  art.append(textSpan("{", "empty-bracket"), textSpan("✳", "empty-spark"), textSpan("}", "empty-bracket"));
  const heading = document.createElement("h3");
  heading.textContent = "Your results will appear here";
  const description = document.createElement("p");
  description.textContent = "Choose the CWEs you want to check, then run a scan to see source-to-sink paths.";
  empty.append(art, heading, description);
  return empty;
}

function noFindings() {
  const empty = document.createElement("div");
  empty.className = "empty-results no-findings";
  const art = document.createElement("div");
  art.className = "empty-art";
  art.setAttribute("aria-hidden", "true");
  art.append(textSpan("✓", "empty-spark"));
  const heading = document.createElement("h3");
  heading.textContent = "No matching flows found";
  const description = document.createElement("p");
  description.textContent = "The selected rules did not find a source-to-sink flow in this module.";
  empty.append(art, heading, description);
  return empty;
}

function createFindingGroup(title, items, type) {
  const group = document.createElement("section");
  group.className = "result-group";
  const heading = document.createElement("h3");
  heading.className = "result-group-heading";
  const label = document.createElement("span");
  label.textContent = title;
  const count = document.createElement("span");
  count.className = "group-count";
  count.textContent = `${items.length} ${items.length === 1 ? "item" : "items"}`;
  heading.append(label, count);
  const list = document.createElement("div");
  list.className = "finding-list";
  for (const item of items) list.append(createResultCard(item, type));
  group.append(heading, list);
  return group;
}

function createResultCard(item, type) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `finding-card finding-card-button${type === "custom" ? " custom-card" : ""}${type === "observation" ? " observation-card" : ""}`;
  const main = document.createElement("span");
  main.className = "finding-main";
  const top = document.createElement("span");
  top.className = "finding-topline";
  const badge = document.createElement("span");
  badge.className = "finding-cwe";
  badge.textContent = type === "cwe" ? `CWE-${item.cwe_id}` : type === "custom" ? "CUSTOM" : "TRACKED";
  top.append(badge);
  if (type === "cwe" && item.finding_kind === "route_heuristic") {
    const candidate = document.createElement("span");
    candidate.className = "heuristic-tag";
    candidate.textContent = "Heuristic candidate";
    top.append(candidate);
  } else {
    top.append(textSpan(item.variable_name || item.rule_name || "tainted flow", "finding-kind"));
  }
  const flow = document.createElement("span");
  flow.className = "finding-flow";
  if (type === "observation") {
    flow.append(textSpan(item.variable_name, "flow-sink"), textSpan(`assigned from ${item.source_expression || "input"}`, "flow-arrow"));
  } else if (type === "cwe" && item.finding_kind === "route_heuristic") {
    flow.append(textSpan(item.variable_name || "route", "flow-sink"));
  } else {
    flow.append(textSpan(item.source_expression || "request input", "flow-source"), textSpan("→", "flow-arrow"), textSpan(item.sink_expression || item.rule_name || "sink", "flow-sink"));
  }
  main.append(top, flow);
  if (Array.isArray(item.evidence) && item.evidence.length) main.append(textSpan(item.evidence.join(" · "), "finding-evidence"));
  if (Array.isArray(item.trace) && item.trace.length) {
    const trace = document.createElement("span");
    trace.className = "trace-list";
    for (const step of item.trace) trace.append(textSpan(step, "trace-step"));
    main.append(trace);
  }
  const location = type === "observation" ? item.line_number : type === "cwe" && item.finding_kind === "route_heuristic" ? item.location_line_number : item.sink_line_number;
  const locationBadge = document.createElement("span");
  locationBadge.className = "finding-location";
  locationBadge.append(createLocationIcon(), document.createTextNode(Number.isInteger(location) ? `Line ${location}` : "View flow"));
  button.append(main, locationBadge);
  button.setAttribute("aria-label", `${type === "cwe" ? `CWE-${item.cwe_id}` : type === "custom" ? "Custom finding" : "Tracked variable"}: ${item.variable_name || item.rule_name || "data flow"}, ${Number.isInteger(location) ? `line ${location}` : "select to view"}`);
  button.addEventListener("click", () => highlightResult(item, type));
  return button;
}

function createSourceGroup(sources) {
  const group = document.createElement("section");
  group.className = "result-group";
  const heading = document.createElement("h3");
  heading.className = "result-group-heading";
  heading.textContent = "Input sources observed";
  const list = document.createElement("div");
  list.className = "finding-list";
  for (const source of sources) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "finding-card finding-card-button";
    button.setAttribute("aria-label", `${source.expression}, line ${source.line_number}`);
    button.append(textSpan(`CWE-${source.cwe_id} · ${source.expression}`, "finding-flow"));
    const location = document.createElement("span");
    location.className = "finding-location";
    location.append(createLocationIcon(), document.createTextNode(`Line ${source.line_number}`));
    button.append(location);
    button.addEventListener("click", () => highlightLines([{ line: source.line_number, type: "source" }]));
    list.append(button);
  }
  group.append(heading, list);
  return group;
}

function highlightResult(item, type) {
  const lineTypes = new Map();
  const addLine = (line, kind) => {
    if (!Number.isInteger(line) || line < 1) return;
    const priority = { flow: 1, source: 2, route: 2, custom: 2, sink: 3 };
    if (!lineTypes.has(line) || priority[kind] > priority[lineTypes.get(line)]) lineTypes.set(line, kind);
  };
  for (const step of Array.isArray(item.trace) ? item.trace : []) {
    for (const match of String(step).matchAll(/\(line\s+(\d+)\)/g)) addLine(Number(match[1]), "flow");
  }
  if (type === "observation") {
    addLine(item.line_number, "custom");
    addLine(item.source_line_number, "source");
  } else if (type === "cwe" && item.finding_kind === "route_heuristic") addLine(item.location_line_number, "route");
  else {
    addLine(item.source_line_number, "source");
    addLine(item.sink_line_number, type === "custom" ? "custom" : "sink");
  }
  highlightLines([...lineTypes.entries()].map(([line, kind]) => ({ line, type: kind })));
}

function lineFromStep(step) {
  const match = String(step).match(/\(line\s+(\d+)\)/);
  return match ? Number(match[1]) : null;
}

function createGraphPath(item, kind, safe = false) {
  const path = document.createElement("article");
  path.className = `flow-graph-path${safe ? " is-sanitized" : " is-finding"}`;
  const heading = document.createElement("div");
  heading.className = "flow-graph-path-heading";
  const label = document.createElement("span");
  label.textContent = safe ? `CWE-${item.cwe_id} · sanitized path` : kind === "custom" ? "Custom sink finding" : `CWE-${item.cwe_id} · potential finding`;
  const status = document.createElement("span");
  status.className = "flow-graph-status";
  status.textContent = safe ? "TAINT STOPPED" : "REVIEW";
  heading.append(label, status);
  const nodes = document.createElement("div");
  nodes.className = "flow-graph-nodes";
  const trace = Array.isArray(item.trace) ? item.trace : [];
  const sourceLine = item.source_line_number;
  const sanitizerLine = item.sanitizer_line_number;
  const sinkLine = item.sink_line_number;
  const steps = trace.length ? trace : [
    `${item.source_expression || "request input"} (line ${sourceLine || "?"})`,
    `${safe ? item.sanitizer_expression : item.sink_expression} (line ${safe ? sanitizerLine : sinkLine})`,
  ];

  steps.forEach((step, index) => {
    const line = lineFromStep(step);
    const isLast = index === steps.length - 1;
    const nodeType = index === 0 ? "source" : safe && isLast ? "sanitizer" : !safe && isLast ? "sink" : "flow";
    const node = document.createElement("button");
    node.type = "button";
    node.className = `flow-graph-node node-${nodeType}`;
    node.disabled = !line;
    node.textContent = String(step).replace(/\s*\(line\s+\d+\)/, "");
    const lineLabel = document.createElement("small");
    lineLabel.textContent = line ? `Line ${line}` : "No line";
    node.append(lineLabel);
    node.setAttribute("aria-label", `${node.textContent}, ${line ? `line ${line}` : "no source line"}`);
    if (line) node.addEventListener("click", () => highlightLines([{ line, type: nodeType === "sanitizer" ? "custom" : nodeType }]));
    nodes.append(node);
    if (!isLast) {
      const connector = document.createElement("span");
      connector.className = "flow-graph-connector";
      connector.setAttribute("aria-hidden", "true");
      connector.textContent = "→";
      nodes.append(connector);
    }
  });
  if (safe) {
    const terminal = document.createElement("span");
    terminal.className = "flow-graph-terminal";
    terminal.textContent = "Taint stopped";
    nodes.append(document.createTextNode("→"), terminal);
  }
  path.append(heading, nodes);
  return path;
}

function createFlowGraph(findings, customFindings, sanitizedFlows) {
  const section = document.createElement("section");
  section.className = "flow-graph-section";
  section.setAttribute("aria-labelledby", "flow-graph-title");
  const heading = document.createElement("div");
  heading.className = "flow-graph-heading";
  const title = document.createElement("h3");
  title.id = "flow-graph-title";
  title.textContent = "Taint flow graph";
  const hint = document.createElement("p");
  hint.textContent = "Select a node to jump to its line in the editor.";
  heading.append(title, hint);
  const paths = document.createElement("div");
  paths.className = "flow-graph-list";
  const traceableFindings = findings.filter((item) => item.finding_kind !== "route_heuristic" && item.source_expression && item.sink_expression);
  for (const item of traceableFindings) paths.append(createGraphPath(item, "cwe"));
  for (const item of customFindings) paths.append(createGraphPath(item, "custom"));
  for (const item of sanitizedFlows) paths.append(createGraphPath(item, "cwe", true));
  if (!paths.childElementCount) {
    const empty = document.createElement("p");
    empty.className = "flow-graph-empty";
    empty.textContent = "No source-to-sink or sanitized flows were identified in this scan.";
    paths.append(empty);
  }
  section.append(heading, paths);
  return section;
}

export function renderResults(result) {
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const customFindings = Array.isArray(result.custom_findings) ? result.custom_findings : [];
  const observations = Array.isArray(result.custom_observations) ? result.custom_observations : [];
  const sanitizedFlows = Array.isArray(result.sanitized_flows) ? result.sanitized_flows : [];
  const sources = Array.isArray(result.sources) ? result.sources : [];
  const total = findings.length + customFindings.length;
  elements.resultsTitle.textContent = String(total);
  elements.resultMeta.hidden = false;
  elements.resultMeta.textContent = `${sources.length} sources · ${total} findings · ${observations.length} tracked variables`;
  elements.resultsContent.replaceChildren();
  elements.resultsContent.append(createFlowGraph(findings, customFindings, sanitizedFlows));
  if (!total && !observations.length && !sources.length) {
    elements.resultsContent.append(noFindings());
    hasResults = true;
    return;
  }
  const groups = document.createElement("div");
  groups.className = "results-groups";
  if (!total && !observations.length) groups.append(noFindings());
  if (findings.length) groups.append(createFindingGroup("CWE findings", findings, "cwe"));
  if (customFindings.length) groups.append(createFindingGroup("Custom sink findings", customFindings, "custom"));
  if (observations.length) groups.append(createFindingGroup("Tracked variable observations", observations, "observation"));
  if (sources.length) groups.append(createSourceGroup(sources));
  elements.resultsContent.append(groups);
  hasResults = true;
}

export function invalidateResults(setStatus) {
  if (!hasResults) return;
  hasResults = false;
  elements.resultsTitle.textContent = "—";
  elements.resultMeta.hidden = true;
  elements.resultsContent.replaceChildren(createEmptyResults());
  setStatus("Source or scan settings changed. Run a new scan to refresh results.");
}

export function resetResults() {
  hasResults = false;
  elements.resultsTitle.textContent = "—";
  elements.resultMeta.hidden = true;
  elements.resultsContent.replaceChildren(createEmptyResults());
}

export function renderError(message) {
  elements.resultsContent.replaceChildren();
  const error = document.createElement("div");
  error.className = "empty-results scan-error";
  const heading = document.createElement("h3");
  heading.textContent = "Scan could not complete";
  const description = document.createElement("p");
  description.textContent = message;
  error.append(heading, description);
  elements.resultsContent.append(error);
  elements.resultsTitle.textContent = "!";
  elements.resultMeta.hidden = true;
  hasResults = true;
}
