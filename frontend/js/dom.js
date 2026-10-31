export const elements = {
  catalogWarning: document.getElementById("catalog-warning"),
  cweList: document.getElementById("cwe-list"),
  selectionCount: document.getElementById("selection-count"),
  scanButton: document.getElementById("scan-button"),
  scanButtonLabel: document.querySelector(".scan-button-label"),
  scanStatus: document.getElementById("scan-status"),
  sourceFallback: document.getElementById("source-fallback"),
  monacoContainer: document.getElementById("monaco-editor"),
  editorWarning: document.getElementById("editor-warning"),
  uploadButton: document.getElementById("upload-button"),
  fileInput: document.getElementById("file-input"),
  fileLabel: document.getElementById("file-label"),
  clearButton: document.getElementById("clear-button"),
  editorPosition: document.getElementById("editor-position"),
  editorLines: document.getElementById("editor-lines"),
  customSinks: document.getElementById("custom-sinks"),
  trackedVariables: document.getElementById("tracked-variables"),
  resultsContent: document.getElementById("results-content"),
  resultsTitle: document.getElementById("result-total"),
  resultMeta: document.getElementById("result-meta"),
  connectionStatus: document.getElementById("connection-status"),
  connectionLabel: document.getElementById("connection-label"),
  themeToggle: document.getElementById("theme-toggle"),
};

export const DEFAULT_SOURCE = `from flask import request


def find_user(cursor):
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(query)
`;

export function setScanStatus(message, kind = "") {
  elements.scanStatus.textContent = message;
  elements.scanStatus.classList.toggle("is-error", kind === "error");
  elements.scanStatus.classList.toggle("is-success", kind === "success");
}

export function readLines(text) {
  return text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}
