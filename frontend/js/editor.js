import { elements, DEFAULT_SOURCE } from "./dom.js";

const MONACO_BASE = "https://cdn.jsdelivr.net/npm/monaco-editor@0.52.2/min";
let editor = null;
let decorations = [];
let onChange = () => {};

export function getEditor() { return editor; }
export function getSource() { return editor ? editor.getValue() : elements.sourceFallback.value; }

export function setSource(value) {
  if (editor) editor.setValue(value);
  else elements.sourceFallback.value = value;
  updateEditorStats();
  if (!editor) onChange();
}

export function sourceLineCount() { return getSource().split("\n").length; }

export function updateEditorStats(position) {
  const lineCount = sourceLineCount();
  elements.editorLines.textContent = `${lineCount} ${lineCount === 1 ? "line" : "lines"}`;
  if (position) elements.editorPosition.textContent = `Ln ${position.lineNumber}, Col ${position.column}`;
}

export function clearDecorations() {
  if (editor && decorations.length) decorations = editor.deltaDecorations(decorations, []);
}

export function highlightLines(lines) {
  if (!lines.length) return;
  if (editor) {
    const maxLine = editor.getModel().getLineCount();
    const next = lines.filter((item) => item.line <= maxLine).map((item) => ({
      range: new window.monaco.Range(item.line, 1, item.line, 1),
      options: {
        isWholeLine: true,
        className: `sast-line-${item.type}`,
        glyphMarginClassName: `sast-glyph-${item.type}`,
        overviewRuler: { color: lineColor(item.type), position: window.monaco.editor.OverviewRulerLane.Right },
      },
    }));
    decorations = editor.deltaDecorations(decorations, next);
    const focusLine = lines.find((item) => item.type === "sink")?.line
      || lines.find((item) => item.type === "custom")?.line
      || lines.find((item) => item.type === "route")?.line || lines[0].line;
    if (focusLine <= maxLine) {
      editor.revealLineInCenter(focusLine);
      editor.setPosition({ lineNumber: focusLine, column: 1 });
      editor.focus();
    }
    return;
  }
  const line = Math.min(Math.max(lines[0].line, 1), sourceLineCount());
  const source = elements.sourceFallback.value;
  const start = source.split("\n").slice(0, line - 1).join("\n").length + (line > 1 ? 1 : 0);
  const end = source.indexOf("\n", start);
  elements.sourceFallback.focus();
  elements.sourceFallback.setSelectionRange(start, end === -1 ? source.length : end);
}

function lineColor(type) {
  return ({ source: "#e9b968", flow: "#73d6ad", sink: "#ff727b", route: "#e9b968", custom: "#82b9ef" })[type] || "#73d6ad";
}

function showFallbackEditor() {
  elements.monacoContainer.hidden = true;
  elements.sourceFallback.hidden = false;
  elements.editorWarning.hidden = false;
  if (!elements.sourceFallback.value) elements.sourceFallback.value = DEFAULT_SOURCE;
  elements.sourceFallback.addEventListener("input", () => { updateEditorStats(); onChange(); });
  const updateCursor = () => {
    const lines = elements.sourceFallback.value.slice(0, elements.sourceFallback.selectionStart).split("\n");
    updateEditorStats({ lineNumber: lines.length, column: lines.at(-1).length + 1 });
  };
  elements.sourceFallback.addEventListener("keyup", updateCursor);
  elements.sourceFallback.addEventListener("click", updateCursor);
  updateEditorStats();
}

export function initializeEditor(onSourceChange) {
  onChange = onSourceChange;
  elements.sourceFallback.value = DEFAULT_SOURCE;
  if (typeof window.require !== "function") { showFallbackEditor(); return; }
  window.MonacoEnvironment = { getWorkerUrl: () => "/assets/monaco-worker.js" };
  window.require.config({ paths: { vs: `${MONACO_BASE}/vs` } });
  window.require(["vs/editor/editor.main"], () => {
    editor = window.monaco.editor.create(elements.monacoContainer, {
      value: elements.sourceFallback.value,
      language: "python",
      theme: document.documentElement.dataset.theme === "light" ? "vs" : "vs-dark",
      automaticLayout: true,
      minimap: { enabled: false },
      scrollBeyondLastLine: false,
      roundedSelection: false,
      renderLineHighlight: "line",
      fontFamily: "DM Mono, Consolas, monospace",
      fontSize: 12,
      lineHeight: 20,
      tabSize: 4,
      padding: { top: 13, bottom: 13 },
      guides: { indentation: true },
      scrollbar: { verticalScrollbarSize: 9, horizontalScrollbarSize: 9 },
      accessibilitySupport: "auto",
    });
    elements.monacoContainer.hidden = false;
    elements.sourceFallback.hidden = true;
    editor.onDidChangeModelContent(() => { updateEditorStats(editor.getPosition()); onChange(); });
    editor.onDidChangeCursorPosition((event) => updateEditorStats(event.position));
    updateEditorStats(editor.getPosition());
  }, showFallbackEditor);
}
