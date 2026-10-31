import { elements } from "./dom.js";
import { getEditor } from "./editor.js";

function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const nextTheme = theme === "dark" ? "light" : "dark";
  elements.themeToggle.setAttribute("aria-label", `Switch to ${nextTheme} theme`);
  elements.themeToggle.title = `Switch to ${nextTheme} theme`;
  if (getEditor() && window.monaco) window.monaco.editor.setTheme(theme === "light" ? "vs" : "vs-dark");
  try { localStorage.setItem("sast-theme", theme); } catch (_error) { /* Storage can be unavailable. */ }
}

export function initializeTheme() {
  let preferred = "dark";
  try {
    const stored = localStorage.getItem("sast-theme");
    if (stored === "light" || stored === "dark") preferred = stored;
  } catch (_error) { /* Keep the default theme. */ }
  setTheme(preferred);
  elements.themeToggle.addEventListener("click", () => {
    setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
  });
}
