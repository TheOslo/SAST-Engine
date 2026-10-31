/* Same-origin worker bootstrap for the CDN-hosted Monaco editor. */
self.MonacoEnvironment = {
  baseUrl: "https://cdn.jsdelivr.net/npm/monaco-editor@0.52.2/min",
};
self.importScripts(`${self.MonacoEnvironment.baseUrl}/vs/base/worker/workerMain.js`);
