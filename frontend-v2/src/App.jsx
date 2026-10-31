import React, { useEffect } from "react";
import { motion, useReducedMotion } from "motion/react";
import { Badge, Button, Card } from "./components/ui.jsx";
import { Reveal } from "./components/motion-primitives.jsx";

const cweDetails = [
  { id: "CWE-78", name: "OS command injection", description: "Untrusted input changes the command or arguments sent to an operating system.", mark: "$_", tone: "amber" },
  { id: "CWE-79", name: "Cross-site scripting", description: "Untrusted content reaches a web page without the escaping needed for its output context.", mark: "<>", tone: "coral" },
  { id: "CWE-89", name: "SQL injection", description: "Untrusted input changes the meaning of a database query instead of remaining data.", mark: "DB", tone: "coral" },
  { id: "CWE-352", name: "Cross-site request forgery", description: "A site accepts a state-changing request without enough evidence that the user intended it.", mark: "CS", tone: "blue" },
  { id: "CWE-787", name: "Out-of-bounds write", description: "A write operation can reach memory outside the intended buffer or object.", mark: "[]", tone: "amber" },
  { id: "CWE-862", name: "Missing authorization", description: "A sensitive action is available without checking whether the caller has permission.", mark: "ID", tone: "blue" },
  { id: "CWE-918", name: "Server-side request forgery", description: "A server uses a user-controlled URL to make requests to unintended destinations.", mark: "URL", tone: "blue" },
];

function ShieldMark() {
  return (
    <span className="brand-mark" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none"><path d="M12 2.8 20 6v5.1c0 5.1-3.3 8.4-8 10.1-4.7-1.7-8-5-8-10.1V6l8-3.2Z" stroke="currentColor" strokeWidth="1.7"/><path d="m8.5 12.2 2.2 2.2 4.9-5" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"/></svg>
    </span>
  );
}

function Header({ isScanner = false }) {
  useEffect(() => {
    if (isScanner) return;
    const toggle = document.getElementById("theme-toggle");
    let theme = "dark";
    try {
      const stored = localStorage.getItem("sast-theme");
      if (stored === "light" || stored === "dark") theme = stored;
    } catch { /* Keep the default theme when storage is unavailable. */ }
    document.documentElement.dataset.theme = theme;
    const onToggle = () => {
      theme = theme === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = theme;
      try { localStorage.setItem("sast-theme", theme); } catch { /* Theme still works for this page. */ }
    };
    toggle?.addEventListener("click", onToggle);
    return () => toggle?.removeEventListener("click", onToggle);
  }, [isScanner]);

  return (
    <header className="topbar site-header">
      <a className="brand" href="/" aria-label="SAST overview"><ShieldMark/><span className="brand-name">SAST<span className="brand-period">.</span></span></a>
      <nav className="site-nav" aria-label="Main navigation">
        {isScanner ? <a href="/" className="nav-try">Back to overview <span aria-hidden="true">&rarr;</span></a> : <><a href="#concepts">SAST &amp; CWE</a><a href="#taint">Taint flow</a><a href="#cwe-catalog">Seven CWEs</a><a href="/scanner" className="nav-try">Open scanner <span aria-hidden="true">&rarr;</span></a></>}
      </nav>
      <div className="topbar-right">
        {isScanner && <span className="connection-status" id="connection-status"><span className="status-dot" aria-hidden="true"/><span id="connection-label">Connecting to analyzer</span></span>}
        <button className="icon-button theme-toggle" id="theme-toggle" type="button" aria-label="Switch to light theme" title="Switch theme">
          <svg className="sun-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="3.8" stroke="currentColor" strokeWidth="1.6"/><path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"/></svg>
          <svg className="moon-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M20.2 15.1A8.6 8.6 0 0 1 8.9 3.8a8.8 8.8 0 1 0 11.3 11.3Z" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round"/></svg>
        </button>
      </div>
    </header>
  );
}

function Hero() {
  const reduceMotion = useReducedMotion();
  const fadeUp = (delay = 0) => reduceMotion ? { initial: false } : {
    initial: { opacity: 0, y: 12 },
    animate: { opacity: 1, y: 0 },
    transition: { duration: .5, delay },
  };
  return (
    <section className="landing-hero" id="top" aria-labelledby="hero-title">
      <div className="hero-glow" aria-hidden="true" />
      <div className="hero-copy">
        <motion.div className="hero-kicker" {...fadeUp()}>
          <span className="live-pulse"/> PYTHON SECURITY, MADE TRACEABLE
        </motion.div>
        <motion.h1 id="hero-title" {...fadeUp(.08)}>
          Catch the risky path<br/><span>before it ships.</span>
        </motion.h1>
        <motion.p className="hero-description" {...(reduceMotion ? { initial: false } : { initial: { opacity: 0 }, animate: { opacity: 1 }, transition: { duration: .55, delay: .2 } })}>
          Follow untrusted data through Python code. Find the source, see where it lands, and understand the weakness behind it.
        </motion.p>
        <motion.div className="hero-actions" {...fadeUp(.28)}>
          <Button onClick={() => window.location.assign("/scanner")}>Open the scanner <span aria-hidden="true">&rarr;</span></Button>
          <a className="text-link" href="#concepts">Understand SAST &amp; CWE <span aria-hidden="true">→</span></a>
        </motion.div>
        <div className="hero-proof"><span className="proof-lock" aria-hidden="true">⌑</span> Deterministic analysis <i/> No code stored <i/> Python &amp; Flask / Django</div>
      </div>
      <motion.div className="hero-visual" {...(reduceMotion ? { initial: false } : { initial: { opacity: 0, scale: .96, y: 8 }, animate: { opacity: 1, scale: 1, y: 0 }, transition: { duration: .7, delay: .14 } })}>
        <div className="visual-orbit orbit-one"/><div className="visual-orbit orbit-two"/>
        <img className="hero-wave" src="/assets/haikei-wave.svg" alt="" aria-hidden="true"/>
        <div className="flow-window">
          <div className="window-top"><span className="window-dots"><i/><i/><i/></span><span>users.py</span><span className="window-language">PY</span></div>
          <div className="code-line"><span className="line-no">12</span><code><span className="code-purple">name</span> = request.args.get(<span className="code-peach">"name"</span>)</code></div>
          <div className="code-line code-focus"><span className="line-no">13</span><code>query = <span className="code-peach">"SELECT ... "</span> + name</code></div>
          <div className="code-line"><span className="line-no">14</span><code>cursor.execute(query)</code></div>
          <div className="flow-connector"><span/><span/><span/></div>
          <div className="finding-chip"><span className="finding-alert">!</span><span><strong>Potential SQL injection</strong><small>CWE-89 · source → sink traced</small></span><span className="finding-arrow">↗</span></div>
        </div>
        <div className="visual-caption"><span className="caption-dot"/> Source to sink, in context</div>
      </motion.div>
      <a className="hero-scroll" href="#how-it-works"><span/> Scroll to explore</a>
    </section>
  );
}

function Explainer() {
  return (
    <section className="explainer-section" id="concepts" aria-labelledby="explainer-title">
      <Reveal className="section-heading">
        <div><div className="eyebrow"><span className="eyebrow-line"/> THE LANGUAGE OF CODE SECURITY</div><h2 id="explainer-title">Two ideas. One clearer<br/><span>security review.</span></h2></div>
        <p>Security findings are easier to act on when you can see both what the tool is doing and how it names the weakness.</p>
      </Reveal>
      <div className="concept-grid">
        <Reveal delay={.06}>
          <Card className="concept-card concept-sast">
            <div className="concept-top"><Badge>01 · THE METHOD</Badge><span className="concept-icon icon-sast" aria-hidden="true">⌘</span></div>
            <h3>What is SAST?</h3>
            <p><strong>Static Application Security Testing</strong> examines source code for security risks without running the application. This scanner follows potentially untrusted input through Python code and reports paths that reach sensitive operations.</p>
            <div className="concept-foot"><span className="mini-spark"/> Read code. Trace flow. Review early.</div>
          </Card>
        </Reveal>
        <Reveal delay={.14}>
          <Card className="concept-card concept-cwe">
            <div className="concept-top"><Badge>02 · THE CLASSIFICATION</Badge><span className="concept-icon icon-cwe" aria-hidden="true">#</span></div>
            <h3>What is CWE?</h3>
            <p><strong>Common Weakness Enumeration</strong> is a shared catalog for describing software weakness types. A CWE identifier gives a finding a consistent name, so teams can discuss, prioritize, and track similar issues.</p>
            <div className="concept-foot"><span className="mini-spark"/> A shared vocabulary for weaknesses.</div>
          </Card>
        </Reveal>
      </div>
      <Reveal className="relationship-note" delay={.18}>
        <span className="relationship-icon" aria-hidden="true">↗</span>
        <p><strong>How they work together</strong><br/>SAST describes the testing approach; CWE labels the kind of weakness a finding may represent. This scanner checks selected weakness categories and shows the code path behind each result.</p>
      </Reveal>
    </section>
  );
}


function TaintGuide() {
  return (
    <section className="taint-section" id="taint" aria-labelledby="taint-title">
      <div className="section-heading">
        <div><div className="eyebrow"><span className="eyebrow-line"/> HOW DATA MOVES</div><h2 id="taint-title">Understand the <span>flow.</span></h2></div>
        <p>Taint tracking follows data from where it enters to the operation that uses it, while checking whether a recognized sanitizer changes the risk.</p>
      </div>
      <div className="taint-grid">
        <Card className="taint-card source-card"><span className="flow-label">SOURCE</span><h3>Where data enters</h3><p>A source is input that may be controlled by someone outside the program, such as a request parameter or form field.</p></Card>
        <Card className="taint-card taint-card-main"><span className="flow-label">TAINT</span><h3>The data&apos;s risk label</h3><p>Taint is a marker the analyzer attaches to untrusted data. It follows assignments and transformations so the analyzer can see where that data travels.</p></Card>
        <Card className="taint-card sanitizer-card"><span className="flow-label">SANITIZER</span><h3>A recognized safety step</h3><p>A sanitizer safely encodes or validates data for a particular use. Recognition depends on the weakness and context; a function name alone is not a universal guarantee.</p></Card>
        <Card className="taint-card sink-card"><span className="flow-label">SINK</span><h3>Where data is used</h3><p>A sink is a sensitive operation, such as executing a SQL query, building a shell command, or rendering HTML. Unchecked tainted data reaching a sink may be reported.</p></Card>
      </div>
      <div className="taint-example" aria-label="Example taint flow from input through analysis">
        <span className="flow-node source-node">request input</span><span className="flow-arrow">&rarr;</span><span className="flow-node">tainted value</span><span className="flow-arrow">&rarr;</span><span className="flow-node sanitizer-node">recognized sanitizer</span><span className="flow-arrow">&rarr;</span><span className="flow-node sink-node">sensitive sink</span>
      </div>
    </section>
  );
}

function CweCatalog() {
  return (
    <section className="cwe-catalog" id="cwe-catalog" aria-labelledby="cwe-catalog-title">
      <div className="section-heading"><div><div className="eyebrow"><span className="eyebrow-line"/> THE AVAILABLE CHECKS</div><h2 id="cwe-catalog-title">Seven weakness <span>classes.</span></h2></div><p>Choose up to four categories for each scan. The analyzer reports potential issues for review.</p></div>
      <div className="cwe-catalog-grid">{cweDetails.map((item) => <Card className={`cwe-detail-card ${item.tone}`} key={item.id}><span className="cwe-detail-mark" aria-hidden="true">{item.mark}</span><span className="cwe-detail-id">{item.id}</span><h3>{item.name}</h3><p>{item.description}</p></Card>)}</div>
    </section>
  );
}

function Process() {
  return (
    <section className="process-section" id="how-it-works" aria-labelledby="process-title">
      <Reveal className="process-heading"><div className="eyebrow"><span className="eyebrow-line"/> FROM INPUT TO INSIGHT</div><h2 id="process-title">Follow the flow,<br/><span>not just the alert.</span></h2><p>A useful finding shows how data moved, where it ended up, and which weakness rule matched.</p></Reveal>
      <div className="process-steps">
        <Reveal delay={.04}><div className="process-step"><span className="process-index">01</span><div className="process-icon icon-source" aria-hidden="true">{ }</div><h3>Untrusted input</h3><p>Identify data entering through request parameters, forms, and other recognized sources.</p></div></Reveal>
        <div className="process-link" aria-hidden="true"><span/></div>
        <Reveal delay={.12}><div className="process-step"><span className="process-index">02</span><div className="process-icon icon-trace" aria-hidden="true">⌁</div><h3>Trace the path</h3><p>Follow assignments and branches to see whether input reaches a sensitive operation.</p></div></Reveal>
        <div className="process-link" aria-hidden="true"><span/></div>
        <Reveal delay={.2}><div className="process-step"><span className="process-index">03</span><div className="process-icon icon-finding" aria-hidden="true">✓</div><h3>Review the finding</h3><p>See the CWE category, source-to-sink path, and relevant lines in your code.</p></div></Reveal>
      </div>
    </section>
  );
}

function Scanner() {
  return (
    <section className="scanner-section" id="scanner" aria-labelledby="scanner-title">
      <div className="scanner-intro"><div><div className="eyebrow"><span className="eyebrow-line"/> YOUR CODE, YOUR CALL</div><h2 id="scanner-title">Put it to the test.</h2><p>Paste a Python module, choose the weaknesses to inspect, and trace what the analyzer finds.</p></div><div className="privacy-pill"><span/> In-memory analysis · source isn’t saved</div></div>
      <div className="catalog-warning" id="catalog-warning" role="status" hidden><span aria-hidden="true">!</span><span>Live CWE details are unavailable. Showing the bundled seven-CWE catalog; scans can still run.</span></div>
      <div className="editor-warning" id="editor-warning" role="status" hidden><span aria-hidden="true">!</span><span>Monaco could not load. You can still scan in the basic editor below.</span></div>
      <div className="workbench">
        <section className="panel code-panel" aria-labelledby="code-title">
          <div className="panel-header code-header"><div className="panel-title-group"><span className="step-index">01</span><div><h2 id="code-title">Source code</h2><p className="panel-subtitle" id="file-label">Python module · unsaved</p></div></div><div className="code-actions"><input id="file-input" className="visually-hidden" type="file" accept=".py,text/x-python,text/plain" tabIndex="-1" aria-hidden="true"/><button className="subtle-button" id="upload-button" type="button"><svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M10 13V3m0 0L6.5 6.5M10 3l3.5 3.5M4 12v4h12v-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>Open .py</button><button className="subtle-button clear-button" id="clear-button" type="button">Clear</button></div></div>
          <div className="editor-frame" id="editor-frame"><div className="editor-toolbar"><span className="language-label"><span className="python-badge">Py</span> Python 3</span><span className="editor-hint">Paste code or open a file</span></div><div id="monaco-editor" className="monaco-editor" aria-label="Python source code editor"/><textarea id="source-fallback" className="source-fallback" aria-label="Python source code editor" spellCheck="false" hidden/><div className="editor-footer"><span id="editor-position">Ln 1, Col 1</span><span id="editor-lines">1 line</span><span className="editor-footer-spacer"/><span>UTF-8</span><span>Spaces: 4</span></div></div>
          <div className="code-panel-bottom"><span className="privacy-note"><svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><rect x="3.2" y="7" width="9.6" height="7" rx="1.5" stroke="currentColor" strokeWidth="1.2"/><path d="M5.3 7V5a2.7 2.7 0 0 1 5.4 0v2" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/></svg> Code is analyzed in memory and isn’t saved.</span><span className="file-limit">.py files · up to 1 MB</span></div>
        </section>
        <aside className="settings-column">
          <section className="panel cwe-panel" aria-labelledby="cwe-title"><div className="panel-header compact-header"><div className="panel-title-group"><span className="step-index">02</span><div><h2 id="cwe-title">Choose weaknesses</h2><p className="panel-subtitle">Select up to four per scan</p></div></div><span className="selection-count" id="selection-count">1 <span>/ 4</span></span></div><div className="cwe-list" id="cwe-list" aria-describedby="cwe-help"><div className="loading-row"><span className="spinner small"/> Loading catalog…</div></div><p className="helper-text" id="cwe-help">Choose at least one class. CWE-89 is selected by default.</p></section>
          <details className="panel custom-panel" id="custom-panel"><summary className="panel-header compact-header"><div className="panel-title-group"><span className="step-index">03</span><div><h2>Custom rules</h2><p className="panel-subtitle">Optional · this scan only</p></div></div><span className="details-chevron" aria-hidden="true"/></summary><div className="custom-fields"><label htmlFor="custom-sinks">Dangerous function names</label><textarea id="custom-sinks" rows="2" placeholder={'internal.query\nrun_unsafe_sql'} spellCheck="false"/><p className="field-hint">One dotted Python call name per line. Tainted inputs reaching these calls are reported.</p><label htmlFor="tracked-variables">Variables to track</label><textarea id="tracked-variables" rows="2" placeholder={'user_input\nquery'} spellCheck="false"/><p className="field-hint">One variable name per line. Tainted assignments are returned as observations.</p></div></details>
          <div className="scan-action-wrap"><Button className="scan-button" id="scan-button" type="button"><span className="scan-button-label">Run security scan</span><svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M4 10h11m0 0-4-4m4 4-4 4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"/></svg></Button><p className="scan-status" id="scan-status" role="status" aria-live="polite">Ready when you are.</p></div>
        </aside>
      </div>
      <section className="results-section" id="results-section" aria-labelledby="results-title"><div className="results-heading"><div><div className="eyebrow"><span className="eyebrow-line"/> ANALYSIS OUTPUT</div><h2 id="results-title">Findings <span className="result-total" id="result-total">—</span></h2></div><div className="result-meta" id="result-meta" hidden/></div><div className="results-content" id="results-content" aria-live="polite"><div className="empty-results" id="empty-results"><div className="empty-art" aria-hidden="true"><span className="empty-bracket">{'{'}</span><span className="empty-spark">✳</span><span className="empty-bracket">{"}"}</span></div><h3>Your results will appear here</h3><p>Choose the CWEs you want to check, then run a scan to see source-to-sink paths.</p></div></div></section>
    </section>
  );
}

function SiteFooter({ isScanner = false }) {
  return (
    <footer className="page-footer">
      <span>SAST <span className="brand-period">&middot;</span> Deterministic Python analysis</span>
      <span>Built for careful code review</span>
      <Button onClick={() => window.location.assign(isScanner ? "/" : "/scanner")}>{isScanner ? "Back to overview" : "Open the scanner"} <span aria-hidden="true">&rarr;</span></Button>
    </footer>
  );
}

export default function App() {
  const isScanner = window.location.pathname.replace(/\/$/, "") === "/scanner";

  useEffect(() => {
    if (isScanner) void import("../../frontend/js/main.js");
  }, [isScanner]);

  return (
    <div className="app-shell">
      <Header isScanner={isScanner}/>
      {isScanner ? (
        <main className="scanner-main"><Scanner/></main>
      ) : (
        <main className="landing-main">
          <Hero/>
          <Explainer/>
          <TaintGuide/>
          <Process/>
          <CweCatalog/>
          <p className="analysis-limit"><span aria-hidden="true">&middot;</span> Static analysis can surface potential problems, but findings need engineering review. No finding is not a guarantee that code is secure.</p>
        </main>
      )}
      <SiteFooter isScanner={isScanner}/>
    </div>
  );
}
