import { r as reactExports, T as jsxRuntimeExports } from "./worker-entry-Txo-XDQl.js";
import { u as useNavigate } from "./router-FrWqa7lY.js";
import "node:events";
import "node:async_hooks";
import "node:stream/web";
import "node:stream";
const GITHUB_REGEX = /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?\/?$/;
const NAV = [{
  label: "How it works",
  href: "#how"
}, {
  label: "Sample finding",
  href: "#sample"
}, {
  label: "Compliance",
  href: "#compliance"
}];
const STEPS = [{
  no: "01",
  title: "Scan",
  body: "Submit any public GitHub repository. SecurePath runs five passes: SAST via Semgrep, dependency CVE audit, secret detection, structural pattern analysis, and configuration review."
}, {
  no: "02",
  title: "Enrich",
  body: "Each finding receives AI enrichment: plain English explanation, business impact analysis, exploit scenario, asset exposure mapping, and three ranked remediation strategies."
}, {
  no: "03",
  title: "Evidence",
  body: "Download a structured PDF report with compliance control mapping, business impact data, and SHA-256 tamper verification. Built for engineering teams preparing audit evidence."
}];
const TERMINAL_LINES = ["> Cloning juice-shop/juice-shop...", "> Running SAST analysis (semgrep)...", "[████████░░] 78%", "■ CRITICAL: SQL injection in routes/vulnCodeSnippets.js:40", "■ CRITICAL: Hardcoded JWT secret in config/index.js:13", "■ HIGH: eval() usage in routes/angular.js:8", "> Enriching with AI analysis...", "> Business impact: $4.4M avg breach cost mapped", "> Asset exposure: 3 systems, external-facing scope", "> Generating compliance evidence PDF...", "✓ Complete. 23 findings. Risk score: 94/100"];
function Landing() {
  const [scrolled, setScrolled] = reactExports.useState(false);
  reactExports.useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, {
      passive: true
    });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-h-screen bg-background text-foreground", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(Nav, { scrolled }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(Hero, {}),
    /* @__PURE__ */ jsxRuntimeExports.jsx(StatsBar, {}),
    /* @__PURE__ */ jsxRuntimeExports.jsx(HowItWorks, {}),
    /* @__PURE__ */ jsxRuntimeExports.jsx(SampleFinding, {}),
    /* @__PURE__ */ jsxRuntimeExports.jsx(Compliance, {}),
    /* @__PURE__ */ jsxRuntimeExports.jsx(Footer, {})
  ] });
}
function Nav({
  scrolled
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("header", { className: `sticky top-0 z-50 transition-all duration-300 surface-obsidian border-b border-white/10 ${scrolled ? "shadow-elevated" : ""}`, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative mx-auto flex h-16 max-w-[1400px] items-center justify-between px-6 md:px-10", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("a", { href: "#", className: "flex items-center gap-2.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-1.5 w-1.5 rounded-full bg-white" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-display text-[15px] font-bold tracking-[0.18em] text-white", children: "SECUREPATH" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "hidden font-mono text-[10px] tracking-wider text-white/40 border border-white/15 px-2 py-0.5 rounded sm:inline", children: "v1.0.0" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("nav", { className: "hidden items-center gap-7 md:flex", children: NAV.map((n) => /* @__PURE__ */ jsxRuntimeExports.jsx("a", { href: n.href, className: "text-[12px] font-semibold tracking-wider uppercase text-white/60 transition-colors hover:text-white", children: n.label }, n.label)) })
    ] })
  ] }) });
}
function Hero() {
  const navigate = useNavigate();
  const [repoUrl, setRepoUrl] = reactExports.useState("");
  const [error, setError] = reactExports.useState("");
  const [submitting, setSubmitting] = reactExports.useState(false);
  async function onSubmit(e) {
    e.preventDefault();
    const url = repoUrl.trim();
    if (!GITHUB_REGEX.test(url)) {
      setError("Enter a valid public GitHub URL, e.g. https://github.com/juice-shop/juice-shop");
      return;
    }
    setError("");
    setSubmitting(true);
    try {
      const response = await fetch("/api/scan/start", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          repo_url: url
        })
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Failed to start scan");
      }
      navigate({
        to: "/scan/$scanId",
        params: {
          scanId: data.scan_id
        }
      });
    } catch (err) {
      setError(err.message);
      setSubmitting(false);
    }
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "relative grid min-h-[calc(100vh-64px)] border-b hairline lg:grid-cols-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col justify-center border-b hairline px-6 py-16 md:px-12 lg:border-b-0 lg:border-r lg:py-20", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-px w-8 bg-foreground" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-eyebrow text-foreground", children: "Security Assessment Platform" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("h1", { className: "font-display mt-6 text-[clamp(2.5rem,5.5vw,4.5rem)] font-bold leading-[1.02] tracking-[-0.025em]", children: [
        "Scan. Analyze.",
        /* @__PURE__ */ jsxRuntimeExports.jsx("br", {}),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "italic font-light text-ink-soft", children: "Generate evidence." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-6 max-w-md text-[15px] leading-relaxed text-ink-soft", children: "Five-pass security analysis with AI-enriched findings, business impact assessment, and compliance mapping. One scan produces audit-ready documentation." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { onSubmit, className: "relative mt-10 max-w-xl rounded-md border hairline bg-surface p-6 shadow-soft", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": true, className: "absolute inset-x-0 top-0 h-[3px] surface-obsidian rounded-t-md" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "repo_url", className: "text-eyebrow block", children: "GitHub Repository URL" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex overflow-hidden rounded-md border hairline bg-background", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("input", { id: "repo_url", name: "repo_url", type: "url", autoComplete: "off", spellCheck: false, required: true, value: repoUrl, onChange: (e) => setRepoUrl(e.target.value), placeholder: "https://github.com/juice-shop/juice-shop", className: "flex-1 bg-transparent px-4 py-3.5 font-mono text-[12px] text-foreground outline-none placeholder:text-ink-soft/60" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "submit", disabled: submitting, className: "surface-obsidian shrink-0 px-6 py-3.5 font-display text-[11px] font-bold tracking-[0.12em] uppercase text-white transition-opacity hover:opacity-90 disabled:opacity-50", children: submitting ? "Scanning…" : "Start Scan" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 min-h-[18px] font-mono text-[11px] text-destructive", children: error }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[12px] leading-relaxed text-ink-soft", children: "No signup required. Works with any public GitHub repository." }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1.5 flex items-center gap-2 text-[12px] text-ink-soft", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": true, children: " " }),
          "Repository is cloned locally and deleted after scan completes."
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex items-center justify-center bg-surface px-6 py-16 md:px-12 lg:py-20", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Terminal, {}) })
  ] });
}
function Terminal() {
  const [lines, setLines] = reactExports.useState([]);
  const bodyRef = reactExports.useRef(null);
  reactExports.useEffect(() => {
    let i = 0;
    let timeout;
    let cancelled = false;
    const tick = () => {
      if (cancelled) return;
      if (i >= TERMINAL_LINES.length) {
        timeout = setTimeout(() => {
          if (cancelled) return;
          i = 0;
          setLines([]);
          tick();
        }, 2800);
        return;
      }
      const next = TERMINAL_LINES[i];
      if (typeof next === "string") {
        setLines((prev) => [...prev, next]);
      }
      i++;
      timeout = setTimeout(tick, 520);
    };
    tick();
    return () => {
      cancelled = true;
      clearTimeout(timeout);
    };
  }, []);
  reactExports.useEffect(() => {
    if (bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
  }, [lines]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "surface-obsidian w-full max-w-[520px] rounded-lg overflow-hidden", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative flex items-center gap-1.5 border-b border-white/10 bg-white/[0.03] px-4 py-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-2.5 w-2.5 rounded-full bg-white/20" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-2.5 w-2.5 rounded-full bg-white/20" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-2.5 w-2.5 rounded-full bg-white/20" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-3 font-mono text-[11px] text-white/40", children: "securepath — scan output" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { ref: bodyRef, className: "relative font-mono text-[12px] leading-[1.9] px-6 py-5 h-[320px] overflow-y-auto", children: lines.map((l, idx) => {
      const safe = l ?? "";
      const isErr = safe.startsWith("■");
      const isOk = safe.startsWith("✓");
      const isCurrent = idx === lines.length - 1;
      return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: isErr ? "text-[oklch(0.65_0.18_25)]" : isOk ? "text-[oklch(0.78_0.14_150)]" : "text-white/70", children: [
        safe,
        isCurrent && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-1 inline-block h-3 w-[7px] align-middle bg-white/70 animate-pulse" })
      ] }, idx);
    }) })
  ] });
}
function StatsBar() {
  const items = ["OWASP Top 10 Coverage", "SOC 2 · ISO 27001 Mapping", "SHA-256 Integrity Verification"];
  return /* @__PURE__ */ jsxRuntimeExports.jsx("section", { className: "surface-obsidian border-b border-white/10", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "relative mx-auto grid max-w-[1400px] grid-cols-1 md:grid-cols-3", children: items.map((t, i) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `px-6 py-5 text-center font-mono text-[10px] font-medium tracking-[0.18em] uppercase text-white/60 transition-colors hover:text-white ${i < items.length - 1 ? "md:border-r border-white/10 border-b md:border-b-0" : ""}`, children: t }, t)) }) });
}
function HowItWorks() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("section", { id: "how", className: "border-b hairline bg-background py-24 md:py-32", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mx-auto max-w-[1400px] px-6 md:px-10", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-baseline gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-[11px] text-ink-soft", children: "01" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-display text-3xl font-bold tracking-[-0.02em] md:text-5xl", children: "How it works" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-2 h-px flex-1 bg-hairline" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-14 grid grid-cols-1 overflow-hidden rounded-md border hairline md:grid-cols-3", children: STEPS.map((s, i) => /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: `p-10 transition-colors hover:bg-surface ${i < STEPS.length - 1 ? "md:border-r border-b md:border-b-0 hairline" : ""}`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "font-mono text-[11px] font-semibold tracking-[0.1em] text-foreground", children: [
        "STEP ",
        s.no
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-display mt-5 text-xl font-bold", children: s.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-[13.5px] font-light leading-[1.8] text-ink-soft", children: s.body })
    ] }, s.no)) })
  ] }) });
}
function SampleFinding() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("section", { id: "sample", className: "border-b hairline bg-surface py-24 md:py-32", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mx-auto max-w-[1400px] px-6 md:px-10", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-baseline gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-[11px] text-ink-soft", children: "02" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-display text-3xl font-bold tracking-[-0.02em] md:text-5xl", children: "Sample finding" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-2 h-px flex-1 bg-hairline" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-14 overflow-hidden rounded-md border hairline bg-background shadow-soft", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "surface-obsidian flex flex-wrap items-center justify-between gap-4 px-7 py-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-[13px] text-white", children: "SQL injection via unsafe query interpolation" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Sev, { sev: "CRITICAL" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { children: "CWE-89" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { children: "A03:2021" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid md:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b md:border-b-0 md:border-r hairline px-7 py-6", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs(Block, { label: "Finding Explanation", children: [
            "In ",
            /* @__PURE__ */ jsxRuntimeExports.jsx("code", { children: "routes/vulnCodeSnippets.js" }),
            " line 40, user input is concatenated into a SQL statement, allowing an attacker to execute arbitrary SQL against production data."
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Block, { label: "Business Impact", children: "SQL injection breaches average $4.4M in remediation costs. GDPR fines can reach 4% of annual revenue. Violates SOC2 CC6.1, ISO 27001 A.9.4.1." }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(Block, { label: "Exploit Scenario", children: [
            "An attacker submits crafted payloads through a search parameter to append",
            /* @__PURE__ */ jsxRuntimeExports.jsx("code", { children: " UNION SELECT" }),
            " queries. They retrieve hashed credentials and pivot into authenticated admin workflows."
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(Block, { label: "Code Location", last: true, children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-[12px] text-foreground", children: "routes/vulnCodeSnippets.js:40" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("pre", { className: "mt-3 surface-obsidian rounded-md p-4 overflow-x-auto", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("code", { className: "font-mono text-[11px] text-white/70 leading-[1.7]", children: [
              "const q = `SELECT * FROM Users WHERE email = '$",
              "${req.query.email}",
              "'`;"
            ] }) })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "px-7 py-6", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Remedy, { title: "OPTION 1 — Quick Fix", meta: "< 1 hour", body: "Replace string interpolation with Sequelize replacements and reject unsafe characters in the input path.", tradeoff: "Tradeoff: immediate containment but doesn't enforce a central query policy." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Remedy, { title: "OPTION 2 — Proper Fix", meta: "< 4 hours", body: "Migrate endpoint to parameterized ORM queries and add schema validation middleware.", tradeoff: "Tradeoff: best risk reduction per effort with moderate refactor impact." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Remedy, { title: "OPTION 3 — Robust Fix", meta: "1–2 days", body: "Centralize data access behind repository interfaces, enforce query linting in CI, and add security regression tests.", tradeoff: "Tradeoff: highest confidence and maintainability, broader engineering coordination.", last: true }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex flex-wrap items-center gap-2 border-t hairline pt-5", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { children: "CC6.1" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { children: "CC6.7" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { children: "CC7.1" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-auto font-mono text-[11px] text-ink-soft", children: "Confidence: 9/10" })
          ] })
        ] })
      ] })
    ] })
  ] }) });
}
function Compliance() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("section", { id: "compliance", className: "border-b hairline bg-background py-24 md:py-32", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mx-auto max-w-[1400px] px-6 md:px-10", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-12 md:grid-cols-12 md:items-end", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "md:col-span-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-eyebrow", children: "Built for evidence" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("h2", { className: "font-display mt-5 text-3xl font-bold leading-[1.05] tracking-[-0.02em] md:text-5xl", children: [
          "One scan,",
          /* @__PURE__ */ jsxRuntimeExports.jsx("br", {}),
          "three frameworks."
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "md:col-span-7", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[15px] leading-relaxed text-ink-soft", children: "Every finding is automatically mapped to SOC 2, ISO 27001 and GDPR controls so the report you download doubles as audit evidence." }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-12 grid grid-cols-1 overflow-hidden rounded-md border hairline md:grid-cols-3", children: [{
      k: "SOC 2",
      v: "CC6.x · CC7.x",
      note: "Logical access & system operations controls"
    }, {
      k: "ISO 27001",
      v: "Annex A.9, A.12, A.14",
      note: "Access control, operations, secure development"
    }, {
      k: "GDPR",
      v: "Article 32",
      note: "Security of processing & data integrity"
    }].map((f, i) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `group relative bg-background p-8 transition-colors hover:surface-obsidian hover:text-white ${i < 2 ? "md:border-r border-b md:border-b-0 hairline" : ""}`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-[10px] tracking-[0.2em] uppercase text-ink-soft group-hover:text-white/50", children: f.v }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-display mt-3 text-2xl font-bold tracking-tight", children: f.k }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-6 text-[12.5px] leading-relaxed text-ink-soft group-hover:text-white/70", children: f.note })
    ] }, f.k)) })
  ] }) });
}
function Footer() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("footer", { className: "surface-obsidian", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative mx-auto flex max-w-[1400px] flex-col items-center justify-between gap-4 px-6 py-7 md:flex-row md:px-10", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-[12px] tracking-wider text-white/50", children: "Built for engineering teams serious about security." }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex items-center gap-7", children: ["GitHub", "Docs", "Contact"].map((l) => /* @__PURE__ */ jsxRuntimeExports.jsx("a", { href: "#", className: "font-display text-[12px] font-semibold tracking-[0.1em] uppercase text-white/60 transition-colors hover:text-white", children: l }, l)) })
  ] }) });
}
function Sev({
  sev
}) {
  const styles = {
    CRITICAL: "border-white text-white",
    HIGH: "border-white/70 text-white/90",
    MEDIUM: "border-white/40 text-white/70",
    LOW: "border-white/25 text-white/60"
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `font-mono inline-block rounded border px-2.5 py-1 text-[9px] font-bold tracking-[0.18em] ${styles[sev]}`, children: sev });
}
function Tag({
  children
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono inline-block rounded border border-white/30 px-2 py-0.5 text-[10px] text-white/70", children });
}
function Block({
  label,
  children,
  last
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `py-5 ${last ? "" : "border-b hairline"}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-eyebrow", children: label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 text-[13px] leading-[1.75] text-ink-soft", children })
  ] });
}
function Remedy({
  title,
  meta,
  body,
  tradeoff,
  last
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `py-5 ${last ? "" : "border-b hairline"}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "font-display text-[11px] font-bold tracking-[0.1em] text-foreground", children: title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-[10px] text-ink-soft", children: meta })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-[13px] font-light leading-[1.7] text-ink-soft", children: body }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-[11px] text-ink-soft/80", children: tradeoff })
  ] });
}
export {
  Landing as component
};
