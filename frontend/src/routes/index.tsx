import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useRef, useState, type FormEvent } from "react";

export const Route = createFileRoute("/")({
  component: Landing,
});

const GITHUB_REGEX = /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?\/?$/;

const NAV = [
  { label: "How it works", href: "#how" },
  { label: "Sample finding", href: "#sample" },
  { label: "Compliance", href: "#compliance" },
];

const STEPS = [
  {
    no: "01",
    title: "Scan",
    body: "Submit any public GitHub repository. SecurePath runs five passes: SAST via Semgrep, dependency CVE audit, secret detection, structural pattern analysis, and configuration review.",
  },
  {
    no: "02",
    title: "Enrich",
    body: "Each finding receives AI enrichment: plain English explanation, business impact analysis, exploit scenario, asset exposure mapping, and three ranked remediation strategies.",
  },
  {
    no: "03",
    title: "Evidence",
    body: "Download a structured PDF report with compliance control mapping, business impact data, and SHA-256 tamper verification. Built for engineering teams preparing audit evidence.",
  },
];

const TERMINAL_LINES = [
  "> Cloning juice-shop/juice-shop...",
  "> Running SAST analysis (semgrep)...",
  "[████████░░] 78%",
  "■ CRITICAL: SQL injection in routes/vulnCodeSnippets.js:40",
  "■ CRITICAL: Hardcoded JWT secret in config/index.js:13",
  "■ HIGH: eval() usage in routes/angular.js:8",
  "> Enriching with AI analysis...",
  "> Business impact: $4.4M avg breach cost mapped",
  "> Asset exposure: 3 systems, external-facing scope",
  "> Generating compliance evidence PDF...",
  "✓ Complete. 23 findings. Risk score: 94/100",
];

function Landing() {
  const [scrolled, setScrolled] = useState(false);
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Nav scrolled={scrolled} />
      <Hero />
      <StatsBar />
      <HowItWorks />
      <SampleFinding />
      <Compliance />
      <Footer />
    </div>
  );
}

function Nav({ scrolled }: { scrolled: boolean }) {
  return (
    <header
      className={`sticky top-0 z-50 transition-all duration-300 surface-obsidian border-b border-white/10 ${
        scrolled ? "shadow-elevated" : ""
      }`}
    >
      <div className="relative mx-auto flex h-16 max-w-[1400px] items-center justify-between px-6 md:px-10">
        <a href="#" className="flex items-center gap-2.5">
          <span className="h-1.5 w-1.5 rounded-full bg-white" />
          <span className="font-display text-[15px] font-bold tracking-[0.18em] text-white">
            SECUREPATH
          </span>
        </a>
        <div className="flex items-center gap-5">
          <span className="hidden font-mono text-[10px] tracking-wider text-white/40 border border-white/15 px-2 py-0.5 rounded sm:inline">
            v1.0.0
          </span>
          <nav className="hidden items-center gap-7 md:flex">
            {NAV.map((n) => (
              <a
                key={n.label}
                href={n.href}
                className="text-[12px] font-semibold tracking-wider uppercase text-white/60 transition-colors hover:text-white"
              >
                {n.label}
              </a>
            ))}
          </nav>
        </div>
      </div>
    </header>
  );
}

function Hero() {
  const navigate = useNavigate();
  const [repoUrl, setRepoUrl] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e: FormEvent) {
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
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_url: url }),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || "Failed to start scan");
      }

      navigate({ to: "/scan/$scanId", params: { scanId: data.scan_id } });
    } catch (err: any) {
      setError(err.message);
      setSubmitting(false);
    }
  }

  return (
    <section className="relative grid min-h-[calc(100vh-64px)] border-b hairline lg:grid-cols-2">
      {/* LEFT — Scan entry */}
      <div className="flex flex-col justify-center border-b hairline px-6 py-16 md:px-12 lg:border-b-0 lg:border-r lg:py-20">
        <div className="flex items-center gap-3">
          <span className="h-px w-8 bg-foreground" />
          <span className="text-eyebrow text-foreground">Security Assessment Platform</span>
        </div>
        <h1 className="font-display mt-6 text-[clamp(2.5rem,5.5vw,4.5rem)] font-bold leading-[1.02] tracking-[-0.025em]">
          Scan. Analyze.<br />
          <span className="italic font-light text-ink-soft">Generate evidence.</span>
        </h1>
        <p className="mt-6 max-w-md text-[15px] leading-relaxed text-ink-soft">
          Five-pass security analysis with AI-enriched findings, business impact assessment,
          and compliance mapping. One scan produces audit-ready documentation.
        </p>

        {/* Scan card */}
        <form
          onSubmit={onSubmit}
          className="relative mt-10 max-w-xl rounded-md border hairline bg-surface p-6 shadow-soft"
        >
          <span aria-hidden className="absolute inset-x-0 top-0 h-[3px] surface-obsidian rounded-t-md" />
          <label htmlFor="repo_url" className="text-eyebrow block">
            GitHub Repository URL
          </label>
          <div className="mt-3 flex overflow-hidden rounded-md border hairline bg-background">
            <input
              id="repo_url"
              name="repo_url"
              type="url"
              autoComplete="off"
              spellCheck={false}
              required
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/juice-shop/juice-shop"
              className="flex-1 bg-transparent px-4 py-3.5 font-mono text-[15px] font-bold text-black outline-none placeholder:text-ink-soft/60 placeholder:font-normal"
            />
            <button
              type="submit"
              disabled={submitting}
              className="surface-obsidian shrink-0 px-6 py-3.5 font-display text-[11px] font-bold tracking-[0.12em] uppercase text-white transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {submitting ? "Scanning…" : "Start Scan"}
            </button>
          </div>
          <p className="mt-2 min-h-[18px] font-mono text-[11px] text-destructive">{error}</p>
          <p className="text-[12px] leading-relaxed text-ink-soft">
            No signup required. Works with any public GitHub repository.
          </p>
          <p className="mt-1.5 flex items-center gap-2 text-[12px] text-ink-soft">
            <span aria-hidden></span>
            Repository is cloned locally and deleted after scan completes.
          </p>
        </form>
      </div>

      {/* RIGHT — Terminal */}
      <div className="flex items-center justify-center bg-surface px-6 py-16 md:px-12 lg:py-20">
        <Terminal />
      </div>
    </section>
  );
}

function Terminal() {
  const [lines, setLines] = useState<string[]>([]);
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let i = 0;
    let timeout: ReturnType<typeof setTimeout>;
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

  useEffect(() => {
    if (bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
  }, [lines]);

  return (
    <div className="surface-obsidian w-full max-w-[520px] rounded-lg overflow-hidden">
      <div className="relative flex items-center gap-1.5 border-b border-white/10 bg-white/[0.03] px-4 py-3">
        <span className="h-2.5 w-2.5 rounded-full bg-white/20" />
        <span className="h-2.5 w-2.5 rounded-full bg-white/20" />
        <span className="h-2.5 w-2.5 rounded-full bg-white/20" />
        <span className="ml-3 font-mono text-[11px] text-white/40">
          securepath — scan output
        </span>
      </div>
      <div
        ref={bodyRef}
        className="relative font-mono text-[12px] leading-[1.9] px-6 py-5 h-[320px] overflow-y-auto"
      >
        {lines.map((l, idx) => {
          const safe = l ?? "";
          const isErr = safe.startsWith("■");
          const isOk = safe.startsWith("✓");
          const isCurrent = idx === lines.length - 1;
          return (
            <div
              key={idx}
              className={
                isErr
                  ? "text-[oklch(0.65_0.18_25)]"
                  : isOk
                  ? "text-[oklch(0.78_0.14_150)]"
                  : "text-white/70"
              }
            >
              {safe}
              {isCurrent && (
                <span className="ml-1 inline-block h-3 w-[7px] align-middle bg-white/70 animate-pulse" />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function StatsBar() {
  const items = [
    "OWASP Top 10 Coverage",
    "SOC 2 · ISO 27001 Mapping",
    "SHA-256 Integrity Verification",
  ];
  return (
    <section className="surface-obsidian border-b border-white/10">
      <div className="relative mx-auto grid max-w-[1400px] grid-cols-1 md:grid-cols-3">
        {items.map((t, i) => (
          <div
            key={t}
            className={`px-6 py-5 text-center font-mono text-[10px] font-medium tracking-[0.18em] uppercase text-white/60 transition-colors hover:text-white ${
              i < items.length - 1 ? "md:border-r border-white/10 border-b md:border-b-0" : ""
            }`}
          >
            {t}
          </div>
        ))}
      </div>
    </section>
  );
}

function HowItWorks() {
  return (
    <section id="how" className="border-b hairline bg-background py-24 md:py-32">
      <div className="mx-auto max-w-[1400px] px-6 md:px-10">
        <div className="flex items-baseline gap-4">
          <span className="font-mono text-[11px] text-ink-soft">01</span>
          <h2 className="font-display text-3xl font-bold tracking-[-0.02em] md:text-5xl">
            How it works
          </h2>
          <span className="ml-2 h-px flex-1 bg-hairline" />
        </div>

        <div className="mt-14 grid grid-cols-1 overflow-hidden rounded-md border hairline md:grid-cols-3">
          {STEPS.map((s, i) => (
            <article
              key={s.no}
              className={`p-10 transition-colors hover:bg-surface ${
                i < STEPS.length - 1 ? "md:border-r border-b md:border-b-0 hairline" : ""
              }`}
            >
              <p className="font-mono text-[11px] font-semibold tracking-[0.1em] text-foreground">
                STEP {s.no}
              </p>
              <h3 className="font-display mt-5 text-xl font-bold">{s.title}</h3>
              <p className="mt-3 text-[13.5px] font-light leading-[1.8] text-ink-soft">
                {s.body}
              </p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

function SampleFinding() {
  return (
    <section id="sample" className="border-b hairline bg-surface py-24 md:py-32">
      <div className="mx-auto max-w-[1400px] px-6 md:px-10">
        <div className="flex items-baseline gap-4">
          <span className="font-mono text-[11px] text-ink-soft">02</span>
          <h2 className="font-display text-3xl font-bold tracking-[-0.02em] md:text-5xl">
            Sample finding
          </h2>
          <span className="ml-2 h-px flex-1 bg-hairline" />
        </div>

        <div className="mt-14 overflow-hidden rounded-md border hairline bg-background shadow-soft">
          <div className="surface-obsidian flex flex-wrap items-center justify-between gap-4 px-7 py-5">
            <p className="font-mono text-[13px] text-white">
              SQL injection via unsafe query interpolation
            </p>
            <div className="flex items-center gap-2">
              <Sev sev="CRITICAL" />
              <Tag>CWE-89</Tag>
              <Tag>A03:2021</Tag>
            </div>
          </div>

          <div className="grid md:grid-cols-2">
            <div className="border-b md:border-b-0 md:border-r hairline px-7 py-6">
              <Block label="Finding Explanation">
                In <code>routes/vulnCodeSnippets.js</code> line 40, user input is concatenated into
                a SQL statement, allowing an attacker to execute arbitrary SQL against production
                data.
              </Block>
              <Block label="Business Impact">
                SQL injection breaches average $4.4M in remediation costs. GDPR fines can reach 4%
                of annual revenue. Violates SOC2 CC6.1, ISO 27001 A.9.4.1.
              </Block>
              <Block label="Exploit Scenario">
                An attacker submits crafted payloads through a search parameter to append
                <code> UNION SELECT</code> queries. They retrieve hashed credentials and pivot into
                authenticated admin workflows.
              </Block>
              <Block label="Code Location" last>
                <span className="font-mono text-[12px] text-foreground">
                  routes/vulnCodeSnippets.js:40
                </span>
                <pre className="mt-3 surface-obsidian rounded-md p-4 overflow-x-auto">
                  <code className="font-mono text-[11px] text-white/70 leading-[1.7]">
                    const q = `SELECT * FROM Users WHERE email = '${"${req.query.email}"}'`;
                  </code>
                </pre>
              </Block>
            </div>

            <div className="px-7 py-6">
              <Remedy
                title="OPTION 1 — Quick Fix"
                meta="< 1 hour"
                body="Replace string interpolation with Sequelize replacements and reject unsafe characters in the input path."
                tradeoff="Tradeoff: immediate containment but doesn't enforce a central query policy."
              />
              <Remedy
                title="OPTION 2 — Proper Fix"
                meta="< 4 hours"
                body="Migrate endpoint to parameterized ORM queries and add schema validation middleware."
                tradeoff="Tradeoff: best risk reduction per effort with moderate refactor impact."
              />
              <Remedy
                title="OPTION 3 — Robust Fix"
                meta="1–2 days"
                body="Centralize data access behind repository interfaces, enforce query linting in CI, and add security regression tests."
                tradeoff="Tradeoff: highest confidence and maintainability, broader engineering coordination."
                last
              />
              <div className="mt-5 flex flex-wrap items-center gap-2 border-t hairline pt-5">
                <Tag>CC6.1</Tag>
                <Tag>CC6.7</Tag>
                <Tag>CC7.1</Tag>
                <span className="ml-auto font-mono text-[11px] text-ink-soft">
                  Confidence: 9/10
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function Compliance() {
  return (
    <section id="compliance" className="border-b hairline bg-background py-24 md:py-32">
      <div className="mx-auto max-w-[1400px] px-6 md:px-10">
        <div className="grid gap-12 md:grid-cols-12 md:items-end">
          <div className="md:col-span-5">
            <p className="text-eyebrow">Built for evidence</p>
            <h2 className="font-display mt-5 text-3xl font-bold leading-[1.05] tracking-[-0.02em] md:text-5xl">
              One scan,<br />audit ready.
            </h2>
          </div>
          <div className="md:col-span-7">
            <p className="text-[15px] leading-relaxed text-ink-soft">
              Every finding is automatically mapped to SOC 2 controls so the
              report you download doubles as audit evidence.
            </p>
          </div>
        </div>

        <div className="mt-12 grid grid-cols-1 overflow-hidden rounded-md border hairline">
          {[
            { k: "SOC 2", v: "CC6.x · CC7.x", note: "Logical access & system operations controls" },
          ].map((f, i) => (
            <div
              key={f.k}
              className={`group relative bg-background p-8 transition-colors hover:surface-obsidian hover:text-white ${
                i < 2 ? "md:border-r border-b md:border-b-0 hairline" : ""
              }`}
            >
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase text-ink-soft group-hover:text-white/50">
                {f.v}
              </p>
              <p className="font-display mt-3 text-2xl font-bold tracking-tight">{f.k}</p>
              <p className="mt-6 text-[12.5px] leading-relaxed text-ink-soft group-hover:text-white/70">
                {f.note}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="surface-obsidian">
      <div className="relative mx-auto flex max-w-[1400px] flex-col items-center justify-between gap-4 px-6 py-7 md:flex-row md:px-10">
        <p className="font-mono text-[12px] tracking-wider text-white/50">
          Built for engineering teams serious about security.
        </p>
        <div className="flex items-center gap-7">
          {["GitHub", "Docs", "Contact"].map((l) => (
            <a
              key={l}
              href="#"
              className="font-display text-[12px] font-semibold tracking-[0.1em] uppercase text-white/60 transition-colors hover:text-white"
            >
              {l}
            </a>
          ))}
        </div>
      </div>
    </footer>
  );
}

/* ── Helpers ─────────────────────────────────────────── */

function Sev({ sev }: { sev: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" }) {
  const styles: Record<string, string> = {
    CRITICAL: "border-white text-white",
    HIGH: "border-white/70 text-white/90",
    MEDIUM: "border-white/40 text-white/70",
    LOW: "border-white/25 text-white/60",
  };
  return (
    <span
      className={`font-mono inline-block rounded border px-2.5 py-1 text-[9px] font-bold tracking-[0.18em] ${styles[sev]}`}
    >
      {sev}
    </span>
  );
}

function Tag({ children }: { children: React.ReactNode }) {
  return (
    <span className="font-mono inline-block rounded border border-white/30 px-2 py-0.5 text-[10px] text-white/70">
      {children}
    </span>
  );
}

function Block({
  label,
  children,
  last,
}: {
  label: string;
  children: React.ReactNode;
  last?: boolean;
}) {
  return (
    <div className={`py-5 ${last ? "" : "border-b hairline"}`}>
      <p className="text-eyebrow">{label}</p>
      <div className="mt-2 text-[13px] leading-[1.75] text-ink-soft">{children}</div>
    </div>
  );
}

function Remedy({
  title,
  meta,
  body,
  tradeoff,
  last,
}: {
  title: string;
  meta: string;
  body: string;
  tradeoff: string;
  last?: boolean;
}) {
  return (
    <div className={`py-5 ${last ? "" : "border-b hairline"}`}>
      <div className="flex items-center justify-between">
        <h4 className="font-display text-[11px] font-bold tracking-[0.1em] text-foreground">
          {title}
        </h4>
        <span className="font-mono text-[10px] text-ink-soft">{meta}</span>
      </div>
      <p className="mt-2 text-[13px] font-light leading-[1.7] text-ink-soft">{body}</p>
      <p className="mt-1.5 text-[11px] text-ink-soft/80">{tradeoff}</p>
    </div>
  );
}
