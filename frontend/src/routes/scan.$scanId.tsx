import { createFileRoute, Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";

export const Route = createFileRoute("/scan/$scanId")({
  component: ScanReport,
  head: ({ params }) => ({
    meta: [
      { title: `Scan ${params.scanId} — SecurePath Report` },
      {
        name: "description",
        content:
          "Security assessment report with AI-enriched findings, business impact, compliance mapping, and developer action plans.",
      },
    ],
  }),
});

/* ── Placeholder data — wire to real scan results later ── */
type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
type ComplianceStatus = "VIOLATED" | "AT RISK" | "COMPLIANT" | "N/A";

interface Finding {
  severity: Severity;
  title: string;
  cwe: string;
  owasp: string;
  cto_summary: string;
  file_path: string;
  line_start: number;
  line_end: number;
  exploit_scenario: string;
  plain_english: string;
  business_impact_analysis: {
    financial_impact: { data_breach_cost: string; regulatory_fine: string; customer_churn_risk: string };
    compliance_violations: { soc2: string; iso27001: string; gdpr: string };
    likelihood_of_exploitation: { level: string; explanation: string };
  };
  asset_exposure_mapping: {
    data_types_exposed: string[];
    systems_affected: string[];
    estimated_exposure: string;
  };
  code_snippet: string;
  compliance: { soc2: ComplianceStatus; iso: ComplianceStatus; gdpr: ComplianceStatus };
  developer_action: { minutes: number; skill: string; steps: string[] };
  controls: string[];
  confidence: number;
  category?: string;
  business_risk?: string;
}

const SCAN_PLACEHOLDER = {
  repo_name: "{{ scan.repo_name }}",
  commit_sha: "{{ scan.commit_sha }}",
  findings_count: 23,
  risk_score: 94,
};

const FINDINGS_PLACEHOLDER: Finding[] = [
  {
    severity: "CRITICAL",
    title: "SQL injection via unsafe query interpolation",
    cwe: "CWE-89",
    owasp: "A03:2021",
    cto_summary:
      "Direct database compromise risk. Single exploit chain leads to full customer data exfiltration and regulatory breach disclosure obligations within 72 hours.",
    file_path: "routes/vulnCodeSnippets.js",
    line_start: 38,
    line_end: 42,
    exploit_scenario:
      "Attacker submits crafted payloads through the email parameter to append UNION SELECT queries, retrieves hashed credentials and pivots into authenticated admin workflows.",
    plain_english:
      "User input is concatenated into a SQL statement without parameterization, letting an attacker run arbitrary database queries.",
    business_risk:
      "SQL injection breaches average $4.4M in remediation costs. GDPR fines can reach 4% of annual revenue.",
    code_snippet: `const q = \`SELECT * FROM Users WHERE email = '\${req.query.email}'\`;\ndb.exec(q, (err, rows) => res.json(rows));`,
    compliance: { soc2: "VIOLATED", iso: "VIOLATED", gdpr: "AT RISK" },
    developer_action: {
      minutes: 45,
      skill: "MID",
      steps: [
        "Replace string interpolation with Sequelize replacements.",
        "Add input schema validation middleware to the route.",
        "Add a regression test covering quote-character payloads.",
      ],
    },
    controls: ["CC6.1", "CC6.7", "CC7.1"],
    confidence: 9,
  },
  {
    severity: "CRITICAL",
    title: "Hardcoded JWT signing secret committed to source",
    cwe: "CWE-798",
    owasp: "A07:2021",
    cto_summary:
      "Authentication trust boundary is publicly verifiable. Any attacker with repo access can mint admin sessions; key rotation alone is insufficient — full session invalidation required.",
    file_path: "config/index.js",
    line_start: 11,
    line_end: 15,
    exploit_scenario:
      "Attacker clones the repository, extracts the secret, and signs JWTs that pass server-side verification — granting persistent admin access until secrets are rotated.",
    plain_english:
      "The secret used to sign authentication tokens is checked into the codebase, making it readable by anyone with repo access.",
    business_risk:
      "Full account takeover. Session-bound trust assumptions collapse. Triggers SOC 2 incident response and customer notification workflows.",
    code_snippet: `module.exports = {\n  jwtSecret: "s3cr3t-do-not-share",\n  tokenTTL: "30d",\n};`,
    compliance: { soc2: "VIOLATED", iso: "VIOLATED", gdpr: "VIOLATED" },
    developer_action: {
      minutes: 30,
      skill: "MID",
      steps: [
        "Move the secret to an environment variable and rotate immediately.",
        "Invalidate all active sessions issued under the old secret.",
        "Add a pre-commit hook running secret scanning (gitleaks).",
      ],
    },
    controls: ["CC6.1", "CC6.6"],
    confidence: 10,
  },
  {
    severity: "HIGH",
    title: "Use of eval() on untrusted input",
    cwe: "CWE-95",
    owasp: "A03:2021",
    cto_summary:
      "Remote code execution surface inside the rendering path. Successful exploitation yields full process compromise and lateral movement opportunities.",
    file_path: "routes/angular.js",
    line_start: 6,
    line_end: 10,
    exploit_scenario:
      "Attacker injects JavaScript through a profile field that is later eval()'d on render, executing arbitrary code in the server context.",
    plain_english:
      "Dynamic JavaScript evaluation is performed on values that originate from user input.",
    business_risk:
      "RCE-class vulnerability. Direct path to data exfiltration, credential theft, and supply chain compromise.",
    code_snippet: `app.get("/render", (req, res) => {\n  const result = eval(req.query.expr);\n  res.send(String(result));\n});`,
    compliance: { soc2: "AT RISK", iso: "VIOLATED", gdpr: "AT RISK" },
    developer_action: {
      minutes: 60,
      skill: "SENIOR",
      steps: [
        "Remove eval() and replace with an explicit allow-list parser.",
        "Add an integration test asserting non-allowed expressions are rejected.",
        "Audit all other eval/Function usages in the codebase.",
      ],
    },
    controls: ["CC6.1", "CC7.2"],
    confidence: 9,
  },
];

function ScanReport() {
  const { scanId } = Route.useParams();
  const [data, setData] = useState<{ scan: any; findings: Finding[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let pollId: ReturnType<typeof setInterval>;

    async function fetchData() {
      try {
        const res = await fetch(`/api/scan/${scanId}/status`);
        if (!res.ok) throw new Error("Scan data not found");
        const payload = await res.json();
        
        // Transform backend findings to Finding interface
        const transformed: Finding[] = (payload.findings || []).map((f: any) => {
          const comp = f.compliance_readiness_json || {};
          const dev = f.developer_action_json || {};
          const bia = f.business_impact_analysis_json || f.business_impact_json || {};
          const aem = f.asset_exposure_mapping_json || f.assets_exposed_json || {};
          
          return {
            severity: f.severity.toUpperCase(),
            title: f.raw_title || f.title,
            cwe: f.cwe_id || "CWE-?",
            owasp: f.owasp_category || "—",
            cto_summary: f.cto_summary || "Strategic impact analysis pending.",
            file_path: f.file_path,
            line_start: f.line_start,
            line_end: f.line_end,
            exploit_scenario: f.exploit_scenario || "Exploit analysis pending.",
            plain_english: f.plain_english || "Reasoning pending...",
            category: f.category || "misc",
            business_risk: f.business_risk || f.cto_summary || "Pending...",
            business_impact_analysis: {
              financial_impact: bia.financial_impact || { 
                data_breach_cost: f.business_risk || "Pending...", 
                regulatory_fine: "Pending...", 
                customer_churn_risk: "Pending..." 
              },
              compliance_violations: bia.compliance_violations || { 
                soc2: "Pending...", 
                iso27001: "Pending...", 
                gdpr: "Pending..." 
              },
              likelihood_of_exploitation: bia.likelihood_of_exploitation || { 
                level: "MEDIUM", 
                explanation: "Exploit analysis pending." 
              },
            },
            asset_exposure_mapping: {
              data_types_exposed: aem.data_types_exposed || ["Data analysis pending"],
              systems_affected: aem.systems_affected || ["System analysis pending"],
              estimated_exposure: aem.estimated_exposure || "Unknown",
            },
            code_snippet: f.code_snippet,
            compliance: {
              soc2: (comp.soc2_status || "AT_RISK").replace("_", " ").toUpperCase() as ComplianceStatus,
              iso: (comp.iso27001_status || "AT_RISK").replace("_", " ").toUpperCase() as ComplianceStatus,
              gdpr: (comp.gdpr_status || "N/A").replace("_", " ").toUpperCase() as ComplianceStatus,
            },
            developer_action: {
              minutes: dev.estimated_fix_time_minutes || 45,
              skill: (dev.skill_required || "MID").toUpperCase(),
              steps: dev.specific_steps || ["Review remediation options", "Apply secure pattern", "Verify fix"],
            },
            controls: f.soc2_controls ? f.soc2_controls.split(",").map((s: string) => s.trim()) : [],
            confidence: f.confidence_score || 0,
          };
        });

        setData({ scan: payload, findings: transformed });
        setLoading(false);

        if (payload.status === "complete" || payload.status === "failed") {
          clearInterval(pollId);
        }
      } catch (err: any) {
        setError(err.message);
        setLoading(false);
        clearInterval(pollId);
      }
    }

    fetchData();
    pollId = setInterval(fetchData, 3000);
    return () => clearInterval(pollId);
  }, [scanId]);

  if (loading && !data) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-surface font-mono text-[13px] text-ink-soft">
        Initializing SecurePath Analysis...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-surface font-mono text-[13px] text-destructive">
        Error: {error}
      </div>
    );
  }

  const { scan, findings } = data!;

  return (
    <div className="min-h-screen bg-surface text-foreground">
      <ReportNav scanId={scanId} />

      <main className="mx-auto max-w-[1200px] px-6 py-10 md:px-10">
        {scan.status !== "complete" && scan.status !== "failed" && (
          <div className="mb-8 rounded-md border hairline bg-background p-6 shadow-soft">
            <h2 className="font-display text-[15px] font-bold tracking-wide text-foreground mb-4 border-b hairline pb-3">
              Repository cloned. Starting SAST analysis...
            </h2>
            <div className="space-y-4">
              <span className="font-display text-[14px] font-bold tracking-wide text-foreground uppercase">
                Scan Metadata
              </span>
              <div className="grid grid-cols-2 gap-y-4 gap-x-8 font-mono text-[13px] text-ink-soft">
                <div><strong className="text-foreground text-[11px] uppercase tracking-wider block mb-1">Repo</strong>{scan.repo_name}</div>
                <div><strong className="text-foreground text-[11px] uppercase tracking-wider block mb-1">Commit</strong>{String(scan.commit_sha).slice(0, 12)}</div>
                <div><strong className="text-foreground text-[11px] uppercase tracking-wider block mb-1">Started</strong>{scan.created_at || "Just now"}</div>
                <div><strong className="text-foreground text-[11px] uppercase tracking-wider block mb-1">Status</strong>{scan.status}</div>
              </div>
            </div>
          </div>
        )}

        <SummaryCard scan={scan} findingsCount={findings.length} findings={findings} />

        <div className="mt-8 mb-3 flex items-center justify-between">
          <h2 className="font-display text-[14px] font-bold tracking-wide text-foreground">
            Findings
          </h2>
          <span className="font-mono text-[11px] text-ink-soft">
            {findings.length} issues identified
          </span>
        </div>

        <div className="flex flex-col gap-3">
          {findings.length > 0 ? (
            findings.map((f, i) => <FindingCard key={i} finding={f} />)
          ) : (
            <div className="rounded-md border hairline bg-background p-10 text-center font-mono text-[12px] text-ink-soft">
              {scan.status === "complete" ? "No findings identified. System is secure." : "Awaiting scan results..."}
            </div>
          )}
        </div>
      </main>

      <ReportFooter />
    </div>
  );
}

function ReportNav({ scanId }: { scanId: string }) {
  return (
    <header className="surface-obsidian sticky top-0 z-50 border-b border-white/10">
      <div className="relative mx-auto flex h-16 max-w-[1400px] items-center justify-between px-6 md:px-10">
        <Link to="/" className="flex items-center gap-2.5">
          <span className="h-1.5 w-1.5 rounded-full bg-white" />
          <span className="font-display text-[15px] font-bold tracking-[0.18em] text-white">
            SECUREPATH
          </span>
        </Link>
        <div className="flex items-center gap-5">
          <span className="hidden font-mono text-[10px] tracking-wider text-white/50 border border-white/15 px-2 py-0.5 rounded sm:inline">
            Report · {scanId}
          </span>
          <Link
            to="/"
            className="text-[12px] font-semibold tracking-wider uppercase text-white/60 transition-colors hover:text-white"
          >
            ← New scan
          </Link>
        </div>
      </div>
    </header>
  );
}

function SummaryCard({
  scan,
  findingsCount,
  findings,
}: {
  scan: any;
  findingsCount: number;
  findings: Finding[];
}) {
  const crit = findings.filter(f => f.severity === "CRITICAL").length;
  const high = findings.filter(f => f.severity === "HIGH").length;
  const med = findings.filter(f => f.severity === "MEDIUM").length;
  const low = findings.filter(f => f.severity === "LOW").length;

  return (
    <>
      <div className="surface-obsidian rounded-md p-8 flex flex-col md:flex-row gap-8 items-start mb-8 shadow-soft">
        <div className="text-center min-w-[120px] flex flex-col items-center justify-center border border-white/10 rounded-md p-4 bg-white/5">
          <h3 className="font-mono text-[10px] text-white/50 uppercase tracking-widest mb-2">Risk Score</h3>
          <p className="font-display text-[48px] font-bold text-white leading-none">
            {["complete", "failed"].includes(scan.status) ? scan.risk_score : "···"}
          </p>
        </div>
        
        <div className="flex-1 font-mono text-[12px] text-white/70 space-y-2 pt-2">
          <p><strong className="text-white">CRITICAL:</strong> {crit}</p>
          <p><strong className="text-white">HIGH:</strong> {high}</p>
          <p><strong className="text-white">MEDIUM:</strong> {med}</p>
          <p><strong className="text-white">LOW:</strong> {low}</p>
        </div>

        <div className="flex-1 font-mono text-[12px] text-white/70 space-y-2 pt-2">
          <p><strong className="text-white">Repo:</strong> {scan.repo_name}</p>
          <p><strong className="text-white">Commit:</strong> {String(scan.commit_sha).slice(0, 12)}</p>
          <p><strong className="text-white">Duration:</strong> {scan.status === "complete" ? "Complete" : "Ongoing"}</p>
          <p><strong className="text-white">Total findings:</strong> {findings.length}</p>
        </div>

        <div className="flex flex-col gap-3">
          {["complete", "failed"].includes(scan.status) ? (
            <a
              href={`/api/scan/${scan.id}/download`}
              target="_blank"
              rel="noopener noreferrer"
              className="bg-white text-black px-5 py-3 text-center font-display text-[11px] font-bold tracking-widest uppercase rounded hover:bg-white/90 transition-colors"
            >
              DOWNLOAD AUDIT REPORT PDF
            </a>
          ) : (
            <button disabled className="bg-white/10 text-white/40 px-5 py-3 text-center font-display text-[11px] font-bold tracking-widest uppercase rounded cursor-not-allowed">
              DOWNLOAD AUDIT REPORT PDF
            </button>
          )}
          <a href="#" onClick={(e) => e.preventDefault()} className="text-center font-mono text-[11px] text-white/50 hover:text-white underline decoration-white/30 underline-offset-4">
            Preview Report
          </a>
        </div>
      </div>
      
      {/* OWASP Grid */}
      <OwaspCoverage findings={findings} />
    </>
  );
}

function OwaspCoverage({ findings }: { findings: Finding[] }) {
  const blocks = [
    { id: "A01", label: "Broken Access Control" },
    { id: "A02", label: "Cryptographic Failures" },
    { id: "A03", label: "Injection" },
    { id: "A04", label: "Insecure Design" },
    { id: "A05", label: "Security Misconfiguration" },
    { id: "A06", label: "Vulnerable Components" },
    { id: "A07", label: "Auth Failures" },
    { id: "A08", label: "Data Integrity" },
    { id: "A09", label: "Logging & Monitoring" },
    { id: "A10", label: "SSRF" }
  ];

  return (
    <div className="mb-10">
      <h3 className="font-display text-[15px] font-bold tracking-wide text-foreground mb-4">OWASP Top 10 Coverage</h3>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {blocks.map(b => {
          const hit = findings.some(f => f.owasp && f.owasp.includes(b.id));
          return (
            <div key={b.id} className={`p-4 rounded-md border text-center ${hit ? "border-foreground bg-foreground/5 shadow-sm" : "hairline bg-surface/30 opacity-60"}`}>
              <p className="font-display text-[16px] font-bold text-foreground mb-1">{b.id}</p>
              <p className="font-mono text-[9px] uppercase tracking-wider text-ink-soft leading-tight">{b.label}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <article className="border hairline bg-background p-6 rounded-md shadow-sm">
      <div className="flex items-center gap-3 mb-4">
        <SevChip sev={finding.severity} />
        <h3 className="flex-1 font-display text-[16px] font-bold text-foreground">{finding.title}</h3>
        <span className="font-mono text-[11px] text-ink-soft border hairline px-2 py-0.5 rounded bg-surface">{finding.cwe}</span>
      </div>
      
      <p className="font-mono text-[11px] text-ink-soft mb-5">
        Location: {finding.file_path}:{finding.line_start}-{finding.line_end}
      </p>
      
      <div className="space-y-4 text-[13px] text-foreground/85 leading-relaxed">
        <p>
          <strong className="text-foreground border-b hairline pb-0.5">Category:</strong> {finding.category || "misc"} &nbsp;|&nbsp; 
          <strong className="text-foreground border-b hairline pb-0.5 ml-2">OWASP:</strong> {finding.owasp}
        </p>
        <p><strong className="text-foreground border-b hairline pb-0.5">Plain English:</strong> {finding.plain_english}</p>
        <p>
          <strong className="text-foreground border-b hairline pb-0.5">Business Risk:</strong> {finding.business_risk || finding.business_impact_analysis?.financial_impact?.data_breach_cost || "Pending..."}
        </p>
        <p>
          <strong className="text-foreground border-b hairline pb-0.5">Compliance:</strong> {finding.controls.join(",") || "Pending"} &nbsp;|&nbsp; 
          <strong className="text-foreground border-b hairline pb-0.5 ml-2">Confidence:</strong> {finding.confidence}/10
        </p>
        
        <pre className="bg-surface border hairline font-mono text-[11.5px] p-4 rounded-md text-ink-soft mt-5 overflow-x-auto whitespace-pre-wrap">
          {finding.code_snippet}
        </pre>
      </div>
    </article>
  );
}

function SevChip({ sev }: { sev: Severity }) {
  const styles: Record<Severity, string> = {
    CRITICAL: "border-white text-white",
    HIGH: "border-white/70 text-white/90",
    MEDIUM: "border-white/45 text-white/75",
    LOW: "border-white/30 text-white/65",
    INFO: "border-white/20 text-white/55",
  };
  return (
    <span
      className={`font-mono inline-block flex-shrink-0 rounded border px-2.5 py-1 text-[9px] font-bold tracking-[0.18em] ${styles[sev]}`}
    >
      {sev}
    </span>
  );
}

function Tag({ children, dark }: { children: React.ReactNode; dark?: boolean }) {
  if (dark) {
    return (
      <span className="font-mono inline-block rounded border hairline bg-background px-2 py-0.5 text-[10px] text-foreground">
        {children}
      </span>
    );
  }
  return (
    <span className="font-mono inline-block rounded border border-white/30 px-2 py-0.5 text-[10px] text-white/70">
      {children}
    </span>
  );
}

function ComplianceBox({ label, status }: { label: string; status: ComplianceStatus }) {
  const dotColor =
    status === "VIOLATED"
      ? "bg-destructive"
      : status === "AT RISK"
      ? "bg-foreground"
      : status === "COMPLIANT"
      ? "bg-foreground/40"
      : "bg-ink-soft/40";
  return (
    <div className="rounded-md border hairline bg-surface p-3">
      <p className="text-eyebrow">{label}</p>
      <p className="mt-1 flex items-center gap-2 font-mono text-[11px] font-bold text-foreground">
        <span className={`h-1.5 w-1.5 rounded-full ${dotColor}`} />
        {status}
      </p>
    </div>
  );
}

function ReportFooter() {
  return (
    <footer className="surface-obsidian mt-12">
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
