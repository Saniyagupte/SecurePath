import { T as jsxRuntimeExports } from "./worker-entry-Txo-XDQl.js";
import { R as Route, L as Link } from "./router-FrWqa7lY.js";
import "node:events";
import "node:async_hooks";
import "node:stream/web";
import "node:stream";
function ScanReport() {
  const {
    scanId
  } = Route.useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let pollId;
    async function fetchData() {
      try {
        const res = await fetch(`/api/scan/${scanId}/status`);
        if (!res.ok) throw new Error("Scan data not found");
        const payload = await res.json();
        const transformed = (payload.findings || []).map((f) => {
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
              }
            },
            asset_exposure_mapping: {
              data_types_exposed: aem.data_types_exposed || ["Data analysis pending"],
              systems_affected: aem.systems_affected || ["System analysis pending"],
              estimated_exposure: aem.estimated_exposure || "Unknown"
            },
            code_snippet: f.code_snippet,
            compliance: {
              soc2: (comp.soc2_status || "AT_RISK").replace("_", " ").toUpperCase(),
              iso: (comp.iso27001_status || "AT_RISK").replace("_", " ").toUpperCase(),
              gdpr: (comp.gdpr_status || "N/A").replace("_", " ").toUpperCase()
            },
            developer_action: {
              minutes: dev.estimated_fix_time_minutes || 45,
              skill: (dev.skill_required || "MID").toUpperCase(),
              steps: dev.specific_steps || ["Review remediation options", "Apply secure pattern", "Verify fix"]
            },
            controls: f.soc2_controls ? f.soc2_controls.split(",").map((s) => s.trim()) : [],
            confidence: f.confidence_score || 0
          };
        });
        setData({
          scan: payload.scan,
          findings: transformed
        });
        setLoading(false);
        if (payload.status === "complete" || payload.status === "failed") {
          clearInterval(pollId);
        }
      } catch (err) {
        setError(err.message);
        setLoading(false);
        clearInterval(pollId);
      }
    }
    fetchData();
    pollId = setInterval(fetchData, 3e3);
    return () => clearInterval(pollId);
  }, [scanId]);
  if (loading && !data) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex min-h-screen items-center justify-center bg-surface font-mono text-[13px] text-ink-soft", children: "Initializing SecurePath Analysis..." });
  }
  if (error) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-screen items-center justify-center bg-surface font-mono text-[13px] text-destructive", children: [
      "Error: ",
      error
    ] });
  }
  const {
    scan,
    findings
  } = data;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-h-screen bg-surface text-foreground", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(ReportNav, { scanId }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { className: "mx-auto max-w-[1200px] px-6 py-10 md:px-10", children: [
      scan.status !== "complete" && scan.status !== "failed" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-8 rounded-md border hairline bg-background p-5 shadow-soft", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between mb-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-eyebrow", children: "Scan in progress" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "font-mono text-[12px] text-accent font-bold", children: [
            scan.progress,
            "%"
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "h-1 w-full bg-surface rounded-full overflow-hidden", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "h-full bg-foreground transition-all duration-500", style: {
          width: `${scan.progress}%`
        } }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-3 font-mono text-[11px] text-ink-soft italic", children: [
          "Current: ",
          scan.current_step,
          "..."
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryCard, { scan, findingsCount: findings.length }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-8 mb-3 flex items-center justify-between", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-display text-[14px] font-bold tracking-wide text-foreground", children: "Findings" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "font-mono text-[11px] text-ink-soft", children: [
          findings.length,
          " issues identified"
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-col gap-3", children: findings.length > 0 ? findings.map((f, i) => /* @__PURE__ */ jsxRuntimeExports.jsx(FindingCard, { finding: f }, i)) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-md border hairline bg-background p-10 text-center font-mono text-[12px] text-ink-soft", children: scan.status === "complete" ? "No findings identified. System is secure." : "Awaiting scan results..." }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(ReportFooter, {})
  ] });
}
function ReportNav({
  scanId
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("header", { className: "surface-obsidian sticky top-0 z-50 border-b border-white/10", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative mx-auto flex h-16 max-w-[1400px] items-center justify-between px-6 md:px-10", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(Link, { to: "/", className: "flex items-center gap-2.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-1.5 w-1.5 rounded-full bg-white" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-display text-[15px] font-bold tracking-[0.18em] text-white", children: "SECUREPATH" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "hidden font-mono text-[10px] tracking-wider text-white/50 border border-white/15 px-2 py-0.5 rounded sm:inline", children: [
        "Report · ",
        scanId
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Link, { to: "/", className: "text-[12px] font-semibold tracking-wider uppercase text-white/60 transition-colors hover:text-white", children: "← New scan" })
    ] })
  ] }) });
}
function SummaryCard({
  scan,
  findingsCount
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "flex flex-wrap items-start justify-between gap-6 rounded-md border hairline bg-background p-7 shadow-soft", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-[260px] flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "font-display text-[22px] font-bold tracking-[-0.01em]", children: "Security Report" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap gap-7", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Meta, { label: "Repository", value: scan.repo_name }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Meta, { label: "Commit", value: String(scan.commit_sha).slice(0, 12) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Meta, { label: "Total Findings", value: String(scan.findings_count ?? findingsCount) })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "surface-obsidian flex min-w-[110px] flex-col items-center justify-center rounded-md px-6 py-4 text-center", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-display text-[36px] font-bold leading-none text-white", children: scan.risk_score }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-1 font-mono text-[9px] tracking-[0.18em] uppercase text-white/50", children: "Risk Score" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("a", { href: "#", className: "surface-obsidian inline-flex items-center gap-2 rounded-md px-5 py-3 font-display text-[12px] font-bold tracking-[0.1em] uppercase text-white transition-opacity hover:opacity-90", children: "↓ Download PDF" })
    ] })
  ] });
}
function Meta({
  label,
  value
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-1", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-eyebrow", children: label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-[13px] font-semibold text-foreground", children: value })
  ] });
}
function FindingCard({
  finding
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "overflow-hidden rounded-md border hairline bg-background transition-colors hover:border-foreground/40", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "surface-obsidian flex flex-wrap items-center gap-3 px-5 py-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SevChip, { sev: finding.severity }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "flex-1 font-sans text-[14px] font-semibold text-white", children: finding.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { children: finding.cwe }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { children: finding.owasp })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 p-5 md:grid-cols-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "surface-obsidian col-span-full rounded-md p-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-[8px] tracking-[0.22em] uppercase text-white/50", children: "Strategic Impact (CTO Summary)" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-[14px] font-semibold leading-relaxed text-white", children: finding.cto_summary })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Field, { label: "Location", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "font-mono text-[11px] text-foreground", children: [
        finding.file_path,
        ":",
        finding.line_start,
        "–",
        finding.line_end
      ] }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Field, { label: "Exploit Scenario", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: finding.exploit_scenario }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Field, { label: "Plain English", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: finding.plain_english }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "col-span-full mt-4 border border-foreground/10 bg-surface p-5 rounded-md", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-eyebrow mb-4 opacity-70", children: "Feature 1 — Business Impact Analysis" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-6 md:grid-cols-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-[10px] font-bold tracking-wider text-ink-soft", children: "FINANCIAL IMPACT" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-[12.5px] space-y-1", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold", children: "Breach Cost:" }),
                " ",
                finding.business_impact_analysis.financial_impact.data_breach_cost
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold", children: "Regulatory Fine:" }),
                " ",
                finding.business_impact_analysis.financial_impact.regulatory_fine
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold", children: "Churn Risk:" }),
                " ",
                finding.business_impact_analysis.financial_impact.customer_churn_risk
              ] })
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-[10px] font-bold tracking-wider text-ink-soft", children: "SPECIFIC VIOLATIONS" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-[12.5px] space-y-1", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold", children: "SOC2:" }),
                " ",
                finding.business_impact_analysis.compliance_violations.soc2
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold", children: "ISO 27001:" }),
                " ",
                finding.business_impact_analysis.compliance_violations.iso27001
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold", children: "GDPR:" }),
                " ",
                finding.business_impact_analysis.compliance_violations.gdpr
              ] })
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-[10px] font-bold tracking-wider text-ink-soft", children: "LIKELIHOOD" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-[12.5px]", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-bold text-foreground mb-1", children: finding.business_impact_analysis.likelihood_of_exploitation.level.toUpperCase() }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "italic text-ink-soft", children: finding.business_impact_analysis.likelihood_of_exploitation.explanation })
            ] })
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "col-span-full border border-foreground/10 bg-white/40 p-5 rounded-md", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-eyebrow mb-4 opacity-70", children: "Feature 2 — Asset Exposure Mapping" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-6 md:grid-cols-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-[10px] font-bold tracking-wider text-ink-soft", children: "DATA TYPES EXPOSED" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap gap-1.5", children: finding.asset_exposure_mapping.data_types_exposed.map((t) => /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { dark: true, children: t }, t)) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-[10px] font-bold tracking-wider text-ink-soft", children: "SYSTEMS AFFECTED" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "text-[12.5px] list-disc list-inside text-ink-soft", children: finding.asset_exposure_mapping.systems_affected.map((s) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: s }, s)) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-[10px] font-bold tracking-wider text-ink-soft", children: "POTENTIAL EXPOSURE" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[14px] font-semibold text-foreground", children: finding.asset_exposure_mapping.estimated_exposure })
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Field, { label: "Code Snippet", full: true, children: /* @__PURE__ */ jsxRuntimeExports.jsx("pre", { className: "mt-2 surface-obsidian rounded-md p-4 overflow-x-auto", children: /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "font-mono text-[11px] leading-[1.7] text-white/75", children: finding.code_snippet }) }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "col-span-full grid grid-cols-1 gap-3 md:grid-cols-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(ComplianceBox, { label: "SOC 2", status: finding.compliance.soc2 }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(ComplianceBox, { label: "ISO 27001", status: finding.compliance.iso }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(ComplianceBox, { label: "GDPR", status: finding.compliance.gdpr })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "col-span-full mt-2 rounded-md border-l-4 border-foreground bg-surface p-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-display text-[12px] font-bold tracking-wide text-foreground", children: "Developer Action Plan" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs(Tag, { dark: true, children: [
              finding.developer_action.minutes,
              " MINS"
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs(Tag, { dark: true, children: [
              finding.developer_action.skill,
              " SKILL"
            ] })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { className: "mt-4 space-y-2", children: finding.developer_action.steps.map((step, i) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex gap-3 text-[12.5px] leading-relaxed text-ink-soft", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "font-mono font-bold text-ink-soft/70", children: [
            i + 1,
            "."
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: step })
        ] }, i)) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "col-span-full flex flex-wrap items-center gap-2 border-t hairline pt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-[10px] tracking-wider uppercase text-ink-soft", children: "Controls:" }),
        finding.controls.map((c) => /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { dark: true, children: c }, c)),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "ml-auto font-mono text-[11px] text-ink-soft", children: [
          "Confidence: ",
          finding.confidence,
          "/10"
        ] })
      ] })
    ] })
  ] });
}
function Field({
  label,
  children,
  full
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: full ? "col-span-full" : "", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-eyebrow block", children: label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-1.5 text-[13px] font-light leading-[1.65] text-ink-soft", children })
  ] });
}
function SevChip({
  sev
}) {
  const styles = {
    CRITICAL: "border-white text-white",
    HIGH: "border-white/70 text-white/90",
    MEDIUM: "border-white/45 text-white/75",
    LOW: "border-white/30 text-white/65",
    INFO: "border-white/20 text-white/55"
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `font-mono inline-block flex-shrink-0 rounded border px-2.5 py-1 text-[9px] font-bold tracking-[0.18em] ${styles[sev]}`, children: sev });
}
function Tag({
  children,
  dark
}) {
  if (dark) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono inline-block rounded border hairline bg-background px-2 py-0.5 text-[10px] text-foreground", children });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono inline-block rounded border border-white/30 px-2 py-0.5 text-[10px] text-white/70", children });
}
function ComplianceBox({
  label,
  status
}) {
  const dotColor = status === "VIOLATED" ? "bg-destructive" : status === "AT RISK" ? "bg-foreground" : status === "COMPLIANT" ? "bg-foreground/40" : "bg-ink-soft/40";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-md border hairline bg-surface p-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-eyebrow", children: label }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 flex items-center gap-2 font-mono text-[11px] font-bold text-foreground", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `h-1.5 w-1.5 rounded-full ${dotColor}` }),
      status
    ] })
  ] });
}
function ReportFooter() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("footer", { className: "surface-obsidian mt-12", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative mx-auto flex max-w-[1400px] flex-col items-center justify-between gap-4 px-6 py-7 md:flex-row md:px-10", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-[12px] tracking-wider text-white/50", children: "Built for engineering teams serious about security." }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex items-center gap-7", children: ["GitHub", "Docs", "Contact"].map((l) => /* @__PURE__ */ jsxRuntimeExports.jsx("a", { href: "#", className: "font-display text-[12px] font-semibold tracking-[0.1em] uppercase text-white/60 transition-colors hover:text-white", children: l }, l)) })
  ] }) });
}
export {
  ScanReport as component
};
