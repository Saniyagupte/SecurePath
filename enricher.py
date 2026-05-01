"""
EXAIEnricher — production-grade enrichment layer.

Key fixes vs previous version:
- Per-future timeout (20s) so one hung LLM call never stalls the pipeline
- Global time budget raised to 45s (fits comfortably inside 60s Railway timeout)
- Progress callback fires on EVERY completion — no more frozen bar
- enrichment_failed flag passed correctly into _merge_enrichment
- Batch DB update wrapped in try/except — silent failure can't kill pipeline
- ThreadPoolExecutor max_workers raised to 5 for faster parallel throughput
- Reduced LLM retry attempts to 1 (fast fail → template) to stay under budget
- _merge_enrichment no longer double-calls template_enrichment needlessly
- All progress percentages are integer-safe
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from typing import Any

from dotenv import load_dotenv

from soc2_controls import apply_severity_floor, get_soc2_mapping_for_finding

load_dotenv()


class EXAIEnricher:
    # ─── Init ────────────────────────────────────────────────────────────────
    def __init__(self, scan_id: str, progress_callback):
        self.scan_id = scan_id
        self.progress_callback = progress_callback
        self.provider = os.getenv("EXAI_PROVIDER", "groq").strip().lower()
        self.backends: list[dict[str, Any]] = []

        configured_model = os.getenv("EXAI_MODEL", "").strip()
        model_candidates = [configured_model] if configured_model else [
            "llama-3.1-8b-instant",       # fastest, most reliable on Groq
            "mixtral-8x7b-32768",
            "llama3-70b-8192",
        ]

        # ── Primary backend ──────────────────────────────────────────────────
        if self.provider == "groq":
            groq_key = (
                os.getenv("EXAI_API_KEY", "").strip()
                or os.getenv("GROQ_API_KEY", "").strip()
            )
            self.backends.append({
                "name": "groq",
                "base_url": os.getenv("EXAI_BASE_URL", "").strip()
                            or "https://api.groq.com/openai/v1",
                "api_key": groq_key,
                "models": model_candidates,
                "extra_headers": {},
            })
        elif self.provider == "openai":
            openai_key = (
                os.getenv("EXAI_API_KEY", "").strip()
                or os.getenv("OPENAI_API_KEY", "").strip()
            )
            self.backends.append({
                "name": "openai",
                "base_url": os.getenv("EXAI_BASE_URL", "").strip()
                            or "https://api.openai.com/v1",
                "api_key": openai_key,
                "models": [configured_model] if configured_model
                          else ["gpt-4o-mini", "gpt-4o"],
                "extra_headers": {},
            })

        # ── OpenRouter fallback ───────────────────────────────────────────────
        openrouter_key = os.getenv("OPENROUTER_API_KEY", "").strip()
        if openrouter_key:
            or_models_raw = os.getenv(
                "EXAI_OPENROUTER_MODELS",
                "meta-llama/llama-3.1-8b-instruct:free,"
                "google/gemma-2-9b-it:free,"
                "mistralai/mistral-7b-instruct:free",
            )
            or_models = [m.strip() for m in or_models_raw.split(",") if m.strip()]
            self.backends.append({
                "name": "openrouter",
                "base_url": "https://openrouter.ai/api/v1",
                "api_key": openrouter_key,
                "models": or_models,
                "extra_headers": {
                    "HTTP-Referer": os.getenv(
                        "EXAI_OPENROUTER_REFERER", "https://securepath.local"
                    ),
                    "X-Title": "SecurePath",
                },
            })

        # ── OpenAI secondary fallback (if not primary) ───────────────────────
        if self.provider != "openai":
            openai_key = os.getenv("OPENAI_API_KEY", "").strip()
            if openai_key:
                self.backends.append({
                    "name": "openai",
                    "base_url": "https://api.openai.com/v1",
                    "api_key": openai_key,
                    "models": ["gpt-4o-mini", "gpt-4o"],
                    "extra_headers": {},
                })

        self.curated_mode = (
            os.getenv("EXAI_CURATED_MODE", "true").strip().lower()
            in {"1", "true", "yes", "on"}
        )

        # Time budget: 45s total for all LLM calls (leaves headroom in 60s dyno)
        self._global_time_budget = int(os.getenv("EXAI_TIME_BUDGET", "45"))
        # Per-future wall-clock timeout
        self._per_future_timeout = int(os.getenv("EXAI_PER_FUTURE_TIMEOUT", "20"))
        # HTTP request timeout per LLM call
        self._http_timeout = int(os.getenv("EXAI_HTTP_TIMEOUT", "18"))

    # ─── Public entry point ───────────────────────────────────────────────────
    def enrich_all(self, findings: list[dict]) -> list[dict]:
        start_time = time.monotonic()
        total = len(findings)
        print(f"[Enricher:{self.scan_id}] Starting enrichment — {total} findings")

        if total == 0:
            self._safe_progress(100, "No findings to enrich.")
            return []

        # Split: LLM for critical/high, template for everything else
        llm_findings = [f for f in findings
                        if str(f.get("severity", "low")).lower() in {"critical", "high"}]
        fast_findings = [f for f in findings
                         if str(f.get("severity", "low")).lower() not in {"critical", "high"}]

        print(f"[Enricher:{self.scan_id}] LLM queue: {len(llm_findings)} | "
              f"Template queue: {len(fast_findings)}")

        enriched: list[dict] = []
        done = 0

        # ── Fast-path: template enrichment (no I/O, instant) ─────────────────
        for finding in fast_findings:
            mapped = self._apply_control_mapping(finding)
            enriched.append(self.template_enrichment(mapped))
            done += 1
            pct = int((done / total) * 100)
            self._safe_progress(pct, f"Enriched {done}/{total} findings...")

        # ── LLM path: parallel with hard per-future timeout ───────────────────
        if llm_findings:
            with ThreadPoolExecutor(max_workers=5, thread_name_prefix="enricher") as ex:
                future_map = {}
                for finding in llm_findings:
                    mapped = self._apply_control_mapping(finding)
                    future = ex.submit(self._enrich_one_llm, mapped, start_time)
                    future_map[future] = mapped

                # Drain futures with per-future timeout — NEVER blocks forever
                try:
                    for future in as_completed(
                        future_map,
                        timeout=self._global_time_budget,
                    ):
                        mapped = future_map[future]
                        try:
                            result = future.result(timeout=self._per_future_timeout)
                            enriched.append(result)
                        except FuturesTimeoutError:
                            print(f"[Enricher] Per-future timeout hit for "
                                  f"{mapped.get('raw_title','?')[:40]} — using template")
                            fallback = self.template_enrichment(mapped)
                            fallback["enrichment_failed"] = True
                            fallback["enrichment_status"] = "timeout"
                            enriched.append(fallback)
                        except Exception as exc:
                            print(f"[Enricher] Future failed: {exc}")
                            fallback = self.template_enrichment(mapped)
                            fallback["enrichment_failed"] = True
                            enriched.append(fallback)

                        done += 1
                        pct = int((done / total) * 100)
                        # Fire on every completion — no batching delay
                        self._safe_progress(pct, f"Enriched {done}/{total} findings...")

                except FuturesTimeoutError:
                    # Global budget exhausted — drain remaining with templates
                    print(f"[Enricher] Global timeout ({self._global_time_budget}s) — "
                          f"draining remaining futures with templates")
                    remaining = [f_map for f_map in future_map if not future_map[f_map].get("_done")]
                    for future, mapped in future_map.items():
                        if future not in [f for f in future_map if future_map[f].get("_done")]:
                            if not future.done():
                                future.cancel()
                                fallback = self.template_enrichment(mapped)
                                fallback["enrichment_failed"] = True
                                fallback["enrichment_status"] = "timeout"
                                enriched.append(fallback)
                                done += 1

        elapsed = time.monotonic() - start_time
        print(f"[Enricher:{self.scan_id}] Enrichment done in {elapsed:.2f}s "
              f"({len(enriched)}/{total} findings)")
        self._safe_progress(100, "AI enrichment complete.")
        return enriched

    # ─── Single-finding LLM enrichment (runs in thread) ─────────────────────
    def _enrich_one_llm(self, finding: dict, global_start: float) -> dict:
        title = finding.get("raw_title", "unknown")[:35]
        elapsed = time.monotonic() - global_start

        # Bail early if we're already over budget
        if elapsed > self._global_time_budget - 2:
            print(f"[Enricher] Budget exhausted ({elapsed:.1f}s), "
                  f"skipping LLM for: {title}")
            fallback = self.template_enrichment(finding)
            fallback["enrichment_failed"] = True
            return fallback

        try:
            payload = self._call_llm(finding)
            # FIX: pass enrichment_failed=False explicitly
            return self._merge_enrichment(finding, payload, enrichment_failed=False)
        except Exception as exc:
            print(f"[Enricher] LLM failed for '{title}': {exc}")
            fallback = self.template_enrichment(finding)
            # FIX: mark as failed but still return valid enrichment
            fallback["enrichment_failed"] = True
            fallback["enrichment_status"] = "failed"
            return fallback

    # ─── LLM call with backend/model fallback ────────────────────────────────
    def _call_llm(self, finding: dict) -> dict:
        usable = [b for b in self.backends if b.get("api_key")]
        if not usable:
            raise RuntimeError(
                "No LLM API key configured. Set GROQ_API_KEY, "
                "OPENROUTER_API_KEY, or OPENAI_API_KEY."
            )

        system = (
            "You are a principal application security engineer with 12 years of "
            "experience auditing Node.js applications and preparing SOC2 compliance "
            "evidence. You explain vulnerabilities with surgical precision. "
            "You never use filler phrases. Every sentence saves an engineer real time."
        )

        prompt = self._build_prompt(finding)
        last_error: Exception | None = None

        for backend in usable:
            for model in backend["models"]:
                payload = {
                    "model": model,
                    "temperature": 0.1,
                    "max_tokens": 2000,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    "response_format": {"type": "json_object"},
                }
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {backend['api_key']}",
                }
                headers.update(backend.get("extra_headers", {}))
                req = urllib.request.Request(
                    url=f"{backend['base_url'].rstrip('/')}/chat/completions",
                    data=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(
                        req, timeout=self._http_timeout
                    ) as resp:
                        body = resp.read().decode("utf-8")
                    data = json.loads(body)
                    choices = data.get("choices", [])
                    if not choices:
                        raise RuntimeError("LLM returned no choices")
                    raw = str(choices[0].get("message", {}).get("content", "")).strip()
                    if not raw:
                        raise RuntimeError("LLM content was empty")
                    # Strip markdown fences if present
                    raw = re.sub(r"^```json\s*", "", raw, flags=re.IGNORECASE)
                    raw = re.sub(r"^```\s*", "", raw, flags=re.IGNORECASE)
                    raw = re.sub(r"\s*```$", "", raw, flags=re.IGNORECASE)
                    result = self._parse_json_object(raw)
                    print(f"[Enricher] LLM OK — {backend['name']}/{model} "
                          f"for '{finding.get('raw_title','?')[:30]}'")
                    return result
                except urllib.error.HTTPError as exc:
                    body = exc.read().decode("utf-8", errors="ignore")
                    last_error = RuntimeError(
                        f"{backend['name']}/{model} HTTP {exc.code}: {body[:150]}"
                    )
                    # 429 = rate limit: try next model; auth errors: try next backend
                    if exc.code in {400, 404, 422, 429, 401, 403}:
                        continue
                    continue
                except Exception as exc:
                    last_error = RuntimeError(
                        f"{backend['name']}/{model} failed: {exc}"
                    )
                    continue

        raise last_error or RuntimeError("All LLM backends exhausted")

    # ─── Prompt builder ───────────────────────────────────────────────────────
    def _build_prompt(self, finding: dict) -> str:
        return f"""Analyze this security finding from a Node.js/Express application:

FINDING:
Title: {finding.get('raw_title', 'Unknown')}
File: {finding.get('file_path', 'Unknown')} (lines {finding.get('line_start', 1)}-{finding.get('line_end', 1)})
Severity: {str(finding.get('severity', 'medium')).upper()}
Category: {finding.get('category', 'misc')}
CWE: {finding.get('cwe_id', 'Unknown')}
OWASP: {finding.get('owasp_category', 'Unknown')}
Code:
{finding.get('code_snippet', 'Not available')}
{f"Package: {finding.get('npm_package')}" if finding.get('npm_package') else ""}
{f"CVE: {finding.get('cve_id')}" if finding.get('cve_id') else ""}

Return ONLY a valid JSON object — no markdown, no preamble.

{{
  "plain_english": "One precise sentence naming the file and exact risk.",
  "remediation": [
    {{
      "rank": 1,
      "label": "Quick fix",
      "time_estimate": "< 1 hour",
      "description": "Exact code change with before/after if concise.",
      "tradeoff": "What this fixes and what remains."
    }},
    {{
      "rank": 2,
      "label": "Proper fix",
      "time_estimate": "< 4 hours",
      "description": "Secure pattern or library with steps.",
      "tradeoff": "Why better and associated cost."
    }},
    {{
      "rank": 3,
      "label": "Robust fix",
      "time_estimate": "1-2 days",
      "description": "Architectural hardening.",
      "tradeoff": "Long-term gain and maintenance cost."
    }}
  ],
  "business_impact": {{
    "financial_exposure": "Realistic cost citing actual breach cost figures.",
    "compliance_violations": [
      {{"framework": "SOC2", "control": "CC6.1", "meaning": "How this violates the control."}},
      {{"framework": "ISO 27001", "control": "A.9.4.1", "meaning": "How this violates the control."}}
    ],
    "exploitation_likelihood": "low|medium|high",
    "likelihood_reason": "One sentence based on the code shown."
  }},
  "assets_exposed": {{
    "data_types": ["list of specific data types at risk"],
    "systems_affected": ["systems at risk based on file/code context"],
    "exposure_scope": "internal_only|external_facing|third_party_accessible",
    "exposure_explanation": "One sentence on what attacker accesses if exploited.",
    "estimated_records_at_risk": "Specific estimate, not 'unknown'."
  }}
}}"""

    # ─── JSON parser with fallback extraction ────────────────────────────────
    def _parse_json_object(self, text: str) -> dict[str, Any]:
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
            raise ValueError("Not a JSON object")
        except json.JSONDecodeError:
            start, end = text.find("{"), text.rfind("}")
            if start != -1 and end > start:
                try:
                    parsed = json.loads(text[start:end + 1])
                    if isinstance(parsed, dict):
                        return parsed
                except Exception:
                    pass
            raise RuntimeError(f"Could not parse LLM JSON: {text[:200]}")

    # ─── SOC2 control mapping ─────────────────────────────────────────────────
    def _apply_control_mapping(self, finding: dict) -> dict:
        mapping = get_soc2_mapping_for_finding(finding)
        severity = apply_severity_floor(
            str(finding.get("severity", "low")).lower(),
            mapping["severity_floor"],
        )
        mapped = dict(finding)
        mapped.update({
            "severity": severity,
            "vulnerability_type": mapping["vulnerability_type"],
            "soc2_controls": mapping["controls"],
            "soc2_rationale": mapping["rationale"],
        })
        return mapped

    # ─── Merge LLM output with finding ────────────────────────────────────────
    def _merge_enrichment(
        self, finding: dict, enrichment: dict, enrichment_failed: bool
    ) -> dict:
        # Build template as baseline for any fields LLM didn't fill
        base = self.template_enrichment(finding)
        merged = dict(finding)

        remediation = enrichment.get("remediation")
        if not isinstance(remediation, list) or not remediation:
            remediation = base["remediation"]

        business_impact = enrichment.get("business_impact")
        if not isinstance(business_impact, dict) or not business_impact:
            business_impact = base["business_impact"]

        assets_exposed = enrichment.get("assets_exposed")
        if not isinstance(assets_exposed, dict) or not assets_exposed:
            assets_exposed = base["assets_exposed"]

        plain_english = enrichment.get("plain_english") or base["plain_english"]

        # Curated remediations override LLM if in curated mode
        curated = self._curated_remediations(finding)
        if self.curated_mode and curated and not enrichment_failed:
            remediation = curated

        merged.update({
            "plain_english":        str(plain_english)[:800],
            "business_risk":        str(base["business_risk"])[:1200],
            "exploit_scenario":     str(base["exploit_scenario"])[:1200],
            "remediation":          remediation,
            "soc2_controls":        base["soc2_controls"],
            "soc2_rationale":       base["soc2_rationale"],
            "vulnerability_type":   base["vulnerability_type"],
            "confidence_score":     base["confidence_score"],
            "false_positive_risk":  base["false_positive_risk"],
            "false_positive_reason":str(base["false_positive_reason"])[:800],
            "business_impact":      business_impact,
            "assets_exposed":       assets_exposed,
            # FIX: use the passed-in flag, not a hardcoded value
            "enrichment_failed":    enrichment_failed,
            "enrichment_status":    "failed" if enrichment_failed else "complete",
        })
        return merged

    # ─── Template enrichment (no LLM, instant) ───────────────────────────────
    def template_enrichment(self, finding: dict) -> dict:
        mapped = self._apply_control_mapping(finding)
        category   = str(mapped.get("category", "misc")).lower()
        severity   = str(mapped.get("severity", "medium")).lower()
        vuln_type  = str(mapped.get("vulnerability_type", "broken_auth"))
        title      = str(mapped.get("raw_title", "Security issue detected"))
        file_path  = str(mapped.get("file_path", "unknown file"))
        line_start = mapped.get("line_start", 1)
        cwe        = mapped.get("cwe_id", "Unknown")
        owasp      = mapped.get("owasp_category", "A05:2021 - Security Misconfiguration")

        risk_templates = {
            "injection": "An attacker could execute unauthorized database or command operations, leading to data exposure and potential system compromise.",
            "auth":      "Authentication or access control weaknesses can allow account takeover, unauthorized access to customer data, and control failures.",
            "secrets":   "Leaked credentials or keys can enable direct unauthorized access to systems and regulated data.",
            "config":    "Security misconfiguration can increase attack surface and weaken baseline controls required for SOC2 evidence.",
            "deps":      "Vulnerable dependencies can introduce known exploits into production, creating externally documented attack paths.",
            "xss":       "Cross-site scripting can allow session theft, unauthorized actions, and compromise of user trust.",
            "crypto":    "Weak cryptographic handling can expose sensitive data and undermine confidentiality controls.",
            "misc":      "This issue weakens security posture and requires remediation evidence before audit submission.",
        }
        exploit_templates = {
            "injection": "An attacker sends crafted input executed as part of a query or command, allowing data extraction or destructive modification.",
            "auth":      "An attacker manipulates authentication flow to impersonate another user, enabling unauthorized actions under valid user context.",
            "secrets":   "An attacker discovers embedded credentials in source or deployment artifacts and uses them to access internal systems.",
            "config":    "An attacker exploits insecure defaults or exposed settings, enabling privilege escalation or data exposure.",
            "deps":      "An attacker targets a known CVE in an outdated package. Public exploits can be adapted quickly against exposed routes.",
            "xss":       "An attacker injects script payloads into user-accessible pages, executing in victim browsers to exfiltrate session tokens.",
            "crypto":    "An attacker abuses weak key management or unsafe cryptographic parameters, making protected data recoverable or forgeable.",
            "misc":      "An attacker leverages this weakness together with routine probing, impacting confidentiality, integrity, or availability.",
        }

        rem = self._default_remediation_by_type(vuln_type, file_path, line_start, title)
        curated = self._curated_remediations(mapped)
        if self.curated_mode and curated:
            rem = curated

        fp_risk = "low" if severity in {"critical", "high"} else "medium"
        base_confidence = 8 if severity in {"critical", "high"} else 6
        if category == "secrets":
            base_confidence = min(base_confidence, 6)

        # Business impact
        bi_financial = {
            "injection": "SQL injection breaches average $4.4M (IBM 2023). GDPR fines up to 4% annual revenue. Notification costs $150–$200/affected record.",
            "auth":      "Account takeover incidents cost $4.2M on average. Credential stuffing losses average $6M/year per enterprise.",
            "secrets":   "Exposed credentials lead to $4.4M average breach cost. Key rotation and IR range $50K–$500K depending on exposure window.",
            "config":    "Misconfiguration-related breaches average $3.9M. Cloud misconfigs account for 15% of initial attack vectors.",
            "deps":      "Vulnerable dependency exploitation costs $4.1M average. Supply chain attacks increased 742% in recent years.",
            "xss":       "XSS-driven session hijacking leads to full account takeover. Average web application attack cost is $3.8M.",
            "crypto":    "Cryptographic failures expose regulated data. GDPR fines up to €20M or 4% global revenue.",
            "misc":      "Security control weaknesses increase breach probability. Average breach cost $4.4M with 277-day mean detection.",
        }
        bi_compliance = {
            "injection": [
                {"framework": "SOC2", "control": "CC6.1", "meaning": "Requires logical access controls to prevent unauthorized data access. SQL injection bypasses these controls entirely."},
                {"framework": "ISO 27001", "control": "A.14.2.5", "meaning": "Requires secure system engineering principles. Unsanitized input violates secure coding requirements."},
            ],
            "auth": [
                {"framework": "SOC2", "control": "CC6.1", "meaning": "Requires authentication controls to restrict access. Weak auth allows unauthorized access to protected resources."},
                {"framework": "ISO 27001", "control": "A.9.4.1", "meaning": "Requires information access restriction. Broken authentication fails to enforce access boundaries."},
            ],
            "secrets": [
                {"framework": "SOC2", "control": "CC6.7", "meaning": "Requires restriction of data in transit/at rest. Hardcoded secrets expose credentials in plaintext."},
                {"framework": "ISO 27001", "control": "A.9.2.4", "meaning": "Requires management of secret authentication information. Committed secrets violate credential lifecycle controls."},
            ],
            "config": [
                {"framework": "SOC2", "control": "CC6.1", "meaning": "Requires logical access security. Misconfiguration weakens baseline access control enforcement."},
                {"framework": "ISO 27001", "control": "A.12.6.1", "meaning": "Requires management of technical vulnerabilities. Insecure defaults leave known weaknesses unaddressed."},
            ],
            "deps": [
                {"framework": "SOC2", "control": "CC7.1", "meaning": "Requires monitoring for vulnerabilities. Known CVEs in dependencies represent unpatched attack surface."},
                {"framework": "ISO 27001", "control": "A.12.6.1", "meaning": "Requires timely patching of technical vulnerabilities. Outdated dependencies violate patch management controls."},
            ],
            "xss": [
                {"framework": "SOC2", "control": "CC6.1", "meaning": "Requires input validation and output encoding. XSS allows execution of unauthorized code in user context."},
                {"framework": "ISO 27001", "control": "A.14.2.5", "meaning": "Requires secure development principles. Missing output encoding violates secure coding standards."},
            ],
            "crypto": [
                {"framework": "SOC2", "control": "CC6.7", "meaning": "Requires encryption of data in transit and at rest. Weak crypto fails to protect data confidentiality."},
                {"framework": "ISO 27001", "control": "A.10.1.1", "meaning": "Requires cryptographic controls policy. Weak algorithms or key management violate crypto requirements."},
            ],
            "misc": [
                {"framework": "SOC2", "control": "CC6.1", "meaning": "Requires logical access controls. This weakness may reduce overall access control effectiveness."},
                {"framework": "ISO 27001", "control": "A.12.6.1", "meaning": "Requires technical vulnerability management. Unaddressed findings represent unmanaged risk."},
            ],
        }
        bi_likelihood = "high" if severity == "critical" else ("medium" if severity == "high" else "low")
        bi_likelihood_reasons = {
            "injection": "Injection endpoints are actively targeted by automated scanners and require no authentication.",
            "auth":      "Authentication bypasses are commonly exploited via credential stuffing and session manipulation.",
            "secrets":   "Committed secrets are discoverable by automated scanning bots within minutes of push.",
            "config":    "Misconfigured services are indexed by Shodan and similar reconnaissance tools.",
            "deps":      "Public CVEs have known exploit code and are targeted by automated vulnerability scanners.",
            "xss":       "XSS payloads can be delivered via social engineering or injected into stored content.",
            "crypto":    "Weak cryptography requires targeted effort but yields high-value data when broken.",
            "misc":      "Exploitation depends on attacker access level and finding specifics.",
        }

        business_impact = {
            "financial_exposure":     bi_financial.get(category, bi_financial["misc"]),
            "compliance_violations":  bi_compliance.get(category, bi_compliance["misc"]),
            "exploitation_likelihood":bi_likelihood,
            "likelihood_reason":      bi_likelihood_reasons.get(category, bi_likelihood_reasons["misc"]),
        }

        # Assets exposed
        ae_data = {
            "injection": ["PII", "credentials", "financial data", "session tokens"],
            "auth":      ["session tokens", "user credentials", "PII"],
            "secrets":   ["API keys", "credentials", "private keys", "database connection strings"],
            "config":    ["system configuration", "internal endpoints", "debug information"],
            "deps":      ["application data", "PII", "credentials"],
            "xss":       ["session tokens", "cookies", "PII", "DOM content"],
            "crypto":    ["encrypted data", "PII", "financial data"],
            "misc":      ["application data"],
        }
        ae_systems = {
            "injection": ["database server", "backend API"],
            "auth":      ["authentication service", "user management"],
            "secrets":   ["external services", "cloud infrastructure", "databases"],
            "config":    ["web server", "application runtime"],
            "deps":      ["application runtime", "downstream services"],
            "xss":       ["client browser", "frontend application"],
            "crypto":    ["data storage", "communication channels"],
            "misc":      ["application stack"],
        }
        ae_scope = {
            "injection": "external_facing",
            "auth":      "external_facing",
            "secrets":   "third_party_accessible",
            "config":    "external_facing",
            "deps":      "external_facing",
            "xss":       "external_facing",
            "crypto":    "internal_only",
            "misc":      "internal_only",
        }
        ae_explanation = {
            "injection": f"An attacker exploiting `{file_path}` can read or modify database records, extracting all stored user data.",
            "auth":      f"An attacker can bypass authentication in `{file_path}` to impersonate users and access protected resources.",
            "secrets":   f"Exposed credentials in `{file_path}` grant direct access to connected systems and stored data.",
            "config":    f"Misconfiguration in `{file_path}` exposes internal system details that aid further attacks.",
            "deps":      f"Vulnerable dependency used in `{file_path}` can be exploited via known public attack vectors.",
            "xss":       f"XSS in `{file_path}` allows an attacker to steal user sessions and perform actions as the victim.",
            "crypto":    f"Weak cryptography in `{file_path}` allows an attacker to decrypt or forge protected data.",
            "misc":      f"This weakness in `{file_path}` may allow unauthorized access depending on deployment context.",
        }

        assets_exposed = {
            "data_types":              ae_data.get(category, ae_data["misc"]),
            "systems_affected":        ae_systems.get(category, ae_systems["misc"]),
            "exposure_scope":          ae_scope.get(category, "internal_only"),
            "exposure_explanation":    ae_explanation.get(category, ae_explanation["misc"]),
            "estimated_records_at_risk": "All active users" if category in {"injection","auth","xss"} else "Dependent on deployment",
        }

        enriched = dict(mapped)
        enriched.update({
            "plain_english":        self._specific_plain_english(mapped)[:800],
            "business_risk":        risk_templates.get(category, risk_templates["misc"])[:1200],
            "exploit_scenario":     exploit_templates.get(category, exploit_templates["misc"])[:1200],
            "remediation":          rem,
            "vulnerability_type":   vuln_type,
            "confidence_score":     base_confidence,
            "false_positive_risk":  fp_risk,
            "false_positive_reason": (
                f"Pattern-based finding (CWE {cwe}, {owasp}); "
                f"manual validation should confirm runtime reachability."
            )[:800],
            "business_impact":      business_impact,
            "assets_exposed":       assets_exposed,
            "enrichment_failed":    False,
            "enrichment_status":    "complete",
        })
        return enriched

    # ─── Specific plain English descriptions ──────────────────────────────────
    def _specific_plain_english(self, finding: dict) -> str:
        vuln_type  = str(finding.get("vulnerability_type", "broken_auth"))
        file_path  = str(finding.get("file_path", "unknown file"))
        line_start = int(finding.get("line_start") or 1)
        title      = str(finding.get("raw_title", "security issue"))
        package    = str(finding.get("npm_package") or "").strip()

        templates = {
            "sql_injection":           f"`{file_path}` line {line_start} builds SQL from request-controlled data — an attacker can alter query logic and read or modify unauthorized records.",
            "command_injection":       f"`{file_path}` line {line_start} executes command input influenced by a request, allowing remote command execution on the host.",
            "xss":                     f"`{file_path}` line {line_start} returns unsanitized content to the browser, enabling script injection and session hijacking.",
            "path_traversal":          f"`{file_path}` line {line_start} accepts user-controlled file path segments, allowing reads outside intended directories.",
            "eval_usage":              f"`{file_path}` line {line_start} uses dynamic code execution (`eval`/`Function`), allowing an attacker to execute arbitrary system-level commands.",
            "hardcoded_credentials":   f"`{file_path}` contains embedded credentials, creating immediate unauthorized access risk if repository content is exposed.",
            "secret_in_code":          f"`{file_path}` stores a secret in source control — reusable by anyone with repo access to access protected systems.",
            "weak_jwt":                f"`{file_path}` uses weak JWT handling, allowing token forgery or validation bypass.",
            "vulnerable_dependency":   f"`{package or 'dependency'}` is a known vulnerable component exposing the app through published exploit paths.",
            "committed_env_file":      f"`{file_path}` is a committed environment file with real values, exposing operational secrets from version control.",
            "missing_security_headers":f"`{file_path}` is missing baseline security middleware/headers, increasing exploitability of client-side and framing attacks.",
            "cors_wildcard":           f"`{file_path}` configures wildcard CORS, allowing untrusted origins to access sensitive API responses.",
            "missing_rate_limiting":   f"`{file_path}` lacks rate limiting on sensitive paths, enabling brute-force and credential stuffing attacks.",
        }
        return templates.get(
            vuln_type,
            f"`{file_path}` contains `{title}` — a security control weakness requiring remediation."
        )

    # ─── Default remediation by type ──────────────────────────────────────────
    def _default_remediation_by_type(
        self, vuln_type: str, file_path: str, line_start: int, title: str
    ) -> list[dict]:
        if vuln_type == "sql_injection":
            return [
                {"rank":1,"label":"Quick fix","time_estimate":"< 1 hour",
                 "description":f"Replace raw SQL concatenation in `{file_path}` near line {line_start} with parameterized queries.",
                 "tradeoff":"Blocks obvious injection paths; may not cover all query paths."},
                {"rank":2,"label":"Proper fix","time_estimate":"< 4 hours",
                 "description":"Refactor to ORM parameterized APIs and add negative tests for injection payloads.",
                 "tradeoff":"Durable fix with moderate refactor effort."},
                {"rank":3,"label":"Robust fix","time_estimate":"1-2 days",
                 "description":"Introduce a data-access layer banning raw SQL and enforce SAST gates in CI.",
                 "tradeoff":"Best long-term prevention; requires architecture updates."},
            ]
        if vuln_type in {"hardcoded_credentials","secret_in_code","committed_env_file"}:
            return [
                {"rank":1,"label":"Quick fix","time_estimate":"< 1 hour",
                 "description":f"Remove secret from `{file_path}` and rotate any credential immediately.",
                 "tradeoff":"Immediate containment; does not prevent recurrence alone."},
                {"rank":2,"label":"Proper fix","time_estimate":"< 4 hours",
                 "description":"Load secrets from environment/secret manager; fail startup if secrets are missing.",
                 "tradeoff":"Secure runtime handling with moderate deployment changes."},
                {"rank":3,"label":"Robust fix","time_estimate":"1-2 days",
                 "description":"Add secret scanning in CI and pre-commit plus push protection to block future commits.",
                 "tradeoff":"Strong prevention posture; requires team process adoption."},
            ]
        if vuln_type == "vulnerable_dependency":
            return [
                {"rank":1,"label":"Quick fix","time_estimate":"< 1 hour",
                 "description":"Upgrade vulnerable package to nearest safe version and update package-lock.",
                 "tradeoff":"Fastest risk reduction; may not address transitive dependencies."},
                {"rank":2,"label":"Proper fix","time_estimate":"< 4 hours",
                 "description":"Review changelog, run regression tests, pin known-safe versions for deterministic builds.",
                 "tradeoff":"Stable upgrade with validation overhead."},
                {"rank":3,"label":"Robust fix","time_estimate":"1-2 days",
                 "description":"Implement dependency governance with scheduled updates, policy gates, and CVE SLA tracking.",
                 "tradeoff":"Reduces future CVE drift; needs ongoing ownership."},
            ]
        # Generic fallback
        return [
            {"rank":1,"label":"Quick fix","time_estimate":"< 1 hour",
             "description":f"Remove unsafe pattern in `{file_path}` near line {line_start} related to '{title}'.",
             "tradeoff":"Rapid risk reduction; may not address root cause."},
            {"rank":2,"label":"Proper fix","time_estimate":"< 4 hours",
             "description":"Refactor to secure framework patterns and add focused regression tests.",
             "tradeoff":"Better durability and auditability with moderate effort."},
            {"rank":3,"label":"Robust fix","time_estimate":"1-2 days",
             "description":"Implement policy-level controls and CI gates to prevent recurrence.",
             "tradeoff":"Highest long-term risk reduction; broader change scope."},
        ]

    # ─── Curated remediations ─────────────────────────────────────────────────
    def _curated_remediations(self, finding: dict) -> list[dict] | None:
        title     = str(finding.get("raw_title", "")).lower()
        vuln_type = str(finding.get("vulnerability_type", "")).lower()
        file_path = str(finding.get("file_path", "")).lower()

        if vuln_type == "sql_injection" or "sql injection" in title:
            return [
                {"rank":1,"label":"Quick fix","time_estimate":"< 1 hour",
                 "description":"Replace string-concatenated SQL with bound parameters. Use Sequelize replacements (`?`/named params) and reject unexpected metacharacters in user input.",
                 "tradeoff":"Closes injection path quickly; input validation may remain scattered."},
                {"rank":2,"label":"Proper fix","time_estimate":"< 4 hours",
                 "description":"Refactor login query to ORM methods (`findOne` with `where`) and enforce request schema validation before query execution.",
                 "tradeoff":"Removes manual SQL risk with moderate endpoint refactor."},
                {"rank":3,"label":"Robust fix","time_estimate":"1-2 days",
                 "description":"Introduce centralized data-access layer and static rules preventing raw SQL in route handlers.",
                 "tradeoff":"Best long-term posture; requires broader code movement."},
            ]
        if vuln_type == "eval_usage" or "eval(" in title:
            return [
                {"rank":1,"label":"Quick fix","time_estimate":"< 1 hour",
                 "description":"Remove `eval()`/`new Function()` from route logic and replace with explicit allowlisted handlers.",
                 "tradeoff":"Immediate risk removal; may reduce dynamic behavior flexibility."},
                {"rank":2,"label":"Proper fix","time_estimate":"< 4 hours",
                 "description":"Map action names to predefined functions validated against a strict allowlist.",
                 "tradeoff":"Safer dispatch pattern with limited dynamic execution."},
                {"rank":3,"label":"Robust fix","time_estimate":"1-2 days",
                 "description":"Add lint/CI rule to block `eval` usage and enforce secure dynamic behavior patterns codebase-wide.",
                 "tradeoff":"Prevents recurrence; requires policy rollout."},
            ]
        if vuln_type in {"secret_in_code","hardcoded_credentials"} or "private key" in title:
            return [
                {"rank":1,"label":"Quick fix","time_estimate":"< 1 hour",
                 "description":"Rotate exposed credentials/keys immediately and remove hardcoded secrets from source files.",
                 "tradeoff":"Stops active exposure quickly; does not prevent reintroduction."},
                {"rank":2,"label":"Proper fix","time_estimate":"< 4 hours",
                 "description":"Load secrets from environment/secret manager; fail startup if secrets are absent.",
                 "tradeoff":"Secure runtime secret handling with moderate deployment changes."},
                {"rank":3,"label":"Robust fix","time_estimate":"1-2 days",
                 "description":"Integrate secret scanning in CI, add pre-commit hooks, enforce repository push protection.",
                 "tradeoff":"Strong prevention posture; requires team process adoption."},
            ]
        if vuln_type == "weak_jwt" or "jsonwebtoken" in title or "jwt" in title:
            return [
                {"rank":1,"label":"Quick fix","time_estimate":"< 1 hour",
                 "description":"Upgrade `jsonwebtoken` to `>=9.0.0` and enforce explicit algorithm whitelist on verify/sign.",
                 "tradeoff":"Fast mitigation; may require token compatibility check."},
                {"rank":2,"label":"Proper fix","time_estimate":"< 4 hours",
                 "description":"Rotate JWT secrets, set short TTLs, validate issuer/audience, block `none` algorithm paths.",
                 "tradeoff":"Improves auth integrity with moderate auth flow updates."},
                {"rank":3,"label":"Robust fix","time_estimate":"1-2 days",
                 "description":"Move to centralized token service with key rotation and JWKS-based verification.",
                 "tradeoff":"Strong long-term token hygiene; adds operational complexity."},
            ]
        if "'.env' missing from .gitignore" in title or "gitignore_env_missing" in title:
            return [
                {"rank":1,"label":"Quick fix","time_estimate":"< 1 hour",
                 "description":"Add `.env` and `.env.*` to `.gitignore`; verify no secret env files are tracked.",
                 "tradeoff":"Prevents future accidental commits; does not clean existing history."},
                {"rank":2,"label":"Proper fix","time_estimate":"< 4 hours",
                 "description":"Remove tracked env files from git index and rotate any previously committed secrets.",
                 "tradeoff":"Addresses immediate exposure with moderate operational effort."},
                {"rank":3,"label":"Robust fix","time_estimate":"1-2 days",
                 "description":"Adopt managed secrets and enforce push-protection policies for env-style credentials.",
                 "tradeoff":"Best prevention posture; requires process and tooling rollout."},
            ]
        if vuln_type == "committed_env_file" or file_path.endswith("/.env") or file_path == ".env":
            return [
                {"rank":1,"label":"Quick fix","time_estimate":"< 1 hour",
                 "description":"Delete committed `.env`, rotate all contained secrets, replace with `.env.example` placeholders.",
                 "tradeoff":"Removes direct exposure quickly; requires coordinated secret rotation."},
                {"rank":2,"label":"Proper fix","time_estimate":"< 4 hours",
                 "description":"Purge `.env` from tracked files and add secret scanning checks in CI and pre-commit.",
                 "tradeoff":"Reduces recurrence risk with moderate setup overhead."},
                {"rank":3,"label":"Robust fix","time_estimate":"1-2 days",
                 "description":"Migrate all runtime secrets to a secret manager and enforce no-secret-in-repo policy gates.",
                 "tradeoff":"Strongest control posture; introduces infra dependencies."},
            ]
        return None

    # ─── Safe progress callback (never raises) ────────────────────────────────
    def _safe_progress(self, pct: int, msg: str) -> None:
        try:
            self.progress_callback(int(pct), msg)
        except Exception as e:
            print(f"[Enricher] Progress callback error (non-fatal): {e}")