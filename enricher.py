import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any

from dotenv import load_dotenv

from soc2_controls import apply_severity_floor, get_soc2_mapping_for_finding

load_dotenv()


class EXAIEnricher:
    def __init__(self, scan_id: str, progress_callback):
        self.scan_id = scan_id
        self.progress_callback = progress_callback
        self.provider = os.getenv("EXAI_PROVIDER", "groq").strip().lower()
        self.backends: list[dict[str, Any]] = []

        configured_model = os.getenv("EXAI_MODEL", "").strip()
        model_candidates = [configured_model] if configured_model else []
        if not model_candidates:
            # Order models by reliability: smaller/simpler work better than large models
            model_candidates = [
                "llama-3.1-8b-instant",
                "mixtral-8x7b-32768",
                "llama3-70b-8192",
                "llama-3.3-70b-versatile",
            ]

        # Primary backend from EXAI_PROVIDER
        if self.provider == "groq":
            groq_key = os.getenv("EXAI_API_KEY", "").strip() or os.getenv("GROQ_API_KEY", "").strip()
            self.backends.append(
                {
                    "name": "groq",
                    "base_url": os.getenv("EXAI_BASE_URL", "").strip() or "https://api.groq.com/openai/v1",
                    "api_key": groq_key,
                    "models": model_candidates,
                    "extra_headers": {},
                }
            )
        elif self.provider == "openai":
            openai_key = os.getenv("EXAI_API_KEY", "").strip() or os.getenv("OPENAI_API_KEY", "").strip()
            self.backends.append(
                {
                    "name": "openai",
                    "base_url": os.getenv("EXAI_BASE_URL", "").strip() or "https://api.openai.com/v1",
                    "api_key": openai_key,
                    "models": [configured_model] if configured_model else ["gpt-4o-mini", "gpt-4o"],
                    "extra_headers": {},
                }
            )

        # Automatic fallback backend: OpenRouter free models (if key provided)
        openrouter_key = os.getenv("OPENROUTER_API_KEY", "").strip()
        if openrouter_key:
            or_models_raw = os.getenv(
                "EXAI_OPENROUTER_MODELS",
                "meta-llama/llama-3.1-8b-instruct:free,google/gemma-2-9b-it:free,mistralai/mistral-7b-instruct:free",
            )
            or_models = [m.strip() for m in or_models_raw.split(",") if m.strip()]
            self.backends.append(
                {
                    "name": "openrouter",
                    "base_url": "https://openrouter.ai/api/v1",
                    "api_key": openrouter_key,
                    "models": or_models,
                    "extra_headers": {
                        "HTTP-Referer": os.getenv("EXAI_OPENROUTER_REFERER", "https://securepath.local"),
                        "X-Title": "SecurePath",
                    },
                }
            )

        # Secondary fallback backend: OpenAI if key exists and not already primary
        if self.provider != "openai":
            openai_key = os.getenv("OPENAI_API_KEY", "").strip()
            if openai_key:
                self.backends.append(
                    {
                        "name": "openai",
                        "base_url": "https://api.openai.com/v1",
                        "api_key": openai_key,
                        "models": ["gpt-4o-mini", "gpt-4o"],
                        "extra_headers": {},
                    }
                )
        self.curated_mode = os.getenv("EXAI_CURATED_MODE", "true").strip().lower() in {"1", "true", "yes", "on"}

    def enrich_all(self, findings: list[dict]) -> list[dict]:
        import time
        start_time = time.time()
        print(f"[Enricher] Starting enrichment for {len(findings)} findings...")
        total = len(findings)
        if total == 0:
            self.progress_callback(100, "No findings to enrich.")
            return []

        enriched: list[dict] = []
        done = 0
        import concurrent.futures

        # Run LLM calls in parallel (up to 3 concurrently) to avoid memory/rate-limit spikes
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_to_finding = {}
            for finding in findings:
                mapped = self._apply_control_mapping(finding)
                sev = str(mapped.get("severity", "low")).lower()
                if sev in {"critical", "high"}:
                    future = executor.submit(self.enrich_finding, mapped)
                else:
                    future = executor.submit(self.template_enrichment, mapped)
                future_to_finding[future] = mapped

            for future in concurrent.futures.as_completed(future_to_finding):
                try:
                    res = future.result()
                    enriched.append(res)
                except Exception as exc:
                    mapped = future_to_finding[future]
                    fallback = self.template_enrichment(mapped)
                    fallback["enrichment_failed"] = True
                    enriched.append(fallback)
                    print(f"[SecurePath] Parallel enrichment failed for a finding: {exc}")
                
                done += 1
                pct = int((done / total) * 100)
                
                # Throttle DB updates to prevent Postgres connection exhaustion
                if done % max(1, total // 10) == 0 or done == total:
                    print(f"[Enricher] Progress: {pct}% ({done}/{total})")
                    try:
                        self.progress_callback(pct, f"Enriching finding {done}/{total} ({pct}%)...")
                    except Exception as p_exc:
                        print(f"[Enricher] Error updating progress: {p_exc}")

        enrich_time = time.time() - start_time
        print(f"[Enricher] Enrichment completed in {enrich_time:.2f}s")
        self.progress_callback(100, "AI enrichment complete (100%).")
        return enriched

    def enrich_finding(self, finding: dict) -> dict:
        import time
        start_t = time.time()
        title = finding.get('raw_title', 'unknown')[:30]
        print(f"[Enricher] Starting LLM call for finding: {title}")
        delays = [1, 2] # Reduced delays to stay within 60s
        last_error: Exception | None = None

        for attempt in range(1, 3): # Reduced to 2 attempts max
            try:
                payload = self._call_llm(finding)
                duration = time.time() - start_t
                print(f"[Enricher] LLM call succeeded for '{title}' in {duration:.2f}s (attempt {attempt})")
                return self._merge_enrichment(finding, payload, enrichment_failed=False)
            except Exception as exc:
                last_error = exc
                duration = time.time() - start_t
                print(f"[Enricher] LLM attempt {attempt} failed for '{title}' after {duration:.2f}s: {exc}")
                if attempt < 2:
                    time.sleep(delays[attempt - 1])

        print(f"[Enricher] Giving up on LLM for '{title}', falling back to template.")
        fallback = self.template_enrichment(finding)
        fallback["enrichment_failed"] = True
        # Don't append error message to false_positive_reason - keep that field for actual security findings
        # API errors are infrastructure issues, not finding-level validation
        return fallback

    def _call_llm(self, finding: dict) -> dict:
        usable_backends = [b for b in self.backends if b.get("api_key")]
        if not usable_backends:
            raise RuntimeError(
                "Missing EXAI key. Set GROQ_API_KEY (or EXAI_API_KEY), "
                "or set OPENROUTER_API_KEY/OPENAI_API_KEY for fallback."
            )

        system = """You are a principal application security engineer with 12 years 
of experience auditing Node.js applications and preparing SOC2 compliance 
evidence. You explain vulnerabilities with surgical precision. You never use 
filler phrases. Every sentence you write saves an engineer real time."""

        prompt = f"""Analyze this security finding from a Node.js/Express application:

FINDING DETAILS:
Title: {finding.get('raw_title', 'Unknown finding')}
File: {finding.get('file_path', 'Unknown file')} (lines {finding.get('line_start', 1)}-{finding.get('line_end', 1)})
Severity: {str(finding.get('severity', 'medium')).upper()}
Category: {finding.get('category', 'misc')}
CWE: {finding.get('cwe_id', 'Unknown')}
OWASP: {finding.get('owasp_category', 'Unknown')}
Code:
{finding.get('code_snippet', 'Not available')}
{f"Package: {finding.get('npm_package')}" if finding.get('npm_package') else ""}
{f"CVE: {finding.get('cve_id')}" if finding.get('cve_id') else ""}

Return ONLY a valid JSON object. No markdown fences. No preamble.
Do not include compliance controls.
Use this exact schema:

{{
  "plain_english": "One precise sentence. Name the specific file and what specifically can go wrong.",
  "remediation": [
    {{
      "rank": 1,
      "label": "Quick fix",
      "time_estimate": "< 1 hour",
      "description": "Exact code change. Show before/after if concise.",
      "tradeoff": "What this fixes and what remains."
    }},
    {{
      "rank": 2,
      "label": "Proper fix",
      "time_estimate": "< 4 hours",
      "description": "Secure pattern/library recommendation with steps.",
      "tradeoff": "Why this is better and associated cost."
    }},
    {{
      "rank": 3,
      "label": "Robust fix",
      "time_estimate": "1-2 days",
      "description": "Architectural hardening with specific packages if needed.",
      "tradeoff": "Long-term posture gain and maintenance cost."
    }}
  ],
  "business_impact": {{
    "financial_exposure": "Realistic cost if exploited - reference actual figures like average breach costs $4.4M, GDPR fines up to 4% annual revenue. Be specific to this finding type.",
    "compliance_violations": [
      {{
        "framework": "SOC2",
        "control": "CC6.1",
        "meaning": "What this control requires and how this finding violates it"
      }},
      {{
        "framework": "ISO 27001",
        "control": "A.9.4.1",
        "meaning": "What this control requires and how this finding violates it"
      }}
    ],
    "exploitation_likelihood": "low/medium/high",
    "likelihood_reason": "One sentence why, based on the specific code shown"
  }},
  "assets_exposed": {{
    "data_types": ["specific data types at risk: PII, credentials, financial data, API keys, session tokens, etc"],
    "systems_affected": ["specific systems or services at risk based on file path and code context"],
    "exposure_scope": "internal_only OR external_facing OR third_party_accessible",
    "exposure_explanation": "One sentence describing exactly what an attacker can access if this is exploited",
    "estimated_records_at_risk": "rough estimate or unknown if cannot be determined from code alone"
  }}
}}"""

        last_error: Exception | None = None
        for backend in usable_backends:
            for model in backend["models"]:
                payload = {
                    "model": model,
                    "temperature": 0.2,
                    "max_tokens": 2400,
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
                    with urllib.request.urlopen(req, timeout=15) as resp: # Reduced timeout from 60 to 15s to respect 60s total deadline
                        body = resp.read().decode("utf-8")
                    data = json.loads(body)
                    choices = data.get("choices", [])
                    if not choices:
                        raise RuntimeError("LLM response missing choices.")
                    message = choices[0].get("message", {}) or {}
                    raw = str(message.get("content", "")).strip()
                    if not raw:
                        raise RuntimeError("LLM response content was empty.")
                    raw = re.sub(r"^```json\s*", "", raw, flags=re.IGNORECASE)
                    raw = re.sub(r"^```\s*", "", raw, flags=re.IGNORECASE)
                    raw = re.sub(r"\s*```$", "", raw, flags=re.IGNORECASE)
                    return self._parse_json_object(raw)
                except urllib.error.HTTPError as exc:
                    error_body = exc.read().decode("utf-8", errors="ignore")
                    # model/provider unavailable -> try next model/backend
                    if exc.code in {400, 404, 422, 429}:
                        last_error = RuntimeError(
                            f"{backend['name']} model {model} unavailable: HTTP {exc.code}: {error_body[:220]}"
                        )
                        continue
                    if exc.code in {401, 403}:
                        # Allow trying fallback providers if this one is blocked
                        last_error = RuntimeError(
                            f"{backend['name']} auth/access blocked (HTTP {exc.code}): {error_body[:220]}"
                        )
                        continue
                    last_error = RuntimeError(
                        f"{backend['name']} model {model} HTTP {exc.code}: {error_body[:220]}"
                    )
                    continue
                except Exception as exc:
                    last_error = RuntimeError(
                        f"{backend['name']} request failed for model {model}: {exc}"
                    )
                    continue
        raise last_error or RuntimeError("All configured EXAI models failed.")

    def _parse_json_object(self, text: str) -> dict[str, Any]:
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
            raise ValueError("Response is not a JSON object")
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1 and end > start:
                parsed = json.loads(text[start : end + 1])
                if isinstance(parsed, dict):
                    return parsed
            raise

    def _apply_control_mapping(self, finding: dict) -> dict:
        mapping = get_soc2_mapping_for_finding(finding)
        severity = apply_severity_floor(
            str(finding.get("severity", "low")).lower(),
            mapping["severity_floor"],
        )
        mapped = dict(finding)
        mapped.update(
            {
                "severity": severity,
                "vulnerability_type": mapping["vulnerability_type"],
                "soc2_controls": mapping["controls"],
                "soc2_rationale": mapping["rationale"],
            }
        )
        return mapped

    def _merge_enrichment(self, finding: dict, enrichment: dict, enrichment_failed: bool) -> dict:
        merged = dict(finding)
        base = self.template_enrichment(finding)

        remediation = enrichment.get("remediation", [])
        if not isinstance(remediation, list):
            remediation = []

        # Extract business_impact from LLM response, fall back to template
        business_impact = enrichment.get("business_impact")
        if not isinstance(business_impact, dict) or not business_impact:
            business_impact = base.get("business_impact", {})

        # Extract assets_exposed from LLM response, fall back to template
        assets_exposed = enrichment.get("assets_exposed")
        if not isinstance(assets_exposed, dict) or not assets_exposed:
            assets_exposed = base.get("assets_exposed", {})

        merged.update(
            {
                "plain_english": str(enrichment.get("plain_english") or base.get("plain_english"))[:800],
                "business_risk": str(base.get("business_risk"))[:1200],
                "exploit_scenario": str(base.get("exploit_scenario"))[:1200],
                "remediation": remediation if remediation else base.get("remediation", []),
                "soc2_controls": base.get("soc2_controls", []),
                "soc2_rationale": base.get("soc2_rationale", {}),
                "vulnerability_type": base.get("vulnerability_type"),
                "confidence_score": base.get("confidence_score", 7),
                "false_positive_risk": base.get("false_positive_risk", "medium"),
                "false_positive_reason": str(base.get("false_positive_reason"))[:800],
                "business_impact": business_impact,
                "assets_exposed": assets_exposed,
                "enrichment_failed": enrichment_failed,
                "enrichment_status": "failed" if enrichment_failed else "complete",
            }
        )
        return merged

    def template_enrichment(self, finding: dict) -> dict:
        mapped = self._apply_control_mapping(finding)
        category = str(mapped.get("category", "misc")).lower()
        severity = str(mapped.get("severity", "medium")).lower()
        vuln_type = str(mapped.get("vulnerability_type", "broken_auth"))
        title = str(mapped.get("raw_title", "Security issue detected"))
        file_path = str(mapped.get("file_path", "unknown file"))
        line_start = mapped.get("line_start", 1)
        cwe = mapped.get("cwe_id", "Unknown")
        owasp = mapped.get("owasp_category", "A05:2021 - Security Misconfiguration")

        risk_templates = {
            "injection": "An attacker could execute unauthorized database or command operations, leading to data exposure and potential system compromise.",
            "auth": "Authentication or access control weaknesses can allow account takeover, unauthorized access to customer data, and control failures.",
            "secrets": "Leaked credentials or keys can enable direct unauthorized access to systems and regulated data.",
            "config": "Security misconfiguration can increase attack surface and weaken baseline controls required for SOC2 evidence.",
            "deps": "Vulnerable dependencies can introduce known exploits into production, creating externally documented attack paths.",
            "xss": "Cross-site scripting can allow session theft, unauthorized actions, and compromise of user trust.",
            "crypto": "Weak cryptographic handling can expose sensitive data and undermine confidentiality controls.",
            "misc": "This issue weakens security posture and requires remediation evidence before audit submission.",
        }
        exploit_templates = {
            "injection": "An attacker sends crafted input that is executed as part of a query or command. This can allow data extraction or destructive modification without authorization.",
            "auth": "An attacker manipulates authentication or session flow to impersonate another user. This can lead to unauthorized actions under valid user context.",
            "secrets": "An attacker discovers embedded credentials in source or deployment artifacts. They then use those credentials to access internal systems or data stores.",
            "config": "An attacker exploits insecure defaults or exposed settings in runtime configuration. This creates easier privilege escalation or data exposure paths.",
            "deps": "An attacker targets a known CVE in an outdated package version. Public exploit techniques can be adapted quickly against exposed routes.",
            "xss": "An attacker injects script payloads into user-accessible pages. The payload executes in victim browsers and can exfiltrate session tokens.",
            "crypto": "An attacker abuses weak key management or unsafe cryptographic parameters. This can make protected data recoverable or forgeable.",
            "misc": "An attacker leverages this weakness together with routine probing. The resulting access can impact confidentiality, integrity, or availability.",
        }

        rem = self._default_remediation_by_type(vuln_type, file_path, line_start, title)
        curated = self._curated_remediations(mapped)
        if self.curated_mode and curated:
            rem = curated

        fp_risk = "low" if severity in {"critical", "high"} else "medium"

        base_confidence = 8 if severity in {"critical", "high"} else 6
        if category == "secrets":
            base_confidence = min(base_confidence, 6)

        # Build default business_impact based on category/severity
        bi_financial_templates = {
            "injection": "SQL injection breaches average $4.4M in remediation costs (IBM 2023). GDPR fines up to 4% annual revenue if PII is exfiltrated. Regulatory notification costs add $150-$200 per affected record.",
            "auth": "Account takeover incidents cost $4.2M on average. Credential stuffing losses average $6M annually per enterprise. SOC2 audit failure can delay revenue-generating contracts.",
            "secrets": "Exposed credentials lead to unauthorized access costing $4.4M average per breach. Key rotation and incident response costs range $50K-$500K depending on exposure window.",
            "config": "Misconfiguration-related breaches cost $3.9M on average. Cloud misconfigurations account for 15% of initial attack vectors.",
            "deps": "Vulnerable dependency exploitation costs average $4.1M per incident. Supply chain attacks increased 742% in recent years.",
            "xss": "XSS-driven session hijacking can lead to full account takeover. Average cost of web application attacks is $3.8M per incident.",
            "crypto": "Cryptographic failures expose regulated data. GDPR fines up to €20M or 4% global revenue, whichever is higher.",
            "misc": "Security control weaknesses increase overall breach probability. Average breach cost is $4.4M with 277-day mean detection time.",
        }
        bi_compliance_templates = {
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
        bi_likelihood = "high" if severity in {"critical"} else ("medium" if severity in {"high"} else "low")
        bi_likelihood_reason_templates = {
            "injection": "Injection endpoints are actively targeted by automated scanners and require no authentication to exploit.",
            "auth": "Authentication bypasses are commonly exploited via credential stuffing and session manipulation.",
            "secrets": "Committed secrets are discoverable by automated GitHub/GitLab scanning bots within minutes of push.",
            "config": "Misconfigured services are indexed by Shodan and similar reconnaissance tools.",
            "deps": "Public CVEs have known exploit code and are targeted by automated vulnerability scanners.",
            "xss": "XSS payloads can be delivered via social engineering or injected into stored content.",
            "crypto": "Weak cryptography requires targeted effort but yields high-value data when broken.",
            "misc": "Exploitation depends on attacker access level and finding specifics.",
        }

        business_impact = {
            "financial_exposure": bi_financial_templates.get(category, bi_financial_templates["misc"]),
            "compliance_violations": bi_compliance_templates.get(category, bi_compliance_templates["misc"]),
            "exploitation_likelihood": bi_likelihood,
            "likelihood_reason": bi_likelihood_reason_templates.get(category, bi_likelihood_reason_templates["misc"]),
        }

        # Build default assets_exposed based on category
        ae_data_types_templates = {
            "injection": ["PII", "credentials", "financial data", "session tokens"],
            "auth": ["session tokens", "user credentials", "PII"],
            "secrets": ["API keys", "credentials", "private keys", "database connection strings"],
            "config": ["system configuration", "internal endpoints", "debug information"],
            "deps": ["application data", "PII", "credentials"],
            "xss": ["session tokens", "cookies", "PII", "DOM content"],
            "crypto": ["encrypted data", "PII", "financial data"],
            "misc": ["application data"],
        }
        ae_systems_templates = {
            "injection": ["database server", "backend API"],
            "auth": ["authentication service", "user management"],
            "secrets": ["external services", "cloud infrastructure", "databases"],
            "config": ["web server", "application runtime"],
            "deps": ["application runtime", "downstream services"],
            "xss": ["client browser", "frontend application"],
            "crypto": ["data storage", "communication channels"],
            "misc": ["application stack"],
        }
        ae_scope_map = {
            "injection": "external_facing",
            "auth": "external_facing",
            "secrets": "third_party_accessible",
            "config": "external_facing",
            "deps": "external_facing",
            "xss": "external_facing",
            "crypto": "internal_only",
            "misc": "internal_only",
        }
        ae_explanation_templates = {
            "injection": f"An attacker exploiting `{file_path}` can read or modify database records, potentially extracting all stored user data.",
            "auth": f"An attacker can bypass authentication in `{file_path}` to impersonate users and access their protected resources.",
            "secrets": f"Exposed credentials in `{file_path}` grant direct access to connected systems and stored data.",
            "config": f"Misconfiguration in `{file_path}` exposes internal system details that aid further attacks.",
            "deps": f"Vulnerable dependency used in `{file_path}` can be exploited via known public attack vectors.",
            "xss": f"XSS in `{file_path}` allows an attacker to steal user sessions and perform actions as the victim.",
            "crypto": f"Weak cryptography in `{file_path}` allows an attacker to decrypt or forge protected data.",
            "misc": f"This weakness in `{file_path}` may allow unauthorized access depending on deployment context.",
        }

        assets_exposed = {
            "data_types": ae_data_types_templates.get(category, ae_data_types_templates["misc"]),
            "systems_affected": ae_systems_templates.get(category, ae_systems_templates["misc"]),
            "exposure_scope": ae_scope_map.get(category, "internal_only"),
            "exposure_explanation": ae_explanation_templates.get(category, ae_explanation_templates["misc"]),
            "estimated_records_at_risk": "unknown",
        }

        enriched = dict(mapped)
        enriched.update(
            {
                "plain_english": self._specific_plain_english(mapped)[:800],
                "business_risk": risk_templates.get(category, risk_templates["misc"])[:1200],
                "exploit_scenario": exploit_templates.get(category, exploit_templates["misc"])[:1200],
                "remediation": rem,
                "vulnerability_type": vuln_type,
                "confidence_score": base_confidence,
                "false_positive_risk": fp_risk,
                "false_positive_reason": (
                    f"The finding is pattern-based (CWE {cwe}, {owasp}); manual validation should confirm runtime reachability and exploitability."
                )[:800],
                "business_impact": business_impact,
                "assets_exposed": assets_exposed,
                "enrichment_failed": False,
                "enrichment_status": "complete",
            }
        )
        return enriched

    def _specific_plain_english(self, finding: dict[str, Any]) -> str:
        vuln_type = str(finding.get("vulnerability_type", "broken_auth"))
        file_path = str(finding.get("file_path", "unknown file"))
        line_start = int(finding.get("line_start") or 1)
        title = str(finding.get("raw_title", "security issue"))
        package = str(finding.get("npm_package") or "").strip()

        templates = {
            "sql_injection": f"`{file_path}` line {line_start} builds SQL from request-controlled data, so an attacker can alter query logic and read or modify unauthorized records.",
            "command_injection": f"`{file_path}` line {line_start} executes command input that can be influenced by a request, allowing remote command execution on the host.",
            "xss": f"`{file_path}` line {line_start} can return unsanitized content to the browser, enabling script injection and session hijacking.",
            "path_traversal": f"`{file_path}` line {line_start} accepts user-controlled file path segments, allowing reads outside intended directories.",
            "eval_usage": f"`{file_path}` line {line_start} uses dynamic code execution (`eval`/`Function`), which can execute attacker-supplied payloads.",
            "hardcoded_credentials": f"`{file_path}` contains embedded credentials or private key material, creating immediate unauthorized access risk if repository content is exposed.",
            "secret_in_code": f"`{file_path}` stores a secret directly in source control, which can be reused to access protected systems and data.",
            "weak_jwt": f"`{file_path}` relies on weak JWT handling or outdated JWT library behavior, allowing token forgery or validation bypass.",
            "vulnerable_dependency": f"`{package or 'dependency'}` in `package.json` is a known vulnerable component and can expose the app through published exploit paths.",
            "committed_env_file": f"`{file_path}` is a committed environment file with real values, exposing operational secrets directly from version control.",
            "missing_security_headers": f"`{file_path}` is missing baseline security middleware/headers, increasing exploitability of client-side and framing attacks.",
            "cors_wildcard": f"`{file_path}` configures wildcard CORS, allowing untrusted origins to access sensitive API responses.",
            "missing_rate_limiting": f"`{file_path}` lacks rate limiting on sensitive paths, enabling brute-force and credential stuffing attacks.",
        }
        return templates.get(vuln_type, f"`{file_path}` contains `{title}`, which is a security control weakness that should be remediated.")

    def _default_remediation_by_type(self, vuln_type: str, file_path: str, line_start: int, title: str) -> list[dict[str, Any]]:
        if vuln_type == "sql_injection":
            return [
                {
                    "rank": 1,
                    "label": "Quick fix",
                    "time_estimate": "< 1 hour",
                    "description": f"In `{file_path}` near line {line_start}, replace raw query interpolation with parameter binding and reject unexpected input patterns.",
                    "tradeoff": "Rapidly blocks obvious payloads but may not cover all unsafe query paths.",
                },
                {
                    "rank": 2,
                    "label": "Proper fix",
                    "time_estimate": "< 4 hours",
                    "description": "Refactor to ORM/query-builder parameterized APIs (`where`, replacements, bind params) and add negative tests for injection payloads.",
                    "tradeoff": "Durable fix with moderate endpoint refactor effort.",
                },
                {
                    "rank": 3,
                    "label": "Robust fix",
                    "time_estimate": "1-2 days",
                    "description": "Introduce a data-access layer banning raw SQL in handlers and enforce SAST/lint gates for SQL concatenation in CI.",
                    "tradeoff": "Best long-term prevention; requires architecture and policy updates.",
                },
            ]
        if vuln_type in {"hardcoded_credentials", "secret_in_code", "committed_env_file"}:
            return [
                {
                    "rank": 1,
                    "label": "Quick fix",
                    "time_estimate": "< 1 hour",
                    "description": f"Remove secret material from `{file_path}` and rotate any credential/key that may have been exposed.",
                    "tradeoff": "Immediate containment; does not prevent recurrence by itself.",
                },
                {
                    "rank": 2,
                    "label": "Proper fix",
                    "time_estimate": "< 4 hours",
                    "description": "Load secrets from environment/secret manager and fail startup if required secrets are missing.",
                    "tradeoff": "Secure runtime handling with moderate deployment changes.",
                },
                {
                    "rank": 3,
                    "label": "Robust fix",
                    "time_estimate": "1-2 days",
                    "description": "Add secret scanning in CI and pre-commit plus push protection to block future committed secrets.",
                    "tradeoff": "Strong prevention posture; requires team process adoption.",
                },
            ]
        if vuln_type == "vulnerable_dependency":
            return [
                {
                    "rank": 1,
                    "label": "Quick fix",
                    "time_estimate": "< 1 hour",
                    "description": "Upgrade vulnerable package to the nearest safe patch/minor version and lock via package-lock.",
                    "tradeoff": "Fastest risk reduction but may not address transitive risk comprehensively.",
                },
                {
                    "rank": 2,
                    "label": "Proper fix",
                    "time_estimate": "< 4 hours",
                    "description": "Review changelog, run regression tests, and pin known-safe dependency versions for deterministic builds.",
                    "tradeoff": "More stable upgrade with validation cost.",
                },
                {
                    "rank": 3,
                    "label": "Robust fix",
                    "time_estimate": "1-2 days",
                    "description": "Implement dependency governance (scheduled updates + policy gates + CVE SLA tracking).",
                    "tradeoff": "Reduces future CVE drift but needs ongoing ownership.",
                },
            ]
        return [
            {
                "rank": 1,
                "label": "Quick fix",
                "time_estimate": "< 1 hour",
                "description": f"Contain immediate risk in `{file_path}` near line {line_start}: remove unsafe pattern related to '{title}'.",
                "tradeoff": "Rapid reduction in exposure, but may not address systemic root causes.",
            },
            {
                "rank": 2,
                "label": "Proper fix",
                "time_estimate": "< 4 hours",
                "description": "Refactor to secure framework patterns and add focused regression tests.",
                "tradeoff": "Better durability and auditability with moderate engineering effort.",
            },
            {
                "rank": 3,
                "label": "Robust fix",
                "time_estimate": "1-2 days",
                "description": "Implement policy-level controls and CI gates to prevent recurrence.",
                "tradeoff": "Highest long-term reduction in recurring risk with broader change scope.",
            },
        ]

    def _curated_remediations(self, finding: dict[str, Any]) -> list[dict[str, Any]] | None:
        title = str(finding.get("raw_title", "")).lower()
        vuln_type = str(finding.get("vulnerability_type", "")).lower()
        file_path = str(finding.get("file_path", "")).lower()

        if vuln_type == "sql_injection" or "sql injection" in title:
            return [
                {
                    "rank": 1,
                    "label": "Quick fix",
                    "time_estimate": "< 1 hour",
                    "description": "Replace string-concatenated SQL with bound parameters immediately. In `routes/login.ts`, use Sequelize replacements (`?`/named params) and reject unexpected metacharacters in user input.",
                    "tradeoff": "Closes injection path quickly, but input validation might remain scattered.",
                },
                {
                    "rank": 2,
                    "label": "Proper fix",
                    "time_estimate": "< 4 hours",
                    "description": "Refactor login query to ORM methods (`findOne` with `where`) and enforce request schema validation before query execution.",
                    "tradeoff": "Removes manual SQL risk with moderate endpoint refactor.",
                },
                {
                    "rank": 3,
                    "label": "Robust fix",
                    "time_estimate": "1-2 days",
                    "description": "Introduce a centralized data-access layer and static rules preventing raw SQL in route handlers.",
                    "tradeoff": "Best long-term posture, requires broader code movement.",
                },
            ]

        if vuln_type == "eval_usage" or "eval(" in title:
            return [
                {
                    "rank": 1,
                    "label": "Quick fix",
                    "time_estimate": "< 1 hour",
                    "description": "Remove `eval()`/`new Function()` from route logic and replace with explicit allowlisted handlers.",
                    "tradeoff": "Immediate risk removal; may reduce dynamic behavior flexibility.",
                },
                {
                    "rank": 2,
                    "label": "Proper fix",
                    "time_estimate": "< 4 hours",
                    "description": "Map action names to predefined functions and validate against a strict allowlist.",
                    "tradeoff": "Safer dispatch pattern with limited dynamic execution.",
                },
                {
                    "rank": 3,
                    "label": "Robust fix",
                    "time_estimate": "1-2 days",
                    "description": "Add lint/CI rule to block `eval` usage and enforce secure dynamic behavior patterns.",
                    "tradeoff": "Prevents recurrence across the codebase; requires policy rollout.",
                },
            ]

        if vuln_type in {"secret_in_code", "hardcoded_credentials"} or "private key" in title:
            return [
                {
                    "rank": 1,
                    "label": "Quick fix",
                    "time_estimate": "< 1 hour",
                    "description": "Rotate exposed credentials/keys immediately and remove hardcoded secrets from source files.",
                    "tradeoff": "Stops active exposure quickly; does not prevent reintroduction.",
                },
                {
                    "rank": 2,
                    "label": "Proper fix",
                    "time_estimate": "< 4 hours",
                    "description": "Load secrets from environment/secret manager and fail startup if required secrets are missing.",
                    "tradeoff": "Secure runtime secret handling with moderate deployment changes.",
                },
                {
                    "rank": 3,
                    "label": "Robust fix",
                    "time_estimate": "1-2 days",
                    "description": "Integrate secret scanning in CI, add pre-commit hooks, and enforce repository push protection.",
                    "tradeoff": "Strong prevention posture; requires team process adoption.",
                },
            ]

        if vuln_type == "weak_jwt" or "jsonwebtoken" in title or "jwt" in title:
            return [
                {
                    "rank": 1,
                    "label": "Quick fix",
                    "time_estimate": "< 1 hour",
                    "description": "Upgrade `jsonwebtoken` to `>=9.0.0` and enforce explicit algorithm whitelist during verify/sign.",
                    "tradeoff": "Fast mitigation; may require token compatibility check.",
                },
                {
                    "rank": 2,
                    "label": "Proper fix",
                    "time_estimate": "< 4 hours",
                    "description": "Rotate JWT secrets, set short token TTLs, validate issuer/audience, and block `none` algorithm paths.",
                    "tradeoff": "Improves auth integrity with moderate auth flow updates.",
                },
                {
                    "rank": 3,
                    "label": "Robust fix",
                    "time_estimate": "1-2 days",
                    "description": "Move to centralized token service with key rotation and JWKS-based verification.",
                    "tradeoff": "Strong long-term token hygiene; added operational complexity.",
                },
            ]

        if "'.env' missing from .gitignore" in title or "gitignore_env_missing" in title:
            return [
                {
                    "rank": 1,
                    "label": "Quick fix",
                    "time_estimate": "< 1 hour",
                    "description": "Add `.env` and `.env.*` to `.gitignore` and verify no secret env files are tracked.",
                    "tradeoff": "Prevents future accidental commits; does not clean existing history.",
                },
                {
                    "rank": 2,
                    "label": "Proper fix",
                    "time_estimate": "< 4 hours",
                    "description": "Remove tracked env files from git index and rotate any previously committed secrets.",
                    "tradeoff": "Addresses immediate exposure with moderate operational effort.",
                },
                {
                    "rank": 3,
                    "label": "Robust fix",
                    "time_estimate": "1-2 days",
                    "description": "Adopt managed secrets and enforce push-protection policies for env-style credentials.",
                    "tradeoff": "Best prevention posture with process/tooling rollout.",
                },
            ]

        if vuln_type == "committed_env_file" or file_path.endswith("/.env") or file_path == ".env":
            return [
                {
                    "rank": 1,
                    "label": "Quick fix",
                    "time_estimate": "< 1 hour",
                    "description": "Delete committed `.env` from repository, rotate all contained secrets immediately, and replace with `.env.example` placeholders.",
                    "tradeoff": "Removes direct exposure quickly but requires coordinated secret rotation.",
                },
                {
                    "rank": 2,
                    "label": "Proper fix",
                    "time_estimate": "< 4 hours",
                    "description": "Purge `.env` from tracked files and add secret scanning checks in CI and pre-commit.",
                    "tradeoff": "Reduces recurrence risk with moderate setup overhead.",
                },
                {
                    "rank": 3,
                    "label": "Robust fix",
                    "time_estimate": "1-2 days",
                    "description": "Migrate all runtime secrets to a secret manager and enforce no-secret-in-repo policy gates.",
                    "tradeoff": "Strongest control posture; introduces infra dependencies.",
                },
            ]

        return None
