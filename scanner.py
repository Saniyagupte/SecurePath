import json
import os
import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from git import Repo
from git.exc import GitCommandError

from db import update_scan


@dataclass
class ScanProgress:
    progress: int
    step: str


class SecurityScanner:
    def __init__(self, repo_url: str, scan_id: str, progress_callback: Callable[[int, str], None]):
        self.repo_url = repo_url
        self.scan_id = scan_id
        self.progress_callback = progress_callback
        self.repo_path: Path | None = None
        self.commit_sha: str | None = None

        self.cwe_map = {
            "sql": "CWE-89",
            "sqli": "CWE-89",
            "injection": "CWE-89",
            "xss": "CWE-79",
            "jwt": "CWE-347",
            "auth": "CWE-287",
            "session": "CWE-384",
            "secrets": "CWE-798",
            "hardcoded": "CWE-798",
            "crypto": "CWE-327",
            "path-traversal": "CWE-22",
            "lfi": "CWE-22",
            "csrf": "CWE-352",
            "ssrf": "CWE-918",
            "command": "CWE-78",
            "exec": "CWE-78",
            "eval": "CWE-95",
            "redirect": "CWE-601",
            "cors": "CWE-942",
            "deserialization": "CWE-502",
            "xxe": "CWE-611",
            "rate-limit": "CWE-770",
        }

        self.secret_patterns = {
            "aws_access_key": (
                re.compile(r"AKIA[0-9A-Z]{16}"),
                "critical",
                "CWE-798",
                "A02:2021 - Cryptographic Failures",
            ),
            "aws_secret_key": (
                re.compile(r"(?i)aws.{0,20}secret.{0,20}[=:].{0,5}[\"'][A-Za-z0-9/+]{40}"),
                "critical",
                "CWE-798",
                "A02:2021 - Cryptographic Failures",
            ),
            "generic_api_key": (
                re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*[\"'][a-zA-Z0-9_\-]{20,}[\"']"),
                "high",
                "CWE-798",
                "A02:2021 - Cryptographic Failures",
            ),
            "hardcoded_password": (
                re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"'][^\"']{6,}[\"']"),
                "high",
                "CWE-259",
                "A07:2021 - Identification Failures",
            ),
            "jwt_secret": (
                re.compile(r"(?i)(jwt.?secret|token.?secret|secret.?key)\s*[:=]\s*[\"'][^\"']{8,}"),
                "critical",
                "CWE-798",
                "A02:2021 - Cryptographic Failures",
            ),
            "private_key_header": (
                re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----"),
                "critical",
                "CWE-321",
                "A02:2021 - Cryptographic Failures",
            ),
            "db_connection_with_creds": (
                re.compile(r"(?i)(mongodb|mysql|postgres|sqlite)://[^:]+:[^@]+@"),
                "critical",
                "CWE-312",
                "A02:2021 - Cryptographic Failures",
            ),
            "bearer_token": (
                re.compile(r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]{20,}={0,2}"),
                "medium",
                "CWE-522",
                "A02:2021 - Cryptographic Failures",
            ),
        }

        self.structure_patterns = [
            {
                "name": "Possible SQL injection with template literal interpolation",
                "regex": re.compile(r"(query|execute|sequelize\.query)\s*\(\s*[`\"'][^`\"']*\$\{"),
                "severity": "critical",
                "cwe_id": "CWE-89",
                "owasp": "A03:2021 - Injection",
                "category": "injection",
            },
            {
                "name": "Possible SQL injection via string concatenation",
                "regex": re.compile(
                    r"(query|execute)\s*\(\s*[\"'`][^\"'`]*(WHERE|SELECT|INSERT|UPDATE|DELETE)[^\"'`]*\+\s*",
                    re.IGNORECASE,
                ),
                "severity": "critical",
                "cwe_id": "CWE-89",
                "owasp": "A03:2021 - Injection",
                "category": "injection",
            },
            {
                "name": "Use of eval() is dangerous",
                "regex": re.compile(r"\beval\s*\("),
                "severity": "high",
                "cwe_id": "CWE-95",
                "owasp": "A03:2021 - Injection",
                "category": "injection",
                "exclude_comment_line": True,
            },
            {
                "name": "Use of Function constructor is dangerous",
                "regex": re.compile(r"\bnew\s+Function\s*\("),
                "severity": "high",
                "cwe_id": "CWE-95",
                "owasp": "A03:2021 - Injection",
                "category": "injection",
                "exclude_comment_line": True,
            },
            {
                "name": "Unvalidated child_process execution from request data",
                "regex": re.compile(r"child_process\.(exec|execSync|spawn)\s*\([^)]*req\."),
                "severity": "critical",
                "cwe_id": "CWE-78",
                "owasp": "A03:2021 - Injection",
                "category": "injection",
            },
            {
                "name": "Potential path traversal from request input",
                "regex": re.compile(r"(readFile|readFileSync|createReadStream)\s*\([^)]*req\.(params|query|body)"),
                "severity": "high",
                "cwe_id": "CWE-22",
                "owasp": "A01:2021 - Broken Access Control",
                "category": "auth",
            },
            {
                "name": "Potential open redirect from user input",
                "regex": re.compile(r"res\.(redirect|location)\s*\([^)]*req\.(params|query|body)"),
                "severity": "medium",
                "cwe_id": "CWE-601",
                "owasp": "A01:2021 - Broken Access Control",
                "category": "auth",
            },
            {
                "name": "CORS wildcard origin detected",
                "regex": re.compile(r"cors\s*\(\s*\{[^}]*origin\s*:\s*[\"'`]\*[\"'`]"),
                "severity": "medium",
                "cwe_id": "CWE-942",
                "owasp": "A05:2021 - Security Misconfiguration",
                "category": "config",
            },
            {
                "name": "Access-Control-Allow-Origin wildcard detected",
                "regex": re.compile(r"Access-Control-Allow-Origin['\"]?\s*[:]\s*['\"]?\*"),
                "severity": "medium",
                "cwe_id": "CWE-942",
                "owasp": "A05:2021 - Security Misconfiguration",
                "category": "config",
            },
            {
                "name": "Insecure cookie/session configuration (missing secure/httpOnly)",
                "regex": re.compile(r"(session|cookie)\s*\(\s*\{[^}]*\}", re.IGNORECASE),
                "severity": "medium",
                "cwe_id": "CWE-614",
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "category": "auth",
                "cookie_check": True,
            },
        ]
        self.skip_dirs_common = {"node_modules", ".git", "dist", "build", "coverage"}
        self.test_dir_markers = ("/test/", "/tests/", "/spec/", "/cypress/", "/__tests__/")
        self.test_file_suffixes = (
            ".spec.ts",
            ".test.ts",
            ".spec.js",
            ".test.js",
            "_spec.ts",
            "_test.ts",
            "_spec.js",
            "_test.js",
        )
        self.intentional_sample_markers = ("/data/static/codefixes/",)

    def _progress(self, p: int, step: str) -> None:
        p = max(0, min(100, int(p)))
        self.progress_callback(p, step)

    def run(self) -> list[dict[str, Any]]:
        all_findings: list[dict[str, Any]] = []
        cloned_path: Path | None = None
        try:
            self._progress(2, "Cloning repository...")
            cloned_path = Path(self.clone_repo(self.repo_url))
            self.repo_path = cloned_path
            self._progress(15, "Repository cloned. Starting SAST analysis...")

            pass1 = self._run_semgrep_pass()
            all_findings.extend(pass1)
            self._progress(35, "SAST completed. Running dependency audit...")

            pass2 = self._run_dependency_pass()
            all_findings.extend(pass2)
            self._progress(50, "Dependency audit completed. Scanning for secrets...")

            pass3 = self._run_secret_pass()
            all_findings.extend(pass3)
            self._progress(65, "Secret scanning completed. Running structural analysis...")

            pass4 = self._run_structural_pass()
            all_findings.extend(pass4)
            self._progress(80, "Structural analysis completed. Auditing config files...")

            pass5 = self._run_config_pass()
            all_findings.extend(pass5)
            self._progress(95, "Config audit completed. Deduplicating findings...")

            deduped = self._deduplicate_findings(all_findings)
            self._progress(100, "Scan complete.")
            return deduped
        finally:
            if cloned_path and cloned_path.exists():
                shutil.rmtree(cloned_path, ignore_errors=True)

    def clone_repo(self, repo_url: str) -> str:
        target = Path(f"/tmp/securepath_{self.scan_id}")
        if os.name == "nt":
            target = Path(os.getenv("TEMP", ".")) / f"securepath_{self.scan_id}"
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)

        try:
            Repo.clone_from(repo_url, str(target), depth=1)
            repo = Repo(str(target))
            self.commit_sha = repo.head.commit.hexsha
            update_scan(self.scan_id, commit_sha=self.commit_sha, status="scanning")
            return str(target)
        except GitCommandError as exc:
            message = str(exc).lower()
            if "not found" in message:
                raise RuntimeError("Repo not found") from exc
            if "authentication" in message or "permission denied" in message:
                raise RuntimeError("Not public or access denied") from exc
            if "repository" in message and "does not exist" in message:
                raise RuntimeError("Repo not found") from exc
            raise RuntimeError(f"Clone failed: {exc}") from exc
        except Exception as exc:
            raise RuntimeError(f"Clone failed: {exc}") from exc

    def _run_semgrep_pass(self) -> list[dict[str, Any]]:
        if not self.repo_path:
            return []

        self._ensure_semgrep()
        findings: list[dict[str, Any]] = []

        commands = [
            [
                "semgrep",
                "--config=p/nodejs",
                "--config=p/owasp-top-ten",
                "--config=p/secrets",
                "--json",
                "--quiet",
                str(self.repo_path),
            ],
            [
                "semgrep",
                "--config=p/javascript",
                "--json",
                "--quiet",
                str(self.repo_path),
            ],
        ]

        for cmd in commands:
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
                parsed = json.loads(proc.stdout or "{}")
                results = parsed.get("results", [])
                for r in results:
                    finding = self._convert_semgrep_result(r)
                    if finding:
                        findings.append(finding)
            except json.JSONDecodeError:
                continue
            except Exception:
                continue

        return findings

    def _ensure_semgrep(self) -> None:
        try:
            check = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                check=False,
            )
            if check.returncode == 0:
                return
        except FileNotFoundError:
            pass
        subprocess.run(["pip", "install", "semgrep", "-q"], capture_output=True, text=True, check=False)

    def _convert_semgrep_result(self, result: dict[str, Any]) -> dict[str, Any] | None:
        if not self.repo_path:
            return None

        path_val = result.get("path")
        if not path_val:
            return None

        start = result.get("start", {}) or {}
        end = result.get("end", {}) or {}
        line_start = int(start.get("line", 1))
        line_end = int(end.get("line", line_start))
        rule_id = str(result.get("check_id", "semgrep-rule"))
        extra = result.get("extra", {}) or {}
        message = str(extra.get("message", rule_id))
        semgrep_sev = str(extra.get("severity", "INFO")).upper()
        metadata = extra.get("metadata", {}) or {}

        severity = {
            "ERROR": "critical",
            "WARNING": "high",
            "INFO": "medium",
        }.get(semgrep_sev, "medium")

        rel_path = str(Path(path_val).as_posix())
        if os.path.isabs(path_val):
            try:
                rel_path = str(Path(path_val).resolve().relative_to(self.repo_path.resolve()).as_posix())
            except Exception:
                rel_path = str(Path(path_val).name)
        if self._is_intentional_sample_path(rel_path):
            return None

        owasp = self._map_owasp_from_rule(rule_id)
        cwe = self._map_cwe_from_rule(rule_id)
        category = self._map_category_from_rule(rule_id)

        cwe_from_meta = metadata.get("cwe")
        if isinstance(cwe_from_meta, list) and cwe_from_meta:
            cwe = str(cwe_from_meta[0]).replace("CWE-", "CWE-")
        elif isinstance(cwe_from_meta, str) and cwe_from_meta.strip():
            cwe = cwe_from_meta.strip()

        snippet = self._extract_snippet(self.repo_path / rel_path, line_start, line_end)

        return {
            "id": str(uuid.uuid4()),
            "pass_name": "sast",
            "file_path": rel_path,
            "line_start": line_start,
            "line_end": line_end,
            "severity": severity,
            "category": category,
            "raw_title": message[:200],
            "code_snippet": snippet[:300],
            "cve_id": None,
            "cwe_id": cwe,
            "owasp_category": owasp,
            "npm_package": None,
            "plain_english": None,
            "business_risk": None,
            "exploit_scenario": None,
            "remediation_json": None,
            "soc2_controls": None,
            "confidence_score": None,
            "false_positive_risk": None,
            "false_positive_reason": None,
            "enrichment_status": "pending",
        }

    def _run_dependency_pass(self) -> list[dict[str, Any]]:
        if not self.repo_path:
            return []

        findings: list[dict[str, Any]] = []
        pkg_json = self.repo_path / "package.json"
        lock_json = self.repo_path / "package-lock.json"
        if not pkg_json.exists():
            return findings

        if lock_json.exists():
            try:
                proc = subprocess.run(
                    ["npm", "audit", "--json"],
                    cwd=str(self.repo_path),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                output = proc.stdout or "{}"
                audit_json = json.loads(output)
                vulns = audit_json.get("vulnerabilities", {}) or {}
                for package_name, vuln in vulns.items():
                    findings.extend(self._convert_npm_audit_vuln(package_name, vuln))
            except Exception:
                pass

        findings.extend(self._check_manual_bad_versions(pkg_json))
        return findings

    def _convert_npm_audit_vuln(self, package_name: str, vuln: dict[str, Any]) -> list[dict[str, Any]]:
        severity = str(vuln.get("severity", "medium")).lower()
        severity = severity if severity in {"critical", "high", "medium", "low"} else "medium"
        via = vuln.get("via", [])
        range_spec = str(vuln.get("range", ""))
        fix_available = vuln.get("fixAvailable")
        title = f"Vulnerable dependency: {package_name}"
        cve_id = None
        cwe_id = "CWE-1104"
        owasp = "A06:2021 - Vulnerable and Outdated Components"

        detail_parts: list[str] = []
        if isinstance(via, list):
            for item in via:
                if isinstance(item, dict):
                    source = item.get("source")
                    if source and not cve_id and str(source).upper().startswith("GHSA"):
                        cve_id = str(source)
                    if item.get("url"):
                        detail_parts.append(str(item["url"]))
                    if item.get("title"):
                        detail_parts.append(str(item["title"]))
                    if item.get("cwe"):
                        cwe_val = item["cwe"]
                        if isinstance(cwe_val, list) and cwe_val:
                            cwe_id = str(cwe_val[0])
                        elif isinstance(cwe_val, str):
                            cwe_id = cwe_val
                elif isinstance(item, str):
                    detail_parts.append(item)

        code_snippet = f"range={range_spec}; fixAvailable={fix_available}; details={' | '.join(detail_parts)[:180]}"
        return [
            {
                "id": str(uuid.uuid4()),
                "pass_name": "deps",
                "file_path": "package.json",
                "line_start": 1,
                "line_end": 1,
                "severity": severity,
                "category": "deps",
                "raw_title": title,
                "code_snippet": code_snippet[:300],
                "cve_id": cve_id,
                "cwe_id": cwe_id,
                "owasp_category": owasp,
                "npm_package": package_name,
                "plain_english": None,
                "business_risk": None,
                "exploit_scenario": None,
                "remediation_json": None,
                "soc2_controls": None,
                "confidence_score": None,
                "false_positive_risk": None,
                "false_positive_reason": None,
                "enrichment_status": "pending",
            }
        ]

    def _check_manual_bad_versions(self, package_json_path: Path) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        try:
            data = json.loads(package_json_path.read_text(encoding="utf-8"))
        except Exception:
            return findings

        deps = {}
        deps.update(data.get("dependencies", {}) or {})
        deps.update(data.get("devDependencies", {}) or {})

        checks = [
            ("lodash", "4.17.21", "prototype pollution risk (CVE-2021-23337)", "CVE-2021-23337", "high"),
            ("express", "4.18.0", "known open redirect issues in old versions", None, "medium"),
            ("jsonwebtoken", "9.0.0", "algorithm confusion risk in outdated releases", None, "high"),
            ("sequelize", "6.28.0", "SQL injection risk in vulnerable versions", None, "high"),
        ]

        for pkg, min_ver, issue, cve_id, sev in checks:
            if pkg in deps and self._is_version_lt(deps[pkg], min_ver):
                findings.append(
                    self._manual_dep_finding(
                        pkg,
                        deps[pkg],
                        min_ver,
                        issue,
                        cve_id,
                        sev,
                    )
                )

        if "marsdb" in deps:
            findings.append(
                self._manual_dep_finding(
                    "marsdb",
                    deps["marsdb"],
                    "n/a",
                    "package is abandoned with historical vulnerability concerns",
                    None,
                    "medium",
                )
            )
        return findings

    def _manual_dep_finding(
        self,
        package: str,
        found_version: str,
        min_safe: str,
        issue: str,
        cve_id: str | None,
        severity: str,
    ) -> dict[str, Any]:
        return {
            "id": str(uuid.uuid4()),
            "pass_name": "deps",
            "file_path": "package.json",
            "line_start": 1,
            "line_end": 1,
            "severity": severity,
            "category": "deps",
            "raw_title": f"{package} version appears vulnerable",
            "code_snippet": f"{package}: {found_version}; minimum safe: {min_safe}; issue: {issue}"[:300],
            "cve_id": cve_id,
            "cwe_id": "CWE-1104",
            "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
            "npm_package": package,
            "plain_english": None,
            "business_risk": None,
            "exploit_scenario": None,
            "remediation_json": None,
            "soc2_controls": None,
            "confidence_score": None,
            "false_positive_risk": None,
            "false_positive_reason": None,
            "enrichment_status": "pending",
        }

    def _is_version_lt(self, current: str, target: str) -> bool:
        def normalize(v: str) -> list[int]:
            stripped = re.sub(r"^[~^<>=\s]*", "", v.strip())
            match = re.search(r"(\d+)\.(\d+)\.(\d+)", stripped)
            if not match:
                return [0, 0, 0]
            return [int(match.group(1)), int(match.group(2)), int(match.group(3))]

        return normalize(current) < normalize(target)

    def _run_secret_pass(self) -> list[dict[str, Any]]:
        if not self.repo_path:
            return []
        findings: list[dict[str, Any]] = []
        skip_dirs = set(self.skip_dirs_common)
        skip_suffixes = (".min.js", ".map")
        false_positive_markers = {"example", "placeholder", "your_key_here", "xxxx"}

        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for filename in files:
                file_path = Path(root) / filename
                rel_path = str(file_path.relative_to(self.repo_path).as_posix())
                if rel_path.endswith(skip_suffixes):
                    continue
                if self._is_excluded_repo_path(rel_path):
                    continue

                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                lines = content.splitlines()
                for idx, line in enumerate(lines, start=1):
                    line_low = line.lower()
                    if any(marker in line_low for marker in false_positive_markers):
                        continue
                    for name, (pattern, severity, cwe_id, owasp) in self.secret_patterns.items():
                        if name == "hardcoded_password" and self._looks_like_sql_injection_line(line):
                            # avoid false positive on SQL query strings containing "pass"/"password" fields
                            continue
                        match = pattern.search(line)
                        if not match:
                            continue
                        redacted = self._redact_match(line, match)
                        findings.append(
                            {
                                "id": str(uuid.uuid4()),
                                "pass_name": "secrets",
                                "file_path": rel_path,
                                "line_start": idx,
                                "line_end": idx,
                                "severity": severity,
                                "category": "secrets",
                                "raw_title": f"Potential {name.replace('_', ' ')} detected",
                                "code_snippet": redacted[:300],
                                "cve_id": None,
                                "cwe_id": cwe_id,
                                "owasp_category": owasp,
                                "npm_package": None,
                                "plain_english": None,
                                "business_risk": None,
                                "exploit_scenario": None,
                                "remediation_json": None,
                                "soc2_controls": None,
                                "confidence_score": None,
                                "false_positive_risk": None,
                                "false_positive_reason": None,
                                "enrichment_status": "pending",
                            }
                        )
        return findings

    def _redact_match(self, line: str, match: re.Match[str]) -> str:
        secret = match.group(0)
        redacted = f"{secret[:4]}***"
        return line.replace(secret, redacted)

    def _run_structural_pass(self) -> list[dict[str, Any]]:
        if not self.repo_path:
            return []
        findings: list[dict[str, Any]] = []

        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in self.skip_dirs_common]
            for filename in files:
                if not (filename.endswith(".js") or filename.endswith(".ts")):
                    continue
                file_path = Path(root) / filename
                rel_path = str(file_path.relative_to(self.repo_path).as_posix())
                if self._is_excluded_repo_path(rel_path):
                    continue
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                lines = content.splitlines()
                for idx, line in enumerate(lines, start=1):
                    for rule in self.structure_patterns:
                        if rule.get("exclude_comment_line") and line.strip().startswith("//"):
                            continue
                        m = rule["regex"].search(line)
                        if not m:
                            continue
                        if rule.get("cookie_check"):
                            lower = line.lower()
                            if "httponly" in lower and "secure" in lower:
                                continue

                        findings.append(
                            {
                                "id": str(uuid.uuid4()),
                                "pass_name": "structural",
                                "file_path": rel_path,
                                "line_start": idx,
                                "line_end": idx,
                                "severity": rule["severity"],
                                "category": rule["category"],
                                "raw_title": rule["name"],
                                "code_snippet": line.strip()[:300],
                                "cve_id": None,
                                "cwe_id": rule["cwe_id"],
                                "owasp_category": rule["owasp"],
                                "npm_package": None,
                                "plain_english": None,
                                "business_risk": None,
                                "exploit_scenario": None,
                                "remediation_json": None,
                                "soc2_controls": None,
                                "confidence_score": None,
                                "false_positive_risk": None,
                                "false_positive_reason": None,
                                "enrichment_status": "pending",
                            }
                        )

                if filename in {"app.js", "server.js", "index.js"}:
                    findings.extend(self._check_missing_headers(rel_path, content))
        return findings

    def _check_missing_headers(self, rel_path: str, content: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        lower = content.lower()
        if "express()" in lower:
            if "helmet" not in lower:
                findings.append(
                    self._static_structural_finding(
                        rel_path,
                        "Missing helmet security headers middleware",
                        "medium",
                        "CWE-693",
                        "A05:2021 - Security Misconfiguration",
                        "config",
                    )
                )
            if "ratelimit" not in lower:
                findings.append(
                    self._static_structural_finding(
                        rel_path,
                        "Missing rate limiting middleware",
                        "medium",
                        "CWE-770",
                        "A05:2021 - Security Misconfiguration",
                        "config",
                    )
                )
        return findings

    def _static_structural_finding(
        self,
        file_path: str,
        title: str,
        severity: str,
        cwe_id: str,
        owasp: str,
        category: str,
    ) -> dict[str, Any]:
        return {
            "id": str(uuid.uuid4()),
            "pass_name": "structural",
            "file_path": file_path,
            "line_start": 1,
            "line_end": 1,
            "severity": severity,
            "category": category,
            "raw_title": title,
            "code_snippet": title,
            "cve_id": None,
            "cwe_id": cwe_id,
            "owasp_category": owasp,
            "npm_package": None,
            "plain_english": None,
            "business_risk": None,
            "exploit_scenario": None,
            "remediation_json": None,
            "soc2_controls": None,
            "confidence_score": None,
            "false_positive_risk": None,
            "false_positive_reason": None,
            "enrichment_status": "pending",
        }

    def _run_config_pass(self) -> list[dict[str, Any]]:
        if not self.repo_path:
            return []
        findings: list[dict[str, Any]] = []

        # 5a .env files
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in self.skip_dirs_common]
            for f in files:
                p = Path(root) / f
                rel_path = str(p.relative_to(self.repo_path).as_posix())
                if self._is_excluded_repo_path(rel_path):
                    continue
                if f == ".env":
                    try:
                        content = p.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        content = ""
                    if self._env_has_real_values(content):
                        findings.append(
                            {
                                "id": str(uuid.uuid4()),
                                "pass_name": "config",
                                "file_path": rel_path,
                                "line_start": 1,
                                "line_end": 1,
                                "severity": "critical",
                                "category": "config",
                                "raw_title": "Committed .env file with non-empty values detected",
                                "code_snippet": "\n".join(content.splitlines()[:5])[:300],
                                "cve_id": None,
                                "cwe_id": "CWE-312",
                                "owasp_category": "A05:2021 - Security Misconfiguration",
                                "npm_package": None,
                                "plain_english": None,
                                "business_risk": None,
                                "exploit_scenario": None,
                                "remediation_json": None,
                                "soc2_controls": None,
                                "confidence_score": None,
                                "false_positive_risk": None,
                                "false_positive_reason": None,
                                "enrichment_status": "pending",
                            }
                        )

        # 5b .gitignore checks
        gitignore = self.repo_path / ".gitignore"
        if gitignore.exists():
            try:
                gi = gitignore.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                gi = ""
            if ".env" not in gi:
                findings.append(
                    self._config_repo_finding(
                        ".gitignore",
                        "'.env' missing from .gitignore",
                        "medium",
                        "CWE-16",
                    )
                )
            if "node_modules" not in gi:
                findings.append(
                    self._config_repo_finding(
                        ".gitignore",
                        "'node_modules' missing from .gitignore",
                        "low",
                        "CWE-16",
                    )
                )

        # 5c package.json scripts exposed credentials
        pkg = self.repo_path / "package.json"
        if pkg.exists():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8"))
                scripts = data.get("scripts", {}) or {}
                for name, val in scripts.items():
                    text = str(val)
                    if re.search(r"[a-z]+://[^/\s:]+:[^@\s]+@", text, re.IGNORECASE):
                        findings.append(
                            {
                                "id": str(uuid.uuid4()),
                                "pass_name": "config",
                                "file_path": "package.json",
                                "line_start": 1,
                                "line_end": 1,
                                "severity": "high",
                                "category": "config",
                                "raw_title": f"Script '{name}' appears to include URL credentials",
                                "code_snippet": text[:300],
                                "cve_id": None,
                                "cwe_id": "CWE-798",
                                "owasp_category": "A05:2021 - Security Misconfiguration",
                                "npm_package": None,
                                "plain_english": None,
                                "business_risk": None,
                                "exploit_scenario": None,
                                "remediation_json": None,
                                "soc2_controls": None,
                                "confidence_score": None,
                                "false_positive_risk": None,
                                "false_positive_reason": None,
                                "enrichment_status": "pending",
                            }
                        )
            except Exception:
                pass

        # 5d weak default secrets
        weak_secret_regex = re.compile(
            r"(?i)(['\"]?secret['\"]?\s*[:=]\s*['\"](changeme|secret|123)['\"])"
        )
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in self.skip_dirs_common]
            for f in files:
                if not (f.endswith(".json") or f.endswith(".js")):
                    continue
                p = Path(root) / f
                rel = str(p.relative_to(self.repo_path).as_posix())
                if self._is_excluded_repo_path(rel):
                    continue
                try:
                    lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
                except Exception:
                    continue
                for idx, line in enumerate(lines, start=1):
                    if weak_secret_regex.search(line):
                        findings.append(
                            {
                                "id": str(uuid.uuid4()),
                                "pass_name": "config",
                                "file_path": rel,
                                "line_start": idx,
                                "line_end": idx,
                                "severity": "critical",
                                "category": "secrets",
                                "raw_title": "Weak default secret configuration detected",
                                "code_snippet": line.strip()[:300],
                                "cve_id": None,
                                "cwe_id": "CWE-798",
                                "owasp_category": "A07:2021 - Identification and Authentication Failures",
                                "npm_package": None,
                                "plain_english": None,
                                "business_risk": None,
                                "exploit_scenario": None,
                                "remediation_json": None,
                                "soc2_controls": None,
                                "confidence_score": None,
                                "false_positive_risk": None,
                                "false_positive_reason": None,
                                "enrichment_status": "pending",
                            }
                        )
        return findings

    def _config_repo_finding(self, file_path: str, title: str, severity: str, cwe_id: str) -> dict[str, Any]:
        return {
            "id": str(uuid.uuid4()),
            "pass_name": "config",
            "file_path": file_path,
            "line_start": 1,
            "line_end": 1,
            "severity": severity,
            "category": "config",
            "raw_title": title,
            "code_snippet": title,
            "cve_id": None,
            "cwe_id": cwe_id,
            "owasp_category": "A05:2021 - Security Misconfiguration",
            "npm_package": None,
            "plain_english": None,
            "business_risk": None,
            "exploit_scenario": None,
            "remediation_json": None,
            "soc2_controls": None,
            "confidence_score": None,
            "false_positive_risk": None,
            "false_positive_reason": None,
            "enrichment_status": "pending",
        }

    def _env_has_real_values(self, content: str) -> bool:
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            _, val = stripped.split("=", 1)
            value = val.strip().strip("\"'")
            if value and value.lower() not in {"", "changeme", "your_value_here", "placeholder"}:
                return True
        return False

    def _map_owasp_from_rule(self, rule_id: str) -> str:
        rid = rule_id.lower()
        if "injection" in rid or "sql" in rid:
            return "A03:2021 - Injection"
        if "auth" in rid or "jwt" in rid or "session" in rid:
            return "A07:2021 - Identification and Authentication Failures"
        if "crypto" in rid or "weak" in rid:
            return "A02:2021 - Cryptographic Failures"
        if "xss" in rid:
            return "A03:2021 - Injection"
        if "path-traversal" in rid or "lfi" in rid:
            return "A01:2021 - Broken Access Control"
        if "secrets" in rid or "hardcoded" in rid:
            return "A02:2021 - Cryptographic Failures"
        return "A05:2021 - Security Misconfiguration"

    def _map_category_from_rule(self, rule_id: str) -> str:
        rid = rule_id.lower()
        if "xss" in rid:
            return "xss"
        if "auth" in rid or "jwt" in rid or "session" in rid:
            return "auth"
        if "secret" in rid:
            return "secrets"
        if "config" in rid:
            return "config"
        if "crypto" in rid:
            return "crypto"
        if "sql" in rid or "inject" in rid:
            return "injection"
        return "misc"

    def _map_cwe_from_rule(self, rule_id: str) -> str:
        rid = rule_id.lower()
        for fragment, cwe in self.cwe_map.items():
            if fragment in rid:
                return cwe
        return "CWE-20"

    def _extract_snippet(self, file_path: Path, line_start: int, line_end: int) -> str:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            start = max(1, line_start - 2)
            end = min(len(lines), line_end + 2)
            snippet = []
            for i in range(start, end + 1):
                snippet.append(f"{i}: {lines[i - 1]}")
            return "\n".join(snippet)
        except Exception:
            return ""

    def _finding_completeness_score(self, finding: dict[str, Any]) -> int:
        score = 0
        for field in ("code_snippet", "cwe_id", "owasp_category", "raw_title", "npm_package", "cve_id"):
            if finding.get(field):
                score += 1
        return score

    def _is_test_path(self, rel_path: str) -> bool:
        lowered = f"/{rel_path.lower().strip('/')}/"
        if any(marker in lowered for marker in self.test_dir_markers):
            return True
        raw = rel_path.lower().strip("/")
        if raw.startswith("test/") or raw.startswith("tests/") or raw.startswith("spec/") or raw.startswith("cypress/"):
            return True
        if raw.endswith(self.test_file_suffixes):
            return True
        return False

    def _is_intentional_sample_path(self, rel_path: str) -> bool:
        lowered = f"/{rel_path.lower().strip('/')}/"
        return any(marker in lowered for marker in self.intentional_sample_markers)

    def _is_excluded_repo_path(self, rel_path: str) -> bool:
        return self._is_test_path(rel_path) or self._is_intentional_sample_path(rel_path)

    def _looks_like_sql_injection_line(self, line: str) -> bool:
        lowered = line.lower()
        sql_keywords = ("select ", "where ", "insert ", "update ", "delete ", " from ")
        if not any(k in lowered for k in sql_keywords):
            return False
        return ("req." in lowered) or ("${" in line) or ("+" in line and ("query" in lowered or "sequelize" in lowered))

    def _normalize_pattern_name(self, finding: dict[str, Any]) -> str:
        title = str(finding.get("raw_title", "")).lower()
        cwe = str(finding.get("cwe_id", "")).upper()
        category = str(finding.get("category", "")).lower()
        if "hardcoded_password" in title or "hardcoded password" in title:
            return "hardcoded_password"
        if "private key" in title:
            return "private_key"
        if "jwt" in title:
            return "weak_jwt"
        if "sql injection" in title or cwe == "CWE-89":
            return "sql_injection"
        if "eval" in title or cwe == "CWE-95":
            return "eval_usage"
        if "missing rate limiting" in title:
            return "missing_rate_limiting"
        if "'.env' missing from .gitignore" in title:
            return "gitignore_env_missing"
        if category == "deps":
            return "vulnerable_dependency"
        return re.sub(r"[^a-z0-9]+", "_", title).strip("_")[:64] or "generic"

    def _aggregate_repetitive_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
        others: list[dict[str, Any]] = []
        for f in findings:
            file_path = str(f.get("file_path", ""))
            pattern = self._normalize_pattern_name(f)
            key = (
                file_path,
                pattern,
                str(f.get("severity", "info")).lower(),
                str(f.get("category", "misc")).lower(),
            )
            # Aggregate only secret/password-like repetitive patterns or very frequent identical signals
            if pattern in {"hardcoded_password", "private_key"} or str(f.get("pass_name")) == "secrets":
                groups.setdefault(key, []).append(f)
            else:
                others.append(f)

        aggregated = list(others)
        for _, items in groups.items():
            if len(items) == 1:
                aggregated.append(items[0])
                continue
            sorted_items = sorted(items, key=lambda x: int(x.get("line_start") or 0))
            base = sorted_items[0].copy()
            count = len(sorted_items)
            min_line = int(sorted_items[0].get("line_start") or 1)
            max_line = int(sorted_items[-1].get("line_end") or min_line)
            file_path = str(base.get("file_path", "unknown"))
            pattern_name = self._normalize_pattern_name(base).replace("_", " ")
            base["line_start"] = min_line
            base["line_end"] = max_line
            base["occurrence_count"] = count
            base["raw_title"] = (
                f"{pattern_name.capitalize()} detected in {Path(file_path).name}: "
                f"{count} occurrences across lines {min_line}-{max_line}"
            )[:200]
            base["code_snippet"] = (
                f"Aggregated repetitive pattern '{pattern_name}' in {file_path}. "
                f"Occurrences: {count}. Line range: {min_line}-{max_line}."
            )[:300]
            aggregated.append(base)
        return aggregated

    def _severity_rank(self, severity: str) -> int:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        return order.get((severity or "info").lower(), 0)

    def _deduplicate_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = self._aggregate_repetitive_findings(findings)
        grouped: dict[tuple[str, int, str, str], dict[str, Any]] = {}
        for f in findings:
            key = (
                str(f.get("file_path", "")),
                int(f.get("line_start") or 0),
                str(f.get("severity", "info")).lower(),
                str(f.get("category", "misc")).lower(),
            )
            if key not in grouped:
                grouped[key] = f
                continue
            current = grouped[key]
            if self._finding_completeness_score(f) > self._finding_completeness_score(current):
                grouped[key] = f

        deduped = list(grouped.values())
        for d in deduped:
            d["id"] = str(uuid.uuid4())
            d["severity"] = str(d.get("severity", "info")).lower()
            d["enrichment_status"] = d.get("enrichment_status") or "pending"

        deduped.sort(
            key=lambda x: (
                -self._severity_rank(str(x.get("severity", "info"))),
                str(x.get("file_path", "")),
                int(x.get("line_start") or 0),
                str(x.get("raw_title", "")),
            )
        )
        return deduped
