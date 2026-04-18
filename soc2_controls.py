from typing import Any


# This is the authoritative SOC2 CC mapping for code-level findings
# Based on AICPA Trust Services Criteria 2017 (updated 2022)
SOC2_CONTROL_MAPPING = {
    # INJECTION VULNERABILITIES
    "sql_injection": {
        "controls": ["CC6.1", "CC7.1"],
        "rationale": {
            "CC6.1": "SQL injection bypasses logical access controls, allowing unauthorized data access",
            "CC7.1": "Undetected SQL injection represents a failure to identify and monitor vulnerabilities",
        },
        "severity_floor": "high",
    },
    "command_injection": {
        "controls": ["CC6.1", "CC6.8", "CC7.1"],
        "rationale": {
            "CC6.1": "Command injection allows unauthorized system access",
            "CC6.8": "Enables execution of unauthorized/malicious commands",
            "CC7.1": "Represents undetected critical vulnerability",
        },
        "severity_floor": "critical",
    },
    "xss": {
        "controls": ["CC6.1", "CC6.7", "CC7.1"],
        "rationale": {
            "CC6.1": "XSS can be used to hijack authenticated sessions",
            "CC6.7": "Enables unauthorized data transmission to third parties",
            "CC7.1": "Undetected XSS represents vulnerability monitoring failure",
        },
        "severity_floor": "medium",
    },
    # AUTHENTICATION & ACCESS
    "broken_auth": {
        "controls": ["CC6.1", "CC6.2", "CC6.3"],
        "rationale": {
            "CC6.1": "Broken auth directly violates logical access controls",
            "CC6.2": "Weak credential systems fail to protect system access",
            "CC6.3": "May allow access by unauthorized or former users",
        },
        "severity_floor": "high",
    },
    "hardcoded_credentials": {
        "controls": ["CC6.1", "CC6.2", "CC8.1"],
        "rationale": {
            "CC6.1": "Hardcoded credentials create unauthorized access vectors",
            "CC6.2": "Violates secure credential management requirements",
            "CC8.1": "Represents failure in change management - credentials should never enter version control",
        },
        "severity_floor": "critical",
    },
    "weak_jwt": {
        "controls": ["CC6.1", "CC6.2"],
        "rationale": {
            "CC6.1": "Weak JWT allows token forgery and auth bypass",
            "CC6.2": "Violates secure authentication mechanism requirements",
        },
        "severity_floor": "critical",
    },
    # SECRETS & CRYPTOGRAPHY
    "secret_in_code": {
        "controls": ["CC6.1", "CC6.7", "CC8.1"],
        "rationale": {
            "CC6.1": "Exposed secrets create unauthorized access paths",
            "CC6.7": "Secrets in version control transmitted to unauthorized parties (all repo viewers)",
            "CC8.1": "Committing secrets violates change management controls",
        },
        "severity_floor": "critical",
    },
    "weak_crypto": {
        "controls": ["CC6.7"],
        "rationale": {
            "CC6.7": "Weak cryptography fails to restrict data transmission to authorized parties only",
        },
        "severity_floor": "high",
    },
    # CONFIGURATION
    "missing_security_headers": {
        "controls": ["CC6.6", "CC6.7"],
        "rationale": {
            "CC6.6": "Missing headers (CSP, HSTS, X-Frame-Options) fail to protect infrastructure from known attack vectors",
            "CC6.7": "Without headers like CSP, data can be transmitted to unauthorized third parties via injected scripts",
        },
        "severity_floor": "medium",
    },
    "cors_wildcard": {
        "controls": ["CC6.1", "CC6.7"],
        "rationale": {
            "CC6.1": "Wildcard CORS removes access restrictions entirely",
            "CC6.7": "Allows any origin to receive API responses, violating data transmission controls",
        },
        "severity_floor": "medium",
    },
    "missing_rate_limiting": {
        "controls": ["CC6.1", "CC6.2"],
        "rationale": {
            "CC6.1": "No rate limiting enables brute force of access controls",
            "CC6.2": "Authentication endpoints without rate limiting allow credential stuffing attacks",
        },
        "severity_floor": "medium",
    },
    # DEPENDENCIES
    "vulnerable_dependency": {
        "controls": ["CC6.8", "CC7.1", "CC9.2"],
        "rationale": {
            "CC6.8": "Known-vulnerable packages constitute malicious/unauthorized software risk per CC6.8",
            "CC7.1": "CVE in production dependency = unmonitored vulnerability",
            "CC9.2": "Vendor/third-party risk management requires tracking dependency vulnerabilities",
        },
        "severity_floor": "medium",
    },
    # PATH TRAVERSAL / FILE ACCESS
    "path_traversal": {
        "controls": ["CC6.1", "CC6.7"],
        "rationale": {
            "CC6.1": "Path traversal allows access to files outside authorized scope",
            "CC6.7": "Can expose sensitive files to unauthorized parties",
        },
        "severity_floor": "high",
    },
    # EVAL / CODE INJECTION
    "eval_usage": {
        "controls": ["CC6.8", "CC7.1"],
        "rationale": {
            "CC6.8": "eval() enables execution of arbitrary/malicious code",
            "CC7.1": "Dynamic code execution creates unmonitorable attack surface",
        },
        "severity_floor": "high",
    },
    # LOGGING / MONITORING
    "missing_logging": {
        "controls": ["CC7.2", "CC7.3"],
        "rationale": {
            "CC7.2": "Without logging, anomalous system behaviour cannot be detected",
            "CC7.3": "Security events cannot be evaluated without audit logs",
        },
        "severity_floor": "medium",
    },
    # CONFIG FILES
    "committed_env_file": {
        "controls": ["CC6.1", "CC6.7", "CC8.1"],
        "rationale": {
            "CC6.1": "Committed .env exposes all system credentials",
            "CC6.7": "Environment secrets transmitted to all repo access holders",
            "CC8.1": "Represents complete breakdown in change management process",
        },
        "severity_floor": "critical",
    },
}


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _contains_any(value: str, needles: list[str]) -> bool:
    return any(n in value for n in needles)


def infer_vulnerability_type(finding: dict[str, Any]) -> str:
    title = str(finding.get("raw_title", "")).lower()
    category = str(finding.get("category", "")).lower()
    cwe = str(finding.get("cwe_id", "")).lower()
    pass_name = str(finding.get("pass_name", "")).lower()
    file_path = str(finding.get("file_path", "")).lower()
    owasp = str(finding.get("owasp_category", "")).lower()

    if file_path.endswith(".env") or "committed .env" in title:
        return "committed_env_file"
    if pass_name == "deps" or bool(finding.get("npm_package")):
        return "vulnerable_dependency"
    if _contains_any(title, ["command injection", "child_process", "execsync"]) or "cwe-78" in cwe:
        return "command_injection"
    if _contains_any(title, ["sql injection", "sequelize.query", "query interpolation"]) or "cwe-89" in cwe:
        return "sql_injection"
    if "xss" in title or category == "xss" or "cwe-79" in cwe:
        return "xss"
    if _contains_any(title, ["path traversal", "lfi"]) or "cwe-22" in cwe:
        return "path_traversal"
    if _contains_any(title, ["eval", "function constructor"]) or "cwe-95" in cwe:
        return "eval_usage"
    if _contains_any(title, ["hardcoded", "credential", "password", "private key"]) and category in {"secrets", "auth"}:
        return "hardcoded_credentials"
    if _contains_any(title, ["jwt", "token secret", "weak default secret"]) or ("jwt" in owasp and "secret" in title):
        return "weak_jwt"
    if category == "secrets":
        return "secret_in_code"
    if category == "crypto" or "cwe-327" in cwe:
        return "weak_crypto"
    if _contains_any(title, ["missing helmet", "missing security headers"]):
        return "missing_security_headers"
    if _contains_any(title, ["cors wildcard", "access-control-allow-origin wildcard"]):
        return "cors_wildcard"
    if "missing rate limiting" in title:
        return "missing_rate_limiting"
    if "missing logging" in title:
        return "missing_logging"
    if category == "auth":
        return "broken_auth"
    if category == "injection":
        return "sql_injection"
    if category == "config":
        return "missing_security_headers"
    return "vulnerable_dependency" if pass_name == "deps" else "broken_auth"


def apply_severity_floor(severity: str, floor: str) -> str:
    current = str(severity or "info").lower()
    required = str(floor or "low").lower()
    if SEVERITY_ORDER.get(current, 0) < SEVERITY_ORDER.get(required, 0):
        return required
    return current


def get_soc2_mapping_for_finding(finding: dict[str, Any]) -> dict[str, Any]:
    vuln_type = infer_vulnerability_type(finding)
    entry = SOC2_CONTROL_MAPPING.get(vuln_type, SOC2_CONTROL_MAPPING["broken_auth"])
    controls = list(entry.get("controls", []))
    rationale = dict(entry.get("rationale", {}))
    severity_floor = str(entry.get("severity_floor", "medium")).lower()
    return {
        "vulnerability_type": vuln_type,
        "controls": controls,
        "rationale": rationale,
        "severity_floor": severity_floor,
    }
