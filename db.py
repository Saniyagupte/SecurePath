"""
SecurePath database layer.

Backend is chosen automatically at startup:
  - DATABASE_URL env var set  →  PostgreSQL  (production on Render / Neon / Supabase)
  - DATABASE_URL not set      →  SQLite       (local development, no setup needed)

All public functions have identical signatures regardless of backend.
"""
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Path config — used only when SQLite backend is active
# ---------------------------------------------------------------------------
_DATA_DIR = os.getenv("DATA_DIR", "")
if _DATA_DIR:
    os.makedirs(_DATA_DIR, exist_ok=True)

DB_PATH     = os.path.join(_DATA_DIR, "securepath.db") if _DATA_DIR else "securepath.db"
REPORTS_DIR = os.path.join(_DATA_DIR, "reports") if _DATA_DIR else "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------
DATABASE_URL  = os.getenv("DATABASE_URL", "")
_USE_POSTGRES = bool(DATABASE_URL)

if _USE_POSTGRES:
    try:
        import psycopg2
        import psycopg2.extras
        print("[SecurePath] DB backend: PostgreSQL")
    except ImportError:
        _USE_POSTGRES = False
        print("[SecurePath] psycopg2 not installed — falling back to SQLite")
else:
    print(f"[SecurePath] DB backend: SQLite -> {DB_PATH}")


# ---------------------------------------------------------------------------
# SQL adapter — converts SQLite syntax → PostgreSQL where needed
# ---------------------------------------------------------------------------
_NAMED_RE = re.compile(r":(\w+)")


def _adapt(sql: str) -> str:
    """Convert SQLite placeholders to PostgreSQL style (no-op for SQLite)."""
    if not _USE_POSTGRES:
        return sql
    sql = _NAMED_RE.sub(r"%(\1)s", sql)  # :foo  →  %(foo)s
    sql = sql.replace("?", "%s")          # ?     →  %s
    return sql


# ---------------------------------------------------------------------------
# Unified connection wrapper
# Gives both backends the same interface so all query code is identical.
# ---------------------------------------------------------------------------
class _Conn:
    """
    Wraps sqlite3 / psycopg2 with a common interface.

        with _get_conn() as conn:
            conn.execute(SQL, params)
            conn.execute(SQL, params).fetchone()
            conn.execute(SQL, params).fetchall()
    """

    def __init__(self) -> None:
        if _USE_POSTGRES:
            self._conn = psycopg2.connect(
                DATABASE_URL,
                cursor_factory=psycopg2.extras.RealDictCursor,
            )
            self._conn.autocommit = False
        else:
            self._conn = sqlite3.connect(DB_PATH)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")

    def execute(self, sql: str, params=None):
        if _USE_POSTGRES:
            cur = self._conn.cursor()
            cur.execute(_adapt(sql), params)
            return cur
        # SQLite: connection.execute() returns a cursor directly
        if params is None:
            return self._conn.execute(sql)
        return self._conn.execute(sql, params)

    def commit(self) -> None:
        self._conn.commit()

    def __enter__(self) -> "_Conn":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if exc_type is None:
            self._conn.commit()
        else:
            self._conn.rollback()
        try:
            self._conn.close()
        except Exception:
            pass
        return False


def _get_conn() -> _Conn:
    return _Conn()


# ---------------------------------------------------------------------------
# Row → dict  (works for both sqlite3.Row and psycopg2 RealDictRow)
# ---------------------------------------------------------------------------
def _row_to_dict(row: Any) -> "dict[str, Any] | None":
    if row is None:
        return None
    if isinstance(row, sqlite3.Row):
        return {k: row[k] for k in row.keys()}
    return dict(row)  # psycopg2 RealDictRow is already dict-like


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_repo_name(repo_url: str) -> "str | None":
    try:
        parsed = urlparse(repo_url.strip())
        path = (parsed.path or "").strip("/")
        if not path:
            return None
        if path.endswith(".git"):
            path = path[:-4]
        parts = [p for p in path.split("/") if p]
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        if len(parts) == 1:
            return parts[0]
        return None
    except Exception:
        return None


def severity_weight(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
        (severity or "").lower(), 0
    )


# ---------------------------------------------------------------------------
# Allowed field sets (prevent SQL injection via kwargs)
# ---------------------------------------------------------------------------
SCAN_FIELDS = {
    "repo_url", "repo_name", "commit_sha", "status", "progress",
    "current_step", "findings_count", "critical_count", "high_count",
    "medium_count", "low_count", "risk_score", "findings_hash",
    "report_path", "error_message", "created_at", "completed_at",
}

FINDING_FIELDS = {
    "scan_id", "pass_name", "file_path", "line_start", "line_end",
    "severity", "category", "raw_title", "code_snippet", "cve_id",
    "cwe_id", "owasp_category", "npm_package", "plain_english",
    "business_risk", "exploit_scenario", "remediation_json",
    "soc2_controls", "confidence_score", "false_positive_risk",
    "false_positive_reason", "enrichment_status", "created_at",
    "business_impact_json", "assets_exposed_json",
}


# ---------------------------------------------------------------------------
# Schema init
# Both SQLite and PostgreSQL accept this SQL syntax identically.
# ---------------------------------------------------------------------------
def init_db() -> None:
    with _get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
              id            TEXT PRIMARY KEY,
              repo_url      TEXT NOT NULL,
              repo_name     TEXT,
              commit_sha    TEXT,
              status        TEXT DEFAULT 'queued',
              progress      INTEGER DEFAULT 0,
              current_step  TEXT,
              findings_count  INTEGER DEFAULT 0,
              critical_count  INTEGER DEFAULT 0,
              high_count      INTEGER DEFAULT 0,
              medium_count    INTEGER DEFAULT 0,
              low_count       INTEGER DEFAULT 0,
              risk_score      INTEGER DEFAULT 0,
              findings_hash   TEXT,
              report_path     TEXT,
              error_message   TEXT,
              created_at      TEXT,
              completed_at    TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
              id                   TEXT PRIMARY KEY,
              scan_id              TEXT NOT NULL,
              pass_name            TEXT,
              file_path            TEXT,
              line_start           INTEGER,
              line_end             INTEGER,
              severity             TEXT,
              category             TEXT,
              raw_title            TEXT,
              code_snippet         TEXT,
              cve_id               TEXT,
              cwe_id               TEXT,
              owasp_category       TEXT,
              npm_package          TEXT,
              plain_english        TEXT,
              business_risk        TEXT,
              exploit_scenario     TEXT,
              remediation_json     TEXT,
              soc2_controls        TEXT,
              confidence_score     INTEGER,
              false_positive_risk  TEXT,
              false_positive_reason TEXT,
              enrichment_status    TEXT DEFAULT 'pending',
              created_at           TEXT,
              FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)"
        )
        # Safely add new columns for Business Impact and Asset Exposure features
        for col_name in ("business_impact_json", "assets_exposed_json"):
            try:
                conn.execute(f"ALTER TABLE findings ADD COLUMN {col_name} TEXT")
            except Exception:
                pass  # Column already exists
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_reports (
              scan_id TEXT PRIMARY KEY,
              pdf_blob BYTEA,
              FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_sessions (
              session_id               TEXT PRIMARY KEY,
              scan_id                  TEXT,
              repo_url                 TEXT,
              repo_name                TEXT,
              ip_address               TEXT,
              country                  TEXT,
              city                     TEXT,
              user_agent               TEXT,
              referrer                 TEXT,
              started_at               TEXT,
              completed_at             TEXT,
              scan_completed           INTEGER DEFAULT 0,
              findings_count           INTEGER DEFAULT 0,
              critical_count           INTEGER DEFAULT 0,
              high_count               INTEGER DEFAULT 0,
              medium_count             INTEGER DEFAULT 0,
              low_count                INTEGER DEFAULT 0,
              risk_score               INTEGER DEFAULT 0,
              pdf_downloaded           INTEGER DEFAULT 0,
              time_to_complete_seconds INTEGER DEFAULT 0,
              FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE SET NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_scan_id ON scan_sessions(scan_id)"
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Scans CRUD
# ---------------------------------------------------------------------------
def create_scan(repo_url: str) -> str:
    scan_id    = str(uuid.uuid4())
    created_at = _utc_now_iso()
    repo_name  = _normalize_repo_name(repo_url)
    with _get_conn() as conn:
        conn.execute(
            """
            INSERT INTO scans
              (id, repo_url, repo_name, status, progress, created_at)
            VALUES (?, ?, ?, 'queued', 0, ?)
            """,
            (scan_id, repo_url, repo_name, created_at),
        )
        conn.commit()
    return scan_id


def update_scan(scan_id: str, **kwargs: Any) -> None:
    updates = {k: v for k, v in kwargs.items() if k in SCAN_FIELDS}
    if not updates:
        return
    placeholders = ", ".join([f"{k} = ?" for k in updates.keys()])
    values = list(updates.values()) + [scan_id]
    with _get_conn() as conn:
        conn.execute(f"UPDATE scans SET {placeholders} WHERE id = ?", values)
        conn.commit()


def get_scan(scan_id: str) -> "dict[str, Any] | None":
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        return _row_to_dict(row)


def get_all_scans() -> "list[dict[str, Any]]":
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC, id DESC"
        ).fetchall()
        return [_row_to_dict(r) for r in rows if r is not None]


# ---------------------------------------------------------------------------
# Findings CRUD
# ---------------------------------------------------------------------------
def insert_finding(scan_id: str, finding_dict: "dict[str, Any]") -> str:
    finding_id = finding_dict.get("id") or str(uuid.uuid4())
    created_at = finding_dict.get("created_at") or _utc_now_iso()

    # Serialize business_impact and assets_exposed dicts to JSON strings for storage
    bi_raw = finding_dict.get("business_impact") or finding_dict.get("business_impact_json")
    if isinstance(bi_raw, dict):
        bi_json = json.dumps(bi_raw)
    elif isinstance(bi_raw, str):
        bi_json = bi_raw
    else:
        bi_json = None

    ae_raw = finding_dict.get("assets_exposed") or finding_dict.get("assets_exposed_json")
    if isinstance(ae_raw, dict):
        ae_json = json.dumps(ae_raw)
    elif isinstance(ae_raw, str):
        ae_json = ae_raw
    else:
        ae_json = None

    values = {
        "id":                   finding_id,
        "scan_id":              scan_id,
        "pass_name":            finding_dict.get("pass_name"),
        "file_path":            finding_dict.get("file_path"),
        "line_start":           finding_dict.get("line_start"),
        "line_end":             finding_dict.get("line_end"),
        "severity":             finding_dict.get("severity"),
        "category":             finding_dict.get("category"),
        "raw_title":            finding_dict.get("raw_title"),
        "code_snippet":         (finding_dict.get("code_snippet") or "")[:300],
        "cve_id":               finding_dict.get("cve_id"),
        "cwe_id":               finding_dict.get("cwe_id"),
        "owasp_category":       finding_dict.get("owasp_category"),
        "npm_package":          finding_dict.get("npm_package"),
        "plain_english":        finding_dict.get("plain_english"),
        "business_risk":        finding_dict.get("business_risk"),
        "exploit_scenario":     finding_dict.get("exploit_scenario"),
        "remediation_json":     finding_dict.get("remediation_json"),
        "soc2_controls":        finding_dict.get("soc2_controls"),
        "confidence_score":     finding_dict.get("confidence_score"),
        "false_positive_risk":  finding_dict.get("false_positive_risk"),
        "false_positive_reason":finding_dict.get("false_positive_reason"),
        "enrichment_status":    finding_dict.get("enrichment_status", "pending"),
        "created_at":           created_at,
        "business_impact_json": bi_json,
        "assets_exposed_json":  ae_json,
    }

    with _get_conn() as conn:
        conn.execute(
            """
            INSERT INTO findings (
              id, scan_id, pass_name, file_path, line_start, line_end,
              severity, category, raw_title, code_snippet, cve_id, cwe_id,
              owasp_category, npm_package, plain_english, business_risk,
              exploit_scenario, remediation_json, soc2_controls,
              confidence_score, false_positive_risk, false_positive_reason,
              enrichment_status, created_at,
              business_impact_json, assets_exposed_json
            ) VALUES (
              :id, :scan_id, :pass_name, :file_path, :line_start, :line_end,
              :severity, :category, :raw_title, :code_snippet, :cve_id, :cwe_id,
              :owasp_category, :npm_package, :plain_english, :business_risk,
              :exploit_scenario, :remediation_json, :soc2_controls,
              :confidence_score, :false_positive_risk, :false_positive_reason,
              :enrichment_status, :created_at,
              :business_impact_json, :assets_exposed_json
            )
            """,
            values,
        )
        conn.commit()
    return finding_id


def update_finding(finding_id: str, **kwargs: Any) -> None:
    updates = {k: v for k, v in kwargs.items() if k in FINDING_FIELDS}
    if "code_snippet" in updates and updates["code_snippet"] is not None:
        updates["code_snippet"] = str(updates["code_snippet"])[:300]
    if not updates:
        return
    placeholders = ", ".join([f"{k} = ?" for k in updates.keys()])
    values = list(updates.values()) + [finding_id]
    with _get_conn() as conn:
        conn.execute(
            f"UPDATE findings SET {placeholders} WHERE id = ?", values
        )
        conn.commit()


def get_findings(scan_id: str) -> "list[dict[str, Any]]":
    with _get_conn() as conn:
        rows = conn.execute(
            """
            SELECT * FROM findings
            WHERE scan_id = ?
            ORDER BY
              CASE LOWER(COALESCE(severity, 'info'))
                WHEN 'critical' THEN 4
                WHEN 'high'     THEN 3
                WHEN 'medium'   THEN 2
                WHEN 'low'      THEN 1
                ELSE 0
              END DESC,
              COALESCE(line_start, 0) ASC,
              COALESCE(file_path, '') ASC,
              created_at ASC
            """,
            (scan_id,),
        ).fetchall()
        return [_row_to_dict(r) for r in rows if r is not None]


def get_finding(finding_id: str) -> "dict[str, Any] | None":
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
        return _row_to_dict(row)


# ---------------------------------------------------------------------------
# Analytics / session tracking
# ---------------------------------------------------------------------------
def log_scan_session(
    scan_id: str,
    repo_url: str,
    ip_address: str,
    user_agent: str,
    referrer: str,
) -> str:
    """Create an analytics row the moment a scan starts. Returns session_id."""
    session_id = str(uuid.uuid4())
    repo_name  = _normalize_repo_name(repo_url) or repo_url
    country, city = _geolocate_ip(ip_address)
    with _get_conn() as conn:
        conn.execute(
            """
            INSERT INTO scan_sessions
              (session_id, scan_id, repo_url, repo_name, ip_address,
               country, city, user_agent, referrer, started_at,
               scan_completed, pdf_downloaded)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)
            """,
            (
                session_id, scan_id, repo_url, repo_name,
                ip_address, country, city,
                user_agent, referrer, _utc_now_iso(),
            ),
        )
        conn.commit()
    return session_id


def update_session_on_complete(scan_id: str) -> None:
    """Copy final counts from the scans table into scan_sessions once done."""
    scan = get_scan(scan_id)
    if not scan:
        return
    started_at   = scan.get("created_at") or ""
    completed_at = scan.get("completed_at") or _utc_now_iso()
    elapsed = 0
    try:
        from datetime import datetime as _dt
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f+00:00",
            "%Y-%m-%dT%H:%M:%S+00:00",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
        ):
            try:
                t0 = _dt.strptime(started_at[:len(fmt)], fmt)
                t1 = _dt.strptime(completed_at[:len(fmt)], fmt)
                elapsed = max(0, int((t1 - t0).total_seconds()))
                break
            except ValueError:
                continue
    except Exception:
        pass

    with _get_conn() as conn:
        conn.execute(
            """
            UPDATE scan_sessions
            SET completed_at             = ?,
                scan_completed           = 1,
                findings_count           = ?,
                critical_count           = ?,
                high_count               = ?,
                medium_count             = ?,
                low_count                = ?,
                risk_score               = ?,
                time_to_complete_seconds = ?
            WHERE scan_id = ?
            """,
            (
                completed_at,
                int(scan.get("findings_count") or 0),
                int(scan.get("critical_count") or 0),
                int(scan.get("high_count") or 0),
                int(scan.get("medium_count") or 0),
                int(scan.get("low_count") or 0),
                int(scan.get("risk_score") or 0),
                elapsed,
                scan_id,
            ),
        )
        conn.commit()


def mark_pdf_downloaded(scan_id: str) -> None:
    """Flip pdf_downloaded flag when a user hits the download endpoint."""
    with _get_conn() as conn:
        conn.execute(
            "UPDATE scan_sessions SET pdf_downloaded = 1 WHERE scan_id = ?",
            (scan_id,),
        )
        conn.commit()


def get_all_sessions(limit: int = 500) -> "list[dict[str, Any]]":
    """Return most recent scan sessions for the admin dashboard."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_sessions ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [_row_to_dict(r) for r in rows if r is not None]


# ---------------------------------------------------------------------------
# PDF Binary Storage
# ---------------------------------------------------------------------------
def save_pdf_to_db(scan_id: str, pdf_bytes: bytes) -> None:
    """Store the physical PDF bytes inside the database permanently."""
    with _get_conn() as conn:
        if _USE_POSTGRES:
            import psycopg2
            blob = psycopg2.Binary(pdf_bytes)
        else:
            blob = pdf_bytes
            
        conn.execute("DELETE FROM scan_reports WHERE scan_id = ?", (scan_id,))
        conn.execute(
            "INSERT INTO scan_reports (scan_id, pdf_blob) VALUES (?, ?)",
            (scan_id, blob)
        )
        conn.commit()


def get_pdf_from_db(scan_id: str) -> "bytes | None":
    """Retrieve the physical PDF bytes out of the database."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT pdf_blob FROM scan_reports WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if not row:
            return None
        # row can be indexable or dict-like
        blob = row[0] if isinstance(row, tuple) else row["pdf_blob"]
        if _USE_POSTGRES and blob is not None:
            return bytes(blob)
        return blob


# ---------------------------------------------------------------------------
# IP geolocation (best-effort, no API key needed)
# ---------------------------------------------------------------------------
def _geolocate_ip(ip: str) -> "tuple[str, str]":
    """Resolve IP → (country, city) via ip-api.com free endpoint."""
    private = ("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
               "172.19.", "172.2", "::1", "localhost", "")
    if not ip or any(ip.startswith(p) for p in private):
        return "Local", "Local"
    try:
        import urllib.request
        url = f"http://ip-api.com/json/{ip}?fields=country,city,status"
        with urllib.request.urlopen(url, timeout=3) as resp:  # noqa: S310
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            return data.get("country", "Unknown"), data.get("city", "Unknown")
    except Exception:
        pass
    return "Unknown", "Unknown"
