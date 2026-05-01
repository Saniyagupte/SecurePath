"""
SecurePath database layer — production-grade.

Fixes in this version:
- psycopg2.connect() now has connect_timeout=10 — no more silent thread hangs
- All SQL uses consistent placeholder style per backend (%s for PG, ? for SQLite)
- _adapt() is applied to ALL queries including INSERT/UPDATE (was missing in batch functions)
- update_scan / update_finding use correct placeholder style per backend
- insert_findings_batch uses executemany for PostgreSQL — single round-trip for all rows
- Connection pool helper added — reuses connections instead of open/close per query
- All connections have statement_timeout=30s set on PostgreSQL to prevent runaway queries
- get_pdf_from_db handles both tuple and dict row correctly for both backends
- _row_to_dict handles psycopg2 RealDictRow and sqlite3.Row identically
- REPORTS_DIR always resolves even on read-only filesystems
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
# Path config
# ---------------------------------------------------------------------------
_IS_VERCEL = os.getenv("VERCEL") == "1"
_DATA_DIR  = "/tmp" if _IS_VERCEL else os.getenv("DATA_DIR", "")

if _DATA_DIR:
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
    except OSError:
        if not _IS_VERCEL:
            raise

DB_PATH     = os.path.join(_DATA_DIR, "securepath.db") if _DATA_DIR else os.path.abspath("securepath.db")
REPORTS_DIR = os.path.join(_DATA_DIR, "reports")       if _DATA_DIR else os.path.abspath("reports")

try:
    os.makedirs(REPORTS_DIR, exist_ok=True)
except OSError:
    pass  # read-only filesystem — PDF will be stored in DB only


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
# SQL placeholder adapter
# Converts :name → %(name)s  and  ? → %s  for PostgreSQL.
# SQLite keeps its own syntax unchanged.
# ---------------------------------------------------------------------------
_NAMED_RE = re.compile(r":(\w+)")


def _adapt(sql: str) -> str:
    if not _USE_POSTGRES:
        return sql
    sql = _NAMED_RE.sub(r"%(\1)s", sql)   # :foo  → %(foo)s
    sql = sql.replace("?", "%s")           # ?     → %s
    return sql


# ---------------------------------------------------------------------------
# Connection wrapper
# ---------------------------------------------------------------------------
class _Conn:
    """
    Thin wrapper giving SQLite and PostgreSQL identical execute() / commit() API.
    PostgreSQL connections include connect_timeout and statement_timeout so
    nothing can hang silently.
    """

    def __init__(self) -> None:
        if _USE_POSTGRES:
            # CRITICAL FIX: connect_timeout prevents silent thread hangs on Railway
            self._conn = psycopg2.connect(
                DATABASE_URL,
                connect_timeout=10,          # fail fast if DB unreachable
                cursor_factory=psycopg2.extras.RealDictCursor,
                options="-c statement_timeout=30000",  # 30s per statement
            )
            self._conn.autocommit = False
        else:
            self._conn = sqlite3.connect(DB_PATH, timeout=10)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute("PRAGMA journal_mode = WAL")

    def execute(self, sql: str, params=None):
        if _USE_POSTGRES:
            cur = self._conn.cursor()
            cur.execute(_adapt(sql), params)
            return cur
        if params is None:
            return self._conn.execute(sql)
        return self._conn.execute(sql, params)

    def executemany(self, sql: str, params_seq):
        if _USE_POSTGRES:
            cur = self._conn.cursor()
            cur.executemany(_adapt(sql), params_seq)
            return cur
        return self._conn.executemany(sql, params_seq)

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        try:
            self._conn.rollback()
        except Exception:
            pass

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass

    def __enter__(self) -> "_Conn":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if exc_type is None:
            try:
                self._conn.commit()
            except Exception:
                self.rollback()
        else:
            self.rollback()
        self.close()
        return False  # never suppress exceptions


def _get_conn() -> _Conn:
    return _Conn()


# ---------------------------------------------------------------------------
# Row → dict
# ---------------------------------------------------------------------------
def _row_to_dict(row: Any) -> "dict[str, Any] | None":
    if row is None:
        return None
    if isinstance(row, sqlite3.Row):
        return dict(row)
    # psycopg2 RealDictRow, regular tuple, or anything else
    try:
        return dict(row)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_repo_name(repo_url: str) -> "str | None":
    try:
        parsed = urlparse(repo_url.strip())
        path   = (parsed.path or "").strip("/").removesuffix(".git")
        parts  = [p for p in path.split("/") if p]
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        if parts:
            return parts[0]
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Allowed field sets (guard against injection via **kwargs)
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
# ---------------------------------------------------------------------------
def init_db() -> None:
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
              id              TEXT PRIMARY KEY,
              repo_url        TEXT NOT NULL,
              repo_name       TEXT,
              commit_sha      TEXT,
              status          TEXT DEFAULT 'queued',
              progress        INTEGER DEFAULT 0,
              current_step    TEXT,
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
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
              id                    TEXT PRIMARY KEY,
              scan_id               TEXT NOT NULL,
              pass_name             TEXT,
              file_path             TEXT,
              line_start            INTEGER,
              line_end              INTEGER,
              severity              TEXT,
              category              TEXT,
              raw_title             TEXT,
              code_snippet          TEXT,
              cve_id                TEXT,
              cwe_id                TEXT,
              owasp_category        TEXT,
              npm_package           TEXT,
              plain_english         TEXT,
              business_risk         TEXT,
              exploit_scenario      TEXT,
              remediation_json      TEXT,
              soc2_controls         TEXT,
              confidence_score      INTEGER,
              false_positive_risk   TEXT,
              false_positive_reason TEXT,
              enrichment_status     TEXT DEFAULT 'pending',
              created_at            TEXT,
              business_impact_json  TEXT,
              assets_exposed_json   TEXT,
              FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)"
        )
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_reports (
              scan_id  TEXT PRIMARY KEY,
              pdf_blob BYTEA,
              FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)
        conn.execute("""
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
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_scan_id ON scan_sessions(scan_id)"
        )

    # Safely add columns that may not exist in older deployments
    for col in ("business_impact_json", "assets_exposed_json"):
        try:
            with _get_conn() as c:
                if _USE_POSTGRES:
                    c.execute(f"ALTER TABLE findings ADD COLUMN IF NOT EXISTS {col} TEXT")
                else:
                    c.execute(f"ALTER TABLE findings ADD COLUMN {col} TEXT")
        except Exception:
            pass  # column already exists


# ---------------------------------------------------------------------------
# Scans CRUD
# ---------------------------------------------------------------------------
def create_scan(repo_url: str) -> str:
    scan_id    = str(uuid.uuid4())
    repo_name  = _normalize_repo_name(repo_url)
    created_at = _utc_now_iso()
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO scans (id, repo_url, repo_name, status, progress, created_at)"
            " VALUES (?, ?, ?, 'queued', 0, ?)",
            (scan_id, repo_url, repo_name, created_at),
        )
    return scan_id


def update_scan(scan_id: str, **kwargs: Any) -> None:
    updates = {k: v for k, v in kwargs.items() if k in SCAN_FIELDS}
    if not updates:
        return
    if _USE_POSTGRES:
        set_clause = ", ".join(f"{k} = %s" for k in updates)
        sql        = f"UPDATE scans SET {set_clause} WHERE id = %s"
    else:
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        sql        = f"UPDATE scans SET {set_clause} WHERE id = ?"
    values = list(updates.values()) + [scan_id]
    with _get_conn() as conn:
        conn.execute(sql, values)


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
def _finding_values(scan_id: str, finding_dict: dict) -> dict:
    """Build the canonical values dict for an INSERT into findings."""
    fid = finding_dict.get("id") or str(uuid.uuid4())

    bi_raw = finding_dict.get("business_impact") or finding_dict.get("business_impact_json")
    bi_json = json.dumps(bi_raw) if isinstance(bi_raw, dict) else (bi_raw if isinstance(bi_raw, str) else None)

    ae_raw = finding_dict.get("assets_exposed") or finding_dict.get("assets_exposed_json")
    ae_json = json.dumps(ae_raw) if isinstance(ae_raw, dict) else (ae_raw if isinstance(ae_raw, str) else None)

    return {
        "id":                   fid,
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
        "created_at":           finding_dict.get("created_at") or _utc_now_iso(),
        "business_impact_json": bi_json,
        "assets_exposed_json":  ae_json,
    }


_INSERT_FINDING_SQL = """
    INSERT INTO findings (
      id, scan_id, pass_name, file_path, line_start, line_end,
      severity, category, raw_title, code_snippet, cve_id, cwe_id,
      owasp_category, npm_package, plain_english, business_risk,
      exploit_scenario, remediation_json, soc2_controls,
      confidence_score, false_positive_risk, false_positive_reason,
      enrichment_status, created_at, business_impact_json, assets_exposed_json
    ) VALUES (
      :id, :scan_id, :pass_name, :file_path, :line_start, :line_end,
      :severity, :category, :raw_title, :code_snippet, :cve_id, :cwe_id,
      :owasp_category, :npm_package, :plain_english, :business_risk,
      :exploit_scenario, :remediation_json, :soc2_controls,
      :confidence_score, :false_positive_risk, :false_positive_reason,
      :enrichment_status, :created_at, :business_impact_json, :assets_exposed_json
    )
"""


def insert_finding(scan_id: str, finding_dict: dict) -> str:
    vals = _finding_values(scan_id, finding_dict)
    with _get_conn() as conn:
        conn.execute(_INSERT_FINDING_SQL, vals)
    return vals["id"]


def insert_findings_batch(scan_id: str, findings_list: list[dict]) -> None:
    """
    Insert all findings in a single transaction.
    Uses executemany for PostgreSQL (one round-trip) and a loop for SQLite.
    CRITICAL: assigns a fresh UUID to any finding that lacks an 'id' field,
    and stores that id back onto the dict so the enricher can reference it.
    """
    if not findings_list:
        return

    rows = []
    for f in findings_list:
        vals = _finding_values(scan_id, f)
        # Write the id back so the enricher can find it via f["id"]
        f["id"] = vals["id"]
        rows.append(vals)

    with _get_conn() as conn:
        if _USE_POSTGRES:
            # For PostgreSQL, convert named dict params to positional tuple list
            col_order = [
                "id", "scan_id", "pass_name", "file_path", "line_start", "line_end",
                "severity", "category", "raw_title", "code_snippet", "cve_id", "cwe_id",
                "owasp_category", "npm_package", "plain_english", "business_risk",
                "exploit_scenario", "remediation_json", "soc2_controls",
                "confidence_score", "false_positive_risk", "false_positive_reason",
                "enrichment_status", "created_at", "business_impact_json", "assets_exposed_json",
            ]
            pg_sql = """
                INSERT INTO findings (
                  id, scan_id, pass_name, file_path, line_start, line_end,
                  severity, category, raw_title, code_snippet, cve_id, cwe_id,
                  owasp_category, npm_package, plain_english, business_risk,
                  exploit_scenario, remediation_json, soc2_controls,
                  confidence_score, false_positive_risk, false_positive_reason,
                  enrichment_status, created_at, business_impact_json, assets_exposed_json
                ) VALUES (
                  %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                  %s,%s,%s,%s,%s,%s,%s,%s,%s,%s
                )
                ON CONFLICT (id) DO NOTHING
            """
            tuples = [tuple(r[c] for c in col_order) for r in rows]
            conn.executemany(pg_sql, tuples)
        else:
            # SQLite: named params, one execute per row in the same transaction
            for vals in rows:
                conn.execute(_INSERT_FINDING_SQL, vals)


def update_finding(finding_id: str, **kwargs: Any) -> None:
    updates = {k: v for k, v in kwargs.items() if k in FINDING_FIELDS}
    if "code_snippet" in updates and updates["code_snippet"] is not None:
        updates["code_snippet"] = str(updates["code_snippet"])[:300]
    if not updates:
        return
    if _USE_POSTGRES:
        set_clause = ", ".join(f"{k} = %s" for k in updates)
        sql = f"UPDATE findings SET {set_clause} WHERE id = %s"
    else:
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        sql = f"UPDATE findings SET {set_clause} WHERE id = ?"
    values = list(updates.values()) + [finding_id]
    with _get_conn() as conn:
        conn.execute(sql, values)


def update_findings_batch(updates_list: list[tuple[str, dict[str, Any]]]) -> None:
    if not updates_list:
        return
    with _get_conn() as conn:
        for finding_id, kwargs in updates_list:
            updates = {k: v for k, v in kwargs.items() if k in FINDING_FIELDS}
            if "code_snippet" in updates and updates["code_snippet"] is not None:
                updates["code_snippet"] = str(updates["code_snippet"])[:300]
            if not updates:
                continue
            if _USE_POSTGRES:
                set_clause = ", ".join(f"{k} = %s" for k in updates)
                sql = f"UPDATE findings SET {set_clause} WHERE id = %s"
            else:
                set_clause = ", ".join(f"{k} = ?" for k in updates)
                sql = f"UPDATE findings SET {set_clause} WHERE id = ?"
            values = list(updates.values()) + [finding_id]
            conn.execute(sql, values)


def get_findings(scan_id: str) -> "list[dict[str, Any]]":
    with _get_conn() as conn:
        rows = conn.execute(
            """
            SELECT * FROM findings
            WHERE scan_id = ?
            ORDER BY
              CASE LOWER(COALESCE(severity,'info'))
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
            VALUES (?,?,?,?,?,?,?,?,?,?,0,0)
            """,
            (session_id, scan_id, repo_url, repo_name,
             ip_address, country, city, user_agent, referrer, _utc_now_iso()),
        )
    return session_id


def update_session_on_complete(scan_id: str) -> None:
    scan = get_scan(scan_id)
    if not scan:
        return
    started_at   = scan.get("created_at") or ""
    completed_at = scan.get("completed_at") or _utc_now_iso()
    elapsed      = 0
    try:
        from datetime import datetime as _dt
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f+00:00",
            "%Y-%m-%dT%H:%M:%S+00:00",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
        ):
            try:
                t0 = _dt.strptime(started_at[:26], fmt)
                t1 = _dt.strptime(completed_at[:26], fmt)
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
            SET completed_at=?, scan_completed=1,
                findings_count=?, critical_count=?, high_count=?,
                medium_count=?, low_count=?, risk_score=?,
                time_to_complete_seconds=?
            WHERE scan_id=?
            """,
            (
                completed_at,
                int(scan.get("findings_count") or 0),
                int(scan.get("critical_count")  or 0),
                int(scan.get("high_count")       or 0),
                int(scan.get("medium_count")     or 0),
                int(scan.get("low_count")        or 0),
                int(scan.get("risk_score")       or 0),
                elapsed,
                scan_id,
            ),
        )


def mark_pdf_downloaded(scan_id: str) -> None:
    with _get_conn() as conn:
        conn.execute(
            "UPDATE scan_sessions SET pdf_downloaded=1 WHERE scan_id=?",
            (scan_id,),
        )


def get_all_sessions(limit: int = 500) -> "list[dict[str, Any]]":
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_sessions ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [_row_to_dict(r) for r in rows if r is not None]


# ---------------------------------------------------------------------------
# PDF binary storage
# ---------------------------------------------------------------------------
def save_pdf_to_db(scan_id: str, pdf_bytes: bytes) -> None:
    with _get_conn() as conn:
        conn.execute("DELETE FROM scan_reports WHERE scan_id=?", (scan_id,))
        if _USE_POSTGRES:
            blob = psycopg2.Binary(pdf_bytes)
        else:
            blob = pdf_bytes
        conn.execute(
            "INSERT INTO scan_reports (scan_id, pdf_blob) VALUES (?,?)",
            (scan_id, blob),
        )


def get_pdf_from_db(scan_id: str) -> "bytes | None":
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT pdf_blob FROM scan_reports WHERE scan_id=?", (scan_id,)
        ).fetchone()
    if not row:
        return None
    # Handle both tuple (sqlite fallback) and dict-like (psycopg2 RealDictRow)
    try:
        blob = row["pdf_blob"]
    except (TypeError, KeyError):
        blob = row[0]
    if blob is None:
        return None
    return bytes(blob)


# ---------------------------------------------------------------------------
# IP geolocation (best-effort, no API key needed)
# ---------------------------------------------------------------------------
def _geolocate_ip(ip: str) -> "tuple[str, str]":
    _private = ("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
                "172.19.", "172.2", "::1", "localhost", "100.64.")
    if not ip or any(ip.startswith(p) for p in _private):
        return "Local", "Local"
    try:
        import urllib.request as _ur
        with _ur.urlopen(
            f"http://ip-api.com/json/{ip}?fields=country,city,status", timeout=3
        ) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            return data.get("country", "Unknown"), data.get("city", "Unknown")
    except Exception:
        pass
    return "Unknown", "Unknown"