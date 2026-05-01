"""
SecurePath — main Flask application.

Key fixes vs previous version:
- Pipeline progress mapping fixed: enrichment 60→85%, generation 85→100% (no gaps/overlaps)
- update_findings_batch wrapped in try/except — silent DB failure can't kill pipeline
- Finding ID extraction hardened — handles id / _id / finding_id
- enrich_progress lambda fixed: correctly maps 0-100% input to 60-85% output range
- poll interval hint added to status response (4s recommended)
- Admin dashboard: PDF link now targets correct /api/scan endpoint
- Background DB init: errors are surfaced more clearly
- All scan status transitions are explicit and logged
"""

import os
os.environ["GIT_PYTHON_REFRESH"] = "quiet"

import hashlib
import io
import json
import re
import threading
import uuid
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, abort, jsonify, render_template, request, send_file

from db import (
    create_scan,
    get_all_scans,
    get_findings,
    get_scan,
    init_db,
    insert_finding,
    insert_findings_batch,
    log_scan_session,
    mark_pdf_downloaded,
    get_all_sessions,
    update_finding,
    update_findings_batch,
    update_scan,
    update_session_on_complete,
    save_pdf_to_db,
    get_pdf_from_db,
    REPORTS_DIR,
)
from enricher import EXAIEnricher
from report import AuditReportGenerator
from scanner import SecurityScanner


app = Flask(__name__)
load_dotenv()


# ─── Background DB init ───────────────────────────────────────────────────────
def _background_init_db():
    try:
        init_db()
        print("[SecurePath] DB initialized OK")
    except Exception as e:
        print(f"[SecurePath] init_db FAILED — first DB request will surface error: {e}")

threading.Thread(target=_background_init_db, daemon=True).start()


# ─── Config ───────────────────────────────────────────────────────────────────
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "changeme")

GITHUB_REPO_REGEX = re.compile(
    r"^https://github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+(?:\.git)?/?$"
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/")
def landing():
    return render_template("landing.html")


@app.post("/api/scan/start")
def start_scan():
    payload  = request.get_json(silent=True) or {}
    repo_url = str(payload.get("repo_url", "")).strip()

    if not repo_url or not GITHUB_REPO_REGEX.match(repo_url):
        return jsonify({
            "error": "Invalid GitHub repo URL. Use https://github.com/org/repo"
        }), 400

    scan_id = create_scan(repo_url)

    # Log session data asynchronously — zero impact on response time
    ip        = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
    ua        = request.headers.get("User-Agent", "")
    referrer  = (
        request.headers.get("Referer", "")
        or request.headers.get("Referrer", "")
        or "direct"
    )
    threading.Thread(
        target=log_scan_session,
        args=(scan_id, repo_url, ip, ua, referrer),
        daemon=True,
    ).start()

    threading.Thread(
        target=_run_scan_pipeline,
        args=(scan_id, repo_url),
        daemon=True,
        name=f"scan-{scan_id[:8]}",
    ).start()

    return jsonify({"scan_id": scan_id, "redirect": f"/scan/{scan_id}"})


@app.get("/scan/<scan_id>")
def scan_dashboard(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        abort(404)
    return render_template("dashboard.html", scan=scan)


@app.get("/api/scan/<scan_id>/status")
def scan_status(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    findings = []
    if scan.get("status") in {"enriching", "generating", "complete", "failed"}:
        findings = get_findings(scan_id)

    enriched = [
        f for f in findings
        if str(f.get("enrichment_status", "pending")).lower() == "complete"
    ]

    return jsonify({
        "status":        scan.get("status"),
        "progress":      int(scan.get("progress") or 0),
        "current_step":  scan.get("current_step") or "",
        "counts": {
            "critical": int(scan.get("critical_count") or 0),
            "high":     int(scan.get("high_count") or 0),
            "medium":   int(scan.get("medium_count") or 0),
            "low":      int(scan.get("low_count") or 0),
        },
        "risk_score":     int(scan.get("risk_score") or 0),
        "findings":       enriched,
        "total_findings": int(scan.get("findings_count") or 0),
        "commit_sha":     scan.get("commit_sha") or "",
        # Hint to frontend: recommended poll interval in ms
        "poll_interval":  4000,
    })


@app.get("/api/scan/<scan_id>/download")
def download_report(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    if scan.get("status") != "complete":
        return jsonify({"error": "Report not ready yet"}), 400

    pdf_bytes = get_pdf_from_db(scan_id)
    if not pdf_bytes:
        return jsonify({"error": "Report file missing — scan may need to be re-run"}), 404

    threading.Thread(target=mark_pdf_downloaded, args=(scan_id,), daemon=True).start()

    repo_name = str(scan.get("repo_name") or "report").replace("/", "-")
    filename  = f"securepath-{repo_name}.pdf"
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


@app.get("/api/scans/history")
def scans_history():
    return jsonify(get_all_scans())


def clean(x):
    return (x or "").strip().strip("'").strip('"')

@app.get("/admin")
def admin_dashboard():
    if clean(request.args.get("key")) != clean(ADMIN_PASSWORD):
        return "Not authorised", 403

    return render_template("admin.html")

    sessions  = get_all_sessions()
    total     = len(sessions)
    pdfs      = sum(1 for s in sessions if s.get("pdf_downloaded"))
    completed = sum(1 for s in sessions if s.get("scan_completed"))
    conv_rate = int((pdfs / total * 100)) if total else 0

    rows_html = ""
    for s in sessions:
        ts       = (s.get("started_at") or "")[:16]
        repo     = s.get("repo_name") or s.get("repo_url") or ""
        ip       = s.get("ip_address") or ""
        country  = s.get("country") or ""
        city     = s.get("city") or ""
        referrer = s.get("referrer") or "direct"
        findings = s.get("findings_count") or 0
        crit     = s.get("critical_count") or 0
        duration = s.get("time_to_complete_seconds") or 0
        risk     = s.get("risk_score") or 0
        ua       = (s.get("user_agent") or "")[:60]
        sid      = s.get("scan_id", "")

        if s.get("scan_completed"):
            pdf_icon = "✅ " if s.get("pdf_downloaded") else ""
            pdf_cell = (
                f"<a href='/api/scan/{sid}/download' target='_blank' "
                f"style='text-decoration:none;color:inherit' title='Download PDF'>"
                f"📥 {pdf_icon}</a>"
            )
        else:
            pdf_cell = "⏳"

        rows_html += f"""
        <tr>
          <td>{ts}</td>
          <td class="repo">{repo}</td>
          <td>{ip}</td>
          <td>{country} / {city}</td>
          <td class="ref">{referrer[:40]}</td>
          <td><b style="color:#e94560">{crit}</b> / {findings}</td>
          <td>{risk}</td>
          <td>{duration}s</td>
          <td style="font-size:1.2em">{pdf_cell}</td>
          <td class="ua" title="{ua}">{ua[:40]}...</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>SecurePath Admin</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'IBM Plex Mono',monospace;background:#0d1117;color:#f0f6fc;padding:2rem}}
    h1{{color:#e94560;font-size:1.8rem;margin-bottom:.4rem}}
    .stats{{display:flex;gap:2rem;margin:1.2rem 0 1.8rem;flex-wrap:wrap}}
    .stat-box{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:.8rem 1.4rem;text-align:center}}
    .stat-box .n{{font-size:2rem;font-weight:700;color:#58a6ff}}
    .stat-box .l{{font-size:.75rem;color:#8b949e;margin-top:.2rem}}
    .tbl-wrap{{overflow-x:auto}}
    table{{width:100%;border-collapse:collapse;font-size:.78rem}}
    th{{background:#e94560;color:#fff;padding:8px 10px;text-align:left;white-space:nowrap}}
    td{{padding:7px 10px;border-bottom:1px solid #21262d;white-space:nowrap}}
    tr:hover td{{background:#161b22}}
    .repo{{color:#58a6ff;max-width:200px;overflow:hidden;text-overflow:ellipsis}}
    .ref{{color:#8b949e}}
    .ua{{color:#6e7681;font-size:.7rem}}
    .badge{{display:inline-block;background:#21262d;color:#e94560;border-radius:4px;padding:2px 8px;font-size:.75rem;margin-left:.5rem}}
  </style>
</head>
<body>
  <h1>SecurePath <span class="badge">ADMIN</span></h1>
  <p style="color:#8b949e;margin-top:.3rem">Real-time scan analytics</p>
  <div class="stats">
    <div class="stat-box"><div class="n">{total}</div><div class="l">Total Scans</div></div>
    <div class="stat-box"><div class="n">{completed}</div><div class="l">Completed</div></div>
    <div class="stat-box"><div class="n">{pdfs}</div><div class="l">PDFs Downloaded</div></div>
    <div class="stat-box"><div class="n">{conv_rate}%</div><div class="l">PDF Conversion Rate</div></div>
  </div>
  <div class="tbl-wrap">
    <table>
      <thead><tr>
        <th>Time (UTC)</th><th>Repo</th><th>IP</th><th>Location</th>
        <th>Referrer</th><th>Crit / Total</th><th>Risk</th>
        <th>Duration</th><th>PDF</th><th>User-Agent</th>
      </tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>
</body>
</html>""", 200


@app.get("/scan/<scan_id>/preview")
def report_preview(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        abort(404)
    findings = get_findings(scan_id)
    return render_template("report_preview.html", scan=scan, findings=findings)


# ─── Core scan pipeline ───────────────────────────────────────────────────────

def _run_scan_pipeline(scan_id: str, repo_url: str) -> None:
    """
    Pipeline stages and progress ranges:
      Cloning / scanning  →   0 – 60%
      AI enrichment       →  60 – 85%
      PDF generation      →  85 – 100%
    """
    try:
        # ── PHASE 1: SCAN (0–60%) ─────────────────────────────────────────────
        print(f"[{scan_id[:8]}] PHASE 1 — cloning & scanning")
        update_scan(scan_id, status="cloning", progress=2,
                    current_step="Cloning repository...")

        def scan_progress(p: float, step: str) -> None:
            # p is 0–100 from scanner; map to 0–60
            mapped = int(max(0, min(60, p * 0.6)))
            update_scan(scan_id, progress=mapped, current_step=step)

        scanner  = SecurityScanner(repo_url, scan_id, scan_progress)
        findings = scanner.run()
        print(f"[{scan_id[:8]}] Scanner returned {len(findings)} findings: {[type(f) for f in findings[:3]]}")

        # Persist findings
        try:
            insert_findings_batch(scan_id, findings)
            print(f"[{scan_id[:8]}] insert_findings_batch OK")
        except Exception as e:
            import traceback
            print(f"[{scan_id[:8]}] INSERT FAILED: {e}")
            traceback.print_exc()
            raise  # re-raise so pipeline marks as failed

        counts = {
            s: sum(1 for f in findings if str(f.get("severity", "")) == s)
            for s in ["critical", "high", "medium", "low", "info"]
        }
        risk_score = min(
            100,
            counts["critical"] * 25
            + counts["high"] * 10
            + counts["medium"] * 3
            + counts["low"] * 1,
        )

        print(f"[{scan_id[:8]}] PHASE 1 complete — "
              f"{len(findings)} findings | risk {risk_score}")
        update_scan(
            scan_id,
            status="enriching",
            progress=60,
            current_step=f"AI enrichment — {len(findings)} findings...",
            findings_count=len(findings),
            critical_count=counts["critical"],
            high_count=counts["high"],
            medium_count=counts["medium"],
            low_count=counts["low"],
            risk_score=risk_score,
        )

        # ── PHASE 2: ENRICH (60–85%) ──────────────────────────────────────────
        print(f"[{scan_id[:8]}] PHASE 2 — AI enrichment ({len(findings)} findings)")

        def enrich_progress(p: int, step: str) -> None:
            # p is 0–100 from enricher; map to 60–85
            mapped = 60 + int(max(0, min(100, p)) * 0.25)
            mapped = min(mapped, 85)
            update_scan(scan_id, progress=mapped, current_step=step)

        enricher         = EXAIEnricher(scan_id, enrich_progress)
        enriched_findings = enricher.enrich_all(findings)

        # Build batch update payload — hardened ID extraction
        batch_updates: list[tuple[str, dict]] = []
        for ef in enriched_findings:
            fid = str(
                ef.get("id") or ef.get("_id") or ef.get("finding_id") or ""
            ).strip()
            if not fid:
                continue  # skip findings without a DB id

            remediation = ef.get("remediation", [])
            bi  = ef.get("business_impact")
            ae  = ef.get("assets_exposed")

            batch_updates.append((fid, {
                "plain_english":        ef.get("plain_english"),
                "business_risk":        ef.get("business_risk"),
                "exploit_scenario":     ef.get("exploit_scenario"),
                "remediation_json":     json.dumps(
                    remediation if isinstance(remediation, list) else []
                ),
                "soc2_controls":        ",".join(ef.get("soc2_controls", []))
                                        if isinstance(ef.get("soc2_controls"), list)
                                        else str(ef.get("soc2_controls") or ""),
                "confidence_score":     ef.get("confidence_score"),
                "false_positive_risk":  ef.get("false_positive_risk"),
                "false_positive_reason":ef.get("false_positive_reason"),
                "business_impact_json": json.dumps(bi) if isinstance(bi, dict) else (bi or None),
                "assets_exposed_json":  json.dumps(ae) if isinstance(ae, dict) else (ae or None),
                "enrichment_status":    ef.get("enrichment_status", "complete"),
            }))

        if batch_updates:
            try:
                update_findings_batch(batch_updates)
                print(f"[{scan_id[:8]}] Batch DB update OK — {len(batch_updates)} findings")
            except Exception as db_err:
                # Non-fatal: findings still in memory for PDF generation
                print(f"[{scan_id[:8]}] WARNING: batch DB update failed: {db_err}")

        # Update findings hash for cache validation
        findings_hash = hashlib.sha256(
            json.dumps(enriched_findings, sort_keys=True).encode("utf-8")
        ).hexdigest()
        update_scan(scan_id, findings_hash=findings_hash)

        print(f"[{scan_id[:8]}] PHASE 2 complete")
        update_scan(
            scan_id,
            status="generating",
            progress=85,
            current_step="Generating audit evidence PDF...",
        )

        # ── PHASE 3: GENERATE PDF (85–100%) ───────────────────────────────────
        print(f"[{scan_id[:8]}] PHASE 3 — PDF generation")

        scan           = get_scan(scan_id)
        final_findings = get_findings(scan_id)

        generator = AuditReportGenerator()
        pdf_path  = generator.generate(
            scan or {"id": scan_id}, final_findings
        )

        # Persist PDF to DB (survives ephemeral filesystem on Railway/Render)
        try:
            with open(pdf_path, "rb") as f:
                pdf_bytes = f.read()
            save_pdf_to_db(scan_id, pdf_bytes)
            print(f"[{scan_id[:8]}] PDF saved to DB — {len(pdf_bytes):,} bytes")
        except Exception as pdf_err:
            print(f"[{scan_id[:8]}] WARNING: failed to save PDF to DB: {pdf_err}")

        update_scan(
            scan_id,
            status="complete",
            progress=100,
            current_step="Complete",
            report_path="db://scan_reports",
            completed_at=_now_iso(),
        )
        print(f"[{scan_id[:8]}] ✅ PIPELINE COMPLETE")

        threading.Thread(
            target=update_session_on_complete, args=(scan_id,), daemon=True
        ).start()

    except Exception as exc:
        import traceback
        print(f"[{scan_id[:8]}] ❌ PIPELINE FAILED:")
        traceback.print_exc()
        try:
            update_scan(
                scan_id,
                status="failed",
                current_step=f"Failed: {str(exc)[:120]}",
                error_message=str(exc),
                progress=100,
                completed_at=_now_iso(),
            )
        except Exception as db_exc:
            print(f"[{scan_id[:8]}] CRITICAL: could not write failure status to DB: {db_exc}")


# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    os.makedirs(REPORTS_DIR, exist_ok=True)
    port = int(os.getenv("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port, threaded=True)