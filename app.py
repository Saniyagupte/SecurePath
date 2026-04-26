import hashlib
import json
import os
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
    log_scan_session,
    mark_pdf_downloaded,
    get_all_sessions,
    update_finding,
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

# Ensure DB schema is ready when gunicorn imports this module
try:
    init_db()
except Exception as _e:
    print(f"[SecurePath] init_db at import: {_e}")

# Admin access — set ADMIN_PASSWORD env var on Railway/Render, default is intentionally weak
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "changeme")

GITHUB_REPO_REGEX = re.compile(
    r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?$"
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@app.get("/")
def landing():
    return render_template("landing.html")


@app.post("/api/scan/start")
def start_scan():
    payload = request.get_json(silent=True) or {}
    repo_url = str(payload.get("repo_url", "")).strip()
    if not repo_url or not GITHUB_REPO_REGEX.match(repo_url):
        return jsonify({"error": "Invalid GitHub repo URL. Use https://github.com/org/repo"}), 400

    scan_id = create_scan(repo_url)

    # Capture session data silently — zero friction for caller
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
    user_agent = request.headers.get("User-Agent", "")
    referrer = request.headers.get("Referer", "") or request.headers.get("Referrer", "") or "direct"
    threading.Thread(
        target=log_scan_session,
        args=(scan_id, repo_url, ip, user_agent, referrer),
        daemon=True,
    ).start()

    thread = threading.Thread(
        target=_run_scan_pipeline,
        args=(scan_id, repo_url),
        daemon=True,
        name=f"scan-{scan_id[:8]}",
    )
    thread.start()
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
        f
        for f in findings
        if str(f.get("enrichment_status", "pending")).lower() == "complete"
    ]

    return jsonify(
        {
            "status": scan.get("status"),
            "progress": int(scan.get("progress") or 0),
            "current_step": scan.get("current_step") or "",
            "counts": {
                "critical": int(scan.get("critical_count") or 0),
                "high": int(scan.get("high_count") or 0),
                "medium": int(scan.get("medium_count") or 0),
                "low": int(scan.get("low_count") or 0),
            },
            "risk_score": int(scan.get("risk_score") or 0),
            "findings": enriched,
            "total_findings": int(scan.get("findings_count") or 0),
            "commit_sha": scan.get("commit_sha") or "",
        }
    )


@app.get("/api/scan/<scan_id>/download")
def download_report(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    if scan.get("status") != "complete":
        return jsonify({"error": "Report not ready"}), 400

    pdf_bytes = get_pdf_from_db(scan_id)
    if not pdf_bytes:
        return jsonify({"error": "Report file missing"}), 404

    # Track PDF download in analytics (fire-and-forget)
    threading.Thread(target=mark_pdf_downloaded, args=(scan_id,), daemon=True).start()

    repo_name = str(scan.get("repo_name") or "report").replace("/", "-")
    filename = f"securepath-{repo_name}.pdf"
    import io
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


@app.get("/api/scans/history")
def scans_history():
    return jsonify(get_all_scans())


@app.get("/admin")
def admin_dashboard():
    """Password-protected admin analytics view. Access via /admin?key=YOUR_PASSWORD."""
    password = request.args.get("key", "")
    if password != ADMIN_PASSWORD:
        return "Not authorised", 403

    sessions = get_all_sessions()
    total = len(sessions)
    pdfs = sum(1 for s in sessions if s.get("pdf_downloaded"))
    completed = sum(1 for s in sessions if s.get("scan_completed"))

    rows_html = ""
    for s in sessions:
        ts = (s.get("started_at") or "")[:16]
        repo = s.get("repo_name") or s.get("repo_url") or ""
        ip = s.get("ip_address") or ""
        country = s.get("country") or ""
        city = s.get("city") or ""
        referrer = s.get("referrer") or "direct"
        findings = s.get("findings_count") or 0
        crit = s.get("critical_count") or 0
        duration = s.get("time_to_complete_seconds") or 0
        pdf_status = "✅ " if s.get("pdf_downloaded") else ""
        if s.get("scan_completed"):
            pdf = f"<a href='/api/scan/{s.get('scan_id')}/download' target='_blank' style='text-decoration:none; color:inherit' title='Download PDF'>📥 {pdf_status}</a>"
        else:
            pdf = "⏳"
        risk = s.get("risk_score") or 0
        ua = (s.get("user_agent") or "")[:60]
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
          <td style="font-size:1.2em">{pdf}</td>
          <td class="ua" title="{ua}">{ua[:40]}...</td>
        </tr>"""

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>SecurePath Admin</title>
      <style>
        *{{box-sizing:border-box; margin:0; padding:0}}
        body{{font-family:'IBM Plex Mono',monospace; background:#0d1117; color:#f0f6fc; padding:2rem}}
        h1{{color:#e94560; font-size:1.8rem; margin-bottom:.4rem}}
        .stats{{display:flex; gap:2rem; margin:1.2rem 0 1.8rem}}
        .stat-box{{background:#161b22; border:1px solid #21262d; border-radius:8px;
                   padding:.8rem 1.4rem; text-align:center}}
        .stat-box .n{{font-size:2rem; font-weight:700; color:#58a6ff}}
        .stat-box .l{{font-size:.75rem; color:#8b949e; margin-top:.2rem}}
        .tbl-wrap{{overflow-x:auto}}
        table{{width:100%; border-collapse:collapse; font-size:.78rem}}
        th{{background:#e94560; color:#fff; padding:8px 10px; text-align:left; white-space:nowrap}}
        td{{padding:7px 10px; border-bottom:1px solid #21262d; white-space:nowrap}}
        tr:hover td{{background:#161b22}}
        .repo{{color:#58a6ff; max-width:200px; overflow:hidden; text-overflow:ellipsis}}
        .ref{{color:#8b949e}}
        .ua{{color:#6e7681; font-size:.7rem}}
        .badge{{display:inline-block; background:#21262d; color:#e94560;
                border-radius:4px; padding:2px 8px; font-size:.75rem; margin-left:.5rem}}
      </style>
    </head>
    <body>
      <h1>SecurePath <span class="badge">ADMIN</span></h1>
      <p style="color:#8b949e; margin-top:.3rem">Real-time scan analytics &mdash; eyes only</p>
      <div class="stats">
        <div class="stat-box"><div class="n">{total}</div><div class="l">Total Scans</div></div>
        <div class="stat-box"><div class="n">{completed}</div><div class="l">Completed</div></div>
        <div class="stat-box"><div class="n">{pdfs}</div><div class="l">PDFs Downloaded</div></div>
        <div class="stat-box"><div class="n">{int(pdfs/total*100) if total else 0}%</div><div class="l">PDF Conversion Rate</div></div>
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
    </html>
    """, 200


@app.get("/scan/<scan_id>/preview")
def report_preview(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        abort(404)
    findings = get_findings(scan_id)
    return render_template("report_preview.html", scan=scan, findings=findings)


def _run_scan_pipeline(scan_id: str, repo_url: str) -> None:
    try:
        def progress_cb(p: int, step: str) -> None:
            update_scan(scan_id, progress=p, current_step=step)

        # PHASE 1: SCAN (0-60%)
        update_scan(
            scan_id,
            status="cloning",
            progress=2,
            current_step="Cloning repository...",
        )
        scanner = SecurityScanner(
            repo_url,
            scan_id,
            lambda p, s: progress_cb(int(max(0, min(100, p * 0.6))), s),
        )
        findings = scanner.run()

        # Persist findings
        for f in findings:
            insert_finding(scan_id, f)

        counts = {s: sum(1 for f in findings if str(f.get("severity")) == s) for s in ["critical", "high", "medium", "low", "info"]}
        risk_score = min(
            100,
            (counts["critical"] * 25)
            + (counts["high"] * 10)
            + (counts["medium"] * 3)
            + (counts["low"] * 1),
        )
        update_scan(
            scan_id,
            status="enriching",
            progress=60,
            current_step="Enriching findings with EXAI...",
            findings_count=len(findings),
            critical_count=counts["critical"],
            high_count=counts["high"],
            medium_count=counts["medium"],
            low_count=counts["low"],
            risk_score=risk_score,
        )

        # PHASE 2: ENRICH (60-85%)
        def enrich_progress(p: int, step: str) -> None:
            mapped = 60 + int(max(0, min(100, p)) * 0.25)
            progress_cb(mapped, step)

        enricher = EXAIEnricher(scan_id, enrich_progress)
        enriched_findings = enricher.enrich_all(findings)

        # Update findings in DB by finding id
        for ef in enriched_findings:
            fid = ef.get("id")
            if not fid:
                continue
            remediation = ef.get("remediation", [])
            # Serialize new impact/exposure fields for DB storage
            bi = ef.get("business_impact")
            ae = ef.get("assets_exposed")
            bi_json = json.dumps(bi) if isinstance(bi, dict) else (bi if isinstance(bi, str) else None)
            ae_json = json.dumps(ae) if isinstance(ae, dict) else (ae if isinstance(ae, str) else None)
            update_finding(
                str(fid),
                plain_english=ef.get("plain_english"),
                business_risk=ef.get("business_risk"),
                exploit_scenario=ef.get("exploit_scenario"),
                remediation_json=json.dumps(remediation if isinstance(remediation, list) else []),
                soc2_controls=",".join(ef.get("soc2_controls", []))
                if isinstance(ef.get("soc2_controls", []), list)
                else str(ef.get("soc2_controls") or ""),
                confidence_score=ef.get("confidence_score"),
                false_positive_risk=ef.get("false_positive_risk"),
                false_positive_reason=ef.get("false_positive_reason"),
                business_impact_json=bi_json,
                assets_exposed_json=ae_json,
                enrichment_status="failed"
                if ef.get("enrichment_failed")
                else "complete",
            )

        findings_str = json.dumps(enriched_findings, sort_keys=True)
        findings_hash = hashlib.sha256(findings_str.encode("utf-8")).hexdigest()
        update_scan(scan_id, findings_hash=findings_hash)

        # PHASE 3: GENERATE (85-100%)
        update_scan(
            scan_id,
            status="generating",
            progress=85,
            current_step="Generating audit evidence PDF...",
        )
        scan = get_scan(scan_id)
        final_findings = get_findings(scan_id)
        generator = AuditReportGenerator()
        pdf_path = generator.generate(scan or {"id": scan_id}, final_findings)

        # Cache it inside the database perfectly for ephemeral environments
        try:
            with open(pdf_path, "rb") as f:
                pdf_bytes = f.read()
            save_pdf_to_db(scan_id, pdf_bytes)
        except Exception as e:
            print(f"[SecurePath] Failed to save PDF to DB for {scan_id}: {e}")

        update_scan(
            scan_id,
            status="complete",
            progress=100,
            current_step="Complete",
            report_path="db://scan_reports",  # pseudo path now
            completed_at=_now_iso(),
        )
        # Update analytics session with final counts asynchronously
        threading.Thread(
            target=update_session_on_complete, args=(scan_id,), daemon=True
        ).start()
    except Exception as exc:
        update_scan(
            scan_id,
            status="failed",
            current_step=f"Failed: {str(exc)[:100]}",
            error_message=str(exc),
            progress=100,
            completed_at=_now_iso(),
        )
        print(f"[SecurePath] Scan {scan_id} failed: {exc}")


if __name__ == "__main__":
    init_db()
    os.makedirs(REPORTS_DIR, exist_ok=True)
    port = int(os.getenv("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port, threaded=True)
