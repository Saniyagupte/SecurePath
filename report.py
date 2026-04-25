import json
import os
from datetime import datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.utils import simpleSplit
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, Table, TableStyle
from soc2_controls import get_soc2_mapping_for_finding
from db import REPORTS_DIR  # resolves to /data/reports in prod, ./reports locally


class AuditReportGenerator:
    # Professional monochrome palette
    BLACK = colors.HexColor("#000000")
    NEAR_BLACK = colors.HexColor("#111111")
    DARK_GRAY = colors.HexColor("#333333")
    MID_GRAY = colors.HexColor("#666666")
    LIGHT_GRAY = colors.HexColor("#999999")
    RULE_GRAY = colors.HexColor("#cccccc")
    BG_LIGHT = colors.HexColor("#f5f5f5")
    BG_ALT = colors.HexColor("#eeeeee")
    WHITE = colors.HexColor("#ffffff")

    # Severity uses weight, not color — but we keep subtle gray tones for badges
    SEV_CRITICAL = colors.HexColor("#111111")
    SEV_HIGH = colors.HexColor("#333333")
    SEV_MEDIUM = colors.HexColor("#666666")
    SEV_LOW = colors.HexColor("#999999")

    PAGE_W, PAGE_H = A4
    MARGIN_X = 48
    MARGIN_Y = 42

    def __init__(self) -> None:
        self.styles = getSampleStyleSheet()
        self.body = ParagraphStyle(
            "Body",
            parent=self.styles["BodyText"],
            fontName="Helvetica",
            fontSize=10,
            leading=13.5,
            textColor=self.NEAR_BLACK,
        )
        self.small = ParagraphStyle(
            "Small",
            parent=self.body,
            fontSize=8,
            leading=10.5,
            textColor=self.MID_GRAY,
        )
        self.h2 = ParagraphStyle(
            "H2",
            parent=self.body,
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=self.BLACK,
        )
        self.mono = "Courier"
        self.finding_counter = 0

    def generate(self, scan: dict, findings: list[dict]) -> str:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        scan_id = str(scan.get("id", "unknown"))
        out_path = os.path.abspath(os.path.join(REPORTS_DIR, f"securepath_{scan_id[:8]}.pdf"))
        # Deduplicate findings by (file_path, line_start, raw_title) to avoid false inflation
        seen: set = set()
        deduped: list[dict] = []
        for f in findings:
            key = (f.get("file_path"), f.get("line_start"), f.get("raw_title"))
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        findings = deduped

        c = canvas.Canvas(out_path, pagesize=A4)
        self._draw_cover_page(c, scan, findings)
        c.showPage()

        self._draw_executive_summary(c, scan, findings)
        c.showPage()

        high_crit = [f for f in findings if str(f.get("severity", "")).lower() in {"critical", "high"}]
        self.finding_counter = 0
        self._extra_pages = 1
        for finding in high_crit:
            self.finding_counter += 1
            self._draw_finding_page(c, finding, self.finding_counter)
            c.showPage()

        self._draw_additional_findings_table(c, findings, page_offset=0)
        c.showPage()

        self._draw_integrity_page(c, scan)
        c.save()
        return out_path

    def _severity_label(self, severity: str) -> str:
        return str(severity).upper()

    def _severity_bg(self, severity: str) -> colors.Color:
        m = {
            "critical": self.SEV_CRITICAL,
            "high": self.SEV_HIGH,
            "medium": self.SEV_MEDIUM,
            "low": self.SEV_LOW,
            "info": self.LIGHT_GRAY,
        }
        return m.get(str(severity).lower(), self.MID_GRAY)

    def _severity_fg(self, severity: str) -> colors.Color:
        return self.WHITE

    @staticmethod
    def _safe(value: Any, maxlen: int = 300, fallback: str = "") -> str:
        """Return a safely truncated, whitespace-normalised string."""
        if value is None:
            return fallback
        s = str(value).replace("\x00", "").strip()
        return s[:maxlen] if len(s) > maxlen else s

    def _draw_footer(self, c: canvas.Canvas, page_num: int) -> None:
        c.setFont("Helvetica", 7.5)
        c.setFillColor(self.LIGHT_GRAY)
        c.drawString(self.MARGIN_X, 20, "SecurePath v1.0.0  ·  Security Assessment Report")
        c.drawRightString(self.PAGE_W - self.MARGIN_X, 20, f"Page {page_num}")
        c.setStrokeColor(self.RULE_GRAY)
        c.setLineWidth(0.3)
        c.line(self.MARGIN_X, 32, self.PAGE_W - self.MARGIN_X, 32)

    def _controls_for_finding(self, finding: dict[str, Any]) -> tuple[list[str], dict[str, str]]:
        controls = finding.get("soc2_controls")
        if isinstance(controls, str):
            parsed = [s.strip() for s in controls.split(",") if s.strip()]
            if parsed:
                return parsed, {}
        if isinstance(controls, list) and controls:
            return [str(s).strip() for s in controls if str(s).strip()], {}
        mapped = get_soc2_mapping_for_finding(finding)
        return mapped["controls"], mapped["rationale"]

    # ────────────────────────────────────────────────────────────────
    # COVER PAGE
    # ────────────────────────────────────────────────────────────────
    def _draw_cover_page(self, c: canvas.Canvas, scan: dict, findings: list[dict]) -> None:
        c.setFillColor(self.WHITE)
        c.rect(0, 0, self.PAGE_W, self.PAGE_H, fill=1, stroke=0)

        # Top black band
        c.setFillColor(self.BLACK)
        c.rect(0, self.PAGE_H - 120, self.PAGE_W, 120, fill=1, stroke=0)

        c.setFillColor(self.WHITE)
        c.setFont("Helvetica-Bold", 32)
        c.drawString(self.MARGIN_X, self.PAGE_H - 60, "SECUREPATH")
        c.setFont("Helvetica", 12)
        c.drawString(self.MARGIN_X, self.PAGE_H - 82, "Security Assessment & Compliance Evidence Report")

        # Thin rule
        c.setStrokeColor(self.BLACK)
        c.setLineWidth(1.5)
        c.line(self.MARGIN_X, self.PAGE_H - 140, self.PAGE_W - self.MARGIN_X, self.PAGE_H - 140)

        # Repository name
        repo_name = str(scan.get("repo_name") or scan.get("repo_url") or "Unknown Repository")
        sha = str(scan.get("commit_sha") or "N/A")
        c.setFillColor(self.BLACK)
        c.setFont("Helvetica-Bold", 24)
        c.drawCentredString(self.PAGE_W / 2, self.PAGE_H - 220, self._safe(repo_name, 60))
        c.setFont(self.mono, 10)
        c.setFillColor(self.MID_GRAY)
        c.drawCentredString(self.PAGE_W / 2, self.PAGE_H - 240, f"Commit: {sha[:12]}")

        # Metadata block
        top_y = 340
        c.setStrokeColor(self.RULE_GRAY)
        c.setLineWidth(0.5)
        c.rect(self.MARGIN_X, top_y, self.PAGE_W - (2 * self.MARGIN_X), 100, fill=0, stroke=1)

        labels = ["Scan Date", "Scan ID", "Scanner Version"]
        values = [
            datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            str(scan.get("id", "N/A")),
            "v1.0.0",
        ]
        left_x = self.MARGIN_X + 16
        right_x = self.PAGE_W / 2 + 16
        for i, lbl in enumerate(labels):
            y = top_y + 72 - (i * 26)
            c.setFillColor(self.MID_GRAY)
            c.setFont("Helvetica", 8.5)
            c.drawString(left_x, y, lbl)
            c.setFillColor(self.BLACK)
            c.setFont("Helvetica-Bold", 10)
            c.drawString(right_x, y, values[i])

        # Risk score
        score = int(scan.get("risk_score") or 0)
        c.setStrokeColor(self.BLACK)
        c.setLineWidth(2)
        c.rect(self.PAGE_W / 2 - 60, 200, 120, 100, fill=0, stroke=1)
        c.setFillColor(self.BLACK)
        c.setFont("Helvetica-Bold", 56)
        c.drawCentredString(self.PAGE_W / 2, 230, str(score))
        c.setFillColor(self.MID_GRAY)
        c.setFont("Helvetica-Bold", 8)
        c.drawCentredString(self.PAGE_W / 2, 210, "RISK SCORE")

        # Severity counts
        counts = {
            "CRITICAL": int(scan.get("critical_count") or 0),
            "HIGH": int(scan.get("high_count") or 0),
            "MEDIUM": int(scan.get("medium_count") or 0),
            "LOW": int(scan.get("low_count") or 0),
        }
        pill_y = 160
        total_w = self.PAGE_W - (2 * self.MARGIN_X)
        pill_w = (total_w - 24) / 4
        for idx, (label, val) in enumerate(counts.items()):
            x = self.MARGIN_X + idx * (pill_w + 8)
            c.setFillColor(self._severity_bg(label.lower()))
            c.roundRect(x, pill_y, pill_w, 26, 4, fill=1, stroke=0)
            c.setFillColor(self.WHITE)
            c.setFont("Helvetica-Bold", 8)
            c.drawCentredString(x + pill_w / 2, pill_y + 9, f"{label}: {val}")

        self._draw_footer(c, 1)

    # ────────────────────────────────────────────────────────────────
    # SECTION HEADER
    # ────────────────────────────────────────────────────────────────
    def _draw_section_header(self, c: canvas.Canvas, title: str, y: float) -> None:
        c.setFillColor(self.BLACK)
        c.rect(self.MARGIN_X, y - 4, 4, 22, fill=1, stroke=0)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(self.MARGIN_X + 10, y, title)

    # ────────────────────────────────────────────────────────────────
    # EXECUTIVE SUMMARY
    # ────────────────────────────────────────────────────────────────
    def _draw_executive_summary(self, c: canvas.Canvas, scan: dict, findings: list[dict]) -> None:
        c.setFillColor(self.WHITE)
        c.rect(0, 0, self.PAGE_W, self.PAGE_H, fill=1, stroke=0)
        self._draw_section_header(c, "EXECUTIVE SUMMARY", self.PAGE_H - 68)

        total = len(findings)
        crit = int(scan.get("critical_count") or 0)
        categories: dict[str, int] = {}
        for f in findings:
            cat = self._safe(f.get("category"), 40) or "misc"
            categories[cat] = categories.get(cat, 0) + 1
        top_category = max(categories.items(), key=lambda x: x[1])[0] if categories else "none identified"
        narrative = (
            f"This assessment identified {total} security findings across "
            f"{len(categories)} categories. "
            f"{crit} critical finding{'s' if crit!=1 else ''} require immediate remediation "
            f"before SOC2 evidence submission. "
            f"The highest concentration of risk appears in {top_category} controls."
        )
        p = Paragraph(narrative, self.body)
        p.wrapOn(c, self.PAGE_W * 0.56, 90)
        p.drawOn(c, self.MARGIN_X, self.PAGE_H - 148)

        # OWASP table
        left_x = self.MARGIN_X
        left_w = self.PAGE_W * 0.57 - self.MARGIN_X
        top10 = [
            "A01:2021 - Broken Access Control",
            "A02:2021 - Cryptographic Failures",
            "A03:2021 - Injection",
            "A04:2021 - Insecure Design",
            "A05:2021 - Security Misconfiguration",
            "A06:2021 - Vulnerable and Outdated Components",
            "A07:2021 - Identification and Authentication Failures",
            "A08:2021 - Software and Data Integrity Failures",
            "A09:2021 - Security Logging and Monitoring Failures",
            "A10:2021 - Server-Side Request Forgery",
        ]
        owasp_present = {str(f.get("owasp_category", "")) for f in findings}
        owasp_data = [["Category", "Status"]]
        for cat in top10:
            owasp_data.append([cat, "FOUND" if cat in owasp_present else "—"])
        table = Table(owasp_data, colWidths=[left_w * 0.78, left_w * 0.22], rowHeights=17)
        ts = TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TEXTCOLOR", (0, 0), (-1, 0), self.WHITE),
                ("BACKGROUND", (0, 0), (-1, 0), self.BLACK),
                ("GRID", (0, 0), (-1, -1), 0.25, self.RULE_GRAY),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
        for i in range(1, len(owasp_data)):
            status = owasp_data[i][1]
            if status == "FOUND":
                ts.add("FONTNAME", (1, i), (1, i), "Helvetica-Bold")
                ts.add("TEXTCOLOR", (1, i), (1, i), self.BLACK)
            else:
                ts.add("TEXTCOLOR", (1, i), (1, i), self.LIGHT_GRAY)
            if i % 2 == 0:
                ts.add("BACKGROUND", (0, i), (-1, i), self.BG_LIGHT)
        table.setStyle(ts)
        table.wrapOn(c, left_w, 220)
        table.drawOn(c, left_x, self.PAGE_H - 400)

        # Right side — Severity breakdown
        right_x = self.PAGE_W * 0.62
        right_w = self.PAGE_W - right_x - self.MARGIN_X

        c.setStrokeColor(self.RULE_GRAY)
        c.setLineWidth(0.5)
        c.rect(right_x, self.PAGE_H - 250, right_w, 150, fill=0, stroke=1)
        c.setFillColor(self.BLACK)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(right_x + 12, self.PAGE_H - 118, "SEVERITY BREAKDOWN")

        breakdown = [
            ("critical", int(scan.get("critical_count") or 0)),
            ("high", int(scan.get("high_count") or 0)),
            ("medium", int(scan.get("medium_count") or 0)),
            ("low", int(scan.get("low_count") or 0)),
        ]
        y = self.PAGE_H - 140
        for sev, cnt in breakdown:
            pct = f"{int((cnt / total) * 100) if total else 0}%"
            c.setFillColor(self._severity_bg(sev))
            c.rect(right_x + 12, y - 6, 8, 8, fill=1, stroke=0)
            c.setFillColor(self.NEAR_BLACK)
            c.setFont("Helvetica-Bold", 8.5)
            c.drawString(right_x + 26, y - 6, sev.upper())
            c.setFont("Helvetica", 8.5)
            c.drawRightString(right_x + right_w - 12, y - 6, f"{cnt} ({pct})")
            y -= 20

        # Top 3 Critical Findings
        c.setStrokeColor(self.RULE_GRAY)
        c.setLineWidth(0.5)
        c.rect(right_x, self.PAGE_H - 440, right_w, 160, fill=0, stroke=1)
        c.setFillColor(self.BLACK)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(right_x + 12, self.PAGE_H - 300, "TOP CRITICAL FINDINGS")
        criticals = [f for f in findings if str(f.get("severity", "")).lower() == "critical"][:3]
        yy = self.PAGE_H - 318
        for f in criticals:
            title = self._safe(f.get("raw_title"), 52, "Untitled finding")
            path = self._safe(f.get("file_path"), 44, "unknown")
            line = self._safe(f.get("line_start"), 10, "1")
            sev = self._safe(f.get("severity"), 20, "critical").upper()
            c.setFillColor(self.BLACK)
            c.setFont("Helvetica-Bold", 8)
            c.drawString(right_x + 12, yy, f"■ {sev}")
            c.setFont("Helvetica-Bold", 8)
            c.drawString(right_x + 62, yy, title)
            c.setFont(self.mono, 7)
            c.setFillColor(self.MID_GRAY)
            c.drawString(right_x + 62, yy - 10, f"{path}:{line}")
            yy -= 30

        # SOC2 Controls
        control_set: set[str] = set()
        for f in findings:
            controls, _ = self._controls_for_finding(f)
            for ctl in controls:
                if ctl:
                    control_set.add(ctl)
        controls_sorted = sorted(control_set)
        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(self.BLACK)
        c.drawString(self.MARGIN_X, 110, "RELEVANT COMPLIANCE CONTROLS")
        bx = self.MARGIN_X
        by = 90
        for ctl in controls_sorted[:12]:
            tw = pdfmetrics.stringWidth(ctl, "Helvetica-Bold", 7.5) + 14
            c.setStrokeColor(self.BLACK)
            c.setLineWidth(0.8)
            c.roundRect(bx, by, tw, 15, 3, fill=0, stroke=1)
            c.setFillColor(self.BLACK)
            c.setFont("Helvetica-Bold", 7.5)
            c.drawCentredString(bx + tw / 2, by + 4.5, ctl)
            bx += tw + 6
            if bx > self.PAGE_W - self.MARGIN_X - 80:
                bx = self.MARGIN_X
                by -= 20

        self._draw_footer(c, 2)

    # ────────────────────────────────────────────────────────────────
    # HELPERS
    # ────────────────────────────────────────────────────────────────
    def _draw_badge(self, c: canvas.Canvas, x: float, y: float, text: str,
                    bg: colors.Color, fg: colors.Color = None) -> float:
        if fg is None:
            fg = self.WHITE
        w = pdfmetrics.stringWidth(text, "Helvetica-Bold", 7.5) + 12
        c.setFillColor(bg)
        c.roundRect(x, y, w, 14, 3, fill=1, stroke=0)
        c.setFillColor(fg)
        c.setFont("Helvetica-Bold", 7.5)
        c.drawCentredString(x + w / 2, y + 4, text)
        return w

    def _draw_outline_badge(self, c: canvas.Canvas, x: float, y: float, text: str,
                            border: colors.Color = None) -> float:
        if border is None:
            border = self.BLACK
        w = pdfmetrics.stringWidth(text, "Helvetica-Bold", 7.5) + 12
        c.setStrokeColor(border)
        c.setLineWidth(0.8)
        c.roundRect(x, y, w, 14, 3, fill=0, stroke=1)
        c.setFillColor(self.NEAR_BLACK)
        c.setFont("Helvetica-Bold", 7.5)
        c.drawCentredString(x + w / 2, y + 4, text)
        return w

    def _draw_wrapped_text(self, c: canvas.Canvas, text: str, x: float, y: float,
                           width: float, font: str, size: float, leading: float,
                           color: colors.Color) -> float:
        c.setFont(font, size)
        c.setFillColor(color)
        lines = simpleSplit(text, font, size, width)
        cursor = y
        for line in lines:
            c.drawString(x, cursor, line)
            cursor -= leading
        return cursor

    def _hard_wrap_mono_line(self, text: str, font: str, size: float, max_width: float) -> list[str]:
        # simpleSplit won't break very long "words" (like private keys), so we force-wrap by glyph width.
        if not text:
            return [""]
        wrapped: list[str] = []
        current = ""
        for ch in text:
            candidate = current + ch
            if pdfmetrics.stringWidth(candidate, font, size) <= max_width:
                current = candidate
            else:
                if current:
                    wrapped.append(current)
                    current = ch
                else:
                    wrapped.append(ch)
                    current = ""
        if current:
            wrapped.append(current)
        return wrapped or [""]

    def _parse_impact_json(self, finding: dict, field: str) -> dict:
        """Safely parse a JSON field from a finding, returning {} on failure."""
        raw = finding.get(field)
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else {}
            except Exception:
                return {}
        return {}

    # ────────────────────────────────────────────────────────────────
    # FINDING PAGE
    # ────────────────────────────────────────────────────────────────
    def _draw_finding_page(self, c: canvas.Canvas, finding: dict, idx: int) -> None:
        c.setFillColor(self.WHITE)
        c.rect(0, 0, self.PAGE_W, self.PAGE_H, fill=1, stroke=0)

        sev = str(finding.get("severity", "medium")).lower()
        title = self._safe(finding.get("raw_title"), 74, "Untitled finding")
        cwe = self._safe(finding.get("cwe_id"), 40, "Unknown")
        owasp = self._safe(finding.get("owasp_category"), 40, "Unknown")

        # Black title bar
        c.setFillColor(self.BLACK)
        c.rect(0, self.PAGE_H - 56, self.PAGE_W, 56, fill=1, stroke=0)
        c.setFillColor(self.WHITE)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(self.MARGIN_X, self.PAGE_H - 36, f"{idx:02d}  {title[:74]}")

        # Badges below title bar
        badge_y = self.PAGE_H - 74
        badge_x = self.MARGIN_X
        w = self._draw_badge(c, badge_x, badge_y, sev.upper(), self._severity_bg(sev))
        badge_x += w + 6
        w = self._draw_badge(c, badge_x, badge_y, cwe, self.DARK_GRAY)
        badge_x += w + 6
        self._draw_badge(c, badge_x, badge_y, owasp[:28], self.MID_GRAY)

        # Layout columns
        left_x = self.MARGIN_X
        left_w = (self.PAGE_W - (2 * self.MARGIN_X)) * 0.52
        right_x = left_x + left_w + 14
        right_w = self.PAGE_W - self.MARGIN_X - right_x
        y = self.PAGE_H - 96

        # ── LEFT COLUMN ──

        # AI Explanation
        c.setFillColor(self.BG_LIGHT)
        c.roundRect(left_x, y - 56, left_w, 54, 4, fill=1, stroke=0)
        c.setFillColor(self.BLACK)
        c.setFont("Helvetica-Bold", 7.5)
        c.drawString(left_x + 8, y - 12, "FINDING EXPLANATION")
        self._draw_wrapped_text(
            c, str(finding.get("plain_english", "Explanation unavailable.")),
            left_x + 8, y - 26, left_w - 16, "Helvetica", 8.5, 11, self.NEAR_BLACK,
        )

        y -= 68

        # Business Risk
        c.setStrokeColor(self.BLACK)
        c.setLineWidth(1.5)
        c.line(left_x, y, left_x, y - 54)
        c.setFillColor(self.BLACK)
        c.setFont("Helvetica-Bold", 7.5)
        c.drawString(left_x + 6, y - 10, "BUSINESS RISK")
        self._draw_wrapped_text(
            c, str(finding.get("business_risk", "Business risk pending.")),
            left_x + 6, y - 24, left_w - 10, "Helvetica", 8.5, 11, self.NEAR_BLACK,
        )

        y -= 68

        # Exploit Scenario
        c.setStrokeColor(self.DARK_GRAY)
        c.setLineWidth(1)
        c.line(left_x, y, left_x, y - 54)
        c.setFillColor(self.DARK_GRAY)
        c.setFont("Helvetica-Bold", 7.5)
        c.drawString(left_x + 6, y - 10, "EXPLOIT SCENARIO")
        self._draw_wrapped_text(
            c, str(finding.get("exploit_scenario", "Exploit scenario pending.")),
            left_x + 6, y - 24, left_w - 10, "Helvetica-Oblique", 8.5, 11, self.DARK_GRAY,
        )

        y -= 66

        # Code Location
        c.setFillColor(self.BLACK)
        c.setFont("Helvetica-Bold", 7.5)
        c.drawString(left_x, y, "CODE LOCATION")
        c.setFillColor(self.MID_GRAY)
        c.setFont(self.mono, 7.5)
        fp = self._safe(finding.get("file_path"), 60, "unknown")
        ln_s = self._safe(finding.get("line_start"), 10, "1")
        ln_e = self._safe(finding.get("line_end"), 10, "1")
        c.drawString(left_x, y - 12, f"{fp}:{ln_s}-{ln_e}")

        snippet = self._safe(finding.get("code_snippet"), 500, "No snippet available.")
        c.setFillColor(self.BG_LIGHT)
        c.roundRect(left_x, y - 90, left_w, 70, 4, fill=1, stroke=0)
        lines = snippet.splitlines()[:5]
        wrapped_code_lines: list[str] = []
        for line in lines:
            wrapped_parts = simpleSplit(str(line), self.mono, 7, left_w - 14)
            if wrapped_parts:
                for part in wrapped_parts:
                    wrapped_code_lines.extend(
                        self._hard_wrap_mono_line(part, self.mono, 7, left_w - 14)
                    )
            else:
                wrapped_code_lines.extend(
                    self._hard_wrap_mono_line(str(line), self.mono, 7, left_w - 14)
                )
        sy = y - 28
        for line in wrapped_code_lines[:6]:
            c.setFillColor(self.NEAR_BLACK)
            c.setFont(self.mono, 7)
            c.drawString(left_x + 7, sy, line)
            sy -= 10

        # ── BUSINESS IMPACT SECTION (below code, spanning left column) ──
        bi = self._parse_impact_json(finding, "business_impact_json")
        if not bi:
            bi = self._parse_impact_json(finding, "business_impact")

        bi_y = y - 108

        c.setFillColor(self.BLACK)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(left_x, bi_y, "BUSINESS IMPACT")
        c.setStrokeColor(self.BLACK)
        c.setLineWidth(0.5)
        c.line(left_x, bi_y - 4, left_x + left_w, bi_y - 4)

        # Financial Exposure
        fin_exp = str(bi.get("financial_exposure", "Financial exposure data unavailable."))
        c.setFillColor(self.BG_ALT)
        c.roundRect(left_x, bi_y - 42, left_w, 34, 4, fill=1, stroke=0)
        c.setFillColor(self.BLACK)
        c.setFont("Helvetica-Bold", 7)
        c.drawString(left_x + 6, bi_y - 14, "FINANCIAL EXPOSURE")
        self._draw_wrapped_text(
            c, fin_exp, left_x + 6, bi_y - 26,
            left_w - 12, "Helvetica", 7.5, 9.5, self.NEAR_BLACK,
        )

        # Exploitation Likelihood badge
        likelihood = str(bi.get("exploitation_likelihood", "medium")).lower()
        likelihood_reason = str(bi.get("likelihood_reason", ""))
        lk_y = bi_y - 54
        c.setFillColor(self.BLACK)
        c.setFont("Helvetica-Bold", 7)
        c.drawString(left_x, lk_y, "EXPLOITATION LIKELIHOOD:")
        lk_bg = {"high": self.BLACK, "medium": self.MID_GRAY, "low": self.LIGHT_GRAY}.get(likelihood, self.MID_GRAY)
        bw = self._draw_badge(c, left_x + 110, lk_y - 2, likelihood.upper(), lk_bg)
        if likelihood_reason:
            c.setFillColor(self.MID_GRAY)
            c.setFont("Helvetica-Oblique", 7)
            reason_lines = simpleSplit(likelihood_reason, "Helvetica-Oblique", 7, left_w - 12)
            ry = lk_y - 14
            for rl in reason_lines[:2]:
                c.drawString(left_x, ry, rl)
                ry -= 9

        # Compliance Violations mini-table
        violations = bi.get("compliance_violations", [])
        if isinstance(violations, list) and violations:
            cv_y = lk_y - 32
            c.setFillColor(self.BLACK)
            c.setFont("Helvetica-Bold", 7)
            c.drawString(left_x, cv_y, "COMPLIANCE VIOLATIONS")
            cv_y -= 4

            tbl_data = [["Framework", "Control", "Implication"]]
            for v in violations[:4]:
                if isinstance(v, dict):
                    tbl_data.append([
                        str(v.get("framework", ""))[:10],
                        str(v.get("control", ""))[:12],
                        str(v.get("meaning", ""))[:60],
                    ])
            if len(tbl_data) > 1:
                col_ws = [50, 50, left_w - 106]
                tbl = Table(tbl_data, colWidths=col_ws, rowHeights=13)
                tbl_style = TableStyle([
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 6.5),
                    ("TEXTCOLOR", (0, 0), (-1, 0), self.WHITE),
                    ("BACKGROUND", (0, 0), (-1, 0), self.BLACK),
                    ("GRID", (0, 0), (-1, -1), 0.2, self.RULE_GRAY),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ])
                for ri in range(1, len(tbl_data)):
                    if ri % 2 == 0:
                        tbl_style.add("BACKGROUND", (0, ri), (-1, ri), self.BG_LIGHT)
                tbl.setStyle(tbl_style)
                tbl.wrapOn(c, left_w, 80)
                tbl.drawOn(c, left_x, cv_y - len(tbl_data) * 13)

        # ── RIGHT COLUMN ──
        ry = self.PAGE_H - 96

        # Remediation Options
        c.setFillColor(self.BLACK)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(right_x, ry, "REMEDIATION OPTIONS")
        ry -= 12
        remediation = finding.get("remediation_json")
        if not remediation:
            remediation = finding.get("remediation", [])
        if isinstance(remediation, str):
            try:
                remediation = json.loads(remediation)
            except Exception:
                remediation = []
        if not isinstance(remediation, list):
            remediation = []
        if len(remediation) < 3:
            remediation = remediation + [
                {
                    "rank": len(remediation) + 1,
                    "label": "Follow-up fix",
                    "time_estimate": "< 4 hours",
                    "description": "Define a secure implementation pattern and add tests.",
                    "tradeoff": "Improves confidence but requires engineering time.",
                }
            ] * (3 - len(remediation))

        for i, opt in enumerate(remediation[:3], start=1):
            box_h = 84
            c.setFillColor(self.BG_LIGHT)
            c.roundRect(right_x, ry - box_h, right_w, box_h - 4, 4, fill=1, stroke=0)
            c.setFillColor(self.BLACK)
            c.setFont("Helvetica-Bold", 8)
            c.drawString(right_x + 6, ry - 12, f"OPTION {i}: {str(opt.get('label', 'Fix')).upper()[:20]}")
            est = str(opt.get("time_estimate", ""))
            self._draw_outline_badge(c, right_x + right_w - 60, ry - 16, est)
            self._draw_wrapped_text(
                c, str(opt.get("description", "")),
                right_x + 6, ry - 28, right_w - 12, "Helvetica", 7.5, 9.5, self.NEAR_BLACK,
            )
            self._draw_wrapped_text(
                c, f"Tradeoff: {str(opt.get('tradeoff', ''))}",
                right_x + 6, ry - 66, right_w - 12, "Helvetica-Oblique", 7, 9, self.MID_GRAY,
            )
            ry -= box_h + 3

        # Compliance Mapping
        c.setFillColor(self.BLACK)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(right_x, ry, "COMPLIANCE MAPPING")
        controls_list, rationale_map = self._controls_for_finding(finding)
        bx = right_x
        by_ctl = ry - 14
        for ctl in controls_list[:6]:
            w = self._draw_outline_badge(c, bx, by_ctl, ctl)
            bx += w + 4
            if bx > right_x + right_w - 50:
                bx = right_x
                by_ctl -= 16

        # CWE / OWASP / Confidence
        info_y = by_ctl - 16
        c.setFillColor(self.NEAR_BLACK)
        c.setFont("Helvetica", 7.5)
        c.drawString(right_x, info_y, f"CWE: {cwe}")
        c.drawString(right_x, info_y - 11, f"OWASP: {owasp}")

        conf = int(finding.get("confidence_score") or 0)
        conf = max(0, min(10, conf))
        c.drawString(right_x, info_y - 22, f"Confidence: {conf}/10")
        bar_x = right_x + 55
        bar_y = info_y - 26
        c.setStrokeColor(self.RULE_GRAY)
        c.setLineWidth(0.5)
        c.rect(bar_x, bar_y, 70, 7, fill=0, stroke=1)
        c.setFillColor(self.BLACK)
        c.rect(bar_x, bar_y, 7 * conf, 7, fill=1, stroke=0)

        # False Positive
        fp = str(finding.get("false_positive_risk", "medium")).upper()
        fp_y = info_y - 38
        self._draw_badge(c, right_x, fp_y, f"FP Risk: {fp}", self.MID_GRAY)
        fp_reason = self._safe(finding.get("false_positive_reason"), 180, "")
        if fp_reason:
            self._draw_wrapped_text(c, fp_reason, right_x, fp_y - 14, right_w, "Helvetica", 7, 8.5, self.LIGHT_GRAY)

        # ── ASSETS EXPOSED SECTION (bottom of right column) ──
        ae = self._parse_impact_json(finding, "assets_exposed_json")
        if not ae:
            ae = self._parse_impact_json(finding, "assets_exposed")

        ae_y = fp_y - 36
        c.setFillColor(self.BLACK)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(right_x, ae_y, "ASSETS EXPOSED")
        c.setStrokeColor(self.BLACK)
        c.setLineWidth(0.5)
        c.line(right_x, ae_y - 4, right_x + right_w, ae_y - 4)

        # Data types as tags
        data_types = ae.get("data_types", [])
        if isinstance(data_types, list) and data_types:
            ae_y -= 14
            c.setFillColor(self.BLACK)
            c.setFont("Helvetica-Bold", 7)
            c.drawString(right_x, ae_y, "DATA AT RISK:")
            tag_x = right_x
            tag_y = ae_y - 12
            for dt in data_types[:5]:
                w = self._draw_outline_badge(c, tag_x, tag_y, str(dt)[:20])
                tag_x += w + 3
                if tag_x > right_x + right_w - 40:
                    tag_x = right_x
                    tag_y -= 14

        # Systems affected
        systems = ae.get("systems_affected", [])
        if isinstance(systems, list) and systems:
            sy = tag_y - 14 if data_types else ae_y - 14
            c.setFillColor(self.BLACK)
            c.setFont("Helvetica-Bold", 7)
            c.drawString(right_x, sy, "SYSTEMS:")
            c.setFont("Helvetica", 7)
            c.setFillColor(self.NEAR_BLACK)
            for s in systems[:4]:
                sy -= 10
                c.drawString(right_x + 4, sy, f"· {str(s)[:40]}")

        # Exposure scope badge
        scope = str(ae.get("exposure_scope", "unknown")).lower()
        scope_labels = {
            "external_facing": "EXTERNAL",
            "third_party_accessible": "THIRD PARTY",
            "internal_only": "INTERNAL",
        }
        scope_bgs = {
            "external_facing": self.BLACK,
            "third_party_accessible": self.MID_GRAY,
            "internal_only": self.LIGHT_GRAY,
        }
        scope_y = sy - 14 if systems else (tag_y - 14 if data_types else ae_y - 14)
        c.setFillColor(self.BLACK)
        c.setFont("Helvetica-Bold", 7)
        c.drawString(right_x, scope_y, "SCOPE:")
        scope_bg = scope_bgs.get(scope, self.MID_GRAY)
        self._draw_badge(c, right_x + 34, scope_y - 2, scope_labels.get(scope, scope.upper()), scope_bg)

        # Exposure explanation
        exp_text = str(ae.get("exposure_explanation", ""))
        if exp_text:
            self._draw_wrapped_text(
                c, exp_text, right_x, scope_y - 16, right_w,
                "Helvetica", 7, 8.5, self.MID_GRAY,
            )

        # Records at risk
        records = str(ae.get("estimated_records_at_risk", "unknown"))
        if records and records != "unknown":
            c.setFillColor(self.NEAR_BLACK)
            c.setFont("Helvetica", 7)
            c.drawString(right_x, scope_y - 34, f"Est. records at risk: {records}")

        self._draw_footer(c, 2 + idx)

    # ────────────────────────────────────────────────────────────────
    # ADDITIONAL FINDINGS TABLE
    # ────────────────────────────────────────────────────────────────
    def _draw_additional_findings_table(self, c: canvas.Canvas, findings: list[dict], page_offset: int = 0) -> None:
        # Include medium, low, and info — not just medium/low
        filtered = [f for f in findings if str(f.get("severity", "")).lower() in {"medium", "low", "info"}]
        ROW_H = 17
        USABLE_H = self.PAGE_H - 140
        MAX_ROWS_PER_PAGE = int(USABLE_H / ROW_H) - 2

        rows_all = []
        for i, f in enumerate(filtered, start=1):
            rows_all.append([
                str(i),
                self._safe(f.get("severity"), 10, "").upper(),
                self._safe(f.get("category"), 20, ""),
                self._safe(f.get("file_path"), 32, "")[-32:],
                str(f.get("line_start") or ""),
                self._safe(f.get("raw_title"), 40, ""),
                ",".join(self._controls_for_finding(f)[0])[:18],
                "NEEDS REMEDIATION",
            ])

        header = ["#", "Severity", "Category", "File", "Line", "Title", "Compliance", "Status"]
        col_widths = [18, 48, 54, 100, 26, 116, 75, 82]

        page_num = page_offset
        for chunk_start in range(0, max(1, len(rows_all)), MAX_ROWS_PER_PAGE):
            chunk = rows_all[chunk_start: chunk_start + MAX_ROWS_PER_PAGE]
            page_num += 1

            c.setFillColor(self.WHITE)
            c.rect(0, 0, self.PAGE_W, self.PAGE_H, fill=1, stroke=0)
            title_sfx = f" (cont. {page_num})" if chunk_start > 0 else ""
            self._draw_section_header(c, f"ADDITIONAL FINDINGS{title_sfx}", self.PAGE_H - 64)

            table_rows = [header] + chunk
            table = Table(table_rows, colWidths=col_widths, repeatRows=1, rowHeights=ROW_H)
            style = TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("TEXTCOLOR", (0, 0), (-1, 0), self.WHITE),
                    ("BACKGROUND", (0, 0), (-1, 0), self.BLACK),
                    ("GRID", (0, 0), (-1, -1), 0.2, self.RULE_GRAY),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("ALIGN", (0, 0), (0, -1), "CENTER"),
                    ("ALIGN", (4, 1), (4, -1), "CENTER"),
                ]
            )
            for i in range(1, len(table_rows)):
                if i % 2 == 0:
                    style.add("BACKGROUND", (0, i), (-1, i), self.BG_LIGHT)
                style.add("FONTNAME", (1, i), (1, i), "Helvetica-Bold")
                style.add("FONTNAME", (7, i), (7, i), "Helvetica-Bold")
            table.setStyle(style)
            w, h = table.wrapOn(c, self.PAGE_W - (2 * self.MARGIN_X), USABLE_H)
            table.drawOn(c, self.MARGIN_X, self.PAGE_H - 80 - h)
            self._draw_footer(c, 2 + self.finding_counter + page_num)
            if chunk_start + MAX_ROWS_PER_PAGE < len(rows_all):
                c.showPage()

        self._extra_pages = page_num

    # ────────────────────────────────────────────────────────────────
    # INTEGRITY PAGE
    # ────────────────────────────────────────────────────────────────
    def _draw_integrity_page(self, c: canvas.Canvas, scan: dict) -> None:
        c.setFillColor(self.BLACK)
        c.rect(0, 0, self.PAGE_W, self.PAGE_H, fill=1, stroke=0)

        c.setFillColor(self.WHITE)
        c.setFont("Helvetica-Bold", 20)
        c.drawString(self.MARGIN_X, self.PAGE_H - 72, "AUDIT INTEGRITY VERIFICATION")

        hash_val = self._safe(scan.get("findings_hash"), 90, "N/A")
        sha = self._safe(scan.get("commit_sha"), 80, "N/A")

        # Hash block
        c.setStrokeColor(colors.HexColor("#333333"))
        c.setLineWidth(1)
        c.rect(self.MARGIN_X, self.PAGE_H - 210, self.PAGE_W - (2 * self.MARGIN_X), 80, fill=0, stroke=1)
        c.setFillColor(self.LIGHT_GRAY)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(self.MARGIN_X + 12, self.PAGE_H - 148, "FINDINGS INTEGRITY HASH (SHA-256)")
        c.setFillColor(self.WHITE)
        c.setFont(self.mono, 9.5)
        c.drawString(self.MARGIN_X + 12, self.PAGE_H - 170, hash_val[:90])

        # Commit SHA block
        c.setStrokeColor(colors.HexColor("#333333"))
        c.rect(self.MARGIN_X, self.PAGE_H - 320, self.PAGE_W - (2 * self.MARGIN_X), 80, fill=0, stroke=1)
        c.setFillColor(self.LIGHT_GRAY)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(self.MARGIN_X + 12, self.PAGE_H - 258, "REPOSITORY COMMIT SHA")
        c.setFillColor(self.WHITE)
        c.setFont(self.mono, 10)
        c.drawString(self.MARGIN_X + 12, self.PAGE_H - 280, sha)

        statement = (
            f"This report was generated by SecurePath v1.0.0 on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}. "
            "The SHA-256 hash above is a cryptographic fingerprint of all findings in this assessment. "
            "Any modification to this report after generation will invalidate this hash. "
            "This report provides structured security findings to support your security remediation workflow and compliance documentation process.<br/><br/>"
            "By using SecurePath, you confirm you are authorized to scan this repository. "
            "Reports are generated for educational and defensive purposes only. "
            "SecurePath is not liable for how this information is used."
        )
        p = Paragraph(statement, ParagraphStyle("stmt", parent=self.body, textColor=self.WHITE, leading=14, fontSize=10))
        p.wrapOn(c, self.PAGE_W - (2 * self.MARGIN_X), 120)
        p.drawOn(c, self.MARGIN_X, self.PAGE_H - 460)

        # Sign-off
        c.setFillColor(self.WHITE)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(self.MARGIN_X, 178, "Reviewed by:")
        c.drawString(self.PAGE_W / 2, 178, "Date:")
        c.setStrokeColor(self.WHITE)
        c.setLineWidth(0.5)
        c.line(self.MARGIN_X + 78, 174, self.PAGE_W / 2 - 20, 174)
        c.line(self.PAGE_W / 2 + 30, 174, self.PAGE_W - self.MARGIN_X, 174)
        c.setFont("Helvetica", 9)
        c.setFillColor(self.LIGHT_GRAY)
        c.drawString(self.MARGIN_X, 158, "Engineering Lead sign-off")

        extra = getattr(self, "_extra_pages", 1)
        self._draw_footer(c, 2 + self.finding_counter + extra + 1)
