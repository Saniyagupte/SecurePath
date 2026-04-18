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
    DARK_BG = colors.HexColor("#0d1117")
    ACCENT_RED = colors.HexColor("#e94560")
    ACCENT_BLUE = colors.HexColor("#58a6ff")
    CRITICAL = colors.HexColor("#ff2d55")
    HIGH = colors.HexColor("#ff9f0a")
    MEDIUM = colors.HexColor("#ffd60a")
    LOW = colors.HexColor("#34c759")
    LIGHT_GRAY = colors.HexColor("#f6f8fa")
    MID_GRAY = colors.HexColor("#8b949e")
    BORDER = colors.HexColor("#21262d")
    WHITE = colors.HexColor("#ffffff")
    DARK_TEXT = colors.HexColor("#0d1117")

    PAGE_W, PAGE_H = A4
    MARGIN_X = 48
    MARGIN_Y = 42

    def __init__(self) -> None:
        self.styles = getSampleStyleSheet()
        self.body = ParagraphStyle(
            "Body",
            parent=self.styles["BodyText"],
            fontName="Helvetica",
            fontSize=10.5,
            leading=14,
            textColor=self.DARK_TEXT,
        )
        self.small = ParagraphStyle(
            "Small",
            parent=self.body,
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#4b5563"),
        )
        self.h2 = ParagraphStyle(
            "H2",
            parent=self.body,
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=self.DARK_TEXT,
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

    def _risk_color(self, score: int) -> colors.Color:
        if score <= 30:
            return self.LOW
        if score <= 60:
            return self.MEDIUM
        if score <= 80:
            return self.HIGH
        return self.CRITICAL

    def _severity_color(self, severity: str) -> colors.Color:
        m = {
            "critical": self.CRITICAL,
            "high": self.HIGH,
            "medium": self.MEDIUM,
            "low": self.LOW,
            "info": self.ACCENT_BLUE,
        }
        return m.get(str(severity).lower(), self.MID_GRAY)

    @staticmethod
    def _safe(value: Any, maxlen: int = 300, fallback: str = "") -> str:
        """Return a safely truncated, whitespace-normalised string."""
        if value is None:
            return fallback
        s = str(value).replace("\x00", "").strip()
        return s[:maxlen] if len(s) > maxlen else s

    def _draw_footer(self, c: canvas.Canvas, page_num: int, dark: bool = False) -> None:
        c.setFont("Helvetica", 8)
        if dark:
            c.setFillColor(self.MID_GRAY)
        else:
            c.setFillColor(colors.HexColor("#6b7280"))
        c.drawString(self.MARGIN_X, 20, "SecurePath v1.0.0")
        c.drawRightString(self.PAGE_W - self.MARGIN_X, 20, f"Page {page_num}")

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

    def _draw_cover_page(self, c: canvas.Canvas, scan: dict, findings: list[dict]) -> None:
        c.setFillColor(self.DARK_BG)
        c.rect(0, 0, self.PAGE_W, self.PAGE_H, fill=1, stroke=0)

        c.setFillColor(self.ACCENT_RED)
        c.setFont("Helvetica-Bold", 36)
        c.drawString(self.MARGIN_X, self.PAGE_H - 85, "SECUREPATH")

        c.setFillColor(self.WHITE)
        c.setFont("Helvetica", 14)
        c.drawString(
            self.MARGIN_X,
            self.PAGE_H - 110,
            "Security Assessment & Compliance Evidence Report",
        )

        c.setStrokeColor(self.ACCENT_RED)
        c.setLineWidth(2)
        c.line(self.MARGIN_X, self.PAGE_H - 125, self.PAGE_W - self.MARGIN_X, self.PAGE_H - 125)

        repo_name = str(scan.get("repo_name") or scan.get("repo_url") or "Unknown Repository")
        sha = str(scan.get("commit_sha") or "N/A")
        c.setFillColor(self.WHITE)
        c.setFont("Helvetica-Bold", 28)
        c.drawCentredString(self.PAGE_W / 2, self.PAGE_H - 250, self._safe(repo_name, 60))
        c.setFont(self.mono, 11)
        c.setFillColor(self.MID_GRAY)
        c.drawCentredString(self.PAGE_W / 2, self.PAGE_H - 272, f"Commit: {sha[:12]}")

        top_y = 260
        c.setFillColor(colors.HexColor("#11161f"))
        c.roundRect(self.MARGIN_X, top_y, self.PAGE_W - (2 * self.MARGIN_X), 130, 8, fill=1, stroke=0)

        labels = ["Scan Date", "Scan ID", "Scanner Version"]
        values = [
            datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            str(scan.get("id", "N/A")),
            "v0.1.0",
        ]
        left_x = self.MARGIN_X + 20
        right_x = self.PAGE_W / 2 + 20
        for i, lbl in enumerate(labels):
            y = top_y + 95 - (i * 28)
            c.setFillColor(self.MID_GRAY)
            c.setFont("Helvetica", 9)
            c.drawString(left_x, y, lbl)
            c.setFillColor(self.WHITE)
            c.setFont("Helvetica-Bold", 10)
            c.drawString(right_x, y, values[i])

        score = int(scan.get("risk_score") or 0)
        c.setFillColor(colors.HexColor("#11161f"))
        c.roundRect(self.PAGE_W / 2 - 120, 125, 240, 115, 10, fill=1, stroke=0)
        c.setFillColor(self._risk_color(score))
        c.setFont("Helvetica-Bold", 72)
        c.drawCentredString(self.PAGE_W / 2, 156, str(score))
        c.setFillColor(self.MID_GRAY)
        c.setFont("Helvetica-Bold", 10)
        c.drawCentredString(self.PAGE_W / 2, 136, "OVERALL RISK SCORE")

        counts = {
            "CRITICAL": int(scan.get("critical_count") or 0),
            "HIGH": int(scan.get("high_count") or 0),
            "MEDIUM": int(scan.get("medium_count") or 0),
            "LOW": int(scan.get("low_count") or 0),
        }
        pill_y = 88
        pill_w = (self.PAGE_W - (2 * self.MARGIN_X) - 24) / 4
        for idx, (label, val) in enumerate(counts.items()):
            x = self.MARGIN_X + idx * (pill_w + 8)
            clr = self._severity_color(label.lower())
            c.setFillColor(clr)
            c.roundRect(x, pill_y, pill_w, 28, 6, fill=1, stroke=0)
            c.setFillColor(self.WHITE if label in {"CRITICAL", "HIGH"} else self.DARK_TEXT)
            c.setFont("Helvetica-Bold", 9)
            c.drawCentredString(x + pill_w / 2, pill_y + 10, f"{label}: {val}")

        c.setFillColor(self.ACCENT_RED)
        c.setFont("Helvetica-Bold", 8)
        c.drawCentredString(
            self.PAGE_W / 2,
            36,
            "CONFIDENTIAL \u2014 FOR AUTHORIZED RECIPIENTS ONLY",
        )
        self._draw_footer(c, 1, dark=True)

    def _draw_section_header(self, c: canvas.Canvas, title: str, y: float) -> None:
        c.setFillColor(self.ACCENT_RED)
        c.rect(self.MARGIN_X, y - 4, 6, 24, fill=1, stroke=0)
        c.setFillColor(self.DARK_TEXT)
        c.setFont("Helvetica-Bold", 18)
        c.drawString(self.MARGIN_X + 12, y, title)

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
        p.drawOn(c, self.MARGIN_X, self.PAGE_H - 150)

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
            owasp_data.append([cat, "FOUND" if cat in owasp_present else "CLEAN"])
        table = Table(owasp_data, colWidths=[left_w * 0.75, left_w * 0.25], rowHeights=18)
        ts = TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("TEXTCOLOR", (0, 0), (-1, 0), self.WHITE),
                ("BACKGROUND", (0, 0), (-1, 0), self.DARK_BG),
                ("GRID", (0, 0), (-1, -1), 0.25, self.BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
        for i in range(1, len(owasp_data)):
            status = owasp_data[i][1]
            if status == "FOUND":
                ts.add("TEXTCOLOR", (1, i), (1, i), self.CRITICAL)
                ts.add("FONTNAME", (1, i), (1, i), "Helvetica-Bold")
            else:
                ts.add("TEXTCOLOR", (1, i), (1, i), self.LOW)
                ts.add("FONTNAME", (1, i), (1, i), "Helvetica-Bold")
        table.setStyle(ts)
        table.wrapOn(c, left_w, 220)
        table.drawOn(c, left_x, self.PAGE_H - 430)

        right_x = self.PAGE_W * 0.62
        right_w = self.PAGE_W - right_x - self.MARGIN_X
        c.setFillColor(colors.HexColor("#111827"))
        c.roundRect(right_x, self.PAGE_H - 260, right_w, 160, 6, fill=1, stroke=0)
        c.setFillColor(self.WHITE)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(right_x + 14, self.PAGE_H - 118, "SEVERITY BREAKDOWN")

        breakdown = [
            ("critical", int(scan.get("critical_count") or 0)),
            ("high", int(scan.get("high_count") or 0)),
            ("medium", int(scan.get("medium_count") or 0)),
            ("low", int(scan.get("low_count") or 0)),
        ]
        y = self.PAGE_H - 142
        for sev, cnt in breakdown:
            pct = f"{int((cnt / total) * 100) if total else 0}%"
            c.setFillColor(self._severity_color(sev))
            c.rect(right_x + 14, y - 8, 8, 8, fill=1, stroke=0)
            c.setFillColor(self.WHITE)
            c.setFont("Helvetica", 9)
            c.drawString(right_x + 28, y - 8, sev.upper())
            c.drawRightString(right_x + right_w - 14, y - 8, f"{cnt} ({pct})")
            y -= 20

        c.setFillColor(self.LIGHT_GRAY)
        c.roundRect(right_x, self.PAGE_H - 470, right_w, 180, 6, fill=1, stroke=0)
        c.setFillColor(self.DARK_TEXT)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(right_x + 12, self.PAGE_H - 308, "TOP 3 CRITICAL FINDINGS")
        criticals = [f for f in findings if str(f.get("severity", "")).lower() == "critical"][:3]
        yy = self.PAGE_H - 328
        for f in criticals:
            title = self._safe(f.get("raw_title"), 58, "Untitled finding")
            impact = self._safe(f.get("business_risk"), 80, "Business impact pending enrichment")
            sev = self._safe(f.get("severity"), 20, "critical").upper()
            path = self._safe(f.get("file_path"), 50, "unknown")
            line = self._safe(f.get("line_start"), 10, "1")
            c.setFillColor(self.CRITICAL)
            c.roundRect(right_x + 12, yy - 4, 54, 12, 3, fill=1, stroke=0)
            c.setFillColor(self.WHITE)
            c.setFont("Helvetica-Bold", 7)
            c.drawCentredString(right_x + 39, yy - 1, sev)
            c.setFillColor(self.DARK_TEXT)
            c.setFont("Helvetica-Bold", 8.5)
            c.drawString(right_x + 72, yy, title)
            c.setFont(self.mono, 7.2)
            c.setFillColor(colors.HexColor("#4b5563"))
            c.drawString(right_x + 72, yy - 11, f"File: {path} (line {line})")
            c.setFont("Helvetica", 7.5)
            c.drawString(right_x + 72, yy - 21, f"Impact: {impact}")
            yy -= 44

        control_set: set[str] = set()
        for f in findings:
            controls, _ = self._controls_for_finding(f)
            for ctl in controls:
                if ctl:
                    control_set.add(ctl)
        controls = sorted(control_set)
        c.setFont("Helvetica-Bold", 10)
        c.setFillColor(self.DARK_TEXT)
        c.drawString(self.MARGIN_X, 118, "SOC2 CONTROLS AFFECTED")
        bx = self.MARGIN_X
        by = 96
        for ctl in controls[:10]:
            tw = pdfmetrics.stringWidth(ctl, "Helvetica-Bold", 8) + 18
            c.setFillColor(colors.HexColor("#fee2e2"))
            c.roundRect(bx, by, tw, 16, 4, fill=1, stroke=0)
            c.setFillColor(colors.HexColor("#991b1b"))
            c.setFont("Helvetica-Bold", 8)
            c.drawCentredString(bx + tw / 2, by + 4.7, ctl)
            bx += tw + 8
            if bx > self.PAGE_W - self.MARGIN_X - 90:
                bx = self.MARGIN_X
                by -= 20

        self._draw_footer(c, 2, dark=False)

    def _draw_badge(self, c: canvas.Canvas, x: float, y: float, text: str, bg: colors.Color, fg: colors.Color = WHITE) -> None:
        w = pdfmetrics.stringWidth(text, "Helvetica-Bold", 8) + 14
        c.setFillColor(bg)
        c.roundRect(x, y, w, 14, 4, fill=1, stroke=0)
        c.setFillColor(fg)
        c.setFont("Helvetica-Bold", 8)
        c.drawCentredString(x + w / 2, y + 4.6, text)

    def _draw_wrapped_text(self, c: canvas.Canvas, text: str, x: float, y: float, width: float, font: str, size: float, leading: float, color: colors.Color) -> float:
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

    def _draw_finding_page(self, c: canvas.Canvas, finding: dict, idx: int) -> None:
        c.setFillColor(self.WHITE)
        c.rect(0, 0, self.PAGE_W, self.PAGE_H, fill=1, stroke=0)

        sev = str(finding.get("severity", "medium")).lower()
        title = self._safe(finding.get("raw_title"), 74, "Untitled finding")
        cwe = self._safe(finding.get("cwe_id"), 40, "Unknown")
        owasp = self._safe(finding.get("owasp_category"), 40, "Unknown")

        c.setFillColor(self.DARK_BG)
        c.rect(0, self.PAGE_H - 66, self.PAGE_W, 66, fill=1, stroke=0)
        c.setFillColor(self.WHITE)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(self.MARGIN_X, self.PAGE_H - 38, f"{idx:02d}  {title[:74]}")
        # Keep header clean; draw severity/CWE/OWASP badges below the black title bar to avoid overlap.
        badge_y = self.PAGE_H - 84
        badge_x = self.MARGIN_X
        self._draw_badge(
            c,
            badge_x,
            badge_y,
            sev.upper(),
            self._severity_color(sev),
            self.WHITE if sev in {"critical", "high"} else self.DARK_TEXT,
        )
        badge_x += pdfmetrics.stringWidth(sev.upper(), "Helvetica-Bold", 8) + 24
        self._draw_badge(c, badge_x, badge_y, cwe, colors.HexColor("#374151"))
        badge_x += pdfmetrics.stringWidth(cwe, "Helvetica-Bold", 8) + 24
        self._draw_badge(c, badge_x, badge_y, owasp[:24], self.ACCENT_BLUE)

        left_x = self.MARGIN_X
        left_w = (self.PAGE_W - (2 * self.MARGIN_X)) * 0.55
        right_x = left_x + left_w + 18
        right_w = self.PAGE_W - self.MARGIN_X - right_x
        y = self.PAGE_H - 108

        # Business risk starts first in left column; EXAI explanation appears in a dedicated center block below code location.
        c.setFillColor(colors.HexColor("#fff7ed"))
        c.roundRect(left_x, y - 82, left_w, 80, 6, fill=1, stroke=0)
        c.setFillColor(colors.HexColor("#9a3412"))
        c.setFont("Helvetica-Bold", 8)
        c.drawString(left_x + 10, y - 16, "BUSINESS RISK")
        self._draw_wrapped_text(
            c,
            str(finding.get("business_risk", "Business risk pending enrichment.")),
            left_x + 10,
            y - 30,
            left_w - 20,
            "Helvetica",
            9.5,
            12,
            self.DARK_TEXT,
        )

        y -= 98
        c.setStrokeColor(self.CRITICAL)
        c.setLineWidth(2.4)
        c.line(left_x, y - 2, left_x, y - 84)
        c.setFillColor(self.CRITICAL)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(left_x + 8, y - 14, "EXPLOIT SCENARIO")
        self._draw_wrapped_text(
            c,
            str(finding.get("exploit_scenario", "Exploit scenario pending enrichment.")),
            left_x + 8,
            y - 28,
            left_w - 10,
            "Helvetica-Oblique",
            9.5,
            12,
            self.DARK_TEXT,
        )

        y -= 106
        c.setFillColor(self.ACCENT_BLUE)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(left_x, y, "CODE LOCATION")
        c.setFillColor(colors.HexColor("#374151"))
        c.setFont(self.mono, 8.2)
        fp = self._safe(finding.get("file_path"), 60, "unknown")
        ln_s = self._safe(finding.get("line_start"), 10, "1")
        ln_e = self._safe(finding.get("line_end"), 10, "1")
        c.drawString(left_x, y - 14, f"{fp}:{ln_s}-{ln_e}")
        snippet = self._safe(finding.get("code_snippet"), 500, "No snippet available.")
        c.setFillColor(self.LIGHT_GRAY)
        c.roundRect(left_x, y - 130, left_w, 106, 6, fill=1, stroke=0)
        lines = snippet.splitlines()[:7]
        wrapped_code_lines: list[str] = []
        for line in lines:
            wrapped_parts = simpleSplit(str(line), self.mono, 7.6, left_w - 16)
            if wrapped_parts:
                for part in wrapped_parts:
                    # Force wrap for long unbroken strings inside each already-split part.
                    wrapped_code_lines.extend(
                        self._hard_wrap_mono_line(part, self.mono, 7.6, left_w - 16)
                    )
            else:
                wrapped_code_lines.extend(
                    self._hard_wrap_mono_line(str(line), self.mono, 7.6, left_w - 16)
                )
        sy = y - 40
        for line in wrapped_code_lines[:8]:
            c.setFillColor(colors.HexColor("#111827"))
            c.setFont(self.mono, 7.6)
            c.drawString(left_x + 8, sy, line)
            sy -= 12

        ry = self.PAGE_H - 118
        c.setFillColor(self.ACCENT_BLUE)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(right_x, ry, "REMEDIATION OPTIONS")
        ry -= 14
        remediation = finding.get("remediation_json")
        if not remediation:
            remediation = finding.get("remediation", [])
        if isinstance(remediation, str):
            try:
                import json

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
            box_h = 110
            c.setFillColor(colors.HexColor("#f8fafc"))
            c.roundRect(right_x, ry - box_h, right_w, box_h - 6, 6, fill=1, stroke=0)
            c.setFillColor(self.DARK_TEXT)
            c.setFont("Helvetica-Bold", 9)
            c.drawString(right_x + 8, ry - 16, f"OPTION {i}: {str(opt.get('label', 'Fix')).upper()[:22]}")
            est = str(opt.get("time_estimate", ""))
            self._draw_badge(c, right_x + right_w - 72, ry - 22, est, colors.HexColor("#e5e7eb"), self.DARK_TEXT)
            self._draw_wrapped_text(
                c,
                str(opt.get("description", "")),
                right_x + 8,
                ry - 34,
                right_w - 16,
                "Helvetica",
                8.2,
                10,
                self.DARK_TEXT,
            )
            self._draw_wrapped_text(
                c,
                f"Tradeoff: {str(opt.get('tradeoff', ''))}",
                right_x + 8,
                ry - 84,
                right_w - 16,
                "Helvetica-Oblique",
                7.6,
                9.5,
                colors.HexColor("#6b7280"),
            )
            ry -= box_h + 6

        c.setFillColor(self.ACCENT_BLUE)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(right_x, 180, "COMPLIANCE MAPPING")
        controls_list, rationale_map = self._controls_for_finding(finding)
        bx = right_x
        by = 164
        for ctl in controls_list[:6]:
            self._draw_badge(c, bx, by, ctl, colors.HexColor("#fee2e2"), colors.HexColor("#991b1b"))
            bx += 62
            if bx > right_x + right_w - 58:
                bx = right_x
                by -= 18

        c.setFillColor(self.DARK_TEXT)
        c.setFont("Helvetica", 8.2)
        c.drawString(right_x, 126, f"CWE: {cwe}")
        c.drawString(right_x, 114, f"OWASP: {owasp}")

        conf = int(finding.get("confidence_score") or 0)
        conf = max(0, min(10, conf))
        c.drawString(right_x, 100, f"Confidence: {conf}/10")
        bar_x, bar_y = right_x + 64, 96
        c.setStrokeColor(colors.HexColor("#d1d5db"))
        c.rect(bar_x, bar_y, 80, 8, fill=0, stroke=1)
        c.setFillColor(colors.HexColor("#059669"))
        c.rect(bar_x, bar_y, 8 * conf, 8, fill=1, stroke=0)

        fp = str(finding.get("false_positive_risk", "medium")).upper()
        fp_color = {"LOW": self.LOW, "MEDIUM": self.MEDIUM, "HIGH": self.CRITICAL}.get(fp, self.MID_GRAY)
        self._draw_badge(c, right_x, 78, f"False Positive: {fp}", fp_color, self.DARK_TEXT if fp == "MEDIUM" else self.WHITE)
        fp_reason = self._safe(finding.get("false_positive_reason"), 200, "No justification provided.")
        self._draw_wrapped_text(c, fp_reason, right_x, 64, right_w, "Helvetica", 7.7, 9.5, colors.HexColor("#4b5563"))
        if controls_list:
            first_ctl = controls_list[0]
            rationale_text = rationale_map.get(first_ctl, "")
            if rationale_text:
                self._draw_wrapped_text(
                    c,
                    f"{first_ctl} rationale: {rationale_text}",
                    right_x,
                    44,
                    right_w,
                    "Helvetica-Oblique",
                    7.2,
                    9,
                    colors.HexColor("#6b7280"),
                )

        # Centered EXAI explanation block below code location, kept in content area for visibility.
        exai_x = self.MARGIN_X
        exai_w = self.PAGE_W - (2 * self.MARGIN_X)
        exai_y = 238
        exai_h = 94
        c.setFillColor(colors.HexColor("#eef6ff"))
        c.roundRect(exai_x, exai_y, exai_w, exai_h, 8, fill=1, stroke=0)
        c.setFillColor(self.ACCENT_BLUE)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(exai_x + 12, exai_y + exai_h - 16, "EXAI EXPLANATION")
        self._draw_wrapped_text(
            c,
            str(finding.get("plain_english", "EXAI explanation unavailable.")),
            exai_x + 12,
            exai_y + exai_h - 32,
            exai_w - 24,
            "Helvetica",
            10.2,
            12.5,
            self.DARK_TEXT,
        )

        self._draw_footer(c, 2 + idx, dark=False)

    def _draw_additional_findings_table(self, c: canvas.Canvas, findings: list[dict], page_offset: int = 0) -> None:
        # Include medium, low, and info — not just medium/low
        filtered = [f for f in findings if str(f.get("severity", "")).lower() in {"medium", "low", "info"}]
        ROW_H = 18
        USABLE_H = self.PAGE_H - 140  # space between top header and footer safe zone
        MAX_ROWS_PER_PAGE = int(USABLE_H / ROW_H) - 2  # subtract header row

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

        header = ["#", "Severity", "Category", "File", "Line", "Title", "SOC2 Control", "Status"]
        col_widths = [18, 52, 56, 110, 28, 130, 78, 88]

        page_num = page_offset
        for chunk_start in range(0, max(1, len(rows_all)), MAX_ROWS_PER_PAGE):
            chunk = rows_all[chunk_start: chunk_start + MAX_ROWS_PER_PAGE]
            page_num += 1

            c.setFillColor(self.WHITE)
            c.rect(0, 0, self.PAGE_W, self.PAGE_H, fill=1, stroke=0)
            title_sfx = f" (cont. {page_num})" if chunk_start > 0 else ""
            self._draw_section_header(c, f"ADDITIONAL FINDINGS \u2014 MEDIUM & LOW SEVERITY{title_sfx}", self.PAGE_H - 64)

            table_rows = [header] + chunk
            table = Table(table_rows, colWidths=col_widths, repeatRows=1, rowHeights=ROW_H)
            style = TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.6),
                    ("TEXTCOLOR", (0, 0), (-1, 0), self.WHITE),
                    ("BACKGROUND", (0, 0), (-1, 0), self.DARK_BG),
                    ("GRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#d1d5db")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("ALIGN", (0, 0), (0, -1), "CENTER"),
                    ("ALIGN", (4, 1), (4, -1), "CENTER"),
                ]
            )
            for i in range(1, len(table_rows)):
                if i % 2 == 0:
                    style.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#f9fafb"))
                sev = table_rows[i][1].lower()
                style.add("TEXTCOLOR", (1, i), (1, i), self._severity_color(sev))
                style.add("FONTNAME", (1, i), (1, i), "Helvetica-Bold")
                style.add("TEXTCOLOR", (7, i), (7, i), colors.HexColor("#b91c1c"))
                style.add("FONTNAME", (7, i), (7, i), "Helvetica-Bold")
            table.setStyle(style)
            table.wrapOn(c, self.PAGE_W - (2 * self.MARGIN_X), USABLE_H)
            table.drawOn(c, self.MARGIN_X, 48)
            self._draw_footer(c, 2 + self.finding_counter + page_num, dark=False)
            if chunk_start + MAX_ROWS_PER_PAGE < len(rows_all):
                c.showPage()

        self._extra_pages = page_num  # track for integrity page numbering

    def _draw_integrity_page(self, c: canvas.Canvas, scan: dict) -> None:
        c.setFillColor(self.DARK_BG)
        c.rect(0, 0, self.PAGE_W, self.PAGE_H, fill=1, stroke=0)
        c.setFillColor(self.WHITE)
        c.setFont("Helvetica-Bold", 22)
        c.drawString(self.MARGIN_X, self.PAGE_H - 72, "AUDIT INTEGRITY VERIFICATION")

        hash_val = self._safe(scan.get("findings_hash"), 90, "N/A")
        sha = self._safe(scan.get("commit_sha"), 80, "N/A")

        c.setFillColor(colors.HexColor("#111827"))
        c.roundRect(self.MARGIN_X, self.PAGE_H - 250, self.PAGE_W - (2 * self.MARGIN_X), 95, 8, fill=1, stroke=0)
        c.setFillColor(self.MID_GRAY)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(self.MARGIN_X + 12, self.PAGE_H - 174, "FINDINGS INTEGRITY HASH (SHA-256)")
        c.setFillColor(self.WHITE)
        c.setFont(self.mono, 10)
        c.drawString(self.MARGIN_X + 12, self.PAGE_H - 196, hash_val[:90])

        c.setFillColor(colors.HexColor("#111827"))
        c.roundRect(self.MARGIN_X, self.PAGE_H - 368, self.PAGE_W - (2 * self.MARGIN_X), 95, 8, fill=1, stroke=0)
        c.setFillColor(self.MID_GRAY)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(self.MARGIN_X + 12, self.PAGE_H - 292, "REPOSITORY COMMIT SHA")
        c.setFillColor(self.WHITE)
        c.setFont(self.mono, 11)
        c.drawString(self.MARGIN_X + 12, self.PAGE_H - 314, sha)

        statement = (
            f"This report was generated by SecurePath v0.1.0 on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}. "
            "The SHA-256 hash above is a cryptographic fingerprint of all findings in this assessment. "
            "Any modification to this report after generation will invalidate this hash. "
            "This document may be submitted as remediation evidence for SOC2 Type II audit purposes."
        )
        p = Paragraph(statement, ParagraphStyle("stmt", parent=self.body, textColor=self.WHITE, leading=15, fontSize=11))
        p.wrapOn(c, self.PAGE_W - (2 * self.MARGIN_X), 120)
        p.drawOn(c, self.MARGIN_X, self.PAGE_H - 505)

        c.setFillColor(self.WHITE)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(self.MARGIN_X, 178, "Reviewed by:")
        c.drawString(self.PAGE_W / 2, 178, "Date:")
        c.setStrokeColor(self.WHITE)
        c.line(self.MARGIN_X + 84, 174, self.PAGE_W / 2 - 20, 174)
        c.line(self.PAGE_W / 2 + 34, 174, self.PAGE_W - self.MARGIN_X, 174)
        c.setFont("Helvetica", 10)
        c.setFillColor(self.MID_GRAY)
        c.drawString(self.MARGIN_X, 156, "Engineering Lead sign-off")

        extra = getattr(self, "_extra_pages", 1)
        self._draw_footer(c, 2 + self.finding_counter + extra + 1, dark=True)
