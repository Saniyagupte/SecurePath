"""
SecurePath PDF Report Generator
Professional black-and-white audit report using ReportLab.
"""

import hashlib
import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas as pdf_canvas
from reportlab.platypus.flowables import Flowable

# ─── COLOR PALETTE ────────────────────────────────────────────────────────────
BLACK       = colors.HexColor("#0a0a0a")
NEAR_BLACK  = colors.HexColor("#111214")
DARK_GRAY   = colors.HexColor("#2a2a2e")
MID_GRAY    = colors.HexColor("#555555")
LIGHT_GRAY  = colors.HexColor("#888888")
RULE_GRAY   = colors.HexColor("#d4d4ce")
OFF_WHITE   = colors.HexColor("#f8f8f6")
WHITE       = colors.white

SEV_CRITICAL = colors.HexColor("#c8232c")
SEV_HIGH     = colors.HexColor("#d97706")
SEV_MEDIUM   = colors.HexColor("#ca8a04")
SEV_LOW      = colors.HexColor("#16a34a")
SEV_INFO     = colors.HexColor("#2563eb")

PAGE_W, PAGE_H = A4
MARGIN_L = 22 * mm
MARGIN_R = 22 * mm
MARGIN_T = 22 * mm
MARGIN_B = 22 * mm
CONTENT_W = PAGE_W - MARGIN_L - MARGIN_R


def severity_color(sev: str):
    return {
        "critical": SEV_CRITICAL,
        "high":     SEV_HIGH,
        "medium":   SEV_MEDIUM,
        "low":      SEV_LOW,
        "info":     SEV_INFO,
    }.get((sev or "").lower(), MID_GRAY)


# ─── STYLES ───────────────────────────────────────────────────────────────────
def make_styles():
    base = dict(fontName="Helvetica", leading=14, textColor=NEAR_BLACK)
    mono = dict(fontName="Courier", textColor=NEAR_BLACK)

    return {
        "cover_title": ParagraphStyle("cover_title",
            fontName="Helvetica-Bold", fontSize=32, leading=36,
            textColor=WHITE, spaceAfter=6),
        "cover_sub": ParagraphStyle("cover_sub",
            fontName="Helvetica", fontSize=13, leading=18,
            textColor=colors.HexColor("#cccccc"), spaceAfter=0),
        "cover_meta": ParagraphStyle("cover_meta",
            fontName="Courier", fontSize=9, leading=14,
            textColor=colors.HexColor("#999999")),

        "section": ParagraphStyle("section",
            fontName="Helvetica-Bold", fontSize=13, leading=18,
            textColor=NEAR_BLACK, spaceBefore=14, spaceAfter=8,
            borderPadding=(0, 0, 4, 0)),
        "subsection": ParagraphStyle("subsection",
            fontName="Helvetica-Bold", fontSize=10, leading=14,
            textColor=MID_GRAY, spaceBefore=10, spaceAfter=4,
            letterSpacing=1.5),
        "body": ParagraphStyle("body",
            **base, fontSize=10, spaceAfter=6, alignment=TA_JUSTIFY),
        "body_small": ParagraphStyle("body_small",
            **base, fontSize=9, leading=13, spaceAfter=4, textColor=MID_GRAY),
        "mono": ParagraphStyle("mono",
            **mono, fontSize=9, leading=13, spaceAfter=4,
            backColor=colors.HexColor("#f2f2ef"),
            borderPadding=4),
        "mono_dark": ParagraphStyle("mono_dark",
            **mono, fontSize=8.5, leading=13, spaceAfter=0,
            textColor=colors.HexColor("#cccccc")),
        "label": ParagraphStyle("label",
            fontName="Courier-Bold", fontSize=7.5, leading=11,
            textColor=LIGHT_GRAY, letterSpacing=1.2, spaceAfter=2),
        "tag": ParagraphStyle("tag",
            fontName="Courier", fontSize=8, leading=11,
            textColor=MID_GRAY),
        "finding_title": ParagraphStyle("finding_title",
            fontName="Helvetica-Bold", fontSize=11, leading=15,
            textColor=NEAR_BLACK, spaceAfter=2),
        "center": ParagraphStyle("center",
            **base, fontSize=10, alignment=TA_CENTER),
        "right": ParagraphStyle("right",
            **base, fontSize=9, alignment=TA_RIGHT, textColor=LIGHT_GRAY),
        "toc_entry": ParagraphStyle("toc_entry",
            fontName="Helvetica", fontSize=10, leading=16,
            textColor=NEAR_BLACK, leftIndent=0),
        "toc_num": ParagraphStyle("toc_num",
            fontName="Courier", fontSize=9, leading=16,
            textColor=LIGHT_GRAY, alignment=TA_RIGHT),
    }


# ─── CUSTOM FLOWABLES ─────────────────────────────────────────────────────────
class HRule(Flowable):
    """Thin horizontal rule."""
    def __init__(self, width=CONTENT_W, color=RULE_GRAY, thickness=0.5, space_before=4, space_after=4):
        super().__init__()
        self.width = width
        self._color = color
        self.thickness = thickness
        self.space_before = space_before
        self.space_after = space_after

    def wrap(self, *args):
        return self.width, self.thickness + self.space_before + self.space_after

    def draw(self):
        self.canv.setStrokeColor(self._color)
        self.canv.setLineWidth(self.thickness)
        self.canv.line(0, self.space_after, self.width, self.space_after)


class SeverityBadge(Flowable):
    """Inline severity pill with border, transparent fill."""
    def __init__(self, severity: str):
        super().__init__()
        self.severity = severity.upper()
        self._color = severity_color(severity)
        self._w = 58
        self._h = 14

    def wrap(self, *args):
        return self._w, self._h

    def draw(self):
        c = self.canv
        c.setStrokeColor(self._color)
        c.setLineWidth(0.8)
        c.setFillColor(WHITE)
        c.roundRect(0, 0, self._w, self._h, 2, stroke=1, fill=1)
        c.setFillColor(self._color)
        c.setFont("Courier-Bold", 6.5)
        c.drawCentredString(self._w / 2, 4, self.severity)


class CodeBlock(Flowable):
    """Dark code block with monospace text."""
    def __init__(self, code: str, width=CONTENT_W):
        super().__init__()
        self._code = code or ""
        self._width = width
        self._padding = 8
        self._font_size = 7.5
        self._line_h = 11
        self._lines = self._code.split("\n")

    def wrap(self, *args):
        self._height = self._padding * 2 + len(self._lines) * self._line_h
        return self._width, self._height

    def draw(self):
        c = self.canv
        h = self._height
        # Background
        c.setFillColor(NEAR_BLACK)
        c.setStrokeColor(DARK_GRAY)
        c.setLineWidth(0.5)
        c.roundRect(0, 0, self._width, h, 3, stroke=1, fill=1)
        # Code text
        c.setFillColor(colors.HexColor("#cccccc"))
        c.setFont("Courier", self._font_size)
        y = h - self._padding - self._font_size
        for line in self._lines:
            # Truncate long lines
            max_chars = int((self._width - self._padding * 2) / (self._font_size * 0.6))
            if len(line) > max_chars:
                line = line[:max_chars - 3] + "..."
            c.drawString(self._padding, y, line)
            y -= self._line_h


# ─── PAGE TEMPLATES ───────────────────────────────────────────────────────────
class HeaderFooterCanvas(pdf_canvas.Canvas):
    """Canvas that draws consistent header/footer on every page."""

    def __init__(self, *args, report_meta=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.report_meta = report_meta or {}
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_page_chrome(num_pages)
            super().showPage()
        super().save()

    def _draw_page_chrome(self, num_pages):
        page_num = self._saved_page_states.index({k: v for k, v in self.__dict__.items() if k in self._saved_page_states[0]}) + 1 if self._saved_page_states else 1

        # Try to get current page number properly
        try:
            page_num = self._pageNumber
        except Exception:
            page_num = 1

        # ── HEADER ──
        # Black band across top
        self.setFillColor(NEAR_BLACK)
        self.rect(0, PAGE_H - 14 * mm, PAGE_W, 14 * mm, stroke=0, fill=1)

        # Brand left
        self.setFont("Helvetica-Bold", 9)
        self.setFillColor(WHITE)
        self.drawString(MARGIN_L, PAGE_H - 9 * mm, "SECUREPATH")

        # Separator dot
        self.setFillColor(SEV_INFO)
        self.circle(MARGIN_L + 66, PAGE_H - 8.5 * mm, 2, stroke=0, fill=1)

        # Repo name center
        repo = self.report_meta.get("repo_name", "")
        if repo:
            self.setFont("Courier", 8)
            self.setFillColor(colors.HexColor("#888888"))
            self.drawCentredString(PAGE_W / 2, PAGE_H - 9 * mm, repo)

        # Page number right
        self.setFont("Courier", 8)
        self.setFillColor(colors.HexColor("#666666"))
        self.drawRightString(PAGE_W - MARGIN_R, PAGE_H - 9 * mm, f"Page {page_num}")

        # ── FOOTER ──
        # Rule
        self.setStrokeColor(RULE_GRAY)
        self.setLineWidth(0.5)
        self.line(MARGIN_L, MARGIN_B - 4 * mm, PAGE_W - MARGIN_R, MARGIN_B - 4 * mm)

        # Footer text
        self.setFont("Courier", 7.5)
        self.setFillColor(LIGHT_GRAY)
        self.drawString(MARGIN_L, MARGIN_B - 8.5 * mm, "CONFIDENTIAL — Security Assessment Report")

        scan_date = self.report_meta.get("scan_date", datetime.utcnow().strftime("%Y-%m-%d"))
        self.drawRightString(PAGE_W - MARGIN_R, MARGIN_B - 8.5 * mm, f"Generated {scan_date} UTC")


def _build_header_footer_canvas(report_meta):
    class _Canvas(HeaderFooterCanvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, report_meta=report_meta, **kwargs)
    return _Canvas


# ─── REPORT BUILDER ───────────────────────────────────────────────────────────
class SecurePathReport:
    """
    Generates a professional audit-ready PDF security report.

    Usage:
        report = SecurePathReport(scan_data, findings)
        pdf_bytes = report.generate()
    """

    def __init__(self, scan: dict, findings: list):
        self.scan = scan
        self.findings = findings
        self.styles = make_styles()
        self.finding_counter = 0

    # ── helpers ──

    def _s(self, name):
        return self.styles[name]

    def _rule(self, color=RULE_GRAY, thickness=0.5, before=3, after=6):
        return HRule(CONTENT_W, color, thickness, before, after)

    def _label(self, text):
        return Paragraph(text.upper(), self._s("label"))

    def _body(self, text):
        return Paragraph(text or "—", self._s("body"))

    def _body_small(self, text):
        return Paragraph(text or "—", self._s("body_small"))

    def _spacer(self, h=4):
        return Spacer(1, h * mm)

    def _code(self, snippet):
        return CodeBlock(snippet or "# No code snippet available", CONTENT_W)

    # ── COVER PAGE ──

    def _cover(self):
        story = []
        # Full-bleed black cover via a Table background hack
        cover_data = [[""]]
        cover_table = Table(cover_data, colWidths=[PAGE_W], rowHeights=[PAGE_H - MARGIN_T - MARGIN_B - 28 * mm])
        cover_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), NEAR_BLACK),
            ("GRID", (0, 0), (-1, -1), 0, NEAR_BLACK),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))

        # Build a canvas-level cover manually via a custom flowable
        class CoverPage(Flowable):
            def __init__(self_, scan, findings):
                super().__init__()
                self_.scan = scan
                self_.findings = findings
                self_.width = CONTENT_W
                self_.height = PAGE_H - MARGIN_T - MARGIN_B

            def wrap(self_, *args):
                return self_.width, self_.height

            def draw(self_):
                c = self_.canv
                w, h = self_.width, self_.height

                # Background panel
                c.setFillColor(NEAR_BLACK)
                c.rect(-MARGIN_L, -MARGIN_B, PAGE_W, PAGE_H, stroke=0, fill=1)

                # Top accent line
                c.setStrokeColor(SEV_INFO)
                c.setLineWidth(3)
                c.line(-MARGIN_L, h + MARGIN_B - 14 * mm, PAGE_W - MARGIN_L, h + MARGIN_B - 14 * mm)

                # SECUREPATH brand
                c.setFont("Helvetica-Bold", 11)
                c.setFillColor(WHITE)
                c.drawString(0, h - 18, "SECUREPATH")

                c.setFont("Helvetica", 9)
                c.setFillColor(colors.HexColor("#555"))
                c.drawString(80, h - 16.5, "Security Assessment Platform")

                # Main title block
                title_y = h - 90
                c.setFont("Helvetica-Bold", 38)
                c.setFillColor(WHITE)
                c.drawString(0, title_y, "Security")
                c.drawString(0, title_y - 44, "Assessment")
                c.drawString(0, title_y - 88, "Report")

                # Gold rule
                c.setStrokeColor(WHITE)
                c.setLineWidth(0.5)
                c.line(0, title_y - 104, 220, title_y - 104)

                # Repo info
                repo = self_.scan.get("repo_name") or self_.scan.get("repo_url") or "—"
                commit = (self_.scan.get("commit_sha") or "pending")[:16]

                c.setFont("Courier", 10)
                c.setFillColor(colors.HexColor("#aaaaaa"))
                c.drawString(0, title_y - 124, repo)

                c.setFont("Courier", 8.5)
                c.setFillColor(colors.HexColor("#666666"))
                c.drawString(0, title_y - 140, f"Commit: {commit}")

                # Scan date
                scan_date = self_.scan.get("scan_date") or datetime.utcnow().strftime("%Y-%m-%d %H:%M")
                c.setFont("Courier", 8.5)
                c.drawString(0, title_y - 154, f"Scan Date: {scan_date} UTC")

                # Stats block — right side
                risk_score = self_.scan.get("risk_score") or 0
                total = len(self_.findings)
                critical = sum(1 for f in self_.findings if (f.get("severity") or "").lower() == "critical")
                high = sum(1 for f in self_.findings if (f.get("severity") or "").lower() == "high")

                box_x = w - 140
                box_y = title_y - 60
                box_w, box_h = 140, 140

                # Stats box
                c.setStrokeColor(DARK_GRAY)
                c.setFillColor(colors.HexColor("#1a1a1e"))
                c.setLineWidth(0.8)
                c.roundRect(box_x, box_y, box_w, box_h, 4, stroke=1, fill=1)

                # Risk score
                c.setFont("Helvetica-Bold", 42)
                c.setFillColor(SEV_CRITICAL if risk_score >= 70 else SEV_HIGH if risk_score >= 40 else SEV_LOW)
                c.drawCentredString(box_x + box_w / 2, box_y + box_h - 52, str(risk_score))

                c.setFont("Courier", 7.5)
                c.setFillColor(colors.HexColor("#666"))
                c.drawCentredString(box_x + box_w / 2, box_y + box_h - 62, "RISK SCORE / 100")

                # Divider
                c.setStrokeColor(DARK_GRAY)
                c.setLineWidth(0.5)
                c.line(box_x + 12, box_y + 70, box_x + box_w - 12, box_y + 70)

                # Finding counts
                stats = [
                    ("TOTAL", str(total), WHITE),
                    ("CRITICAL", str(critical), SEV_CRITICAL),
                    ("HIGH", str(high), SEV_HIGH),
                ]
                col_w = box_w / 3
                for i, (lbl, val, col) in enumerate(stats):
                    cx = box_x + col_w * i + col_w / 2
                    c.setFont("Helvetica-Bold", 18)
                    c.setFillColor(col)
                    c.drawCentredString(cx, box_y + 38, val)
                    c.setFont("Courier", 6.5)
                    c.setFillColor(colors.HexColor("#666"))
                    c.drawCentredString(cx, box_y + 26, lbl)

                # SHA-256 at bottom
                sha = self_.scan.get("sha256") or "—"
                c.setFont("Courier", 7)
                c.setFillColor(colors.HexColor("#444"))
                c.drawString(0, 8, f"SHA-256: {sha[:40]}...")

                # CONFIDENTIAL watermark
                c.setFont("Helvetica-Bold", 7)
                c.setFillColor(colors.HexColor("#333"))
                c.drawRightString(w, 8, "CONFIDENTIAL")

        story.append(CoverPage(self.scan, self.findings))
        story.append(PageBreak())
        return story

    # ── TABLE OF CONTENTS ──

    def _toc(self):
        s = self._s
        story = []
        story.append(Paragraph("Table of Contents", s("section")))
        story.append(self._rule(thickness=1, color=NEAR_BLACK, after=8))

        sections = [
            ("1", "Executive Summary"),
            ("2", "Scan Overview"),
            ("3", "Severity Distribution"),
            ("4", "Compliance Mapping"),
            ("5", "Detailed Findings"),
            ("6", "Remediation Roadmap"),
            ("7", "Integrity Verification"),
        ]

        toc_data = []
        for num, title in sections:
            toc_data.append([
                Paragraph(f"{num}. {title}", s("toc_entry")),
                Paragraph("•••", s("toc_num")),
            ])

        toc_table = Table(toc_data, colWidths=[CONTENT_W - 40, 40])
        toc_table.setStyle(TableStyle([
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE_GRAY),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(toc_table)
        story.append(PageBreak())
        return story

    # ── EXECUTIVE SUMMARY ──

    def _executive_summary(self):
        s = self._s
        scan = self.scan
        findings = self.findings

        critical_n = sum(1 for f in findings if (f.get("severity") or "").lower() == "critical")
        high_n = sum(1 for f in findings if (f.get("severity") or "").lower() == "high")
        medium_n = sum(1 for f in findings if (f.get("severity") or "").lower() == "medium")
        low_n = sum(1 for f in findings if (f.get("severity") or "").lower() == "low")
        risk_score = scan.get("risk_score") or 0

        story = []
        story.append(Paragraph("1. Executive Summary", s("section")))
        story.append(self._rule(thickness=1, color=NEAR_BLACK, after=10))

        # Summary table
        summary_data = [
            [Paragraph("Repository", s("label")),    Paragraph(scan.get("repo_name") or scan.get("repo_url") or "—", s("body"))],
            [Paragraph("Commit SHA", s("label")),     Paragraph(scan.get("commit_sha") or "—", s("mono"))],
            [Paragraph("Scan Date", s("label")),      Paragraph(scan.get("scan_date") or datetime.utcnow().strftime("%Y-%m-%d"), s("body"))],
            [Paragraph("Risk Score", s("label")),     Paragraph(f"{risk_score} / 100", s("body"))],
            [Paragraph("Total Findings", s("label")), Paragraph(str(len(findings)), s("body"))],
            [Paragraph("Critical / High", s("label")),Paragraph(f"{critical_n} / {high_n}", s("body"))],
        ]
        summary_table = Table(summary_data, colWidths=[50 * mm, CONTENT_W - 50 * mm])
        summary_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE_GRAY),
            ("BACKGROUND", (0, 0), (0, -1), OFF_WHITE),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(summary_table)
        story.append(self._spacer(6))

        # Risk level prose
        if risk_score >= 70:
            summary_text = (
                f"This scan identified <b>{len(findings)} security findings</b> across the repository, "
                f"including <b>{critical_n} critical</b> and <b>{high_n} high severity</b> issues. "
                f"The overall risk score of <b>{risk_score}/100</b> indicates a <b>HIGH RISK</b> posture "
                f"that requires immediate remediation before any production deployment or compliance audit. "
                f"Critical findings should be addressed within 24–48 hours."
            )
        elif risk_score >= 40:
            summary_text = (
                f"This scan identified <b>{len(findings)} security findings</b>, with <b>{critical_n} critical</b> "
                f"and <b>{high_n} high severity</b> issues. The risk score of <b>{risk_score}/100</b> indicates a "
                f"<b>MODERATE RISK</b> posture. A structured remediation plan should be implemented within the current sprint."
            )
        else:
            summary_text = (
                f"This scan identified <b>{len(findings)} security findings</b>. The risk score of "
                f"<b>{risk_score}/100</b> indicates a <b>LOW–MODERATE RISK</b> posture. "
                f"Review all findings and prioritize critical and high severity items."
            )

        story.append(Paragraph(summary_text, s("body")))
        story.append(self._spacer(8))

        # Severity breakdown table
        story.append(self._label("Severity Breakdown"))
        story.append(self._spacer(2))

        sev_data = [
            [Paragraph("Severity", s("label")), Paragraph("Count", s("label")), Paragraph("Action", s("label"))],
            [Paragraph("CRITICAL", s("body")), Paragraph(str(critical_n), s("body")), Paragraph("Immediate — within 24h", s("body_small"))],
            [Paragraph("HIGH",     s("body")), Paragraph(str(high_n),     s("body")), Paragraph("Urgent — within 7 days", s("body_small"))],
            [Paragraph("MEDIUM",   s("body")), Paragraph(str(medium_n),   s("body")), Paragraph("Planned — within 30 days", s("body_small"))],
            [Paragraph("LOW",      s("body")), Paragraph(str(low_n),      s("body")), Paragraph("Scheduled — next cycle", s("body_small"))],
        ]
        sev_table = Table(sev_data, colWidths=[40 * mm, 25 * mm, CONTENT_W - 65 * mm])
        sev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NEAR_BLACK),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE_GRAY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, OFF_WHITE]),
            # Color the severity cells
            ("TEXTCOLOR", (0, 1), (0, 1), SEV_CRITICAL),
            ("TEXTCOLOR", (0, 2), (0, 2), SEV_HIGH),
            ("TEXTCOLOR", (0, 3), (0, 3), SEV_MEDIUM),
            ("TEXTCOLOR", (0, 4), (0, 4), SEV_LOW),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            ("BOX", (0, 0), (-1, -1), 0.5, RULE_GRAY),
        ]))
        story.append(sev_table)
        story.append(PageBreak())
        return story

    # ── SCAN OVERVIEW ──

    def _scan_overview(self):
        s = self._s
        story = []
        story.append(Paragraph("2. Scan Overview", s("section")))
        story.append(self._rule(thickness=1, color=NEAR_BLACK, after=10))

        passes = [
            ("SAST Analysis",         "Semgrep rule engine scanning for code-level vulnerabilities across all source files."),
            ("Dependency CVE Audit",  "Cross-referencing third-party dependencies against the NVD CVE database."),
            ("Secret Detection",      "Pattern-matching for hardcoded credentials, API keys, tokens, and private keys."),
            ("Structural Patterns",   "Analysis of authentication flows, error handling, input validation, and security controls."),
            ("Configuration Review",  "Inspection of deployment configs, security headers, TLS settings, and environment files."),
        ]

        for i, (name, desc) in enumerate(passes):
            row = [
                Paragraph(f"0{i+1}", s("label")),
                Paragraph(name, s("subsection")),
                Paragraph(desc, s("body_small")),
            ]
            row_table = Table([[row[0], row[1], row[2]]], colWidths=[12 * mm, 52 * mm, CONTENT_W - 64 * mm])
            row_table.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE_GRAY),
                ("BACKGROUND", (0, 0), (0, -1), OFF_WHITE),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(row_table)

        story.append(self._spacer(10))
        story.append(PageBreak())
        return story

    # ── COMPLIANCE MAPPING ──

    def _compliance_section(self):
        s = self._s
        story = []
        story.append(Paragraph("4. Compliance Mapping", s("section")))
        story.append(self._rule(thickness=1, color=NEAR_BLACK, after=10))

        story.append(Paragraph(
            "Each finding is mapped to applicable compliance controls. The table below summarizes "
            "control coverage identified in this scan. This mapping supports SOC 2 Type II and ISO 27001 evidence packages.",
            s("body")))
        story.append(self._spacer(6))

        # Aggregate controls
        control_map = {}
        for f in self.findings:
            controls = (f.get("soc2_controls") or "").split(",")
            for ctl in controls:
                ctl = ctl.strip()
                if ctl:
                    control_map.setdefault(ctl, []).append(f.get("severity", "low"))

        if control_map:
            header = [Paragraph("Control", s("label")), Paragraph("Findings", s("label")), Paragraph("Max Severity", s("label")), Paragraph("Framework", s("label"))]
            rows = [header]
            for ctl, sevs in sorted(control_map.items()):
                sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
                max_sev = max(sevs, key=lambda x: sev_order.get(x.lower(), 0))
                framework = "SOC 2" if ctl.startswith("CC") else "ISO 27001"
                rows.append([
                    Paragraph(ctl, s("mono")),
                    Paragraph(str(len(sevs)), s("body")),
                    Paragraph(max_sev.upper(), s("body")),
                    Paragraph(framework, s("body_small")),
                ])
            col_ws = [40*mm, 25*mm, 35*mm, CONTENT_W - 100*mm]
            ct = Table(rows, colWidths=col_ws)
            ct.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NEAR_BLACK),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE_GRAY),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, OFF_WHITE]),
                ("BOX", (0, 0), (-1, -1), 0.5, RULE_GRAY),
            ]))
            story.append(ct)
        else:
            story.append(Paragraph("No compliance controls have been mapped yet. Ensure AI enrichment has completed.", s("body_small")))

        story.append(PageBreak())
        return story

    # ── DETAILED FINDINGS ──

    def _finding_block(self, f: dict, idx: int):
        s = self._s
        sev = (f.get("severity") or "low").lower()
        sev_col = severity_color(sev)
        story = []

        # Finding header bar
        header_data = [[
            SeverityBadge(sev),
            Paragraph(f.get("raw_title") or "Untitled Finding", s("finding_title")),
            Paragraph(f"{f.get('cwe_id') or '—'}", s("tag")),
        ]]
        header_table = Table(header_data, colWidths=[60, CONTENT_W - 120, 60])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), OFF_WHITE),
            ("LINEABOVE", (0, 0), (-1, 0), 2, sev_col),
            ("LINEBELOW", (0, 0), (-1, 0), 0.4, RULE_GRAY),
            ("BOX", (0, 0), (-1, -1), 0.5, RULE_GRAY),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(header_table)

        # Detail rows
        fields = [
            ("Location",       f"{f.get('file_path', '—')}:{f.get('line_start', '?')}–{f.get('line_end', '?')}",  "mono"),
            ("Category",       f"{f.get('category', '—')} | OWASP: {f.get('owasp_category', '—')}",               "body"),
            ("Explanation",    f.get("plain_english") or "Pending enrichment.",                                     "body"),
            ("Business Risk",  f.get("business_risk") or "Pending enrichment.",                                     "body"),
            ("Exploit Scenario", f.get("exploit_scenario") or "—",                                                  "body"),
            ("Compliance",     f.get("soc2_controls") or "Not mapped",                                              "mono"),
        ]

        for label, value, style_key in fields:
            row = Table([
                [Paragraph(label, s("label")), Paragraph(value, s(style_key))]
            ], colWidths=[35 * mm, CONTENT_W - 35 * mm])
            row.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LINEBELOW", (0, 0), (-1, -1), 0.3, RULE_GRAY),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("BACKGROUND", (0, 0), (0, -1), OFF_WHITE),
                ("BOX", (0, 0), (-1, -1), 0.4, RULE_GRAY),
            ]))
            story.append(row)

        # Code snippet
        snippet = f.get("code_snippet")
        if snippet:
            story.append(self._spacer(2))
            story.append(self._label("Code Snippet"))
            story.append(self._spacer(1))
            story.append(self._code(snippet))

        # Remediation options
        rem_opts = [
            (f.get("remediation_quick"),  "OPTION 1 — Quick Fix"),
            (f.get("remediation_proper"), "OPTION 2 — Proper Fix"),
            (f.get("remediation_robust"), "OPTION 3 — Robust Fix"),
        ]
        has_rem = any(r for r, _ in rem_opts)
        if has_rem:
            story.append(self._spacer(3))
            story.append(self._label("Remediation Options"))
            story.append(self._spacer(1))
            for rem_text, rem_label in rem_opts:
                if rem_text:
                    rem_row = Table([
                        [Paragraph(rem_label, s("label")), Paragraph(rem_text, s("body_small"))]
                    ], colWidths=[42 * mm, CONTENT_W - 42 * mm])
                    rem_row.setStyle(TableStyle([
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ("LINEBELOW", (0, 0), (-1, -1), 0.3, RULE_GRAY),
                        ("LEFTPADDING", (0, 0), (-1, -1), 10),
                        ("BACKGROUND", (0, 0), (0, -1), OFF_WHITE),
                    ]))
                    story.append(rem_row)

        # Confidence
        conf = f.get("confidence_score")
        if conf:
            story.append(self._spacer(1))
            story.append(Paragraph(f"Confidence: {conf}/10", s("right")))

        story.append(self._spacer(8))
        return story

    def _findings_section(self):
        s = self._s
        story = []
        story.append(Paragraph("5. Detailed Findings", s("section")))
        story.append(self._rule(thickness=1, color=NEAR_BLACK, after=10))

        if not self.findings:
            story.append(Paragraph("No findings recorded for this scan.", s("body")))
        else:
            # Sort: critical → high → medium → low
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_findings = sorted(
                self.findings,
                key=lambda f: order.get((f.get("severity") or "low").lower(), 5)
            )
            for i, f in enumerate(sorted_findings):
                block = self._finding_block(f, i + 1)
                story.extend(block)
                if i < len(sorted_findings) - 1:
                    story.append(self._rule(thickness=0.3, color=colors.HexColor("#cccccc"), before=2, after=4))

        story.append(PageBreak())
        return story

    # ── REMEDIATION ROADMAP ──

    def _roadmap_section(self):
        s = self._s
        story = []
        story.append(Paragraph("6. Remediation Roadmap", s("section")))
        story.append(self._rule(thickness=1, color=NEAR_BLACK, after=10))

        tiers = [
            ("Immediate (24–48h)", "critical", "Address all critical severity findings that present active exploit risk or expose production data."),
            ("Urgent (7 days)", "high", "Remediate high severity findings through sprint planning. Assign ownership and verify fixes in staging."),
            ("Planned (30 days)", "medium", "Schedule medium severity issues into the next planning cycle with appropriate testing."),
            ("Backlog", "low", "Track low severity items in your security backlog. Review during quarterly security reviews."),
        ]

        for tier_label, sev, desc in tiers:
            count = sum(1 for f in self.findings if (f.get("severity") or "").lower() == sev)
            col = severity_color(sev)

            row_data = [[
                Paragraph(tier_label, s("subsection")),
                Paragraph(str(count), s("body")),
                Paragraph(desc, s("body_small")),
            ]]
            t = Table(row_data, colWidths=[55 * mm, 20 * mm, CONTENT_W - 75 * mm])
            t.setStyle(TableStyle([
                ("LINESTART", (0, 0), (0, 0), 3, col),
                ("BACKGROUND", (0, 0), (-1, -1), OFF_WHITE),
                ("BOX", (0, 0), (-1, -1), 0.4, RULE_GRAY),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(t)
            story.append(self._spacer(3))

        story.append(PageBreak())
        return story

    # ── INTEGRITY ──

    def _integrity_section(self):
        s = self._s
        story = []
        story.append(Paragraph("7. Integrity Verification", s("section")))
        story.append(self._rule(thickness=1, color=NEAR_BLACK, after=10))

        story.append(Paragraph(
            "This report includes a SHA-256 integrity hash computed over the scan findings payload. "
            "This hash can be used to verify the report has not been tampered with after generation.",
            s("body")))
        story.append(self._spacer(6))

        sha = self.scan.get("sha256") or "—"
        hash_data = [
            [Paragraph("Algorithm", s("label")), Paragraph("SHA-256", s("mono"))],
            [Paragraph("Digest", s("label")),    Paragraph(sha, s("mono"))],
            [Paragraph("Generated", s("label")), Paragraph(datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), s("mono"))],
            [Paragraph("Scope", s("label")),      Paragraph("Scan findings payload (JSON)", s("body_small"))],
        ]
        ht = Table(hash_data, colWidths=[35 * mm, CONTENT_W - 35 * mm])
        ht.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), OFF_WHITE),
            ("BOX", (0, 0), (-1, -1), 0.5, RULE_GRAY),
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, RULE_GRAY),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(ht)
        return story

    # ── GENERATE ──

    def generate(self) -> bytes:
        """Build and return the PDF as bytes."""
        buf = io.BytesIO()

        report_meta = {
            "repo_name": self.scan.get("repo_name") or self.scan.get("repo_url") or "",
            "scan_date": self.scan.get("scan_date") or datetime.utcnow().strftime("%Y-%m-%d"),
        }

        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            leftMargin=MARGIN_L,
            rightMargin=MARGIN_R,
            topMargin=MARGIN_T + 14 * mm,   # extra for header band
            bottomMargin=MARGIN_B + 10 * mm, # extra for footer
            title=f"SecurePath Security Report — {report_meta['repo_name']}",
            author="SecurePath",
            subject="Security Assessment Report",
            creator="SecurePath v1.0",
        )

        story = []
        story += self._cover()
        story += self._toc()
        story += self._executive_summary()
        story += self._scan_overview()
        # Severity distribution is embedded in exec summary; skip standalone page
        story += self._compliance_section()
        story += self._findings_section()
        story += self._roadmap_section()
        story += self._integrity_section()

        CanvasClass = _build_header_footer_canvas(report_meta)
        doc.build(story, canvasmaker=CanvasClass)

        buf.seek(0)
        return buf.read()


# ─── CONVENIENCE FUNCTION ─────────────────────────────────────────────────────

def generate_report(scan: dict, findings: list) -> bytes:
    """
    Generate a PDF security report.

    Args:
        scan: dict with keys: id, repo_name, repo_url, commit_sha, scan_date,
                              risk_score, sha256, status, findings_count
        findings: list of dicts with keys: severity, raw_title, cwe_id, owasp_category,
                  file_path, line_start, line_end, category, plain_english, business_risk,
                  exploit_scenario, code_snippet, soc2_controls, confidence_score,
                  remediation_quick, remediation_proper, remediation_robust

    Returns:
        PDF bytes
    """
    return SecurePathReport(scan, findings).generate()


# ─── EXAMPLE / TEST ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    sample_scan = {
        "id": "scan-001",
        "repo_name": "juice-shop/juice-shop",
        "repo_url": "https://github.com/juice-shop/juice-shop",
        "commit_sha": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "scan_date": "2026-04-25 14:32",
        "risk_score": 94,
        "findings_count": 3,
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "status": "complete",
    }

    sample_findings = [
        {
            "severity": "critical",
            "raw_title": "SQL Injection via unsafe query interpolation",
            "cwe_id": "CWE-89",
            "owasp_category": "A03:2021",
            "file_path": "routes/vulnCodeSnippets.js",
            "line_start": 40,
            "line_end": 42,
            "category": "Injection",
            "plain_english": "User input is concatenated directly into a SQL query string without sanitization, allowing an attacker to inject arbitrary SQL commands.",
            "business_risk": "SQL injection breaches average $4.4M in remediation costs. GDPR fines can reach 4% of annual revenue. Violates SOC2 CC6.1, ISO 27001 A.9.4.1.",
            "exploit_scenario": "An attacker submits crafted payloads through the email search parameter. By appending UNION SELECT statements, they extract hashed password credentials and session tokens from the database.",
            "code_snippet": "routes/vulnCodeSnippets.js:40\nconst query = `SELECT * FROM Users WHERE email = '${req.query.email}'`;\ndb.sequelize.query(query).then(users => res.json(users));",
            "soc2_controls": "CC6.1, CC6.7, CC7.1",
            "confidence_score": 9,
            "remediation_quick": "Replace string interpolation with Sequelize replacements: db.sequelize.query('SELECT * FROM Users WHERE email = ?', { replacements: [req.query.email] })",
            "remediation_proper": "Migrate to parameterized ORM queries using Sequelize model methods and add Joi schema validation middleware on all input parameters.",
            "remediation_robust": "Centralize all data access behind repository interfaces, enforce query linting in CI pipeline, and add comprehensive SQL injection regression tests.",
        },
        {
            "severity": "critical",
            "raw_title": "Hardcoded JWT secret in configuration",
            "cwe_id": "CWE-798",
            "owasp_category": "A02:2021",
            "file_path": "config/index.js",
            "line_start": 13,
            "line_end": 13,
            "category": "Secret Detection",
            "plain_english": "A static, hardcoded string is used as the JWT signing secret. Anyone with access to the source code can forge authentication tokens.",
            "business_risk": "Compromised JWT secret allows complete authentication bypass. Every user account and admin session can be impersonated without credentials.",
            "exploit_scenario": "An attacker extracts the secret from the public repository, generates a JWT for the administrator user ID, and gains full admin access to the application.",
            "code_snippet": "config/index.js:13\njwtSecret: 'supersecret',  // hardcoded!",
            "soc2_controls": "CC6.1, CC6.3",
            "confidence_score": 10,
            "remediation_quick": "Move the JWT secret to an environment variable: process.env.JWT_SECRET",
            "remediation_proper": "Use a secrets manager (AWS Secrets Manager, HashiCorp Vault) and rotate the secret immediately since it has been exposed.",
            "remediation_robust": "Implement a key rotation policy, use asymmetric RS256 signing, and add secret scanning to the CI pipeline to prevent future regressions.",
        },
        {
            "severity": "high",
            "raw_title": "eval() usage with user-controlled input",
            "cwe_id": "CWE-95",
            "owasp_category": "A03:2021",
            "file_path": "routes/angular.js",
            "line_start": 8,
            "line_end": 10,
            "category": "Code Injection",
            "plain_english": "The eval() function is called with data that may be influenced by user input, enabling arbitrary JavaScript code execution on the server.",
            "business_risk": "Remote code execution vulnerabilities are catastrophic. Complete server compromise allows data exfiltration, lateral movement, and ransomware deployment.",
            "exploit_scenario": "An attacker crafts a request payload containing JavaScript code that, when passed to eval(), executes in the Node.js process context with full server privileges.",
            "code_snippet": "routes/angular.js:8\nconst result = eval(req.body.code);\nres.json({ result });",
            "soc2_controls": "CC6.1, CC7.1",
            "confidence_score": 8,
            "remediation_quick": "Remove eval() entirely. If dynamic execution is needed, use a sandboxed evaluation library like vm2.",
            "remediation_proper": "Replace eval() with a safe expression parser. Validate and whitelist all accepted operations server-side.",
            "remediation_robust": "Add a linting rule (no-eval) to ESLint config and CI, implement Content Security Policy headers, and conduct a full audit for other dynamic code execution patterns.",
        },
    ]

    print("Generating SecurePath PDF report...")
    pdf_bytes = generate_report(sample_scan, sample_findings)

    with open("securepath_report_sample.pdf", "wb") as f:
        f.write(pdf_bytes)

    print(f"Report generated: securepath_report_sample.pdf ({len(pdf_bytes):,} bytes)")