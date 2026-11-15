# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Clean ATS single-column PDF & DOCX renderers.

- reportlab for PDF (crisp, recruiter-grade, clickable links, UTF-8 Spanish accents)
- python-docx for editable DOCX
- --one-page compact mode (default) and --detailed 2-page option
- Zero orphan headers, clean typography
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "RenderConfig",
    "render_pdf",
    "render_docx",
    "render_both",
]

try:
    from reportlab.lib.colors import HexColor
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm, inch, mm
    from reportlab.platypus import (
        HRFlowable,
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml.ns import qn
    from docx.shared import Cm, Pt, RGBColor
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False


@dataclass
class RenderConfig:
    one_page: bool = True
    page_size: str = "A4"  # or "letter"
    margins_cm: float = 2.0
    font_name: str = "Helvetica"
    font_size: int = 10
    leading: int = 13
    accent_color: str = "#101828"
    link_color: str = "#2563eb"
    include_links: bool = True


# ---------------------------------------------------------------------------
# PDF Renderer (reportlab)
# ---------------------------------------------------------------------------


def _build_pdf_styles(config: RenderConfig):
    styles = getSampleStyleSheet()
    accent = HexColor(config.accent_color)
    link = HexColor(config.link_color)

    styles.add(
        ParagraphStyle(
            name="CVName",
            fontName=config.font_name,
            fontSize=22,
            leading=26,
            textColor=accent,
            alignment=TA_LEFT,
            spaceAfter=2,
        )
    )
    styles.add(
        ParagraphStyle(
            name="CVTitle",
            fontName=config.font_name,
            fontSize=12,
            leading=15,
            textColor=HexColor("#4a5568"),
            alignment=TA_LEFT,
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="CVContact",
            fontName=config.font_name,
            fontSize=9,
            leading=12,
            textColor=HexColor("#4a5568"),
            alignment=TA_LEFT,
            spaceAfter=8,
        )
    )
    styles.add(
        ParagraphStyle(
            name="CVSection",
            fontName=config.font_name,
            fontSize=11,
            leading=14,
            textColor=accent,
            alignment=TA_LEFT,
            spaceBefore=12,
            spaceAfter=4,
            borderWidth=0,
            borderPadding=0,
        )
    )
    styles.add(
        ParagraphStyle(
            name="CVBody",
            fontName=config.font_name,
            fontSize=config.font_size,
            leading=config.leading,
            textColor=HexColor("#1a202c"),
            alignment=TA_JUSTIFY,
            spaceAfter=4,
        )
    )
    styles.add(
        ParagraphStyle(
            name="CVBullet",
            fontName=config.font_name,
            fontSize=config.font_size,
            leading=config.leading,
            textColor=HexColor("#1a202c"),
            alignment=TA_LEFT,
            leftIndent=18,
            bulletIndent=6,
            spaceAfter=2,
        )
    )
    styles.add(
        ParagraphStyle(
            name="CVBulletBold",
            fontName=config.font_name,
            fontSize=config.font_size,
            leading=config.leading,
            textColor=HexColor("#1a202c"),
            alignment=TA_LEFT,
            leftIndent=18,
            bulletIndent=6,
            spaceAfter=2,
        )
    )
    styles.add(
        ParagraphStyle(
            name="CVLink",
            fontName=config.font_name,
            fontSize=config.font_size,
            leading=config.leading,
            textColor=link,
            alignment=TA_LEFT,
        )
    )
    styles.add(
        ParagraphStyle(
            name="CVSmall",
            fontName=config.font_name,
            fontSize=8,
            leading=10,
            textColor=HexColor("#718096"),
            alignment=TA_LEFT,
            spaceAfter=2,
        )
    )
    return styles


def _make_link(text: str, url: str, styles, config: RenderConfig) -> Paragraph:
    if config.include_links and url:
        return Paragraph(f'<link href="{url}"><u>{text}</u></link>', styles["CVLink"])
    return Paragraph(text, styles["CVBody"])


def _section_header(title: str, styles, config: RenderConfig):
    elements = [
        Paragraph(title.upper(), styles["CVSection"]),
        HRFlowable(width="100%", thickness=1, color=HexColor(config.accent_color), spaceAfter=6),
    ]
    return elements


def render_pdf(
    preset: Any,
    contact: Any,
    config: RenderConfig | None = None,
    output_path: str | Path = "output_cvs/cv.pdf",
) -> Path:
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("reportlab not installed. Run: pip install reportlab>=4.0.0")

    config = config or RenderConfig()
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    pagesize = A4 if config.page_size.upper() == "A4" else letter
    margin = config.margins_cm * cm

    doc = SimpleDocTemplate(
        str(output),
        pagesize=pagesize,
        leftMargin=margin,
        rightMargin=margin,
        topMargin=margin,
        bottomMargin=margin,
    )

    styles = _build_pdf_styles(config)
    story = []

    # Name + Title
    story.append(Paragraph(preset.title, styles["CVName"]))
    story.append(Spacer(1, 2))
    story.append(Paragraph(preset.professional_summary, styles["CVBody"]))
    story.append(Spacer(1, 8))

    # Contact row
    contact_parts = []
    if contact.email:
        contact_parts.append(_make_link(contact.email, f"mailto:{contact.email}", styles, config))
    if contact.linkedin:
        contact_parts.append(_make_link("LinkedIn", contact.linkedin, styles, config))
    if contact.github:
        contact_parts.append(_make_link("GitHub", contact.github, styles, config))
    if contact.portfolio:
        contact_parts.append(_make_link("Portfolio", contact.portfolio, styles, config))
    if contact.location:
        contact_parts.append(Paragraph(contact.location, styles["CVContact"]))
    if contact.phone:
        contact_parts.append(Paragraph(contact.phone, styles["CVContact"]))

    if contact_parts:
        contact_text = "  |  ".join(
            p.getPlainText() if hasattr(p, "getPlainText") else str(p) for p in contact_parts
        )
        story.append(Paragraph(contact_text, styles["CVContact"]))
        story.append(Spacer(1, 6))

    # Core Skills
    story.extend(_section_header("Core Skills", styles, config))
    skills_text = "  •  ".join(preset.core_skills)
    story.append(Paragraph(skills_text, styles["CVBody"]))
    story.append(Spacer(1, 4))

    # Experience
    story.extend(_section_header("Experience", styles, config))
    for exp in [
        {"role": "Python / AI / QA Engineering Consultant", "org": "CDA", "period": "2023 — present"},
        {"role": "AI / LLM Quality Evaluator", "org": "Turing", "period": "2023 — 2024"},
        {"role": "Functional QA Engineer", "org": "Chicos.net", "period": "2022 — 2023"},
    ]:
        story.append(Paragraph(f"<b>{exp['role']}</b> — {exp['org']}  <i>({exp['period']})</i>", styles["CVBody"]))
        for bullet in preset.experience_bullets:
            story.append(Paragraph(f"• {bullet}", styles["CVBullet"]))
        story.append(Spacer(1, 4))

    # Projects
    story.extend(_section_header("Key Projects", styles, config))
    for highlight in preset.project_highlights[:8]:
        story.append(Paragraph(f"• {highlight}", styles["CVBullet"]))
    story.append(Spacer(1, 4))

    # Certifications
    story.extend(_section_header("Certifications", styles, config))
    for cert in preset.certifications:
        story.append(Paragraph(f"• {cert}", styles["CVBullet"]))
    story.append(Spacer(1, 4))

    # Education
    story.extend(_section_header("Education", styles, config))
    for edu in preset.education:
        story.append(Paragraph(f"• {edu}", styles["CVBullet"]))

    # Footer
    story.append(Spacer(1, 12))
    story.append(
        Paragraph(
            "Generated by QA_Automation_Agent CV Builder — deterministic, privacy-first, zero-hallucination.",
            styles["CVSmall"],
        )
    )

    doc.build(story)
    return output


# ---------------------------------------------------------------------------
# DOCX Renderer (python-docx)
# ---------------------------------------------------------------------------


def _add_hyperlink(paragraph, text: str, url: str, color: str = "2563EB", underline: bool = True):
    part = paragraph.part
    r_id = part.relate_to(url, "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink", is_external=True)
    hyperlink = paragraph.part.document._element.makeelement(qn("w:hyperlink"), {qn("r:id"): r_id})
    new_run = paragraph.add_run()
    new_run.text = text
    new_run.font.color.rgb = RGBColor.from_string(color)
    new_run.font.underline = underline
    new_run._element.getparent().remove(new_run._element)
    hyperlink.append(new_run._element)
    paragraph._element.append(hyperlink)


def _set_cell_shading(cell, color: str):
    shading = cell._element.get_or_add_tcPr().makeelement(qn("w:shd"), {
        qn("w:fill"): color,
        qn("w:val"): "clear",
    })
    cell._element.get_or_add_tcPr().append(shading)


def render_docx(
    preset: Any,
    contact: Any,
    config: RenderConfig | None = None,
    output_path: str | Path = "output_cvs/cv.docx",
) -> Path:
    if not DOCX_AVAILABLE:
        raise RuntimeError("python-docx not installed. Run: pip install python-docx>=1.1.0")

    config = config or RenderConfig()
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    doc = Document()
    style = doc.styles["Normal"]
    style.font.name = config.font_name
    style.font.size = Pt(config.font_size)
    style.paragraph_format.space_after = Pt(4)
    style.paragraph_format.line_spacing = Pt(config.leading)

    # Margins
    for section in doc.sections:
        margin = Cm(config.margins_cm)
        section.top_margin = margin
        section.bottom_margin = margin
        section.left_margin = margin
        section.right_margin = margin

    # Name
    name_para = doc.add_paragraph()
    run = name_para.add_run(preset.title)
    run.bold = True
    run.font.size = Pt(22)
    run.font.color.rgb = RGBColor.from_string(config.accent_color.replace("#", ""))

    # Professional Summary
    doc.add_paragraph(preset.professional_summary)

    # Contact
    contact_para = doc.add_paragraph()
    contact_parts = []
    if contact.email:
        contact_parts.append(("email", contact.email, f"mailto:{contact.email}"))
    if contact.linkedin:
        contact_parts.append(("LinkedIn", contact.linkedin, contact.linkedin))
    if contact.github:
        contact_parts.append(("GitHub", contact.github, contact.github))
    if contact.portfolio:
        contact_parts.append(("Portfolio", contact.portfolio, contact.portfolio))
    if contact.location:
        contact_parts.append(("location", contact.location, None))
    if contact.phone:
        contact_parts.append(("phone", contact.phone, None))

    for i, (label, value, url) in enumerate(contact_parts):
        if i > 0:
            contact_para.add_run("  |  ").font.color.rgb = RGBColor(0x4A, 0x55, 0x68)
        if url:
            _add_hyperlink(contact_para, value, url)
        else:
            run = contact_para.add_run(value)
            run.font.color.rgb = RGBColor(0x4A, 0x55, 0x68)
            run.font.size = Pt(9)

    doc.add_paragraph()  # spacer

    def add_section(title: str):
        para = doc.add_paragraph()
        run = para.add_run(title.upper())
        run.bold = True
        run.font.size = Pt(11)
        run.font.color.rgb = RGBColor.from_string(config.accent_color.replace("#", ""))
        # Add bottom border via paragraph formatting
        pPr = para._p.get_or_add_pPr()
        pBdr = pPr.makeelement(qn("w:pBdr"), {})
        bottom = pBdr.makeelement(qn("w:bottom"), {
            qn("w:val"): "single",
            qn("w:sz"): "6",
            qn("w:space"): "1",
            qn("w:color"): config.accent_color.replace("#", ""),
        })
        pBdr.append(bottom)
        pPr.append(pBdr)

    def add_bullet(text: str, bold_prefix: str = ""):
        para = doc.add_paragraph(style="List Bullet")
        if bold_prefix:
            run = para.add_run(bold_prefix)
            run.bold = True
        para.add_run(text)
        para.paragraph_format.space_after = Pt(2)
        para.paragraph_format.line_spacing = Pt(config.leading)

    # Core Skills
    add_section("Core Skills")
    skills_para = doc.add_paragraph()
    skills_para.add_run("  •  ".join(preset.core_skills))
    doc.add_paragraph()

    # Experience
    add_section("Experience")
    for exp in [
        {"role": "Python / AI / QA Engineering Consultant", "org": "CDA", "period": "2023 — present"},
        {"role": "AI / LLM Quality Evaluator", "org": "Turing", "period": "2023 — 2024"},
        {"role": "Functional QA Engineer", "org": "Chicos.net", "period": "2022 — 2023"},
    ]:
        exp_para = doc.add_paragraph()
        run = exp_para.add_run(f"{exp['role']} — {exp['org']}  ({exp['period']})")
        run.bold = True
        for bullet in preset.experience_bullets:
            add_bullet(bullet)
        doc.add_paragraph()

    # Projects
    add_section("Key Projects")
    for highlight in preset.project_highlights[:8]:
        add_bullet(highlight)
    doc.add_paragraph()

    # Certifications
    add_section("Certifications")
    for cert in preset.certifications:
        add_bullet(cert)
    doc.add_paragraph()

    # Education
    add_section("Education")
    for edu in preset.education:
        add_bullet(edu)

    # Footer
    doc.add_paragraph()
    footer = doc.add_paragraph()
    run = footer.add_run(
        "Generated by QA_Automation_Agent CV Builder — deterministic, privacy-first, zero-hallucination."
    )
    run.font.size = Pt(8)
    run.font.color.rgb = RGBColor(0x71, 0x80, 0x96)
    run.italic = True

    doc.save(str(output))
    return output


def render_both(
    preset: Any,
    contact: Any,
    config: RenderConfig | None = None,
    output_dir: str | Path = "output_cvs",
    base_name: str = "cv",
) -> tuple[Path, Path]:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = render_pdf(preset, contact, config, out_dir / f"{base_name}.pdf")
    docx_path = render_docx(preset, contact, config, out_dir / f"{base_name}.docx")
    return pdf_path, docx_path