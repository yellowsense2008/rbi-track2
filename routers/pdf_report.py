import json
import os
from datetime import datetime
from fastapi import APIRouter
from fastapi.responses import FileResponse
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT

router = APIRouter()

# Colors
RBI_BLUE = colors.HexColor("#003366")
DANGER_RED = colors.HexColor("#CC0000")
WARNING_ORANGE = colors.HexColor("#E65C00")
SAFE_GREEN = colors.HexColor("#1A6B1A")
LIGHT_GRAY = colors.HexColor("#F5F5F5")
MID_GRAY = colors.HexColor("#CCCCCC")

def get_verdict_color(verdict: str):
    if verdict == "HIGH" or verdict == "CRITICAL":
        return DANGER_RED
    elif verdict == "MEDIUM":
        return WARNING_ORANGE
    return SAFE_GREEN

def build_pdf_report(static_data: dict, dynamic_data: dict, output_path: str):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=15*mm,
        leftMargin=15*mm,
        topMargin=15*mm,
        bottomMargin=15*mm
    )

    styles = getSampleStyleSheet()
    story = []

    # Header style
    header_style = ParagraphStyle(
        'Header',
        parent=styles['Normal'],
        fontSize=22,
        fontName='Helvetica-Bold',
        textColor=colors.white,
        alignment=TA_CENTER,
        spaceAfter=4
    )
    sub_header_style = ParagraphStyle(
        'SubHeader',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.white,
        alignment=TA_CENTER
    )
    section_style = ParagraphStyle(
        'Section',
        parent=styles['Normal'],
        fontSize=12,
        fontName='Helvetica-Bold',
        textColor=RBI_BLUE,
        spaceBefore=8,
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor("#333333"),
        spaceAfter=3
    )
    flag_style = ParagraphStyle(
        'Flag',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.HexColor("#333333"),
        leftIndent=8,
        spaceAfter=2
    )

    verdict = static_data.get("verdict", "UNKNOWN")
    dynamic_verdict = dynamic_data.get("final_dynamic_verdict", "PENDING")
    final_verdict = "CRITICAL" if dynamic_verdict == "CRITICAL" else verdict
    verdict_color = get_verdict_color(final_verdict)
    package_id = static_data.get("package_id", "Unknown")
    app_name = static_data.get("playstore_name") or "Sideloaded APK"
    developer = static_data.get("developer") or "Unknown"
    risk_breakdown = static_data.get("risk_breakdown", {})
    threat_intel = static_data.get("threat_intelligence", {})

    # --- HEADER BANNER ---
    header_data = [[
        Paragraph("AppGuard AI", header_style),
    ]]
    header_table = Table(header_data, colWidths=[180*mm])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), RBI_BLUE),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('ROUNDEDCORNERS', [4, 4, 4, 4]),
    ]))
    story.append(header_table)

    sub_data = [[Paragraph("RBI Digital Lending Compliance & Threat Intelligence Report", sub_header_style)]]
    sub_table = Table(sub_data, colWidths=[180*mm])
    sub_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), RBI_BLUE),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(sub_table)
    story.append(Spacer(1, 6*mm))

    # --- VERDICT BANNER ---
    verdict_data = [[
        Paragraph(f"FINAL VERDICT: {final_verdict}", ParagraphStyle(
            'Verdict',
            parent=styles['Normal'],
            fontSize=18,
            fontName='Helvetica-Bold',
            textColor=colors.white,
            alignment=TA_CENTER
        ))
    ]]
    verdict_table = Table(verdict_data, colWidths=[180*mm])
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), verdict_color),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('ROUNDEDCORNERS', [4, 4, 4, 4]),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 5*mm))

    # --- APP IDENTITY ---
    story.append(Paragraph("App Identity", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GRAY))
    story.append(Spacer(1, 2*mm))

    identity_data = [
        ["Package ID", package_id],
        ["App Name", app_name],
        ["Developer", developer],
        ["Analysis Date", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Distribution", "Play Store" if static_data.get("playstore_name") else "Sideloaded (Ghost App)"],
    ]
    identity_table = Table(identity_data, colWidths=[45*mm, 135*mm])
    identity_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('TEXTCOLOR', (0, 0), (0, -1), RBI_BLUE),
        ('BACKGROUND', (0, 0), (-1, -1), LIGHT_GRAY),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, LIGHT_GRAY]),
        ('GRID', (0, 0), (-1, -1), 0.5, MID_GRAY),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(identity_table)
    story.append(Spacer(1, 4*mm))

    # --- RISK SCORE BREAKDOWN ---
    story.append(Paragraph("Risk Score Breakdown", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GRAY))
    story.append(Spacer(1, 2*mm))

    score_data = [["Engine", "Risk Score", "Weight"]]
    engine_map = [
        ("ML Binary Analysis (XGBoost + RF + LR)", "ml_binary_risk", "35%"),
        ("NLP Brand Impersonation", "nlp_semantic_risk", "25%"),
        ("OSINT Domain Analysis", "osint_domain_risk", "15%"),
        ("Anomaly Detection", "anomaly_risk", "10%"),
        ("Regulatory Feature Penalty", "custom_feature_penalty", "15%"),
    ]
    for label, key, weight in engine_map:
        val = risk_breakdown.get(key, 0)
        score_data.append([label, f"{val:.3f}", weight])

    score_data.append([
        "COMPOSITE RISK SCORE",
        f"{risk_breakdown.get('final_composite_score', 0):.3f}",
        "100%"
    ])

    score_table = Table(score_data, colWidths=[105*mm, 40*mm, 35*mm])
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), RBI_BLUE),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('BACKGROUND', (0, -1), (-1, -1), verdict_color),
        ('TEXTCOLOR', (0, -1), (-1, -1), colors.white),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -2), [colors.white, LIGHT_GRAY]),
        ('GRID', (0, 0), (-1, -1), 0.5, MID_GRAY),
        ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 4*mm))

    # --- PERMISSION VIOLATIONS ---
    perm_flags = threat_intel.get("permission_flags", [])
    if perm_flags:
        story.append(Paragraph("RBI Permission Violations", section_style))
        story.append(HRFlowable(width="100%", thickness=1, color=MID_GRAY))
        story.append(Spacer(1, 2*mm))
        for flag in perm_flags:
            bullet_color = DANGER_RED if "Critical" in flag.get("signal", "") else WARNING_ORANGE
            story.append(Paragraph(
                f'<font color="red">&#9632;</font> <b>{flag.get("signal", "")}</b>',
                flag_style
            ))
            story.append(Paragraph(
                f'  {flag.get("detail", "")}',
                ParagraphStyle('Detail', parent=flag_style, textColor=colors.HexColor("#666666"), leftIndent=16)
            ))
        story.append(Spacer(1, 4*mm))

    # --- OSINT FLAGS ---
    osint_flags = threat_intel.get("osint_flags", [])
    if osint_flags:
        story.append(Paragraph("OSINT Intelligence Flags", section_style))
        story.append(HRFlowable(width="100%", thickness=1, color=MID_GRAY))
        story.append(Spacer(1, 2*mm))
        for flag in osint_flags:
            story.append(Paragraph(f'&#9679; {flag}', flag_style))
        story.append(Spacer(1, 4*mm))

    # --- DYNAMIC SANDBOX ---
    if dynamic_data and dynamic_data.get("status") == "success":
        story.append(Paragraph("Dynamic Sandbox Intelligence", section_style))
        story.append(HRFlowable(width="100%", thickness=1, color=MID_GRAY))
        story.append(Spacer(1, 2*mm))

        heuristics = dynamic_data.get("sandbox_heuristics", {})
        story.append(Paragraph(
            f'<b>Sandbox Status:</b> {heuristics.get("status", "N/A")}',
            body_style
        ))
        story.append(Paragraph(
            f'<b>Interpretation:</b> {heuristics.get("interpretation", "N/A")}',
            body_style
        ))

        fin_intel = dynamic_data.get("financial_intelligence", {})
        burner_domains = fin_intel.get("flagged_burner_domains", [])
        if burner_domains:
            story.append(Spacer(1, 2*mm))
            story.append(Paragraph("<b>Flagged Malicious Domains:</b>", body_style))
            for domain in burner_domains:
                story.append(Paragraph(f'&#9888; {domain}', ParagraphStyle(
                    'Domain', parent=flag_style,
                    textColor=DANGER_RED, fontName='Helvetica-Bold'
                )))

        upis = fin_intel.get("extracted_upis", [])
        if upis:
            story.append(Spacer(1, 2*mm))
            story.append(Paragraph("<b>Extracted UPI Payment Addresses:</b>", body_style))
            for upi in upis:
                story.append(Paragraph(f'&#9658; {upi}', flag_style))

        story.append(Spacer(1, 4*mm))

    # --- FOOTER ---
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GRAY))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        "Generated by AppGuard AI | YellowSense Technologies | RBI HaRBInger 2025",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8,
                       textColor=colors.HexColor("#999999"), alignment=TA_CENTER)
    ))
    story.append(Paragraph(
        "This report is generated for regulatory compliance purposes under RBI Digital Lending Directions 2025.",
        ParagraphStyle('Footer2', parent=styles['Normal'], fontSize=7,
                       textColor=colors.HexColor("#BBBBBB"), alignment=TA_CENTER)
    ))

    doc.build(story)

@router.get("/report/pdf/{package_id}")
def generate_pdf_report(package_id: str):
    static_path = f"threat_reports/{package_id}_static_report.json"
    dynamic_path = f"threat_reports/{package_id}_dynamic_report.json"

    if not os.path.exists(static_path):
        return {"error": f"No report found for {package_id}. Analyze the app first."}

    with open(static_path, "r") as f:
        static_data = json.load(f)

    dynamic_data = {}
    if os.path.exists(dynamic_path):
        with open(dynamic_path, "r") as f:
            dynamic_data = json.load(f)

    os.makedirs("threat_reports", exist_ok=True)
    pdf_path = f"threat_reports/{package_id}_report.pdf"

    try:
        build_pdf_report(static_data, dynamic_data, pdf_path)
        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=f"AppGuard_Report_{package_id}.pdf"
        )
    except Exception as e:
        return {"error": f"PDF generation failed: {str(e)}"}