import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.graphics.shapes import Drawing, Rect, String, Line

# Resilient imports of database and mitre mapping
try:
    from backend.database import get_alerts, get_session_stats
    from backend.mitre import map_threat_to_mitre
except ImportError:
    try:
        from database import get_alerts, get_session_stats
        from mitre import map_threat_to_mitre
    except ImportError:
        pass

# Define Color Scheme
NAVY = colors.HexColor("#1e3a8a")
DARK_BLUE = colors.HexColor("#0f172a")
MUTED_TEXT = colors.HexColor("#475569")
LIGHT_GRAY = colors.HexColor("#f8fafc")
BORDER_COLOR = colors.HexColor("#cbd5e1")

# Severity Colors
COLOR_CRITICAL = colors.HexColor("#ef4444")
COLOR_HIGH = colors.HexColor("#f97316")
COLOR_MEDIUM = colors.HexColor("#eab308")
COLOR_LOW = colors.HexColor("#3b82f6")

def draw_header_footer(canvas, doc):
    """Draws a professional running header and footer on later pages."""
    canvas.saveState()
    # Don't draw on first page (cover page)
    if doc.page > 1:
        # Header
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(NAVY)
        canvas.drawString(54, 750, "THREATSENTINEL LITE — NETWORK TRAFFIC AUDIT REPORT")
        canvas.setStrokeColor(BORDER_COLOR)
        canvas.setLineWidth(0.5)
        canvas.line(54, 742, 558, 742)
        
        # Footer
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED_TEXT)
        canvas.drawString(54, 40, f"Confidential  |  Generated on {datetime_str()}")
        canvas.drawRightString(558, 40, f"Page {doc.page}")
    canvas.restoreState()

def datetime_str():
    from datetime import datetime
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def draw_severity_chart(stats):
    """Programmatically draws a beautiful horizontal bar chart of alert severities."""
    sevs = stats.get('severities', {"Critical": 0, "High": 0, "Medium": 0, "Low": 0})
    
    # Setup drawing canvas
    d = Drawing(400, 150)
    
    # Background border
    d.add(Rect(0, 0, 400, 150, fillColor=LIGHT_GRAY, strokeColor=BORDER_COLOR, strokeWidth=0.5))
    
    categories = ["Critical", "High", "Medium", "Low"]
    counts = [sevs.get(c, 0) for c in categories]
    colors_list = [COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW]
    
    max_count = max(counts) if max(counts) > 0 else 1
    
    # Draw bars
    y = 110
    bar_height = 18
    max_bar_width = 240
    
    # Title inside drawing
    d.add(String(20, 132, "Severity Breakdown", fontName="Helvetica-Bold", fontSize=10, fillColor=DARK_BLUE))
    
    for i, cat in enumerate(categories):
        count = counts[i]
        bar_width = (count / max_count) * max_bar_width if count > 0 else 2
        
        # Category label
        d.add(String(20, y + 4, f"{cat}:", fontName="Helvetica-Bold", fontSize=9, fillColor=DARK_BLUE))
        
        # Colored bar
        d.add(Rect(90, y, bar_width, bar_height, fillColor=colors_list[i], strokeColor=None))
        
        # Count label
        d.add(String(95 + bar_width, y + 4, f"{count} flow(s)", fontName="Helvetica", fontSize=8, fillColor=MUTED_TEXT))
        
        y -= 28
        
    return d

def generate_pdf_report(session_id, filename, ai_summary, output_path):
    """Generates the structured PDF audit report using ReportLab."""
    # Retrieve data
    alerts = get_alerts(session_id=session_id)
    stats = get_session_stats(session_id)
    
    # Setup document
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    # Define custom styles
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=32,
        leading=38,
        textColor=NAVY,
        spaceAfter=10
    )
    
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=14,
        leading=18,
        textColor=MUTED_TEXT,
        spaceAfter=40
    )
    
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=NAVY,
        spaceAfter=15,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'ReportBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=DARK_BLUE,
        spaceAfter=12
    )
    
    summary_box_style = ParagraphStyle(
        'SummaryBox',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=11,
        leading=16,
        textColor=DARK_BLUE
    )
    
    header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=11,
        textColor=colors.white
    )
    
    cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=10,
        textColor=DARK_BLUE
    )
    
    story = []
    
    # ================= PAGE 1: COVER PAGE =================
    story.append(Spacer(1, 100))
    story.append(Paragraph("THREATSENTINEL LITE", title_style))
    story.append(Paragraph("AI-Powered Zero-Day Threat Detection Report", subtitle_style))
    story.append(Spacer(1, 40))
    
    # Metadata block
    metadata_data = [
        [Paragraph("<b>Audit Session ID:</b>", body_style), Paragraph(session_id, body_style)],
        [Paragraph("<b>PCAP File Audited:</b>", body_style), Paragraph(filename, body_style)],
        [Paragraph("<b>Execution Time:</b>", body_style), Paragraph(datetime_str(), body_style)],
        [Paragraph("<b>Total Flows Scanned:</b>", body_style), Paragraph(str(stats['total_alerts']), body_style)],
        [Paragraph("<b>Total Threats Flagged:</b>", body_style), Paragraph(str(stats['total_alerts'] - stats['attack_types'].get('Normal', 0)), body_style)]
    ]
    meta_table = Table(metadata_data, colWidths=[150, 350])
    meta_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
    ]))
    story.append(meta_table)
    story.append(PageBreak())
    
    # ================= PAGE 2: AI EXECUTIVE SUMMARY =================
    story.append(Spacer(1, 20))
    story.append(Paragraph("Executive Summary", section_heading))
    story.append(Paragraph("The following summary was compiled automatically by the ThreatSentinel AI co-pilot, evaluating anomalous behavior profiles and attack signatures discovered within the uploaded flow capture.", body_style))
    story.append(Spacer(1, 15))
    
    # Styled AI Executive Summary Callout Box
    summary_data = [[Paragraph(ai_summary, summary_box_style)]]
    summary_table = Table(summary_data, colWidths=[500])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_GRAY),
        ('BOX', (0,0), (-1,-1), 1, NAVY),
        ('TOPPADDING', (0,0), (-1,-1), 20),
        ('BOTTOMPADDING', (0,0), (-1,-1), 20),
        ('LEFTPADDING', (0,0), (-1,-1), 20),
        ('RIGHTPADDING', (0,0), (-1,-1), 20),
    ]))
    story.append(summary_table)
    
    # Audit confidence statement
    story.append(Spacer(1, 40))
    story.append(Paragraph("<b>Audit Methodology Statement:</b> This traffic analysis was performed using a hybrid threat detection framework. Normal statistical profiles were calibrated using an unsupervised Isolation Forest model (contamination rate 5%). Known threat vectors (DDoS, Port Scan, Brute Force) were identified using a supervised Random Forest classifier. High-anomaly flows that did not match known signatures are flagged as Zero-Day Anomalies.", body_style))
    story.append(PageBreak())
    
    # ================= PAGE 3: THREAT STATISTICS & SEVERITY CHART =================
    story.append(Spacer(1, 20))
    story.append(Paragraph("Threat Statistics & Distribution", section_heading))
    story.append(Paragraph("This section presents the numeric breakdown of severity levels and classified threats detected across all bidirectional flows.", body_style))
    story.append(Spacer(1, 10))
    
    # Table of metrics
    sevs = stats['severities']
    types = stats['attack_types']
    
    stats_data = [
        [Paragraph("<b>Severity</b>", body_style), Paragraph("<b>Count</b>", body_style), Paragraph("<b>Threat Type</b>", body_style), Paragraph("<b>Count</b>", body_style)],
        [Paragraph("Critical", body_style), Paragraph(str(sevs.get('Critical', 0)), body_style), Paragraph("Normal Traffic", body_style), Paragraph(str(types.get('Normal', 0)), body_style)],
        [Paragraph("High", body_style), Paragraph(str(sevs.get('High', 0)), body_style), Paragraph("DDoS", body_style), Paragraph(str(types.get('DDoS', 0)), body_style)],
        [Paragraph("Medium", body_style), Paragraph(str(sevs.get('Medium', 0)), body_style), Paragraph("Port Scan", body_style), Paragraph(str(types.get('Port Scan', 0)), body_style)],
        [Paragraph("Low", body_style), Paragraph(str(sevs.get('Low', 0)), body_style), Paragraph("Brute Force", body_style), Paragraph(str(types.get('Brute Force', 0)), body_style)],
        [Paragraph("", body_style), Paragraph("", body_style), Paragraph("Zero-Day Anomaly", body_style), Paragraph(str(types.get('Zero-Day Anomaly', 0) + types.get('Anomaly', 0)), body_style)]
    ]
    
    stats_table = Table(stats_data, colWidths=[120, 80, 200, 100])
    stats_table.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('BACKGROUND', (0,0), (1,0), LIGHT_GRAY),
        ('BACKGROUND', (2,0), (3,0), LIGHT_GRAY),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
    ]))
    
    story.append(stats_table)
    story.append(Spacer(1, 30))
    
    # Add severity chart
    chart_flowable = draw_severity_chart(stats)
    story.append(KeepTogether([
        Paragraph("<b>Visual Severity Distribution Chart</b>", ParagraphStyle('Sub', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=11, spaceAfter=8)),
        chart_flowable
    ]))
    
    story.append(PageBreak())
    
    # ================= PAGE 4: TOP ALERTS TABLE =================
    story.append(Spacer(1, 20))
    story.append(Paragraph("High-Priority Threat Alerts Detail", section_heading))
    story.append(Paragraph("The table below documents the top anomalous flows sorted by anomaly index. Normal traffic and low severity flows have been filtered out for readability.", body_style))
    story.append(Spacer(1, 10))
    
    # Filter alerts that are not normal
    priority_alerts = [a for a in alerts if a['attack_type'] != 'Normal'][:15] # Top 15 threats
    
    if not priority_alerts:
        story.append(Paragraph("<i>No suspicious threat alerts detected in this session. All parsed traffic falls within baseline normal parameters.</i>", body_style))
    else:
        # Table headers
        table_content = [[
            Paragraph("Source Endpoint", header_style),
            Paragraph("Destination Endpoint", header_style),
            Paragraph("Proto", header_style),
            Paragraph("Threat Type", header_style),
            Paragraph("Severity", header_style),
            Paragraph("Anomaly Score", header_style)
        ]]
        
        # Populate rows
        for i, a in enumerate(priority_alerts):
            proto_str = "TCP" if a['protocol'] == 6 else ("UDP" if a['protocol'] == 17 else f"P{a['protocol']}")
            
            # Highlight Critical/High in bold/red
            sev_text = f"<b>{a['severity']}</b>"
            if a['severity'] == "Critical":
                sev_color_style = ParagraphStyle('sc', parent=cell_style, textColor=COLOR_CRITICAL, fontName="Helvetica-Bold")
            elif a['severity'] == "High":
                sev_color_style = ParagraphStyle('sh', parent=cell_style, textColor=COLOR_HIGH, fontName="Helvetica-Bold")
            else:
                sev_color_style = cell_style
                
            table_content.append([
                Paragraph(f"{a['src_ip']}:{a['src_port']}", cell_style),
                Paragraph(f"{a['dst_ip']}:{a['dst_port']}", cell_style),
                Paragraph(proto_str, cell_style),
                Paragraph(a['attack_type'], cell_style),
                Paragraph(a['severity'], sev_color_style),
                Paragraph(f"{a['anomaly_score']:.3f}", cell_style)
            ])
            
        alerts_table = Table(table_content, colWidths=[130, 130, 40, 90, 60, 50])
        
        # Styling table
        table_style = TableStyle([
            ('BACKGROUND', (0,0), (-1,0), NAVY),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('GRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ])
        
        # Add alternating row background colors
        for idx in range(1, len(table_content)):
            if idx % 2 == 0:
                table_style.add('BACKGROUND', (0, idx), (-1, idx), LIGHT_GRAY)
                
        alerts_table.setStyle(table_style)
        story.append(alerts_table)
        
    story.append(PageBreak())
    
    # ================= PAGE 5: MITRE ATT&CK & RECOMMENDATIONS =================
    story.append(Spacer(1, 20))
    story.append(Paragraph("MITRE ATT&CK Mappings & Recommendations", section_heading))
    story.append(Paragraph("Detected threats have been mapped to the MITRE ATT&CK framework. Below are specific technical explanations and incident response actions recommended for each threat class.", body_style))
    story.append(Spacer(1, 10))
    
    # Gather unique attack types in this session (excluding Normal)
    unique_attacks = list(set([a['attack_type'] for a in alerts if a['attack_type'] != 'Normal']))
    
    if not unique_attacks:
        story.append(Paragraph("No active remediation plans required. The system remains in standard baseline operation mode.", body_style))
    else:
        for attack in unique_attacks:
            mitre_info = map_threat_to_mitre(attack)
            
            story.append(Paragraph(f"<b>Threat Type: {attack} ({mitre_info.get('mitre_id', 'N/A')})</b>", ParagraphStyle('a_title', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=12, textColor=NAVY, spaceAfter=5)))
            story.append(Paragraph(f"<b>MITRE Technique:</b> {mitre_info.get('technique', 'N/A')}  |  <b>Tactic:</b> {mitre_info.get('tactic', 'N/A')}", ParagraphStyle('a_meta', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=9, textColor=MUTED_TEXT, spaceAfter=5)))
            story.append(Paragraph(f"<b>Description:</b> {mitre_info.get('description', 'N/A')}", ParagraphStyle('a_desc', parent=styles['Normal'], fontName='Helvetica', fontSize=9, leading=12, spaceAfter=8)))
            
            # Mitigations list
            story.append(Paragraph("<b>Recommended Tactical Mitigations:</b>", ParagraphStyle('mit_title', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=9, spaceAfter=4)))
            for mit in mitre_info.get('mitigations', []):
                story.append(Paragraph(f"• {mit}", ParagraphStyle('mit_bullet', parent=styles['Normal'], fontName='Helvetica', fontSize=8.5, leading=11, leftIndent=15, spaceAfter=3)))
            
            story.append(Spacer(1, 15))
            
    # Build Document
    doc.build(story, onFirstPage=draw_header_footer, onLaterPages=draw_header_footer)
    print(f"[+] PDF Report successfully generated at: {output_path}")
