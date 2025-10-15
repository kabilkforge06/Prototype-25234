"""
Report Export Service
Generates professional reports in multiple formats (PDF, HTML, JSON, CSV)
"""

import os
import json
import csv
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from io import StringIO, BytesIO
import base64

# PDF generation
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import Color, black, red, orange, yellow, green
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.platypus import Image as RLImage
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# HTML/Template rendering
from jinja2 import Template

from app.models.report import VulnerabilityReport, EnhancedVulnerability, AttackPath
from app.services.report_service import vulnerability_report_service

logger = logging.getLogger(__name__)

class ReportExportService:
    """Service for exporting vulnerability reports in various formats"""
    
    def __init__(self):
        self.output_dir = os.path.join(os.getcwd(), 'reports', 'exports')
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Color scheme for severity levels
        self.severity_colors = {
            'Critical': Color(0.8, 0.1, 0.1),  # Red
            'High': Color(1.0, 0.4, 0.0),      # Orange
            'Medium': Color(1.0, 0.8, 0.0),    # Yellow
            'Low': Color(0.4, 0.7, 0.4),       # Green
            'Info': Color(0.6, 0.6, 0.6)       # Gray
        }
    
    async def export_report(self, report_id: str, export_format: str, 
                          include_attachments: bool = True) -> Tuple[str, str]:
        """Export report in specified format"""
        logger.info(f"Exporting report {report_id} in {export_format} format")
        
        # Get report data
        report = await vulnerability_report_service.get_report(report_id)
        if not report:
            raise ValueError(f"Report {report_id} not found")
        
        vulnerabilities = await vulnerability_report_service.get_report_vulnerabilities(report_id)
        attack_paths = await vulnerability_report_service.get_report_attack_paths(report_id)
        
        # Generate filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_name = "".join(c for c in report.report_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
        filename = f"{safe_name}_{timestamp}.{export_format.lower()}"
        filepath = os.path.join(self.output_dir, filename)
        
        # Export based on format
        if export_format.lower() == 'pdf':
            content_type = 'application/pdf'
            await self._export_pdf(report, vulnerabilities, attack_paths, filepath)
        elif export_format.lower() == 'html':
            content_type = 'text/html'
            await self._export_html(report, vulnerabilities, attack_paths, filepath)
        elif export_format.lower() == 'json':
            content_type = 'application/json'
            await self._export_json(report, vulnerabilities, attack_paths, filepath)
        elif export_format.lower() == 'csv':
            content_type = 'text/csv'
            await self._export_csv(report, vulnerabilities, attack_paths, filepath)
        else:
            raise ValueError(f"Unsupported export format: {export_format}")
        
        logger.info(f"Report exported to {filepath}")
        return filepath, content_type
    
    async def _export_pdf(self, report: VulnerabilityReport, vulnerabilities: List[EnhancedVulnerability],
                         attack_paths: List[AttackPath], filepath: str):
        """Export report as PDF"""
        if not PDF_AVAILABLE:
            raise RuntimeError("PDF export not available. Install reportlab: pip install reportlab")
        
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1  # Center
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=20
        )
        
        # Title Page
        story.append(Paragraph("VULNERABILITY ASSESSMENT REPORT", title_style))
        story.append(Spacer(1, 20))
        story.append(Paragraph(f"<b>Report Name:</b> {report.report_name}", styles['Normal']))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%B %d, %Y at %I:%M %p')}", styles['Normal']))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"<b>Assessment Period:</b> {report.scan_start_time.strftime('%B %d, %Y')} - {report.scan_end_time.strftime('%B %d, %Y')}", styles['Normal']))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"<b>Risk Level:</b> {report.risk_level}", styles['Normal']))
        story.append(PageBreak())
        
        # Executive Summary
        if report.executive_summary:
            story.append(Paragraph("Executive Summary", heading_style))
            # Convert markdown-like formatting to HTML
            summary_html = self._markdown_to_html(report.executive_summary)
            story.append(Paragraph(summary_html, styles['Normal']))
            story.append(PageBreak())
        
        # Vulnerability Statistics
        story.append(Paragraph("Vulnerability Overview", heading_style))
        
        stats_data = [
            ['Severity Level', 'Count', 'Percentage'],
            ['Critical', str(report.critical_count), f"{(report.critical_count/report.total_vulnerabilities*100):.1f}%" if report.total_vulnerabilities > 0 else "0%"],
            ['High', str(report.high_count), f"{(report.high_count/report.total_vulnerabilities*100):.1f}%" if report.total_vulnerabilities > 0 else "0%"],
            ['Medium', str(report.medium_count), f"{(report.medium_count/report.total_vulnerabilities*100):.1f}%" if report.total_vulnerabilities > 0 else "0%"],
            ['Low', str(report.low_count), f"{(report.low_count/report.total_vulnerabilities*100):.1f}%" if report.total_vulnerabilities > 0 else "0%"],
            ['Total', str(report.total_vulnerabilities), '100%']
        ]
        
        stats_table = Table(stats_data)
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(stats_table)
        story.append(PageBreak())
        
        # Detailed Vulnerabilities
        story.append(Paragraph("Detailed Vulnerability Findings", heading_style))
        
        # Group vulnerabilities by severity
        vuln_by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
        for vuln in vulnerabilities:
            if vuln.severity in vuln_by_severity:
                vuln_by_severity[vuln.severity].append(vuln)
        
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            if vuln_by_severity[severity]:
                story.append(Paragraph(f"{severity} Severity Vulnerabilities", styles['Heading3']))
                
                for vuln in vuln_by_severity[severity]:
                    story.append(self._create_vulnerability_section(vuln, styles))
                    story.append(Spacer(1, 20))
        
        # Attack Paths
        if attack_paths:
            story.append(PageBreak())
            story.append(Paragraph("Attack Path Analysis", heading_style))
            
            for i, path in enumerate(attack_paths[:5], 1):  # Top 5 attack paths
                story.append(Paragraph(f"Attack Path {i}: {path.path_name}", styles['Heading3']))
                story.append(Paragraph(f"<b>Type:</b> {path.path_type.replace('_', ' ').title()}", styles['Normal']))
                story.append(Paragraph(f"<b>Risk Score:</b> {path.risk_score:.1f}/10", styles['Normal']))
                story.append(Paragraph(f"<b>Likelihood:</b> {path.likelihood}", styles['Normal']))
                story.append(Paragraph(f"<b>Impact:</b> {path.impact}", styles['Normal']))
                
                if path.attack_steps:
                    story.append(Paragraph("<b>Attack Steps:</b>", styles['Normal']))
                    for j, step in enumerate(path.attack_steps[:3], 1):  # Show first 3 steps
                        story.append(Paragraph(f"{j}. {step.get('title', 'Unknown Step')}", styles['Normal']))
                
                story.append(Spacer(1, 15))
        
        # Build PDF
        doc.build(story)
    
    def _create_vulnerability_section(self, vuln: EnhancedVulnerability, styles) -> List:
        """Create a vulnerability section for PDF"""
        section = []
        
        # Vulnerability title with severity color
        title_text = f"<b>{vuln.title}</b>"
        section.append(Paragraph(title_text, styles['Heading4']))
        
        # Basic information
        info_text = f"<b>Host:</b> {vuln.target_host}"
        if vuln.target_port:
            info_text += f":{vuln.target_port}"
        if vuln.service_name:
            info_text += f" ({vuln.service_name})"
        section.append(Paragraph(info_text, styles['Normal']))
        
        # CVE information
        if vuln.cve_ids:
            cve_text = f"<b>CVE IDs:</b> {', '.join(vuln.cve_ids)}"
            section.append(Paragraph(cve_text, styles['Normal']))
        
        # CVSS Score
        if vuln.cvss_v3_score:
            cvss_text = f"<b>CVSS v3 Score:</b> {vuln.cvss_v3_score}/10.0"
            section.append(Paragraph(cvss_text, styles['Normal']))
        
        # Description
        if vuln.description:
            section.append(Paragraph(f"<b>Description:</b> {vuln.description}", styles['Normal']))
        
        # Remediation
        if vuln.remediation_steps:
            section.append(Paragraph(f"<b>Remediation:</b> {vuln.remediation_steps}", styles['Normal']))
        
        return section
    
    async def _export_html(self, report: VulnerabilityReport, vulnerabilities: List[EnhancedVulnerability],
                          attack_paths: List[AttackPath], filepath: str):
        """Export report as HTML"""
        
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ report.report_name }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 3px solid #2c3e50; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { color: #2c3e50; margin: 0; font-size: 2.5em; }
        .header .subtitle { color: #7f8c8d; font-size: 1.2em; margin-top: 10px; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        .section h3 { color: #34495e; margin-top: 25px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-card h3 { margin: 0 0 10px 0; }
        .stat-card .number { font-size: 2em; font-weight: bold; }
        .vulnerability { border: 1px solid #bdc3c7; border-radius: 8px; margin-bottom: 20px; overflow: hidden; }
        .vuln-header { padding: 15px; font-weight: bold; }
        .vuln-content { padding: 15px; background-color: #f8f9fa; }
        .severity-critical { background-color: #e74c3c; color: white; }
        .severity-high { background-color: #e67e22; color: white; }
        .severity-medium { background-color: #f39c12; color: white; }
        .severity-low { background-color: #27ae60; color: white; }
        .cve-badge { display: inline-block; background-color: #3498db; color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; margin: 2px; }
        .attack-path { border: 1px solid #9b59b6; border-radius: 8px; margin-bottom: 15px; }
        .attack-path-header { background-color: #9b59b6; color: white; padding: 10px; font-weight: bold; }
        .attack-path-content { padding: 15px; }
        .risk-score { font-size: 1.2em; font-weight: bold; }
        .risk-critical { color: #e74c3c; }
        .risk-high { color: #e67e22; }
        .risk-medium { color: #f39c12; }
        .risk-low { color: #27ae60; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #bdc3c7; color: #7f8c8d; }
        .toc { background-color: #ecf0f1; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
        .toc ul { list-style-type: none; padding-left: 0; }
        .toc li { margin: 5px 0; }
        .toc a { text-decoration: none; color: #2c3e50; }
        .toc a:hover { color: #3498db; }
        .metadata { background-color: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .metadata-item { margin-bottom: 8px; }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>{{ report.report_name }}</h1>
            <div class="subtitle">Vulnerability Assessment Report</div>
        </div>

        <!-- Metadata -->
        <div class="metadata">
            <div class="metadata-item"><strong>Report Generated:</strong> {{ current_time }}</div>
            <div class="metadata-item"><strong>Assessment Period:</strong> {{ report.scan_start_time.strftime('%B %d, %Y') }} - {{ report.scan_end_time.strftime('%B %d, %Y') }}</div>
            <div class="metadata-item"><strong>Scan Duration:</strong> {{ scan_duration }}</div>
            <div class="metadata-item"><strong>Tools Used:</strong> {{ ', '.join(report.tools_used) if report.tools_used else 'N/A' }}</div>
            <div class="metadata-item"><strong>Overall Risk Level:</strong> 
                <span class="risk-score risk-{{ report.risk_level.lower() }}">{{ report.risk_level }}</span>
                ({{ "%.1f"|format(report.overall_risk_score) }}/10.0)
            </div>
        </div>

        <!-- Table of Contents -->
        <div class="toc">
            <h3>Table of Contents</h3>
            <ul>
                <li><a href="#executive-summary">Executive Summary</a></li>
                <li><a href="#vulnerability-overview">Vulnerability Overview</a></li>
                <li><a href="#detailed-findings">Detailed Findings</a></li>
                {% if attack_paths %}
                <li><a href="#attack-paths">Attack Path Analysis</a></li>
                {% endif %}
                <li><a href="#recommendations">Recommendations</a></li>
            </ul>
        </div>

        <!-- Executive Summary -->
        {% if report.executive_summary %}
        <div class="section" id="executive-summary">
            <h2>Executive Summary</h2>
            <div>{{ report.executive_summary | markdown_to_html | safe }}</div>
        </div>
        {% endif %}

        <!-- Vulnerability Overview -->
        <div class="section" id="vulnerability-overview">
            <h2>Vulnerability Overview</h2>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>Total Vulnerabilities</h3>
                    <div class="number">{{ report.total_vulnerabilities }}</div>
                </div>
                <div class="stat-card">
                    <h3>Critical</h3>
                    <div class="number">{{ report.critical_count }}</div>
                </div>
                <div class="stat-card">
                    <h3>High</h3>
                    <div class="number">{{ report.high_count }}</div>
                </div>
                <div class="stat-card">
                    <h3>Medium</h3>
                    <div class="number">{{ report.medium_count }}</div>
                </div>
                <div class="stat-card">
                    <h3>Low</h3>
                    <div class="number">{{ report.low_count }}</div>
                </div>
            </div>
        </div>

        <!-- Detailed Findings -->
        <div class="section" id="detailed-findings">
            <h2>Detailed Vulnerability Findings</h2>
            
            {% for severity in ['Critical', 'High', 'Medium', 'Low'] %}
                {% set sevvulns = vulnerabilities | selectattr('severity', 'equalto', severity) | list %}
                {% if sevvulns %}
                <h3>{{ severity }} Severity ({{ sevvulns | length }})</h3>
                {% for vuln in sevvulns %}
                <div class="vulnerability">
                    <div class="vuln-header severity-{{ severity.lower() }}">
                        {{ vuln.title }}
                        {% if vuln.cvss_v3_score %}
                        <span style="float: right;">CVSS: {{ "%.1f"|format(vuln.cvss_v3_score) }}</span>
                        {% endif %}
                    </div>
                    <div class="vuln-content">
                        <p><strong>Target:</strong> {{ vuln.target_host }}{% if vuln.target_port %}:{{ vuln.target_port }}{% endif %}{% if vuln.service_name %} ({{ vuln.service_name }}){% endif %}</p>
                        
                        {% if vuln.cve_ids %}
                        <p><strong>CVE IDs:</strong> 
                            {% for cve in vuln.cve_ids %}
                            <span class="cve-badge">{{ cve }}</span>
                            {% endfor %}
                        </p>
                        {% endif %}
                        
                        {% if vuln.description %}
                        <p><strong>Description:</strong> {{ vuln.description }}</p>
                        {% endif %}
                        
                        {% if vuln.exploit_available %}
                        <p><strong>Exploit Available:</strong> <span style="color: #e74c3c;">Yes ({{ vuln.exploitability }} exploitability)</span></p>
                        {% endif %}
                        
                        {% if vuln.remediation_steps %}
                        <p><strong>Remediation:</strong> {{ vuln.remediation_steps }}</p>
                        {% elif vuln.patch_available %}
                        <p><strong>Remediation:</strong> Security patch available</p>
                        {% endif %}
                    </div>
                </div>
                {% endfor %}
                {% endif %}
            {% endfor %}
        </div>

        <!-- Attack Paths -->
        {% if attack_paths %}
        <div class="section" id="attack-paths">
            <h2>Attack Path Analysis</h2>
            <p>The following attack paths represent possible exploitation scenarios based on identified vulnerabilities:</p>
            
            {% for path in attack_paths %}
            <div class="attack-path">
                <div class="attack-path-header">
                    Attack Path: {{ path.path_name }}
                    <span style="float: right;">Risk: {{ "%.1f"|format(path.risk_score) }}/10</span>
                </div>
                <div class="attack-path-content">
                    <p><strong>Type:</strong> {{ path.path_type.replace('_', ' ').title() }}</p>
                    <p><strong>Likelihood:</strong> {{ path.likelihood }} | <strong>Impact:</strong> {{ path.impact }}</p>
                    
                    {% if path.entry_points %}
                    <p><strong>Entry Points:</strong> {{ ', '.join(path.entry_points) }}</p>
                    {% endif %}
                    
                    {% if path.target_assets %}
                    <p><strong>Target Assets:</strong> {{ ', '.join(path.target_assets) }}</p>
                    {% endif %}
                    
                    {% if path.attack_steps %}
                    <p><strong>Attack Steps:</strong></p>
                    <ol>
                        {% for step in path.attack_steps[:5] %}
                        <li>{{ step.get('title', 'Unknown Step') }}</li>
                        {% endfor %}
                    </ol>
                    {% endif %}
                    
                    {% if path.mitigation_strategies %}
                    <p><strong>Mitigation Strategies:</strong></p>
                    <ul>
                        {% for strategy in path.mitigation_strategies[:3] %}
                        <li>{{ strategy }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </div>
        {% endif %}

        <!-- Recommendations -->
        <div class="section" id="recommendations">
            <h2>Recommendations</h2>
            <h3>Immediate Actions (0-30 days)</h3>
            <ul>
                <li>Address all Critical severity vulnerabilities immediately</li>
                <li>Implement network segmentation to limit attack surface</li>
                <li>Deploy monitoring for exploit attempts on high-risk vulnerabilities</li>
                <li>Conduct emergency patching for systems with known active exploits</li>
            </ul>
            
            <h3>Short-term Actions (1-3 months)</h3>
            <ul>
                <li>Remediate all High severity vulnerabilities</li>
                <li>Implement vulnerability management program</li>
                <li>Deploy intrusion detection and prevention systems</li>
                <li>Conduct security awareness training for staff</li>
            </ul>
            
            <h3>Long-term Actions (3-6 months)</h3>
            <ul>
                <li>Address Medium and Low severity vulnerabilities</li>
                <li>Implement continuous security monitoring</li>
                <li>Establish regular penetration testing schedule</li>
                <li>Deploy security orchestration and automated response (SOAR)</li>
            </ul>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>This report was generated automatically by the Centralized Vulnerability Detection System.</p>
            <p>Report generated on {{ current_time }}</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Render template
        template = Template(html_template)
        
        # Calculate scan duration
        scan_duration = "Unknown"
        if report.scan_duration:
            hours = report.scan_duration // 3600
            minutes = (report.scan_duration % 3600) // 60
            if hours > 0:
                scan_duration = f"{hours}h {minutes}m"
            else:
                scan_duration = f"{minutes}m"
        
        html_content = template.render(
            report=report,
            vulnerabilities=vulnerabilities,
            attack_paths=attack_paths,
            current_time=datetime.now().strftime('%B %d, %Y at %I:%M %p'),
            scan_duration=scan_duration,
            markdown_to_html=self._markdown_to_html
        )
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    async def _export_json(self, report: VulnerabilityReport, vulnerabilities: List[EnhancedVulnerability],
                          attack_paths: List[AttackPath], filepath: str):
        """Export report as JSON"""
        
        report_data = {
            'report': report.to_dict(),
            'vulnerabilities': [vuln.to_dict() for vuln in vulnerabilities],
            'attack_paths': [path.to_dict() for path in attack_paths],
            'export_metadata': {
                'export_time': datetime.now().isoformat(),
                'export_version': '1.0',
                'total_vulnerabilities': len(vulnerabilities),
                'total_attack_paths': len(attack_paths)
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
    
    async def _export_csv(self, report: VulnerabilityReport, vulnerabilities: List[EnhancedVulnerability],
                         attack_paths: List[AttackPath], filepath: str):
        """Export report as CSV"""
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'ID', 'Title', 'Severity', 'CVSS_Score', 'Target_Host', 'Target_Port',
                'Service_Name', 'CVE_IDs', 'Description', 'Attack_Vector', 'Attack_Complexity',
                'Privileges_Required', 'User_Interaction', 'Exploit_Available', 'Patch_Available',
                'First_Detected', 'Status'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for vuln in vulnerabilities:
                writer.writerow({
                    'ID': vuln.id,
                    'Title': vuln.title,
                    'Severity': vuln.severity,
                    'CVSS_Score': vuln.cvss_v3_score or '',
                    'Target_Host': vuln.target_host,
                    'Target_Port': vuln.target_port or '',
                    'Service_Name': vuln.service_name or '',
                    'CVE_IDs': ', '.join(vuln.cve_ids) if vuln.cve_ids else '',
                    'Description': vuln.description or '',
                    'Attack_Vector': vuln.attack_vector or '',
                    'Attack_Complexity': vuln.attack_complexity or '',
                    'Privileges_Required': vuln.privileges_required or '',
                    'User_Interaction': vuln.user_interaction or '',
                    'Exploit_Available': 'Yes' if vuln.exploit_available else 'No',
                    'Patch_Available': 'Yes' if vuln.patch_available else 'No',
                    'First_Detected': vuln.first_detected.isoformat() if vuln.first_detected else '',
                    'Status': vuln.status
                })
    
    def _markdown_to_html(self, text: str) -> str:
        """Convert simple markdown to HTML"""
        if not text:
            return ""
        
        # Split text into lines for proper processing
        lines = text.split('\n')
        html_lines = []
        in_paragraph = False
        
        for line in lines:
            line = line.strip()
            
            # Skip empty lines
            if not line:
                if in_paragraph:
                    html_lines.append('</p>')
                    in_paragraph = False
                continue
            
            # Handle headers
            if line.startswith('### '):
                if in_paragraph:
                    html_lines.append('</p>')
                    in_paragraph = False
                html_lines.append(f'<h4>{line[4:]}</h4>')
            elif line.startswith('## '):
                if in_paragraph:
                    html_lines.append('</p>')
                    in_paragraph = False
                html_lines.append(f'<h3>{line[3:]}</h3>')
            elif line.startswith('# '):
                if in_paragraph:
                    html_lines.append('</p>')
                    in_paragraph = False
                html_lines.append(f'<h2>{line[2:]}</h2>')
            else:
                # Handle regular text and bold formatting
                line = line.replace('**', '<strong>').replace('**', '</strong>')
                
                # Start paragraph if needed
                if not in_paragraph:
                    html_lines.append('<p>')
                    in_paragraph = True
                else:
                    html_lines.append('<br />')
                
                html_lines.append(line)
        
        # Close any open paragraph
        if in_paragraph:
            html_lines.append('</p>')
        
        return ''.join(html_lines)
    
    async def get_available_reports(self) -> List[Dict[str, Any]]:
        """Get list of available exported reports"""
        reports = []
        
        if not os.path.exists(self.output_dir):
            return reports
        
        for filename in os.listdir(self.output_dir):
            filepath = os.path.join(self.output_dir, filename)
            if os.path.isfile(filepath):
                stat = os.stat(filepath)
                reports.append({
                    'filename': filename,
                    'filepath': filepath,
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
        
        return sorted(reports, key=lambda x: x['modified'], reverse=True)

# Singleton instance
report_export_service = ReportExportService()