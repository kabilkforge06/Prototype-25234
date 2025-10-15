"""
Report Routes
API endpoints for vulnerability report generation, management, and export
"""

import asyncio
import logging
from flask import Blueprint, request, jsonify, send_file, abort
from datetime import datetime
import os
from typing import Dict, Any, List

from app.services.report_service import vulnerability_report_service, ReportConfiguration
from app.services.report_export import report_export_service
from app.models.report import VulnerabilityReport, EnhancedVulnerability, AttackPath

logger = logging.getLogger(__name__)

report_bp = Blueprint('reports', __name__, url_prefix='/api/reports')

@report_bp.route('/generate', methods=['POST'])
def generate_report():
    """Generate a comprehensive vulnerability report"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Extract scan results and target info
        scan_results = data.get('scan_results', [])
        target_info = data.get('target_info', {})
        
        if not scan_results:
            return jsonify({'error': 'No scan results provided'}), 400
        
        # Parse report configuration
        config_data = data.get('config', {})
        config = ReportConfiguration(
            include_executive_summary=config_data.get('include_executive_summary', True),
            include_technical_details=config_data.get('include_technical_details', True),
            include_attack_paths=config_data.get('include_attack_paths', True),
            include_threat_intelligence=config_data.get('include_threat_intelligence', True),
            include_remediation=config_data.get('include_remediation', True),
            include_appendices=config_data.get('include_appendices', True),
            export_formats=config_data.get('export_formats', ['html', 'pdf']),
            severity_filter=config_data.get('severity_filter', ['Critical', 'High', 'Medium', 'Low'])
        )
        
        # Start report generation asynchronously
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            report_id = loop.run_until_complete(
                vulnerability_report_service.generate_comprehensive_report(
                    scan_results, target_info, config
                )
            )
            
            return jsonify({
                'success': True,
                'report_id': report_id,
                'message': 'Report generation completed successfully'
            })
            
        finally:
            loop.close()
        
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return jsonify({'error': f'Failed to generate report: {str(e)}'}), 500

@report_bp.route('/status/<report_id>', methods=['GET'])
def get_report_status(report_id):
    """Get report generation status"""
    try:
        status = vulnerability_report_service.get_report_status(report_id)
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Error getting report status: {e}")
        return jsonify({'error': str(e)}), 500

@report_bp.route('/<report_id>', methods=['GET'])
def get_report(report_id):
    """Get report details"""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            report = loop.run_until_complete(vulnerability_report_service.get_report(report_id))
            
            if not report:
                return jsonify({'error': 'Report not found'}), 404
            
            return jsonify({
                'success': True,
                'report': report.to_dict()
            })
            
        finally:
            loop.close()
        
    except Exception as e:
        logger.error(f"Error getting report: {e}")
        return jsonify({'error': str(e)}), 500

@report_bp.route('/<report_id>/vulnerabilities', methods=['GET'])
def get_report_vulnerabilities(report_id):
    """Get vulnerabilities for a report"""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            vulnerabilities = loop.run_until_complete(
                vulnerability_report_service.get_report_vulnerabilities(report_id)
            )
            
            # Apply filters
            severity_filter = request.args.getlist('severity')
            if severity_filter:
                vulnerabilities = [v for v in vulnerabilities if v.severity in severity_filter]
            
            # Apply pagination
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 50))
            start_idx = (page - 1) * per_page
            end_idx = start_idx + per_page
            
            paginated_vulns = vulnerabilities[start_idx:end_idx]
            
            return jsonify({
                'success': True,
                'vulnerabilities': [v.to_dict() for v in paginated_vulns],
                'total': len(vulnerabilities),
                'page': page,
                'per_page': per_page,
                'pages': (len(vulnerabilities) + per_page - 1) // per_page
            })
            
        finally:
            loop.close()
        
    except Exception as e:
        logger.error(f"Error getting report vulnerabilities: {e}")
        return jsonify({'error': str(e)}), 500

@report_bp.route('/<report_id>/attack-paths', methods=['GET'])
def get_report_attack_paths(report_id):
    """Get attack paths for a report"""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            attack_paths = loop.run_until_complete(
                vulnerability_report_service.get_report_attack_paths(report_id)
            )
            
            return jsonify({
                'success': True,
                'attack_paths': [ap.to_dict() for ap in attack_paths]
            })
            
        finally:
            loop.close()
        
    except Exception as e:
        logger.error(f"Error getting attack paths: {e}")
        return jsonify({'error': str(e)}), 500

@report_bp.route('/<report_id>/export/<export_format>', methods=['POST'])
def export_report(report_id, export_format):
    """Export report in specified format"""
    try:
        if export_format.lower() not in ['pdf', 'html', 'json', 'csv']:
            return jsonify({'error': 'Unsupported export format'}), 400
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            filepath, content_type = loop.run_until_complete(
                report_export_service.export_report(report_id, export_format)
            )
            
            if not os.path.exists(filepath):
                return jsonify({'error': 'Export file not found'}), 404
            
            return send_file(
                filepath,
                as_attachment=True,
                download_name=os.path.basename(filepath),
                mimetype=content_type
            )
            
        finally:
            loop.close()
        
    except Exception as e:
        logger.error(f"Error exporting report: {e}")
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

@report_bp.route('/list', methods=['GET'])
def list_reports():
    """List all available reports"""
    try:
        # Get reports from database
        reports = VulnerabilityReport.query.order_by(VulnerabilityReport.created_at.desc()).all()
        
        report_list = []
        for report in reports:
            report_dict = report.to_dict()
            
            # Add summary statistics
            report_dict['summary'] = {
                'total_vulnerabilities': report.total_vulnerabilities,
                'critical_count': report.critical_count,
                'high_count': report.high_count,
                'medium_count': report.medium_count,
                'low_count': report.low_count,
                'risk_level': report.risk_level,
                'risk_score': report.overall_risk_score
            }
            
            report_list.append(report_dict)
        
        return jsonify({
            'success': True,
            'reports': report_list,
            'total': len(report_list)
        })
        
    except Exception as e:
        logger.error(f"Error listing reports: {e}")
        return jsonify({'error': str(e)}), 500

@report_bp.route('/exported', methods=['GET'])
def list_exported_reports():
    """List all exported report files"""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            exported_reports = loop.run_until_complete(
                report_export_service.get_available_reports()
            )
            
            return jsonify({
                'success': True,
                'exported_reports': exported_reports,
                'total': len(exported_reports)
            })
            
        finally:
            loop.close()
        
    except Exception as e:
        logger.error(f"Error listing exported reports: {e}")
        return jsonify({'error': str(e)}), 500

@report_bp.route('/download/<filename>', methods=['GET'])
def download_exported_report(filename):
    """Download an exported report file"""
    try:
        # Security check: ensure filename doesn't contain path traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            return jsonify({'error': 'Invalid filename'}), 400
        
        filepath = os.path.join(report_export_service.output_dir, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'File not found'}), 404
        
        # Determine content type based on extension
        content_types = {
            '.pdf': 'application/pdf',
            '.html': 'text/html',
            '.json': 'application/json',
            '.csv': 'text/csv'
        }
        
        ext = os.path.splitext(filename)[1].lower()
        content_type = content_types.get(ext, 'application/octet-stream')
        
        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename,
            mimetype=content_type
        )
        
    except Exception as e:
        logger.error(f"Error downloading report: {e}")
        return jsonify({'error': str(e)}), 500

@report_bp.route('/<report_id>/summary', methods=['GET'])
def get_report_summary(report_id):
    """Get executive summary and key metrics for a report"""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            report = loop.run_until_complete(vulnerability_report_service.get_report(report_id))
            vulnerabilities = loop.run_until_complete(
                vulnerability_report_service.get_report_vulnerabilities(report_id)
            )
            attack_paths = loop.run_until_complete(
                vulnerability_report_service.get_report_attack_paths(report_id)
            )
            
            if not report:
                return jsonify({'error': 'Report not found'}), 404
            
            # Calculate additional metrics
            exploitable_vulns = len([v for v in vulnerabilities if v.exploit_available])
            
            # Top vulnerabilities by CVSS score
            scored_vulns = [v for v in vulnerabilities if v.cvss_v3_score]
            top_vulnerabilities = sorted(scored_vulns, key=lambda x: x.cvss_v3_score, reverse=True)[:5]
            
            # Top attack paths by risk score
            top_attack_paths = sorted(attack_paths, key=lambda x: x.risk_score, reverse=True)[:3]
            
            summary = {
                'report_info': {
                    'id': report.id,
                    'name': report.report_name,
                    'status': report.status,
                    'created_at': report.created_at.isoformat() if report.created_at else None,
                    'risk_level': report.risk_level,
                    'risk_score': report.overall_risk_score
                },
                'vulnerability_statistics': {
                    'total': report.total_vulnerabilities,
                    'by_severity': {
                        'Critical': report.critical_count,
                        'High': report.high_count,
                        'Medium': report.medium_count,
                        'Low': report.low_count
                    },
                    'exploitable_count': exploitable_vulns,
                    'exploitable_percentage': (exploitable_vulns / max(report.total_vulnerabilities, 1)) * 100
                },
                'top_vulnerabilities': [
                    {
                        'title': v.title,
                        'severity': v.severity,
                        'cvss_score': v.cvss_v3_score,
                        'target_host': v.target_host,
                        'cve_ids': v.cve_ids
                    } for v in top_vulnerabilities
                ],
                'attack_path_summary': {
                    'total_paths': len(attack_paths),
                    'high_risk_paths': len([ap for ap in attack_paths if ap.risk_score >= 7.0]),
                    'top_paths': [
                        {
                            'name': ap.path_name,
                            'type': ap.path_type,
                            'risk_score': ap.risk_score,
                            'likelihood': ap.likelihood,
                            'impact': ap.impact
                        } for ap in top_attack_paths
                    ]
                },
                'recommendations': {
                    'immediate_actions': [
                        f"Address {report.critical_count} Critical vulnerabilities",
                        "Implement network monitoring for exploit attempts",
                        "Deploy emergency patches for known exploited vulnerabilities"
                    ],
                    'short_term_actions': [
                        f"Remediate {report.high_count} High severity vulnerabilities",
                        "Implement vulnerability management program",
                        "Deploy intrusion detection systems"
                    ]
                }
            }
            
            return jsonify({
                'success': True,
                'summary': summary
            })
            
        finally:
            loop.close()
        
    except Exception as e:
        logger.error(f"Error getting report summary: {e}")
        return jsonify({'error': str(e)}), 500

@report_bp.route('/<report_id>/delete', methods=['DELETE'])
def delete_report(report_id):
    """Delete a report and its associated data"""
    try:
        report = VulnerabilityReport.query.get(report_id)
        
        if not report:
            return jsonify({'error': 'Report not found'}), 404
        
        # Delete associated vulnerabilities and attack paths
        EnhancedVulnerability.query.filter_by(report_id=report_id).delete()
        AttackPath.query.filter_by(report_id=report_id).delete()
        
        # Delete the report
        from app.models.report import db
        db.session.delete(report)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Report deleted successfully'
        })
        
    except Exception as e:
        logger.error(f"Error deleting report: {e}")
        return jsonify({'error': str(e)}), 500

# Error handlers
@report_bp.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@report_bp.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500