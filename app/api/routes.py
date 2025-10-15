"""
Main API Routes
"""

from flask import Blueprint, jsonify
from app.services.scanner_service import ScannerService
from app.services.vulnerability_service import VulnerabilityService

api_bp = Blueprint('api', __name__)

@api_bp.route('/health', methods=['GET'])
def health_check():
    """API health check"""
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'message': 'Centralized Vulnerability Detection API'
    })

@api_bp.route('/stats', methods=['GET'])
def get_stats():
    """Get vulnerability statistics"""
    # This would normally query the database
    stats = {
        'total_vulnerabilities': 247,
        'critical_vulnerabilities': 12,
        'high_vulnerabilities': 45,
        'medium_vulnerabilities': 98,
        'low_vulnerabilities': 92,
        'completed_scans': 18,
        'risk_score': 7.2
    }

    return jsonify(stats)