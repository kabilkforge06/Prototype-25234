"""
Scan API Routes
"""

from flask import Blueprint, request, jsonify
from app.services.scanner_service import ScannerService
import logging

logger = logging.getLogger(__name__)
scan_bp = Blueprint('scan', __name__)

scanner_service = ScannerService()

@scan_bp.route('/start', methods=['POST'])
def start_scan():
    """Start a new vulnerability scan"""
    try:
        data = request.get_json()

        if not data or 'target' not in data:
            return jsonify({'error': 'Target is required'}), 400

        target = data['target']
        tools = data.get('tools', ['nmap'])

        # Start scan
        scan_id = scanner_service.start_scan(target, tools)

        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'target': target,
            'tools': tools
        }), 200

    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@scan_bp.route('/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status"""
    try:
        status = scanner_service.get_scan_status(scan_id)
        return jsonify(status), 200

    except Exception as e:
        logger.error(f"Error getting scan status: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@scan_bp.route('/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get scan results"""
    try:
        results = scanner_service.get_scan_results(scan_id)

        # Convert results to JSON-serializable format
        serialized_results = []
        for result in results:
            serialized_results.append({
                'tool': result.tool,
                'target': result.target,
                'vulnerabilities': result.vulnerabilities,
                'scan_time': result.scan_time.isoformat(),
                'status': result.status,
                'metadata': result.metadata
            })

        return jsonify({
            'scan_id': scan_id,
            'results': serialized_results
        }), 200

    except Exception as e:
        logger.error(f"Error getting scan results: {e}")
        return jsonify({'error': 'Internal server error'}), 500