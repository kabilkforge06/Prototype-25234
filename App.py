"""
Centralized Vulnerability Detection System - Complete Application
Main Flask Application with All Frontend and API Routes
"""

import os
import logging
import threading
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, session
from flask_cors import CORS
from dotenv import load_dotenv
import uuid
from app.services.lightweight_scanner import lightweight_vulnerability_scanner as vulnerability_scanner

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__, 
           template_folder='app/templates',
           static_folder='app/static')

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-change-in-production-vulndetector-2024')
app.config['GOOGLE_API_KEY'] = os.getenv('GOOGLE_API_KEY')
app.config['REDIS_URL'] = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Initialize CORS
CORS(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize RAG Service
rag_service = None
try:
    from app.services.rag_service import RAGService
    api_key = app.config['GOOGLE_API_KEY']
    if api_key:
        rag_service = RAGService(api_key)
        logger.info("RAG Service initialized successfully")
    else:
        logger.warning("No Google API key found - RAG service disabled")
except Exception as e:
    logger.error(f"Failed to initialize RAG service: {e}")
    rag_service = None

# Make RAG service available to the app
app.rag_service = rag_service

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///vulnerabilities.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
from app.models.report import db
db.init_app(app)

# Register API blueprints
from app.api.chat_routes import chat_bp
from app.api.report_routes import report_bp
app.register_blueprint(chat_bp, url_prefix='/api/chat')
app.register_blueprint(report_bp)

# Mock data storage (in production, this would be a database)
vulnerabilities_data = [
    {
        'id': 'vuln-001',
        'title': 'Apache HTTP Server Remote Code Execution',
        'description': 'Critical RCE vulnerability in Apache HTTP Server allowing remote attackers to execute arbitrary code.',
        'severity': 'Critical',
        'cvss_score': 9.8,
        'target_host': '192.168.1.10',
        'target_port': 80,
        'service_name': 'http',
        'cve_ids': ['CVE-2023-12345'],
        'remediation': 'Update Apache to version 2.4.58 or later',
        'status': 'Open',
        'discovered_date': '2024-10-01 10:30:00'
    },
    {
        'id': 'vuln-002',
        'title': 'SSH Weak Encryption Algorithm',
        'description': 'SSH server supports weak encryption algorithms that can be exploited.',
        'severity': 'Medium',
        'cvss_score': 5.3,
        'target_host': '192.168.1.10',
        'target_port': 22,
        'service_name': 'ssh',
        'cve_ids': ['CVE-2023-48795'],
        'remediation': 'Configure SSH to use only strong encryption algorithms',
        'status': 'In Progress',
        'discovered_date': '2024-10-01 11:45:00'
    },
    {
        'id': 'vuln-003',
        'title': 'Cross-Site Scripting (XSS) Vulnerability',
        'description': 'Reflected XSS vulnerability in web application user input field.',
        'severity': 'High',
        'cvss_score': 7.5,
        'target_host': '192.168.1.15',
        'target_port': 443,
        'service_name': 'https',
        'cve_ids': [],
        'remediation': 'Implement proper input validation and output encoding',
        'status': 'Open',
        'discovered_date': '2024-10-01 09:15:00'
    },
    {
        'id': 'vuln-004',
        'title': 'SQL Injection Vulnerability',
        'description': 'Database query vulnerability allowing unauthorized data access.',
        'severity': 'High',
        'cvss_score': 8.2,
        'target_host': '192.168.1.20',
        'target_port': 3306,
        'service_name': 'mysql',
        'cve_ids': [],
        'remediation': 'Use parameterized queries and input validation',
        'status': 'Fixed',
        'discovered_date': '2024-09-28 14:20:00'
    }
]

scans_data = [
    {
        'id': 'scan-001',
        'target': '192.168.1.0/24',
        'status': 'Completed',
        'start_time': '2024-10-01 10:00:00',
        'end_time': '2024-10-01 12:30:00',
        'vulnerabilities_found': 15,
        'tools_used': ['nmap', 'nessus'],
        'scan_type': 'Network Scan'
    },
    {
        'id': 'scan-002',
        'target': 'example.com',
        'status': 'Running',
        'start_time': '2024-10-01 11:30:00',
        'end_time': None,
        'vulnerabilities_found': 3,
        'tools_used': ['nmap'],
        'scan_type': 'Web Application Scan'
    },
    {
        'id': 'scan-003',
        'target': '10.0.0.1',
        'status': 'Completed',
        'start_time': '2024-09-30 16:45:00',
        'end_time': '2024-09-30 18:20:00',
        'vulnerabilities_found': 8,
        'tools_used': ['openvas'],
        'scan_type': 'Infrastructure Scan'
    }
]

# ================================
# MAIN ROUTES (Frontend Pages)
# ================================

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/scan')
def scan_page():
    """Vulnerability scanning page"""
    return render_template('dashboard.html')

@app.route('/chat')
def chat_page():
    """AI chatbot interface page"""
    return render_template('chat.html')

@app.route('/reports')
def reports_page():
    """Vulnerability reports page"""
    return render_template('reports.html')

# ================================
# API ROUTES - HEALTH & STATS
# ================================

@app.route('/health')
@app.route('/api/health')
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'message': 'Centralized Vulnerability Detection System',
        'timestamp': datetime.now().isoformat(),
        'services': {
            'web_server': 'running',
            'api': 'operational',
            'frontend': 'loaded'
        }
    })

@app.route('/api/stats')
def get_stats():
    """Get vulnerability statistics for dashboard"""
    # Calculate stats from mock data
    total_vulns = len(vulnerabilities_data)
    critical_vulns = len([v for v in vulnerabilities_data if v['severity'] == 'Critical'])
    high_vulns = len([v for v in vulnerabilities_data if v['severity'] == 'High'])
    medium_vulns = len([v for v in vulnerabilities_data if v['severity'] == 'Medium'])
    low_vulns = len([v for v in vulnerabilities_data if v['severity'] == 'Low'])
    completed_scans = len([s for s in scans_data if s['status'] == 'Completed'])
    
    # Calculate risk score (weighted average)
    severity_weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}
    total_weight = sum(severity_weights[v['severity']] for v in vulnerabilities_data)
    risk_score = (total_weight / total_vulns) if total_vulns > 0 else 0

    stats = {
        'total_vulnerabilities': total_vulns,
        'critical_vulnerabilities': critical_vulns,
        'high_vulnerabilities': high_vulns,
        'medium_vulnerabilities': medium_vulns,
        'low_vulnerabilities': low_vulns,
        'completed_scans': completed_scans,
        'risk_score': round(risk_score, 1),
        'last_updated': datetime.now().isoformat()
    }

    return jsonify(stats)

# ================================
# VULNERABILITY API ROUTES
# ================================

@app.route('/api/vulnerabilities')
def list_vulnerabilities():
    """List all vulnerabilities with optional filtering"""
    try:
        severity_filter = request.args.get('severity')
        status_filter = request.args.get('status')
        limit = request.args.get('limit', type=int)
        
        filtered_vulns = vulnerabilities_data.copy()
        
        if severity_filter:
            filtered_vulns = [v for v in filtered_vulns if v['severity'].lower() == severity_filter.lower()]
        
        if status_filter:
            filtered_vulns = [v for v in filtered_vulns if v['status'].lower() == status_filter.lower()]
        
        if limit:
            filtered_vulns = filtered_vulns[:limit]

        return jsonify({
            'vulnerabilities': filtered_vulns,
            'total': len(filtered_vulns),
            'total_all': len(vulnerabilities_data)
        }), 200

    except Exception as e:
        logger.error(f"Error listing vulnerabilities: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/vulnerabilities/<vuln_id>')
def get_vulnerability(vuln_id):
    """Get specific vulnerability details"""
    try:
        vulnerability = next((v for v in vulnerabilities_data if v['id'] == vuln_id), None)
        
        if not vulnerability:
            return jsonify({'error': 'Vulnerability not found'}), 404

        return jsonify(vulnerability), 200

    except Exception as e:
        logger.error(f"Error getting vulnerability {vuln_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/vulnerabilities/<vuln_id>/status', methods=['PUT'])
def update_vulnerability_status(vuln_id):
    """Update vulnerability status"""
    try:
        data = request.get_json()
        if not data or 'status' not in data:
            return jsonify({'error': 'Status is required'}), 400

        vulnerability = next((v for v in vulnerabilities_data if v['id'] == vuln_id), None)
        if not vulnerability:
            return jsonify({'error': 'Vulnerability not found'}), 404

        vulnerability['status'] = data['status']
        
        return jsonify({
            'message': 'Status updated successfully',
            'vulnerability': vulnerability
        }), 200

    except Exception as e:
        logger.error(f"Error updating vulnerability status: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# ================================
# SCAN API ROUTES
# ================================

@app.route('/api/scans')
def list_scans():
    """List all scans"""
    try:
        status_filter = request.args.get('status')
        limit = request.args.get('limit', type=int)
        
        filtered_scans = scans_data.copy()
        
        if status_filter:
            filtered_scans = [s for s in filtered_scans if s['status'].lower() == status_filter.lower()]
        
        if limit:
            filtered_scans = filtered_scans[:limit]

        return jsonify({
            'scans': filtered_scans,
            'total': len(filtered_scans)
        }), 200

    except Exception as e:
        logger.error(f"Error listing scans: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/scans/start', methods=['POST'])
def start_scan():
    """Start a new vulnerability scan"""
    try:
        data = request.get_json()

        if not data or 'target' not in data:
            return jsonify({'error': 'Target is required'}), 400

        target = data['target']
        tools = data.get('tools', ['nmap', 'shodan', 'cve', 'web'])
        scan_type = data.get('scan_type', 'Comprehensive Scan')

        # Generate scan ID
        scan_id = f"scan-{str(uuid.uuid4())[:8]}"

        # Create new scan entry
        new_scan = {
            'id': scan_id,
            'target': target,
            'status': 'Running',
            'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': None,
            'vulnerabilities_found': 0,
            'tools_used': tools,
            'scan_type': scan_type,
            'results': []
        }

        # Add to scans data
        scans_data.append(new_scan)

        # Start scan in background thread
        def run_scan():
            try:
                logger.info(f"Starting scan {scan_id} for target {target}")
                
                # Perform the actual vulnerability scan
                scan_results = vulnerability_scanner.scan_target(target, tools)
                
                # Process results and update scan data
                all_vulnerabilities = []
                for result in scan_results:
                    all_vulnerabilities.extend(result.vulnerabilities)
                    # Add result to scan data
                    for scan in scans_data:
                        if scan['id'] == scan_id:
                            scan['results'].append({
                                'tool': result.tool,
                                'status': result.status,
                                'vulnerabilities_count': len(result.vulnerabilities),
                                'metadata': result.metadata
                            })
                
                # Update scan status
                for scan in scans_data:
                    if scan['id'] == scan_id:
                        scan['status'] = 'Completed'
                        scan['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        scan['vulnerabilities_found'] = len(all_vulnerabilities)
                        
                        # Add vulnerabilities to global data
                        for vuln in all_vulnerabilities:
                            vuln['scan_id'] = scan_id
                            vuln['discovered_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            vulnerabilities_data.append(vuln)
                        
                        break
                
                logger.info(f"Scan {scan_id} completed. Found {len(all_vulnerabilities)} vulnerabilities")
                
            except Exception as e:
                logger.error(f"Error in scan {scan_id}: {str(e)}")
                # Update scan status to failed
                for scan in scans_data:
                    if scan['id'] == scan_id:
                        scan['status'] = 'Failed'
                        scan['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        break
        
        # Start scan in background
        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()

        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'target': target,
            'tools': tools,
            'message': 'Comprehensive vulnerability scan started successfully'
        }), 200

    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/scans/<scan_id>')
def get_scan_details(scan_id):
    """Get specific scan details"""
    try:
        scan = next((s for s in scans_data if s['id'] == scan_id), None)
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        return jsonify(scan), 200

    except Exception as e:
        logger.error(f"Error getting scan details: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/scans/<scan_id>/status')
def get_scan_status(scan_id):
    """Get scan status"""
    try:
        scan = next((s for s in scans_data if s['id'] == scan_id), None)
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        return jsonify({
            'scan_id': scan_id,
            'status': scan['status'],
            'progress': 85 if scan['status'] == 'Running' else 100,
            'vulnerabilities_found': scan['vulnerabilities_found']
        }), 200

    except Exception as e:
        logger.error(f"Error getting scan status: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/scans/<scan_id>/results')
def get_scan_results(scan_id):
    """Get scan results"""
    try:
        scan = next((s for s in scans_data if s['id'] == scan_id), None)
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        # Return vulnerabilities found in this scan
        scan_vulns = [v for v in vulnerabilities_data if scan['target'] in v.get('target_host', '')]

        return jsonify({
            'scan_id': scan_id,
            'scan_details': scan,
            'vulnerabilities': scan_vulns,
            'summary': {
                'total_vulnerabilities': len(scan_vulns),
                'critical': len([v for v in scan_vulns if v['severity'] == 'Critical']),
                'high': len([v for v in scan_vulns if v['severity'] == 'High']),
                'medium': len([v for v in scan_vulns if v['severity'] == 'Medium']),
                'low': len([v for v in scan_vulns if v['severity'] == 'Low'])
            }
        }), 200

    except Exception as e:
        logger.error(f"Error getting scan results: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# ================================
# CHAT/AI ASSISTANT API ROUTES
# ================================

@app.route('/api/chat/query', methods=['POST'])
def chat_query():
    """Process user query through AI assistant"""
    try:
        data = request.get_json()

        if not data or 'query' not in data:
            return jsonify({'error': 'Query is required'}), 400

        user_query = data['query'].strip()
        user_id = session.get('user_id', 'anonymous')

        # Validate query
        if not user_query:
            return jsonify({'error': 'Query cannot be empty'}), 400

        if len(user_query) > 1000:
            return jsonify({'error': 'Query too long. Maximum 1000 characters.'}), 400

        # Simple keyword-based responses for demo
        response_text = generate_ai_response(user_query)

        response = {
            'response': response_text,
            'timestamp': datetime.now().isoformat(),
            'confidence': 0.85,
            'query': user_query,
            'sources': ['Vulnerability Database', 'CVE Database', 'Security Knowledge Base']
        }

        # Store in chat history
        if 'chat_history' not in session:
            session['chat_history'] = []

        session['chat_history'].append({
            'query': user_query,
            'response': response_text,
            'timestamp': response['timestamp'],
            'confidence': response['confidence']
        })

        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Error processing chat query: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/chat/history')
def get_chat_history():
    """Get chat history for current session"""
    try:
        history = session.get('chat_history', [])
        return jsonify({
            'history': history,
            'total_queries': len(history)
        }), 200

    except Exception as e:
        logger.error(f"Error retrieving chat history: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/chat/clear', methods=['DELETE'])
def clear_chat_history():
    """Clear chat history for current session"""
    try:
        session['chat_history'] = []
        return jsonify({'message': 'Chat history cleared successfully'}), 200

    except Exception as e:
        logger.error(f"Error clearing chat history: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/chat/suggestions')
def get_query_suggestions():
    """Get suggested queries for users"""
    suggestions = [
        "What are the most critical vulnerabilities in my system?",
        "How do I fix the Apache RCE vulnerability?",
        "Show me all vulnerabilities with CVSS score above 7",
        "What are the latest scan results?",
        "Explain the SQL injection vulnerability remediation steps",
        "Which vulnerabilities should I prioritize for patching?",
        "Show me network scan statistics",
        "What MITRE ATT&CK techniques are associated with these vulnerabilities?"
    ]

    return jsonify({'suggestions': suggestions}), 200

# ================================
# GOVERNMENT DASHBOARD API ROUTES
# ================================

@app.route('/api/dashboard/stats')
def get_dashboard_stats():
    """Get executive dashboard statistics"""
    try:
        # Calculate real-time statistics
        total_vulnerabilities = len(vulnerabilities_data)
        critical_vulnerabilities = len([v for v in vulnerabilities_data if v['severity'] == 'Critical'])
        high_vulnerabilities = len([v for v in vulnerabilities_data if v['severity'] == 'High'])
        completed_scans = len([s for s in scans_data if s['status'] == 'Completed'])
        active_scans = len([s for s in scans_data if s['status'] == 'Running'])
        
        # Calculate risk score (simplified algorithm)
        risk_score = min((critical_vulnerabilities * 3 + high_vulnerabilities * 2) / 10 * 100, 100)
        
        stats = {
            'total_vulnerabilities': total_vulnerabilities,
            'critical_vulnerabilities': critical_vulnerabilities,
            'high_vulnerabilities': high_vulnerabilities,
            'active_scans': active_scans,
            'completed_scans': completed_scans,
            'system_health': '98.7%',
            'vulnerability_trend': f'+{int((total_vulnerabilities/20)*100)}% from last week',
            'critical_trend': 'Requires immediate attention' if critical_vulnerabilities > 0 else 'Under control',
            'scan_status': f'{active_scans} active monitoring sessions',
            'health_status': 'All systems operational',
            'risk_score': round(risk_score, 1)
        }
        
        return jsonify(stats), 200
    
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        return jsonify({'error': 'Failed to retrieve dashboard statistics'}), 500

@app.route('/api/threat/posture')
def get_threat_posture():
    """Get national threat posture data"""
    try:
        posture_data = {
            'national_risk_score': '4.2',
            'active_campaigns': '12',
            'protected_assets': '847',
            'avg_response_time': '2.3m',
            'threat_level': 'ELEVATED',
            'last_updated': datetime.now().isoformat(),
            'classification': 'UNCLASSIFIED//FOR OFFICIAL USE ONLY'
        }
        
        return jsonify(posture_data), 200
    
    except Exception as e:
        logger.error(f"Error getting threat posture: {e}")
        return jsonify({'error': 'Failed to retrieve threat posture'}), 500

@app.route('/api/scanners/status')
def get_scanner_status():
    """Get status of all vulnerability scanners"""
    try:
        scanner_status = {
            'nmap': {
                'status': 'OPERATIONAL',
                'last_scan': '14:28 UTC',
                'targets_scanned': 156,
                'version': '7.94'
            },
            'openvas': {
                'status': 'OPERATIONAL', 
                'last_scan': '14:20 UTC',
                'vulnerabilities_found': 23,
                'version': '22.4'
            },
            'nessus': {
                'status': 'MAINTENANCE',
                'last_scan': '12:45 UTC',
                'scheduled_maintenance': '15:00 UTC',
                'version': '10.6.4'
            },
            'nikto': {
                'status': 'OPERATIONAL',
                'last_scan': '14:15 UTC',
                'web_apps_tested': 12,
                'version': '2.5.0'
            },
            'ai_analyzer': {
                'status': 'LEARNING',
                'confidence_level': '94%',
                'threats_analyzed': 1247,
                'model_version': 'v2.1'
            }
        }
        
        return jsonify(scanner_status), 200
    
    except Exception as e:
        logger.error(f"Error getting scanner status: {e}")
        return jsonify({'error': 'Failed to retrieve scanner status'}), 500

@app.route('/api/targets/priority')
def get_priority_targets():
    """Get priority targets for monitoring"""
    try:
        priority_targets = [
            {
                'id': 'target-001',
                'name': 'Critical Infrastructure Grid',
                'sector': 'Power & Utilities',
                'risk_level': 'CRITICAL',
                'last_scanned': '2 hours ago',
                'vulnerabilities': 15,
                'status': 'MONITORED'
            },
            {
                'id': 'target-002', 
                'name': 'Banking Network Core',
                'sector': 'Financial Services',
                'risk_level': 'HIGH',
                'last_scanned': '6 hours ago',
                'vulnerabilities': 8,
                'status': 'MONITORED'
            },
            {
                'id': 'target-003',
                'name': 'Government Portal',
                'sector': 'Public Services', 
                'risk_level': 'MEDIUM',
                'last_scanned': '1 day ago',
                'vulnerabilities': 3,
                'status': 'SCHEDULED'
            }
        ]
        
        return jsonify({'targets': priority_targets}), 200
    
    except Exception as e:
        logger.error(f"Error getting priority targets: {e}")
        return jsonify({'error': 'Failed to retrieve priority targets'}), 500

@app.route('/api/intelligence/recent')
def get_recent_intelligence():
    """Get recent intelligence and security activities"""
    try:
        recent_activities = [
            {
                'id': 'intel-001',
                'timestamp': (datetime.now() - timedelta(minutes=2)).isoformat(),
                'source': 'AI Analyzer',
                'source_color': 'primary',
                'description': 'New APT campaign detected targeting financial sector',
                'severity': 'CRITICAL',
                'classification': 'SECRET'
            },
            {
                'id': 'intel-002',
                'timestamp': (datetime.now() - timedelta(minutes=4)).isoformat(),
                'source': 'Nmap',
                'source_color': 'success',
                'description': 'Completed scan of 192.168.1.0/24 - 15 vulnerabilities found',
                'severity': 'HIGH',
                'classification': 'UNCLASSIFIED'
            },
            {
                'id': 'intel-003',
                'timestamp': (datetime.now() - timedelta(minutes=7)).isoformat(),
                'source': 'OSINT',
                'source_color': 'warning',
                'description': 'CVE-2024-12345 published - affects Apache servers',
                'severity': 'MEDIUM',
                'classification': 'UNCLASSIFIED'
            },
            {
                'id': 'intel-004',
                'timestamp': (datetime.now() - timedelta(minutes=10)).isoformat(),
                'source': 'OpenVAS',
                'source_color': 'info',
                'description': 'Scheduled infrastructure scan initiated',
                'severity': 'INFO',
                'classification': 'UNCLASSIFIED'
            },
            {
                'id': 'intel-005',
                'timestamp': (datetime.now() - timedelta(minutes=15)).isoformat(),
                'source': 'System',
                'source_color': 'secondary',
                'description': 'Agent Smith logged in from secure terminal',
                'severity': 'LOW',
                'classification': 'UNCLASSIFIED'
            }
        ]
        
        return jsonify({'activities': recent_activities}), 200
    
    except Exception as e:
        logger.error(f"Error getting recent intelligence: {e}")
        return jsonify({'error': 'Failed to retrieve recent intelligence'}), 500

@app.route('/api/threat/intelligence')
def get_threat_intelligence():
    """Get comprehensive threat intelligence data"""
    try:
        threat_intel = {
            'global_threat_level': 'ELEVATED',
            'active_campaigns': [
                {
                    'name': 'Volt Typhoon',
                    'type': 'Nation State',
                    'target_sectors': ['Government', 'Critical Infrastructure'],
                    'confidence': 'HIGH'
                },
                {
                    'name': 'APT29 (Cozy Bear)',
                    'type': 'Nation State', 
                    'target_sectors': ['Government', 'Defense'],
                    'confidence': 'MEDIUM'
                }
            ],
            'trending_cves': [
                'CVE-2024-12345',
                'CVE-2024-23456', 
                'CVE-2024-34567'
            ],
            'iocs_today': 1247,
            'malware_families': ['Ryuk', 'Conti', 'BlackMatter'],
            'last_updated': datetime.now().isoformat()
        }
        
        return jsonify(threat_intel), 200
    
    except Exception as e:
        logger.error(f"Error getting threat intelligence: {e}")
        return jsonify({'error': 'Failed to retrieve threat intelligence'}), 500

# ================================
# HELPER FUNCTIONS
# ================================

def generate_ai_response(query):
    """Generate AI response based on query (simplified for demo)"""
    query_lower = query.lower()
    
    # Critical vulnerabilities
    if any(word in query_lower for word in ['critical', 'severe', 'important']):
        critical_count = len([v for v in vulnerabilities_data if v['severity'] == 'Critical'])
        return f"You currently have {critical_count} critical vulnerabilities in your system. The Apache HTTP Server RCE (CVE-2023-12345) is the most severe with a CVSS score of 9.8. I recommend prioritizing the patching of this vulnerability as it allows remote code execution."
    
    # Vulnerability count
    elif any(word in query_lower for word in ['how many', 'count', 'total']):
        total_count = len(vulnerabilities_data)
        return f"Your system currently has {total_count} total vulnerabilities: {len([v for v in vulnerabilities_data if v['severity'] == 'Critical'])} Critical, {len([v for v in vulnerabilities_data if v['severity'] == 'High'])} High, {len([v for v in vulnerabilities_data if v['severity'] == 'Medium'])} Medium, and {len([v for v in vulnerabilities_data if v['severity'] == 'Low'])} Low severity."
    
    # Scan results
    elif any(word in query_lower for word in ['scan', 'scanning', 'scanned']):
        completed_scans = len([s for s in scans_data if s['status'] == 'Completed'])
        running_scans = len([s for s in scans_data if s['status'] == 'Running'])
        return f"You have {completed_scans} completed scans and {running_scans} currently running scans. The latest completed scan found vulnerabilities in the 192.168.1.0/24 network range."
    
    # Remediation
    elif any(word in query_lower for word in ['fix', 'remediate', 'patch', 'resolve']):
        return "For effective vulnerability remediation, I recommend: 1) Prioritize critical and high-severity vulnerabilities first, 2) Update Apache HTTP Server to version 2.4.58+, 3) Implement proper input validation for XSS and SQL injection vulnerabilities, 4) Configure SSH to use strong encryption algorithms. Would you like detailed steps for any specific vulnerability?"
    
    # CVE information
    elif 'cve' in query_lower:
        return "CVE-2023-12345 is a critical Apache HTTP Server vulnerability with remote code execution capabilities. It affects versions prior to 2.4.58. The vulnerability allows attackers to execute arbitrary code on the server. Immediate patching is recommended."
    
    # Default response
    else:
        return "I'm your AI security assistant. I can help you analyze vulnerabilities, explain CVEs, provide remediation guidance, and answer questions about your security scans. Try asking about critical vulnerabilities, scan results, or specific CVEs."

# ================================
# ERROR HANDLERS
# ================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found', 'status': 404}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f'Internal server error: {error}')
    return jsonify({'error': 'Internal server error', 'status': 500}), 500

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request', 'status': 400}), 400

# ================================
# APPLICATION STARTUP
# ================================

if __name__ == '__main__':
    logger.info("Starting Centralized Vulnerability Detection System...")
    logger.info(f"Static files: {app.static_folder}")
    logger.info(f"Templates: {app.template_folder}")
    
    # Create database tables
    with app.app_context():
        db.create_all()
        logger.info("Database tables created successfully")
    
    # Development server
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=os.getenv('FLASK_ENV') == 'development'
    )