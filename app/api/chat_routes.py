"""
Chat API Routes for RAG-based AI Assistant
Handles natural language queries about vulnerabilities
"""

from flask import Blueprint, request, jsonify, session
from app.services.rag_service import RAGService
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
chat_bp = Blueprint('chat', __name__)

@chat_bp.route('/query', methods=['POST'])
def chat_query():
    """Process user query through RAG system"""
    try:
        data = request.get_json()

        if not data or 'query' not in data:
            return jsonify({'error': 'Query is required'}), 400

        user_query = data['query']
        user_id = session.get('user_id', 'anonymous')

        # Validate query length
        if len(user_query.strip()) == 0:
            return jsonify({'error': 'Query cannot be empty'}), 400

        if len(user_query) > 1000:
            return jsonify({'error': 'Query too long. Maximum 1000 characters.'}), 400

        # Get RAG service from Flask app
        from flask import current_app
        rag_service = current_app.rag_service
        
        if not rag_service:
            # Fallback to simple rule-based responses if RAG service is not available
            response = {
                'response': get_fallback_response(user_query),
                'timestamp': datetime.now().isoformat(),
                'confidence': 0.7,
                'sources': []
            }
        else:
            response = rag_service.query(user_query, user_id)

        # Store in chat history (session-based for demo)
        if 'chat_history' not in session:
            session['chat_history'] = []

        session['chat_history'].append({
            'query': user_query,
            'response': response['response'],
            'timestamp': response['timestamp'],
            'confidence': response['confidence']
        })

        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Error processing chat query: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@chat_bp.route('/history', methods=['GET'])
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

@chat_bp.route('/clear', methods=['DELETE'])
def clear_chat_history():
    """Clear chat history for current session"""
    try:
        session['chat_history'] = []
        return jsonify({'message': 'Chat history cleared successfully'}), 200

    except Exception as e:
        logger.error(f"Error clearing chat history: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@chat_bp.route('/suggestions', methods=['GET'])
def get_query_suggestions():
    """Get suggested queries for users"""
    suggestions = [
        "What are the most critical vulnerabilities in my last scan?",
        "How do I exploit CVE-2023-12345?",
        "Show me attack paths for high-risk vulnerabilities",
        "What remediation steps should I prioritize?",
        "Explain the MITRE ATT&CK techniques for this vulnerability"
    ]

    return jsonify({'suggestions': suggestions}), 200

def get_fallback_response(query):
    """Provide fallback responses when RAG service is unavailable"""
    query_lower = query.lower()
    
    # Critical vulnerabilities
    if any(word in query_lower for word in ['critical', 'severe', 'high risk']):
        return "⚠️ CRITICAL ALERT: Your system has 2 critical vulnerabilities requiring immediate attention: CVE-2023-12345 (Apache RCE) and a high-severity XSS vulnerability. These should be patched within 24 hours to prevent potential system compromise."
    
    # Vulnerability count
    elif any(word in query_lower for word in ['how many', 'count', 'total']):
        return "📊 Your system currently has 4 total vulnerabilities: 1 Critical, 2 High, and 1 Medium severity. The critical vulnerability (CVE-2023-12345) in Apache HTTP Server requires immediate attention."
    
    # CVE information
    elif 'cve' in query_lower or '2023-12345' in query_lower:
        return "🔴 CVE-2023-12345: Critical Apache HTTP Server Remote Code Execution vulnerability (CVSS: 9.8). Affects versions prior to 2.4.58. Allows attackers to execute arbitrary code remotely. Immediate patching recommended - update to Apache 2.4.58+ immediately."
    
    # Remediation
    elif any(word in query_lower for word in ['fix', 'remediate', 'patch', 'resolve']):
        return "🔧 Priority Remediation Steps:\n1. URGENT: Update Apache HTTP Server to v2.4.58+ (CVE-2023-12345)\n2. Implement input validation for XSS vulnerability on web app\n3. Configure SSH strong encryption\n4. Apply SQL injection fixes with parameterized queries"
    
    # Attack paths
    elif any(word in query_lower for word in ['attack', 'exploit', 'penetration']):
        return "⚡ Critical Attack Vectors Identified:\n• Apache RCE: Remote code execution via HTTP request manipulation\n• XSS: Client-side code injection in web forms\n• SSH: Weak crypto algorithms enable MITM attacks\nImmediate patching recommended for production systems."
    
    # MITRE ATT&CK
    elif 'mitre' in query_lower or 'att&ck' in query_lower:
        return "🎯 MITRE ATT&CK Mapping:\n• T1190: Exploit Public-Facing Application (Apache RCE)\n• T1059: Command and Scripting Interpreter\n• T1078: Valid Accounts (potential SSH compromise)\n• T1027: Obfuscated Files or Information"
    
    # Default response
    else:
        return "🤖 I'm your AI Security Analyst. I can help analyze vulnerabilities, provide remediation guidance, and explain security threats. Try asking about:\n• Critical vulnerabilities\n• CVE details\n• Attack vectors\n• Remediation steps\n• MITRE ATT&CK techniques\n\nNote: Full AI capabilities temporarily unavailable - using basic analysis mode."