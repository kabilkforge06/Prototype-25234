"""
RAG Service Implementation with Google Gemini
Handles intelligent query processing and threat intelligence analysis
"""

import os
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import json

# Google Generative AI
import google.generativeai as genai

logger = logging.getLogger(__name__)

class RAGService:
    """
    Retrieval-Augmented Generation service for cybersecurity intelligence
    Uses Google Gemini for contextual vulnerability analysis
    """

    def __init__(self, api_key: str):
        """Initialize RAG service with Google Gemini"""
        self.api_key = api_key
        
        # Try different models in order of preference
        model_options = [
            "gemini-2.0-flash",
            "gemini-flash-latest", 
            "gemini-2.5-flash",
            "gemini-2.0-flash-001"
        ]

        # Configure Google Generative AI
        genai.configure(api_key=api_key)

        # Try to initialize with available models
        self.model = None
        self.model_name = None
        
        for model_name in model_options:
            try:
                self.model = genai.GenerativeModel(model_name)
                self.model_name = model_name
                logger.info(f"Successfully initialized with model: {model_name}")
                break
            except Exception as e:
                logger.warning(f"Failed to initialize model {model_name}: {e}")
                continue
        
        if not self.model:
            raise ValueError("Failed to initialize any Gemini model")

        # Initialize knowledge base
        self.knowledge_base = self._load_knowledge_base()

        # Create system prompt for cybersecurity context
        self.system_prompt = self._create_system_prompt()

        logger.info("RAG Service initialized with Google Gemini")

    def _load_knowledge_base(self) -> Dict[str, Any]:
        """Load cybersecurity knowledge base"""
        return {
            "vulnerabilities": [
                {
                    "id": "CVE-2023-12345",
                    "title": "Apache HTTP Server Remote Code Execution",
                    "description": "Critical RCE vulnerability in Apache HTTP Server allowing remote attackers to execute arbitrary code.",
                    "severity": "Critical",
                    "cvss_score": 9.8,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "affected_versions": "Apache HTTP Server < 2.4.58",
                    "remediation": "Update Apache HTTP Server to version 2.4.58 or later immediately",
                    "attack_techniques": ["T1190: Exploit Public-Facing Application", "T1059: Command and Scripting Interpreter"],
                    "references": ["https://httpd.apache.org/security/", "https://nvd.nist.gov/"]
                },
                {
                    "id": "CVE-2023-48795",
                    "title": "SSH Terrapin Attack",
                    "description": "Prefix truncation attack against SSH protocol allowing manipulation of extension negotiation.",
                    "severity": "Medium",
                    "cvss_score": 5.9,
                    "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
                    "affected_versions": "Multiple SSH implementations",
                    "remediation": "Update SSH client/server software, configure strict key exchange algorithms",
                    "attack_techniques": ["T1557: Adversary-in-the-Middle", "T1021.004: SSH"],
                    "references": ["https://terrapin-attack.com/", "https://cve.mitre.org/"]
                }
            ],
            "attack_patterns": {
                "T1190": {
                    "name": "Exploit Public-Facing Application",
                    "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.",
                    "tactics": ["Initial Access"],
                    "platforms": ["Linux", "Windows", "macOS", "Network"]
                },
                "T1059": {
                    "name": "Command and Scripting Interpreter",
                    "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                    "tactics": ["Execution"],
                    "platforms": ["Linux", "Windows", "macOS"]
                }
            },
            "remediation_guidance": {
                "patch_management": "Implement a structured patch management process prioritizing critical and high-severity vulnerabilities",
                "network_segmentation": "Isolate critical systems and implement defense-in-depth strategies",
                "monitoring": "Deploy continuous monitoring and threat detection capabilities",
                "incident_response": "Maintain an updated incident response plan with clear escalation procedures"
            }
        }

    def _create_system_prompt(self) -> str:
        """Create system prompt for cybersecurity queries"""
        return """You are a cybersecurity expert assistant with deep knowledge of vulnerabilities, 
        attack techniques, and remediation strategies. You have access to the National Cybersecurity 
        and Vulnerability Database (NCVD) and provide accurate, actionable security intelligence.

        Instructions:
        1. Provide accurate technical information based on available context
        2. Include CVE IDs, CVSS scores, and severity levels when available
        3. Explain attack vectors and potential impact clearly
        4. Suggest specific, actionable remediation steps
        5. Reference MITRE ATT&CK techniques when relevant
        6. If discussing exploitation, ensure it's for authorized testing purposes only
        7. Format responses in a professional, government-appropriate style
        8. Always prioritize security and safety in recommendations

        Respond in a clear, structured format suitable for security professionals."""

    def _get_relevant_context(self, query: str) -> str:
        """Get relevant context from knowledge base based on query"""
        query_lower = query.lower()
        relevant_info = []
        
        # Check for specific CVEs
        for vuln in self.knowledge_base["vulnerabilities"]:
            if (vuln["id"].lower() in query_lower or 
                any(keyword in query_lower for keyword in vuln["title"].lower().split()) or
                vuln["severity"].lower() in query_lower):
                relevant_info.append(f"**{vuln['id']}: {vuln['title']}**\n"
                                   f"Severity: {vuln['severity']} (CVSS: {vuln['cvss_score']})\n"
                                   f"Description: {vuln['description']}\n"
                                   f"Remediation: {vuln['remediation']}\n"
                                   f"MITRE ATT&CK: {', '.join(vuln['attack_techniques'])}")
        
        # Check for MITRE ATT&CK techniques
        if 'mitre' in query_lower or 'att&ck' in query_lower or any(f't{i}' in query_lower for i in range(1000, 2000)):
            for technique_id, technique in self.knowledge_base["attack_patterns"].items():
                if technique_id.lower() in query_lower or technique["name"].lower() in query_lower:
                    relevant_info.append(f"**MITRE ATT&CK {technique_id}: {technique['name']}**\n"
                                       f"Description: {technique['description']}\n"
                                       f"Tactics: {', '.join(technique['tactics'])}\n"
                                       f"Platforms: {', '.join(technique['platforms'])}")
        
        # Add general remediation guidance if asked
        if any(word in query_lower for word in ['remediation', 'fix', 'patch', 'resolve', 'mitigation']):
            guidance = self.knowledge_base["remediation_guidance"]
            relevant_info.append(f"**General Remediation Guidance:**\n"
                               f"• Patch Management: {guidance['patch_management']}\n"
                               f"• Network Security: {guidance['network_segmentation']}\n"
                               f"• Monitoring: {guidance['monitoring']}\n"
                               f"• Incident Response: {guidance['incident_response']}")
        
        return "\n\n".join(relevant_info) if relevant_info else "No specific context found in knowledge base."

    def query(self, question: str, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Process user query and return intelligent response using Google Gemini"""
        try:
            logger.info(f"Processing query: {question[:100]}...")

            # Get relevant context from knowledge base
            context = self._get_relevant_context(question)
            
            # Prepare the prompt for Gemini
            prompt = f"""{self.system_prompt}

**Context from NCVD Knowledge Base:**
{context}

**User Query:** {question}

**Instructions:** Provide a comprehensive, professional response based on the context above. Include specific technical details, remediation steps, and security recommendations where appropriate. Format the response for a government cybersecurity professional."""

            # Generate response using Gemini
            response = self.model.generate_content(prompt)
            
            # Extract the response text
            response_text = response.text if response.text else "Unable to generate response"
            
            return {
                "response": response_text,
                "sources": [{"content": context[:500] + "..." if len(context) > 500 else context}],
                "confidence": self._calculate_confidence(response_text, context),
                "timestamp": datetime.utcnow().isoformat(),
                "user_id": user_id
            }

        except Exception as e:
            logger.error(f"Error processing query: {e}")
            return {
                "response": f"I apologize, but I encountered an error processing your query. The AI system may be temporarily unavailable. Please try again or contact the Security Operations Center.\n\nError details: {str(e)}",
                "sources": [],
                "confidence": 0.0,
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(e)
            }

    def _calculate_confidence(self, response: str, context: str) -> float:
        """Calculate confidence score based on response quality and context"""
        confidence = 0.5  # Base confidence

        # Increase confidence if we have relevant context
        if context and len(context) > 100:
            confidence += 0.3

        # Increase confidence if response contains specific security terms
        security_terms = [
            "cve", "cvss", "vulnerability", "exploit", "remediation",
            "attack", "mitigation", "security", "patch", "mitre"
        ]

        found_terms = sum(1 for term in security_terms if term.lower() in response.lower())
        confidence += min(found_terms * 0.04, 0.2)

        # Check if response length indicates comprehensive answer
        if len(response) > 200:
            confidence += 0.1

        return min(confidence, 1.0)

    def get_vulnerability_analysis(self, cve_id: str) -> Dict[str, Any]:
        """Get detailed analysis for a specific CVE"""
        query = f"Provide detailed analysis of {cve_id} including CVSS score, attack vector, impact, and remediation steps"
        return self.query(query)

    def get_attack_path_analysis(self, vulnerabilities: List[str]) -> Dict[str, Any]:
        """Analyze potential attack paths using multiple vulnerabilities"""
        vuln_list = ", ".join(vulnerabilities)
        query = f"Analyze possible attack paths using these vulnerabilities: {vuln_list}. Include MITRE ATT&CK techniques and chaining possibilities."
        return self.query(query)

    def get_remediation_guidance(self, vulnerability_title: str) -> Dict[str, Any]:
        """Get specific remediation guidance for a vulnerability"""
        query = f"Provide step-by-step remediation guidance for {vulnerability_title} including patch information, configuration changes, and monitoring recommendations"
        return self.query(query)