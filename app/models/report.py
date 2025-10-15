"""
Enhanced Database Models for Vulnerability Reporting System
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
import json
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

db = SQLAlchemy()

class VulnerabilityReport(db.Model):
    """Enhanced vulnerability report model with threat intelligence"""
    __tablename__ = 'vulnerability_reports'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_name = db.Column(db.String(255), nullable=False)
    target_info = db.Column(db.JSON)  # Target hosts, networks, services
    executive_summary = db.Column(db.Text)
    
    # Scan metadata
    scan_start_time = db.Column(db.DateTime, nullable=False)
    scan_end_time = db.Column(db.DateTime, nullable=False)
    scan_duration = db.Column(db.Integer)  # seconds
    tools_used = db.Column(db.JSON)
    
    # Statistics
    total_vulnerabilities = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    info_count = db.Column(db.Integer, default=0)
    
    # Risk assessment
    overall_risk_score = db.Column(db.Float)
    risk_level = db.Column(db.String(20))  # Critical, High, Medium, Low
    
    # Attack path analysis
    attack_paths = db.Column(db.JSON)  # Serialized attack path data
    
    # Threat intelligence correlation
    threat_intel_summary = db.Column(db.JSON)
    
    # Report metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = db.Column(db.String(20), default='generating')  # generating, completed, failed
    
    # Relationships
    vulnerabilities = db.relationship('EnhancedVulnerability', backref='report', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id,
            'report_name': self.report_name,
            'target_info': self.target_info,
            'executive_summary': self.executive_summary,
            'scan_start_time': self.scan_start_time.isoformat() if self.scan_start_time else None,
            'scan_end_time': self.scan_end_time.isoformat() if self.scan_end_time else None,
            'scan_duration': self.scan_duration,
            'tools_used': self.tools_used,
            'total_vulnerabilities': self.total_vulnerabilities,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'info_count': self.info_count,
            'overall_risk_score': self.overall_risk_score,
            'risk_level': self.risk_level,
            'attack_paths': self.attack_paths,
            'threat_intel_summary': self.threat_intel_summary,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'status': self.status
        }

class EnhancedVulnerability(db.Model):
    """Enhanced vulnerability model with detailed threat intelligence"""
    __tablename__ = 'enhanced_vulnerabilities'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id = db.Column(db.String(36), db.ForeignKey('vulnerability_reports.id'))
    
    # Basic vulnerability info
    title = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), nullable=False)
    
    # Target information
    target_host = db.Column(db.String(255), nullable=False)
    target_port = db.Column(db.Integer)
    service_name = db.Column(db.String(100))
    service_version = db.Column(db.String(100))
    
    # CVE and scoring information
    cve_ids = db.Column(db.JSON)  # List of CVE IDs
    cvss_v3_score = db.Column(db.Float)
    cvss_v3_vector = db.Column(db.String(100))
    cvss_v2_score = db.Column(db.Float)
    cvss_v2_vector = db.Column(db.String(100))
    
    # Threat intelligence
    exploitability = db.Column(db.String(20))  # High, Medium, Low
    exploit_available = db.Column(db.Boolean, default=False)
    exploit_sources = db.Column(db.JSON)  # ExploitDB, Metasploit, etc.
    threat_actor_usage = db.Column(db.JSON)  # Known threat actors using this vuln
    
    # NVD enrichment
    nvd_data = db.Column(db.JSON)  # Full NVD data
    cpe_data = db.Column(db.JSON)  # CPE information
    weakness_data = db.Column(db.JSON)  # CWE information
    
    # Attack chain information
    attack_vector = db.Column(db.String(50))  # Network, Adjacent, Local, Physical
    attack_complexity = db.Column(db.String(20))  # High, Low
    privileges_required = db.Column(db.String(20))  # None, Low, High
    user_interaction = db.Column(db.String(20))  # None, Required
    
    # Impact assessment
    confidentiality_impact = db.Column(db.String(20))  # None, Low, High
    integrity_impact = db.Column(db.String(20))
    availability_impact = db.Column(db.String(20))
    
    # Detection information
    source_tool = db.Column(db.String(50))
    detection_method = db.Column(db.String(100))
    false_positive_likelihood = db.Column(db.String(20))  # High, Medium, Low
    
    # Remediation
    remediation_available = db.Column(db.Boolean, default=False)
    remediation_steps = db.Column(db.Text)
    patch_available = db.Column(db.Boolean, default=False)
    patch_info = db.Column(db.JSON)
    
    # Timestamps
    first_detected = db.Column(db.DateTime, default=datetime.utcnow)
    last_verified = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Status
    status = db.Column(db.String(20), default='open')  # open, investigating, fixed, false_positive
    
    def to_dict(self):
        return {
            'id': self.id,
            'report_id': self.report_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'target_host': self.target_host,
            'target_port': self.target_port,
            'service_name': self.service_name,
            'service_version': self.service_version,
            'cve_ids': self.cve_ids,
            'cvss_v3_score': self.cvss_v3_score,
            'cvss_v3_vector': self.cvss_v3_vector,
            'cvss_v2_score': self.cvss_v2_score,
            'cvss_v2_vector': self.cvss_v2_vector,
            'exploitability': self.exploitability,
            'exploit_available': self.exploit_available,
            'exploit_sources': self.exploit_sources,
            'threat_actor_usage': self.threat_actor_usage,
            'nvd_data': self.nvd_data,
            'cpe_data': self.cpe_data,
            'weakness_data': self.weakness_data,
            'attack_vector': self.attack_vector,
            'attack_complexity': self.attack_complexity,
            'privileges_required': self.privileges_required,
            'user_interaction': self.user_interaction,
            'confidentiality_impact': self.confidentiality_impact,
            'integrity_impact': self.integrity_impact,
            'availability_impact': self.availability_impact,
            'source_tool': self.source_tool,
            'detection_method': self.detection_method,
            'false_positive_likelihood': self.false_positive_likelihood,
            'remediation_available': self.remediation_available,
            'remediation_steps': self.remediation_steps,
            'patch_available': self.patch_available,
            'patch_info': self.patch_info,
            'first_detected': self.first_detected.isoformat() if self.first_detected else None,
            'last_verified': self.last_verified.isoformat() if self.last_verified else None,
            'status': self.status
        }

class AttackPath(db.Model):
    """Model for attack path analysis"""
    __tablename__ = 'attack_paths'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id = db.Column(db.String(36), db.ForeignKey('vulnerability_reports.id'))
    
    # Path metadata
    path_name = db.Column(db.String(255))
    path_type = db.Column(db.String(50))  # simple, chain, lateral_movement, privilege_escalation
    risk_score = db.Column(db.Float)
    likelihood = db.Column(db.String(20))  # Very High, High, Medium, Low, Very Low
    impact = db.Column(db.String(20))  # Critical, High, Medium, Low
    
    # Path steps
    attack_steps = db.Column(db.JSON)  # Ordered list of attack steps
    vulnerabilities_involved = db.Column(db.JSON)  # List of vulnerability IDs
    
    # Technical details
    entry_points = db.Column(db.JSON)  # Possible entry points
    target_assets = db.Column(db.JSON)  # Target systems/data
    required_conditions = db.Column(db.JSON)  # Prerequisites for attack
    
    # Mitigation
    mitigation_strategies = db.Column(db.JSON)
    detection_methods = db.Column(db.JSON)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'report_id': self.report_id,
            'path_name': self.path_name,
            'path_type': self.path_type,
            'risk_score': self.risk_score,
            'likelihood': self.likelihood,
            'impact': self.impact,
            'attack_steps': self.attack_steps,
            'vulnerabilities_involved': self.vulnerabilities_involved,
            'entry_points': self.entry_points,
            'target_assets': self.target_assets,
            'required_conditions': self.required_conditions,
            'mitigation_strategies': self.mitigation_strategies,
            'detection_methods': self.detection_methods,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

@dataclass
class ThreatIntelligenceData:
    """Data class for threat intelligence information"""
    source: str
    cve_id: str
    exploit_available: bool
    exploit_maturity: str
    exploit_sources: List[str]
    threat_actors: List[str]
    attack_patterns: List[str]
    iocs: List[str]  # Indicators of Compromise
    references: List[str]
    last_updated: datetime

@dataclass
class AttackStep:
    """Data class for individual attack steps"""
    step_number: int
    title: str
    description: str
    technique_id: str  # MITRE ATT&CK technique ID
    vulnerability_ids: List[str]
    prerequisites: List[str]
    tools_used: List[str]
    detection_rules: List[str]
    mitigation_options: List[str]