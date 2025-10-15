"""
Comprehensive Vulnerability Report Service
Aggregates scan results, correlates with threat intelligence, generates attack paths, and creates professional reports
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
import uuid
from dataclasses import dataclass, asdict

from app.models.report import VulnerabilityReport, EnhancedVulnerability, AttackPath, db
from app.services.threat_intelligence import threat_intelligence_service, ThreatIntelResult
from app.services.attack_path_analyzer import attack_path_analyzer, AttackPath as AnalyzedAttackPath

logger = logging.getLogger(__name__)

@dataclass
class ReportConfiguration:
    """Configuration for report generation"""
    include_executive_summary: bool = True
    include_technical_details: bool = True
    include_attack_paths: bool = True
    include_threat_intelligence: bool = True
    include_remediation: bool = True
    include_appendices: bool = True
    export_formats: List[str] = None  # ['pdf', 'html', 'json', 'csv']
    severity_filter: List[str] = None  # ['Critical', 'High', 'Medium', 'Low']
    
    def __post_init__(self):
        if self.export_formats is None:
            self.export_formats = ['html', 'pdf']
        if self.severity_filter is None:
            self.severity_filter = ['Critical', 'High', 'Medium', 'Low']

class VulnerabilityReportService:
    """Service for generating comprehensive vulnerability reports"""
    
    def __init__(self):
        self.processing_status = {}
    
    async def generate_comprehensive_report(self, 
                                          scan_results: List[Dict[str, Any]], 
                                          target_info: Dict[str, Any],
                                          config: ReportConfiguration = None) -> str:
        """Generate a comprehensive vulnerability report"""
        if config is None:
            config = ReportConfiguration()
        
        report_id = str(uuid.uuid4())
        self.processing_status[report_id] = {
            'status': 'processing',
            'progress': 0,
            'message': 'Initializing report generation'
        }
        
        try:
            logger.info(f"Starting comprehensive report generation for {len(scan_results)} vulnerabilities")
            
            # Step 1: Create report record
            report = await self._create_report_record(report_id, target_info, scan_results)
            self._update_progress(report_id, 10, "Report record created")
            
            # Step 2: Normalize and enrich vulnerability data
            enhanced_vulnerabilities = await self._normalize_vulnerabilities(scan_results, report_id)
            self._update_progress(report_id, 30, "Vulnerabilities normalized")
            
            # Step 3: Correlate with threat intelligence
            if config.include_threat_intelligence:
                threat_intel_data = await self._correlate_threat_intelligence(enhanced_vulnerabilities)
                await self._apply_threat_intelligence(enhanced_vulnerabilities, threat_intel_data)
                self._update_progress(report_id, 50, "Threat intelligence correlated")
            
            # Step 4: Generate attack paths
            if config.include_attack_paths:
                attack_paths = await self._generate_attack_paths(enhanced_vulnerabilities)
                await self._save_attack_paths(report_id, attack_paths)
                self._update_progress(report_id, 70, "Attack paths generated")
            
            # Step 5: Calculate risk assessment
            await self._calculate_risk_assessment(report, enhanced_vulnerabilities)
            self._update_progress(report_id, 80, "Risk assessment completed")
            
            # Step 6: Generate executive summary
            if config.include_executive_summary:
                executive_summary = await self._generate_executive_summary(report, enhanced_vulnerabilities)
                report.executive_summary = executive_summary
            
            # Step 7: Save enhanced vulnerabilities
            await self._save_enhanced_vulnerabilities(enhanced_vulnerabilities)
            self._update_progress(report_id, 90, "Vulnerabilities saved")
            
            # Step 8: Update report status
            report.status = 'completed'
            report.updated_at = datetime.utcnow()
            db.session.commit()
            
            self._update_progress(report_id, 100, "Report generation completed")
            logger.info(f"Report {report_id} generated successfully")
            
            return report_id
            
        except Exception as e:
            logger.error(f"Error generating report {report_id}: {e}")
            self.processing_status[report_id] = {
                'status': 'failed',
                'progress': 0,
                'message': f'Error: {str(e)}'
            }
            
            # Update database record
            if 'report' in locals():
                report.status = 'failed'
                db.session.commit()
            
            raise
    
    async def _create_report_record(self, report_id: str, target_info: Dict, scan_results: List[Dict]) -> VulnerabilityReport:
        """Create initial report record in database"""
        
        # Extract scan metadata
        scan_start_times = [
            datetime.fromisoformat(result.get('scan_time', datetime.utcnow().isoformat()))
            for result in scan_results if result.get('scan_time')
        ]
        scan_start_time = min(scan_start_times) if scan_start_times else datetime.utcnow()
        scan_end_time = max(scan_start_times) if scan_start_times else datetime.utcnow()
        
        # Extract tools used
        tools_used = list(set(result.get('source_tool', 'unknown') for result in scan_results))
        
        # Generate report name
        target_hosts = target_info.get('hosts', ['Unknown'])
        report_name = f"Vulnerability Assessment - {', '.join(target_hosts[:3])} - {scan_start_time.strftime('%Y-%m-%d')}"
        
        report = VulnerabilityReport(
            id=report_id,
            report_name=report_name,
            target_info=target_info,
            scan_start_time=scan_start_time,
            scan_end_time=scan_end_time,
            scan_duration=int((scan_end_time - scan_start_time).total_seconds()),
            tools_used=tools_used,
            status='generating'
        )
        
        db.session.add(report)
        db.session.commit()
        
        return report
    
    async def _normalize_vulnerabilities(self, scan_results: List[Dict[str, Any]], report_id: str) -> List[EnhancedVulnerability]:
        """Normalize vulnerability data from different scanners into enhanced format"""
        enhanced_vulns = []
        
        for scan_result in scan_results:
            try:
                # Extract vulnerabilities from scan result
                vulnerabilities = scan_result.get('vulnerabilities', [])
                tool_name = scan_result.get('tool', 'unknown')
                
                # If scan_result itself is a vulnerability (legacy format), handle it directly
                if not vulnerabilities and ('title' in scan_result or 'name' in scan_result):
                    vulnerabilities = [scan_result]
                
                for vuln in vulnerabilities:
                    try:
                        # Extract vulnerability data
                        vuln_data = self._extract_vulnerability_data(vuln)
                        
                        # Override tool name if not present in vuln data
                        if not vuln_data.get('source_tool') or vuln_data.get('source_tool') == 'unknown':
                            vuln_data['source_tool'] = tool_name
                        
                        # Create enhanced vulnerability record
                        enhanced_vuln = EnhancedVulnerability(
                            id=str(uuid.uuid4()),
                            report_id=report_id,
                            title=vuln_data.get('title', 'Unknown Vulnerability'),
                            description=vuln_data.get('description', ''),
                            severity=vuln_data.get('severity', 'Medium'),
                            target_host=vuln_data.get('target_host', ''),
                            target_port=vuln_data.get('target_port'),
                            service_name=vuln_data.get('service_name', ''),
                            service_version=vuln_data.get('service_version', ''),
                            cve_ids=vuln_data.get('cve_ids', []),
                            cvss_v3_score=vuln_data.get('cvss_v3_score'),
                            cvss_v3_vector=vuln_data.get('cvss_v3_vector', ''),
                            cvss_v2_score=vuln_data.get('cvss_v2_score'),
                            cvss_v2_vector=vuln_data.get('cvss_v2_vector', ''),
                            source_tool=vuln_data.get('source_tool', 'unknown'),
                            detection_method=vuln_data.get('detection_method', 'automated_scan'),
                            false_positive_likelihood='Medium',  # Default, can be refined
                            status='open'
                        )
                        
                        enhanced_vulns.append(enhanced_vuln)
                        
                    except Exception as e:
                        logger.error(f"Error processing individual vulnerability: {e}")
                        continue
                
            except Exception as e:
                logger.error(f"Error normalizing scan result: {e}")
                continue
        
        logger.info(f"Normalized {len(enhanced_vulns)} vulnerabilities")
        return enhanced_vulns
    
    def _extract_vulnerability_data(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and normalize vulnerability data from scan result"""
        # Handle different scanner output formats
        
        # Common fields mapping
        vuln_data = {
            'title': scan_result.get('title') or scan_result.get('name') or 'Unknown Vulnerability',
            'description': scan_result.get('description') or scan_result.get('summary', ''),
            'severity': self._normalize_severity(scan_result.get('severity', 'Medium')),
            'target_host': scan_result.get('target_host') or scan_result.get('host') or scan_result.get('ip', ''),
            'target_port': scan_result.get('target_port') or scan_result.get('port'),
            'service_name': scan_result.get('service_name') or scan_result.get('service', ''),
            'service_version': scan_result.get('service_version') or scan_result.get('version', ''),
            'source_tool': scan_result.get('source_tool') or scan_result.get('scanner', 'unknown'),
            'cve_ids': self._extract_cve_ids(scan_result),
            'cvss_v3_score': scan_result.get('cvss_v3_score') or scan_result.get('cvss_score'),
            'cvss_v3_vector': scan_result.get('cvss_v3_vector') or scan_result.get('cvss_vector', ''),
            'cvss_v2_score': scan_result.get('cvss_v2_score'),
            'cvss_v2_vector': scan_result.get('cvss_v2_vector', '')
        }
        
        return vuln_data
    
    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity values across different scanners"""
        severity_lower = severity.lower() if severity else 'medium'
        
        severity_mapping = {
            'critical': 'Critical',
            'high': 'High',
            'medium': 'Medium',
            'moderate': 'Medium',
            'low': 'Low',
            'info': 'Low',
            'informational': 'Low'
        }
        
        return severity_mapping.get(severity_lower, 'Medium')
    
    def _extract_cve_ids(self, scan_result: Dict[str, Any]) -> List[str]:
        """Extract CVE IDs from scan result"""
        cve_ids = []
        
        # Check different possible fields
        cve_fields = ['cve_ids', 'cves', 'cve', 'references']
        
        for field in cve_fields:
            if field in scan_result:
                value = scan_result[field]
                if isinstance(value, list):
                    cve_ids.extend([cve for cve in value if cve.startswith('CVE-')])
                elif isinstance(value, str) and value.startswith('CVE-'):
                    cve_ids.append(value)
        
        # Extract CVE IDs from description or title
        import re
        text_fields = [scan_result.get('description', ''), scan_result.get('title', '')]
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        
        for text in text_fields:
            if text:
                found_cves = re.findall(cve_pattern, text)
                cve_ids.extend(found_cves)
        
        return list(set(cve_ids))  # Remove duplicates
    
    async def _correlate_threat_intelligence(self, vulnerabilities: List[EnhancedVulnerability]) -> Dict[str, ThreatIntelResult]:
        """Correlate vulnerabilities with threat intelligence sources"""
        logger.info("Correlating vulnerabilities with threat intelligence...")
        
        # Extract all unique CVE IDs
        all_cve_ids = set()
        for vuln in vulnerabilities:
            if vuln.cve_ids:
                all_cve_ids.update(vuln.cve_ids)
        
        cve_list = list(all_cve_ids)
        logger.info(f"Found {len(cve_list)} unique CVE IDs for threat intelligence lookup")
        
        if not cve_list:
            return {}
        
        # Correlate with threat intelligence
        threat_intel_results = await threat_intelligence_service.enrich_multiple_vulnerabilities(cve_list)
        
        return threat_intel_results
    
    async def _apply_threat_intelligence(self, vulnerabilities: List[EnhancedVulnerability], 
                                       threat_intel_data: Dict[str, ThreatIntelResult]):
        """Apply threat intelligence data to enhanced vulnerabilities"""
        logger.info("Applying threat intelligence to vulnerabilities...")
        
        for vuln in vulnerabilities:
            if not vuln.cve_ids:
                continue
            
            # Find relevant threat intelligence
            for cve_id in vuln.cve_ids:
                if cve_id in threat_intel_data:
                    intel_result = threat_intel_data[cve_id]
                    
                    # Apply NVD data
                    if intel_result.nvd_data:
                        nvd = intel_result.nvd_data
                        vuln.nvd_data = nvd
                        
                        # Update CVSS information if not already present
                        if not vuln.cvss_v3_score and nvd.get('cvss_v3', {}).get('base_score'):
                            vuln.cvss_v3_score = nvd['cvss_v3']['base_score']
                            vuln.cvss_v3_vector = nvd['cvss_v3'].get('vector_string', '')
                            
                            # Extract attack vector details
                            cvss_v3 = nvd.get('cvss_v3', {})
                            vuln.attack_vector = cvss_v3.get('attack_vector', '')
                            vuln.attack_complexity = cvss_v3.get('attack_complexity', '')
                            vuln.privileges_required = cvss_v3.get('privileges_required', '')
                            vuln.user_interaction = cvss_v3.get('user_interaction', '')
                            vuln.confidentiality_impact = cvss_v3.get('confidentiality_impact', '')
                            vuln.integrity_impact = cvss_v3.get('integrity_impact', '')
                            vuln.availability_impact = cvss_v3.get('availability_impact', '')
                        
                        # Update weakness data
                        vuln.weakness_data = nvd.get('weakness_data', [])
                        vuln.cpe_data = nvd.get('cpe_data', [])
                    
                    # Apply exploit information
                    vuln.exploit_available = intel_result.exploit_available
                    vuln.exploitability = self._determine_exploitability(intel_result)
                    
                    if intel_result.exploitdb_data:
                        vuln.exploit_sources = [
                            {'source': 'ExploitDB', 'url': exploit.get('url', '')}
                            for exploit in intel_result.exploitdb_data
                        ]
                    
                    # Apply threat actor information
                    if intel_result.threat_actors:
                        vuln.threat_actor_usage = {
                            'known_usage': True,
                            'actors': intel_result.threat_actors
                        }
                    
                    # Apply remediation information
                    if intel_result.remediation_info:
                        vuln.remediation_available = intel_result.remediation_info.get('patch_available', False)
                        vuln.patch_available = intel_result.remediation_info.get('patch_available', False)
                        vuln.patch_info = intel_result.remediation_info
                    
                    # Only process first CVE for simplicity
                    break
    
    def _determine_exploitability(self, intel_result: ThreatIntelResult) -> str:
        """Determine exploitability level based on threat intelligence"""
        if intel_result.exploit_available:
            if intel_result.exploit_maturity == 'functional':
                return 'High'
            elif intel_result.exploit_maturity == 'proof-of-concept':
                return 'Medium'
        
        # Check CVSS score for exploitability
        if intel_result.nvd_data and intel_result.nvd_data.get('cvss_v3'):
            score = intel_result.nvd_data['cvss_v3'].get('base_score', 0)
            if score >= 9.0:
                return 'High'
            elif score >= 7.0:
                return 'Medium'
            else:
                return 'Low'
        
        return 'Medium'  # Default
    
    async def _generate_attack_paths(self, vulnerabilities: List[EnhancedVulnerability]) -> List[AnalyzedAttackPath]:
        """Generate attack paths for vulnerabilities"""
        logger.info("Generating attack paths...")
        
        # Convert to format expected by attack path analyzer
        vuln_dicts = []
        for vuln in vulnerabilities:
            vuln_dict = {
                'id': vuln.id,
                'title': vuln.title,
                'description': vuln.description,
                'severity': vuln.severity,
                'target_host': vuln.target_host,
                'target_port': vuln.target_port,
                'service_name': vuln.service_name,
                'cvss_v3_score': vuln.cvss_v3_score or 0,
                'attack_vector': vuln.attack_vector,
                'attack_complexity': vuln.attack_complexity,
                'privileges_required': vuln.privileges_required,
                'user_interaction': vuln.user_interaction,
                'cve_ids': vuln.cve_ids
            }
            vuln_dicts.append(vuln_dict)
        
        # Generate attack paths
        attack_paths = attack_path_analyzer.analyze_vulnerabilities(vuln_dicts)
        
        logger.info(f"Generated {len(attack_paths)} attack paths")
        return attack_paths
    
    async def _save_attack_paths(self, report_id: str, attack_paths: List[AnalyzedAttackPath]):
        """Save attack paths to database"""
        for path in attack_paths:
            attack_path_record = AttackPath(
                id=str(uuid.uuid4()),
                report_id=report_id,
                path_name=path.name,
                path_type=path.attack_type,
                risk_score=path.total_risk_score,
                likelihood=path.likelihood,
                impact=path.impact,
                attack_steps=[asdict(step) for step in path.steps],
                vulnerabilities_involved=path.steps[0].vulnerability_ids if path.steps else [],
                entry_points=path.entry_points,
                target_assets=path.target_assets,
                mitigation_strategies=path.mitigation_strategies,
                detection_methods=path.detection_methods
            )
            
            db.session.add(attack_path_record)
        
        db.session.commit()
    
    async def _calculate_risk_assessment(self, report: VulnerabilityReport, 
                                       vulnerabilities: List[EnhancedVulnerability]):
        """Calculate overall risk assessment for the report"""
        
        # Count vulnerabilities by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        total_cvss_score = 0.0
        scored_vulns = 0
        
        for vuln in vulnerabilities:
            severity = vuln.severity
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            if vuln.cvss_v3_score:
                total_cvss_score += vuln.cvss_v3_score
                scored_vulns += 1
        
        # Update report statistics
        report.total_vulnerabilities = len(vulnerabilities)
        report.critical_count = severity_counts['Critical']
        report.high_count = severity_counts['High']
        report.medium_count = severity_counts['Medium']
        report.low_count = severity_counts['Low']
        
        # Calculate overall risk score
        if scored_vulns > 0:
            avg_cvss = total_cvss_score / scored_vulns
            
            # Weight by severity distribution
            severity_weight = (
                severity_counts['Critical'] * 10 +
                severity_counts['High'] * 7 +
                severity_counts['Medium'] * 4 +
                severity_counts['Low'] * 1
            ) / max(len(vulnerabilities), 1)
            
            report.overall_risk_score = min((avg_cvss + severity_weight) / 2, 10.0)
        else:
            report.overall_risk_score = 5.0  # Default
        
        # Determine risk level
        if report.overall_risk_score >= 9.0:
            report.risk_level = 'Critical'
        elif report.overall_risk_score >= 7.0:
            report.risk_level = 'High'
        elif report.overall_risk_score >= 4.0:
            report.risk_level = 'Medium'
        else:
            report.risk_level = 'Low'
    
    async def _generate_executive_summary(self, report: VulnerabilityReport, 
                                        vulnerabilities: List[EnhancedVulnerability]) -> str:
        """Generate executive summary for the report"""
        
        target_hosts = report.target_info.get('hosts', ['Unknown'])
        scan_duration_hours = report.scan_duration / 3600 if report.scan_duration else 0
        
        summary = f"""
# Executive Summary

This vulnerability assessment was conducted on {len(target_hosts)} target system(s) using {len(report.tools_used)} security scanning tools. The assessment identified **{report.total_vulnerabilities} vulnerabilities** with an overall risk rating of **{report.risk_level}**.

## Key Findings

- **{report.critical_count} Critical** vulnerabilities requiring immediate attention
- **{report.high_count} High** severity vulnerabilities
- **{report.medium_count} Medium** severity vulnerabilities  
- **{report.low_count} Low** severity vulnerabilities

## Risk Assessment

The overall risk score for this assessment is **{report.overall_risk_score:.1f}/10.0**, indicating a **{report.risk_level}** risk level.

### Critical Issues
"""
        
        # Add details about critical vulnerabilities
        critical_vulns = [v for v in vulnerabilities if v.severity == 'Critical']
        if critical_vulns:
            summary += "\nThe following critical vulnerabilities require immediate remediation:\n\n"
            for vuln in critical_vulns[:5]:  # Top 5 critical
                cve_text = f" ({', '.join(vuln.cve_ids)})" if vuln.cve_ids else ""
                summary += f"- **{vuln.title}**{cve_text} on {vuln.target_host}\n"
        else:
            summary += "\nNo critical vulnerabilities were identified.\n"
        
        summary += f"""

## Recommendations

1. **Immediate Action**: Address all Critical and High severity vulnerabilities within 30 days
2. **Patch Management**: Implement a regular patching schedule for all systems
3. **Security Monitoring**: Deploy continuous monitoring for exploit attempts
4. **Network Segmentation**: Limit attack surface through proper network controls
5. **Security Awareness**: Train personnel on security best practices

## Conclusion

This assessment provides a comprehensive view of the security posture of the target environment. The identification of {report.total_vulnerabilities} vulnerabilities indicates areas for security improvement. Prioritizing the remediation of Critical and High severity vulnerabilities will significantly reduce the organization's risk exposure.
        """
        
        return summary.strip()
    
    async def _save_enhanced_vulnerabilities(self, vulnerabilities: List[EnhancedVulnerability]):
        """Save enhanced vulnerabilities to database"""
        for vuln in vulnerabilities:
            db.session.add(vuln)
        
        db.session.commit()
    
    def _update_progress(self, report_id: str, progress: int, message: str):
        """Update processing progress"""
        self.processing_status[report_id] = {
            'status': 'processing',
            'progress': progress,
            'message': message
        }
        logger.info(f"Report {report_id}: {progress}% - {message}")
    
    def get_report_status(self, report_id: str) -> Dict[str, Any]:
        """Get report generation status"""
        return self.processing_status.get(report_id, {
            'status': 'not_found',
            'progress': 0,
            'message': 'Report not found'
        })
    
    async def get_report(self, report_id: str) -> Optional[VulnerabilityReport]:
        """Get report by ID"""
        return VulnerabilityReport.query.get(report_id)
    
    async def get_report_vulnerabilities(self, report_id: str) -> List[EnhancedVulnerability]:
        """Get vulnerabilities for a report"""
        return EnhancedVulnerability.query.filter_by(report_id=report_id).all()
    
    async def get_report_attack_paths(self, report_id: str) -> List[AttackPath]:
        """Get attack paths for a report"""
        return AttackPath.query.filter_by(report_id=report_id).all()

# Singleton instance
vulnerability_report_service = VulnerabilityReportService()