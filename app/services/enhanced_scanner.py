"""
Enhanced Vulnerability Scanner Service - No Docker Required
Integrates multiple scanning tools and APIs
"""

import os
import json
import logging
import subprocess
import threading
import requests
import nmap
import shodan
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    """Data class for scan results"""
    tool: str
    target: str
    vulnerabilities: List[Dict[str, Any]]
    scan_time: datetime
    status: str
    metadata: Dict[str, Any]

class EnhancedVulnerabilityScanner:
    """Main vulnerability scanner class that orchestrates different tools"""

    def __init__(self):
        self.nmap_scanner = NmapScanner()
        self.shodan_scanner = ShodanScanner()
        self.cve_scanner = CVEScanner()
        self.web_scanner = WebApplicationScanner()
        
    def scan_target(self, target: str, scan_types: List[str] = None) -> List[ScanResult]:
        """
        Perform comprehensive vulnerability scan on target
        
        Args:
            target: IP address or domain to scan
            scan_types: List of scan types ['nmap', 'shodan', 'cve', 'web']
        
        Returns:
            List of ScanResult objects
        """
        if scan_types is None:
            scan_types = ['nmap', 'shodan', 'cve', 'web']
        
        results = []
        
        try:
            # Nmap Network Scan
            if 'nmap' in scan_types:
                logger.info(f"Starting Nmap scan for {target}")
                nmap_result = self.nmap_scanner.scan(target)
                results.append(nmap_result)
            
            # Shodan Intelligence
            if 'shodan' in scan_types:
                logger.info(f"Starting Shodan lookup for {target}")
                shodan_result = self.shodan_scanner.lookup(target)
                results.append(shodan_result)
            
            # CVE Database Lookup
            if 'cve' in scan_types:
                logger.info(f"Starting CVE lookup for {target}")
                cve_result = self.cve_scanner.lookup_vulnerabilities(target)
                results.append(cve_result)
            
            # Web Application Scan
            if 'web' in scan_types and (target.startswith('http') or ':80' in target or ':443' in target):
                logger.info(f"Starting web application scan for {target}")
                web_result = self.web_scanner.scan(target)
                results.append(web_result)
                
        except Exception as e:
            logger.error(f"Error during vulnerability scan: {str(e)}")
        
        return results

class NmapScanner:
    """Nmap integration for port scanning and NSE vulnerability detection"""

    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan(self, target: str, scan_type: str = "comprehensive") -> ScanResult:
        """Execute Nmap scan with vulnerability detection scripts"""
        try:
            logger.info(f"Starting Nmap scan for {target}")

            # Define scan arguments based on type
            scan_args = {
                "quick": "-T4 -F --script vuln",
                "comprehensive": "-T4 -sV --script vuln,exploit,auth,brute",
                "stealth": "-T2 -sS --script vuln"
            }

            arguments = scan_args.get(scan_type, scan_args["quick"])
            
            # Execute scan
            self.nm.scan(target, arguments=arguments)
            
            vulnerabilities = []
            
            # Parse results
            for host in self.nm.all_hosts():
                host_data = self.nm[host]
                
                # Check for vulnerable services
                for port in host_data['tcp']:
                    port_info = host_data['tcp'][port]
                    
                    # Look for vulnerability script results
                    if 'script' in port_info:
                        for script_name, script_output in port_info['script'].items():
                            if any(keyword in script_output.lower() for keyword in ['vulnerable', 'exploit', 'cve-']):
                                vulnerability = {
                                    'id': f"nmap-{host}-{port}-{script_name}",
                                    'title': f"Vulnerability detected via {script_name}",
                                    'description': script_output,
                                    'severity': self._determine_severity(script_output),
                                    'target_host': host,
                                    'target_port': port,
                                    'service_name': port_info.get('name', 'unknown'),
                                    'tool': 'Nmap NSE',
                                    'script': script_name
                                }
                                vulnerabilities.append(vulnerability)
            
            return ScanResult(
                tool="Nmap",
                target=target,
                vulnerabilities=vulnerabilities,
                scan_time=datetime.now(),
                status="completed",
                metadata={"scan_type": scan_type, "hosts_scanned": len(self.nm.all_hosts())}
            )
            
        except Exception as e:
            logger.error(f"Nmap scan failed: {str(e)}")
            return ScanResult(
                tool="Nmap",
                target=target,
                vulnerabilities=[],
                scan_time=datetime.now(),
                status="failed",
                metadata={"error": str(e)}
            )

    def _determine_severity(self, script_output: str) -> str:
        """Determine vulnerability severity based on script output"""
        output_lower = script_output.lower()
        if any(keyword in output_lower for keyword in ['critical', 'remote code execution', 'rce']):
            return 'Critical'
        elif any(keyword in output_lower for keyword in ['high', 'privilege escalation']):
            return 'High'
        elif any(keyword in output_lower for keyword in ['medium', 'disclosure']):
            return 'Medium'
        else:
            return 'Low'

class ShodanScanner:
    """Shodan API integration for exposed service detection"""

    def __init__(self):
        api_key = os.getenv('SHODAN_API_KEY')
        if api_key:
            self.api = shodan.Shodan(api_key)
        else:
            self.api = None
            logger.warning("Shodan API key not found")

    def lookup(self, target: str) -> ScanResult:
        """Lookup target in Shodan database"""
        vulnerabilities = []
        
        if not self.api:
            return ScanResult(
                tool="Shodan",
                target=target,
                vulnerabilities=[],
                scan_time=datetime.now(),
                status="failed",
                metadata={"error": "API key not configured"}
            )
        
        try:
            # Query Shodan for the target
            host_info = self.api.host(target)
            
            # Extract vulnerabilities from Shodan data
            if 'vulns' in host_info:
                for cve in host_info['vulns']:
                    vulnerability = {
                        'id': f"shodan-{target}-{cve}",
                        'title': f"Exposed service vulnerability: {cve}",
                        'description': f"CVE {cve} detected on exposed service",
                        'severity': 'Medium',  # Default, could be enhanced
                        'target_host': target,
                        'cve_ids': [cve],
                        'tool': 'Shodan',
                        'source': 'shodan_database'
                    }
                    vulnerabilities.append(vulnerability)
            
            # Check for risky services
            for service in host_info.get('data', []):
                port = service.get('port')
                product = service.get('product', '')
                version = service.get('version', '')
                
                # Flag potentially risky services
                risky_services = ['ssh', 'telnet', 'ftp', 'smb', 'rdp', 'vnc']
                if any(risk in product.lower() for risk in risky_services):
                    vulnerability = {
                        'id': f"shodan-service-{target}-{port}",
                        'title': f"Exposed {product} service",
                        'description': f"Service {product} {version} exposed on port {port}",
                        'severity': 'Medium',
                        'target_host': target,
                        'target_port': port,
                        'service_name': product,
                        'tool': 'Shodan'
                    }
                    vulnerabilities.append(vulnerability)
            
            return ScanResult(
                tool="Shodan",
                target=target,
                vulnerabilities=vulnerabilities,
                scan_time=datetime.now(),
                status="completed",
                metadata={"services_found": len(host_info.get('data', []))}
            )
            
        except shodan.APIError as e:
            logger.error(f"Shodan API error: {str(e)}")
            return ScanResult(
                tool="Shodan",
                target=target,
                vulnerabilities=[],
                scan_time=datetime.now(),
                status="failed",
                metadata={"error": str(e)}
            )
        except Exception as e:
            logger.error(f"Shodan lookup failed: {str(e)}")
            return ScanResult(
                tool="Shodan",
                target=target,
                vulnerabilities=[],
                scan_time=datetime.now(),
                status="failed",
                metadata={"error": str(e)}
            )

class CVEScanner:
    """CVE database integration using NVD API"""

    def __init__(self):
        self.nvd_api_key = os.getenv('NVD_API_KEY')
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def lookup_vulnerabilities(self, target: str) -> ScanResult:
        """Look up CVEs for common services and technologies"""
        vulnerabilities = []
        
        try:
            # For demonstration, we'll search for recent critical CVEs
            # In practice, this would be based on detected services
            
            params = {
                'resultsPerPage': 20,
                'cvssV3Severity': 'CRITICAL'
            }
            
            if self.nvd_api_key:
                headers = {'apiKey': self.nvd_api_key}
            else:
                headers = {}
                
            response = requests.get(self.base_url, params=params, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for cve_item in data.get('vulnerabilities', []):
                    cve = cve_item.get('cve', {})
                    cve_id = cve.get('id', '')
                    
                    # Extract vulnerability details
                    descriptions = cve.get('descriptions', [])
                    description = descriptions[0].get('value', '') if descriptions else 'No description available'
                    
                    # Get CVSS score
                    metrics = cve.get('metrics', {})
                    cvss_score = 0.0
                    if 'cvssMetricV31' in metrics:
                        cvss_score = metrics['cvssMetricV31'][0]['cvssData'].get('baseScore', 0.0)
                    elif 'cvssMetricV30' in metrics:
                        cvss_score = metrics['cvssMetricV30'][0]['cvssData'].get('baseScore', 0.0)
                    
                    vulnerability = {
                        'id': f"cve-{cve_id}",
                        'title': f"Critical vulnerability: {cve_id}",
                        'description': description,
                        'severity': 'Critical',
                        'cvss_score': cvss_score,
                        'cve_ids': [cve_id],
                        'tool': 'NVD',
                        'target_host': target,
                        'published_date': cve.get('published', '')
                    }
                    vulnerabilities.append(vulnerability)
            
            return ScanResult(
                tool="CVE Scanner",
                target=target,
                vulnerabilities=vulnerabilities,
                scan_time=datetime.now(),
                status="completed",
                metadata={"cves_found": len(vulnerabilities)}
            )
            
        except Exception as e:
            logger.error(f"CVE lookup failed: {str(e)}")
            return ScanResult(
                tool="CVE Scanner",
                target=target,
                vulnerabilities=[],
                scan_time=datetime.now(),
                status="failed",
                metadata={"error": str(e)}
            )

class WebApplicationScanner:
    """Basic web application vulnerability scanner"""

    def scan(self, target: str) -> ScanResult:
        """Perform basic web application security checks"""
        vulnerabilities = []
        
        try:
            # Ensure target has protocol
            if not target.startswith('http'):
                target = f"http://{target}"
            
            # Common vulnerability checks
            vulnerabilities.extend(self._check_common_files(target))
            vulnerabilities.extend(self._check_headers(target))
            vulnerabilities.extend(self._check_ssl_issues(target))
            
            return ScanResult(
                tool="Web Scanner",
                target=target,
                vulnerabilities=vulnerabilities,
                scan_time=datetime.now(),
                status="completed",
                metadata={"checks_performed": 3}
            )
            
        except Exception as e:
            logger.error(f"Web application scan failed: {str(e)}")
            return ScanResult(
                tool="Web Scanner",
                target=target,
                vulnerabilities=[],
                scan_time=datetime.now(),
                status="failed",
                metadata={"error": str(e)}
            )

    def _check_common_files(self, target: str) -> List[Dict]:
        """Check for common sensitive files"""
        vulnerabilities = []
        common_files = [
            '/admin', '/phpmyadmin', '/wp-admin', '/.git', '/.env',
            '/backup.sql', '/config.php', '/phpinfo.php'
        ]
        
        for file_path in common_files:
            try:
                response = requests.get(f"{target}{file_path}", timeout=10, verify=False)
                if response.status_code == 200:
                    vulnerability = {
                        'id': f"web-file-{file_path.replace('/', '-')}",
                        'title': f"Sensitive file exposed: {file_path}",
                        'description': f"Potentially sensitive file {file_path} is accessible",
                        'severity': 'Medium',
                        'target_host': target,
                        'tool': 'Web Scanner',
                        'path': file_path
                    }
                    vulnerabilities.append(vulnerability)
            except:
                continue
                
        return vulnerabilities

    def _check_headers(self, target: str) -> List[Dict]:
        """Check for missing security headers"""
        vulnerabilities = []
        
        try:
            response = requests.get(target, timeout=10, verify=False)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME type sniffing protection',
                'X-XSS-Protection': 'XSS protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'Content security policy'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    vulnerability = {
                        'id': f"web-header-{header.lower()}",
                        'title': f"Missing security header: {header}",
                        'description': f"Missing {description} header",
                        'severity': 'Low',
                        'target_host': target,
                        'tool': 'Web Scanner',
                        'header': header
                    }
                    vulnerabilities.append(vulnerability)
                    
        except:
            pass
            
        return vulnerabilities

    def _check_ssl_issues(self, target: str) -> List[Dict]:
        """Check for SSL/TLS issues"""
        vulnerabilities = []
        
        if target.startswith('https://'):
            try:
                response = requests.get(target, timeout=10, verify=True)
            except requests.exceptions.SSLError:
                vulnerability = {
                    'id': 'web-ssl-error',
                    'title': 'SSL/TLS Certificate Issue',
                    'description': 'SSL certificate verification failed',
                    'severity': 'High',
                    'target_host': target,
                    'tool': 'Web Scanner'
                }
                vulnerabilities.append(vulnerability)
            except:
                pass
                
        return vulnerabilities

# Main scanner instance
vulnerability_scanner = EnhancedVulnerabilityScanner()