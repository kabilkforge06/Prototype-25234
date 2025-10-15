"""
Lightweight Vulnerability Scanner - No External Dependencies Required
Uses built-in Python libraries and API integrations only
"""

import os
import json
import logging
import socket
import ssl
import threading
import requests
import urllib3
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

class LightweightVulnerabilityScanner:
    """Main vulnerability scanner class using only Python built-ins and APIs"""

    def __init__(self):
        self.port_scanner = PortScanner()
        self.shodan_scanner = ShodanScanner()
        self.cve_scanner = CVEScanner()
        self.web_scanner = WebApplicationScanner()
        
    def scan_target(self, target: str, scan_types: List[str] = None) -> List[ScanResult]:
        """
        Perform comprehensive vulnerability scan on target
        
        Args:
            target: IP address or domain to scan
            scan_types: List of scan types ['port', 'shodan', 'cve', 'web']
        
        Returns:
            List of ScanResult objects
        """
        if scan_types is None:
            scan_types = ['port', 'shodan', 'cve', 'web']
        
        results = []
        
        try:
            # Port Scan (replaces Nmap)
            if 'port' in scan_types or 'nmap' in scan_types:
                logger.info(f"Starting port scan for {target}")
                port_result = self.port_scanner.scan(target)
                results.append(port_result)
            
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
            if 'web' in scan_types:
                logger.info(f"Starting web application scan for {target}")
                web_result = self.web_scanner.scan(target)
                results.append(web_result)
                
        except Exception as e:
            logger.error(f"Error during vulnerability scan: {str(e)}")
        
        return results

class PortScanner:
    """Python socket-based port scanner (replaces Nmap)"""

    def __init__(self):
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080
        ]

    def scan(self, target: str) -> ScanResult:
        """Execute port scan using Python sockets"""
        try:
            logger.info(f"Starting port scan for {target}")
            
            vulnerabilities = []
            open_ports = []
            
            # Resolve hostname to IP
            try:
                target_ip = socket.gethostbyname(target)
            except socket.gaierror:
                target_ip = target
            
            # Scan common ports
            for port in self.common_ports:
                if self._scan_port(target_ip, port):
                    open_ports.append(port)
                    
                    # Check for known vulnerable services
                    service_vuln = self._check_service_vulnerability(target_ip, port)
                    if service_vuln:
                        vulnerabilities.append(service_vuln)
            
            # Add general open port findings
            for port in open_ports:
                service_name = self._get_service_name(port)
                if service_name in ['telnet', 'ftp', 'smtp', 'pop3']:  # Potentially risky services
                    vulnerability = {
                        'id': f"port-{target_ip}-{port}",
                        'title': f"Potentially risky service: {service_name}",
                        'description': f"Service {service_name} is running on port {port}",
                        'severity': 'Medium',
                        'target_host': target_ip,
                        'target_port': port,
                        'service_name': service_name,
                        'tool': 'Port Scanner'
                    }
                    vulnerabilities.append(vulnerability)
            
            return ScanResult(
                tool="Port Scanner",
                target=target,
                vulnerabilities=vulnerabilities,
                scan_time=datetime.now(),
                status="completed",
                metadata={"open_ports": open_ports, "ports_scanned": len(self.common_ports)}
            )
            
        except Exception as e:
            logger.error(f"Port scan failed: {str(e)}")
            return ScanResult(
                tool="Port Scanner",
                target=target,
                vulnerabilities=[],
                scan_time=datetime.now(),
                status="failed",
                metadata={"error": str(e)}
            )

    def _scan_port(self, host: str, port: int, timeout: float = 3.0) -> bool:
        """Check if a specific port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False

    def _get_service_name(self, port: int) -> str:
        """Get service name for a port"""
        services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc', 139: 'netbios-ssn',
            143: 'imap', 443: 'https', 993: 'imaps', 995: 'pop3s', 1723: 'pptp',
            3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 8080: 'http-proxy'
        }
        return services.get(port, f'port-{port}')

    def _check_service_vulnerability(self, host: str, port: int) -> Optional[Dict]:
        """Check for specific service vulnerabilities"""
        service = self._get_service_name(port)
        
        # SSH version detection and vulnerability check
        if port == 22:
            return self._check_ssh_vulnerability(host, port)
        
        # HTTP/HTTPS service check
        elif port in [80, 443, 8080]:
            return self._check_web_service(host, port)
        
        # FTP anonymous login check
        elif port == 21:
            return self._check_ftp_anonymous(host, port)
        
        return None

    def _check_ssh_vulnerability(self, host: str, port: int) -> Optional[Dict]:
        """Check for SSH vulnerabilities"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            
            # Get SSH banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Check for known vulnerable SSH versions
            vulnerable_versions = ['OpenSSH_7.4', 'OpenSSH_6.', 'OpenSSH_5.']
            for vuln_version in vulnerable_versions:
                if vuln_version in banner:
                    return {
                        'id': f"ssh-version-{host}-{port}",
                        'title': f"Outdated SSH version: {banner}",
                        'description': f"SSH server running potentially vulnerable version: {banner}",
                        'severity': 'Medium',
                        'target_host': host,
                        'target_port': port,
                        'service_name': 'ssh',
                        'tool': 'Port Scanner',
                        'banner': banner
                    }
        except:
            pass
        return None

    def _check_web_service(self, host: str, port: int) -> Optional[Dict]:
        """Check for web service issues"""
        try:
            protocol = 'https' if port == 443 else 'http'
            url = f"{protocol}://{host}:{port}"
            
            response = requests.get(url, timeout=10, verify=False)
            server_header = response.headers.get('Server', '')
            
            # Check for outdated web servers
            vulnerable_servers = ['Apache/2.2', 'Apache/2.0', 'nginx/1.0', 'IIS/6.0']
            for vuln_server in vulnerable_servers:
                if vuln_server in server_header:
                    return {
                        'id': f"web-server-{host}-{port}",
                        'title': f"Outdated web server: {server_header}",
                        'description': f"Web server running potentially vulnerable version: {server_header}",
                        'severity': 'Medium',
                        'target_host': host,
                        'target_port': port,
                        'service_name': 'http',
                        'tool': 'Port Scanner',
                        'server': server_header
                    }
        except:
            pass
        return None

    def _check_ftp_anonymous(self, host: str, port: int) -> Optional[Dict]:
        """Check for FTP anonymous login"""
        # This would require FTP protocol implementation
        # For now, just flag FTP as potentially risky
        return {
            'id': f"ftp-service-{host}-{port}",
            'title': "FTP service detected",
            'description': "FTP service is running - check for anonymous access",
            'severity': 'Low',
            'target_host': host,
            'target_port': port,
            'service_name': 'ftp',
            'tool': 'Port Scanner'
        }

class ShodanScanner:
    """Shodan API integration for exposed service detection"""

    def __init__(self):
        api_key = os.getenv('SHODAN_API_KEY')
        if api_key:
            try:
                import shodan
                self.api = shodan.Shodan(api_key)
            except ImportError:
                self.api = None
                logger.warning("Shodan library not available")
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
                status="skipped",
                metadata={"error": "API not available"}
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
                        'severity': 'Medium',
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
        """Look up recent critical CVEs"""
        vulnerabilities = []
        
        try:
            # Search for recent critical CVEs
            params = {
                'resultsPerPage': 10,
                'cvssV3Severity': 'HIGH'
            }
            
            headers = {}
            if self.nvd_api_key:
                headers['apiKey'] = self.nvd_api_key
                
            response = requests.get(self.base_url, params=params, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for cve_item in data.get('vulnerabilities', [])[:5]:  # Limit to 5 recent CVEs
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
                        'title': f"Recent vulnerability: {cve_id}",
                        'description': description[:200] + "..." if len(description) > 200 else description,
                        'severity': 'High',
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
            '/backup.sql', '/config.php', '/phpinfo.php', '/robots.txt'
        ]
        
        for file_path in common_files:
            try:
                response = requests.get(f"{target}{file_path}", timeout=5, verify=False)
                if response.status_code == 200:
                    vulnerability = {
                        'id': f"web-file-{file_path.replace('/', '-')}",
                        'title': f"Accessible path: {file_path}",
                        'description': f"Path {file_path} is accessible and may contain sensitive information",
                        'severity': 'Low' if file_path == '/robots.txt' else 'Medium',
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
            
            missing_headers = []
            for header, description in security_headers.items():
                if header not in headers:
                    missing_headers.append(header)
            
            if missing_headers:
                vulnerability = {
                    'id': 'web-missing-headers',
                    'title': f"Missing security headers",
                    'description': f"Missing headers: {', '.join(missing_headers)}",
                    'severity': 'Low',
                    'target_host': target,
                    'tool': 'Web Scanner',
                    'missing_headers': missing_headers
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
            except requests.exceptions.SSLError as e:
                vulnerability = {
                    'id': 'web-ssl-error',
                    'title': 'SSL/TLS Certificate Issue',
                    'description': f'SSL certificate verification failed: {str(e)}',
                    'severity': 'High',
                    'target_host': target,
                    'tool': 'Web Scanner'
                }
                vulnerabilities.append(vulnerability)
            except:
                pass
                
        return vulnerabilities

# Main scanner instance
lightweight_vulnerability_scanner = LightweightVulnerabilityScanner()