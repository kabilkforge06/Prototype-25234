"""
Threat Intelligence Service
Correlates vulnerability data with multiple threat intelligence sources
"""

import asyncio
import aiohttp
import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import requests
from urllib.parse import quote
import re

logger = logging.getLogger(__name__)

@dataclass
class ThreatIntelResult:
    """Result from threat intelligence lookup"""
    cve_id: str
    nvd_data: Optional[Dict]
    exploitdb_data: List[Dict]
    rapid7_data: Optional[Dict]
    exploit_available: bool
    exploit_maturity: str
    threat_actors: List[str]
    attack_patterns: List[str]
    remediation_info: Dict
    last_updated: datetime

class ThreatIntelligenceService:
    """Service for correlating vulnerabilities with threat intelligence sources"""
    
    def __init__(self, api_keys: Dict[str, str] = None):
        self.api_keys = api_keys or {}
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour cache
        self.session = requests.Session()
        
        # Rate limiting
        self.last_nvd_request = 0
        self.nvd_rate_limit = 2  # seconds between requests
        
        # API endpoints
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.exploitdb_base_url = "https://www.exploit-db.com/api/v1/search"
        self.rapid7_base_url = "https://vdb-kasf7mkb6a-uc.a.run.app/v1"
        
    async def enrich_vulnerability(self, cve_id: str) -> ThreatIntelResult:
        """Enrich a single CVE with threat intelligence data"""
        if not cve_id or not cve_id.startswith('CVE-'):
            return self._empty_result(cve_id)
            
        # Check cache first
        cache_key = f"threat_intel_{cve_id}"
        if cache_key in self.cache:
            cache_entry = self.cache[cache_key]
            if datetime.now() - cache_entry['timestamp'] < timedelta(seconds=self.cache_ttl):
                logger.info(f"Using cached threat intel for {cve_id}")
                return cache_entry['data']
        
        logger.info(f"Enriching {cve_id} with threat intelligence...")
        
        # Gather data from all sources concurrently
        tasks = [
            self._get_nvd_data(cve_id),
            self._get_exploitdb_data(cve_id),
            self._get_rapid7_data(cve_id)
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                nvd_data, exploitdb_data, rapid7_data = await asyncio.gather(*tasks, return_exceptions=True)
                
            # Handle exceptions
            if isinstance(nvd_data, Exception):
                logger.error(f"NVD lookup failed for {cve_id}: {nvd_data}")
                nvd_data = None
                
            if isinstance(exploitdb_data, Exception):
                logger.error(f"ExploitDB lookup failed for {cve_id}: {exploitdb_data}")
                exploitdb_data = []
                
            if isinstance(rapid7_data, Exception):
                logger.error(f"Rapid7 lookup failed for {cve_id}: {rapid7_data}")
                rapid7_data = None
                
            # Analyze and correlate data
            result = self._analyze_threat_data(cve_id, nvd_data, exploitdb_data, rapid7_data)
            
            # Cache the result
            self.cache[cache_key] = {
                'data': result,
                'timestamp': datetime.now()
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to enrich {cve_id}: {e}")
            return self._empty_result(cve_id)
    
    async def enrich_multiple_vulnerabilities(self, cve_ids: List[str]) -> Dict[str, ThreatIntelResult]:
        """Enrich multiple CVEs with rate limiting"""
        results = {}
        
        # Process in batches to respect rate limits
        batch_size = 5
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i + batch_size]
            
            batch_tasks = [self.enrich_vulnerability(cve_id) for cve_id in batch]
            batch_results = await asyncio.gather(*batch_tasks)
            
            for cve_id, result in zip(batch, batch_results):
                results[cve_id] = result
                
            # Rate limiting between batches
            if i + batch_size < len(cve_ids):
                await asyncio.sleep(1)
                
        return results
    
    async def _get_nvd_data(self, cve_id: str) -> Optional[Dict]:
        """Get vulnerability data from NVD"""
        try:
            # Respect rate limiting
            current_time = time.time()
            if current_time - self.last_nvd_request < self.nvd_rate_limit:
                await asyncio.sleep(self.nvd_rate_limit - (current_time - self.last_nvd_request))
            
            url = f"{self.nvd_base_url}?cveId={cve_id}"
            headers = {'User-Agent': 'VulnScanner/1.0'}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    self.last_nvd_request = time.time()
                    
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('vulnerabilities'):
                            vuln_data = data['vulnerabilities'][0]['cve']
                            return self._parse_nvd_data(vuln_data)
                    
                    logger.warning(f"NVD API returned status {response.status} for {cve_id}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error fetching NVD data for {cve_id}: {e}")
            return None
    
    async def _get_exploitdb_data(self, cve_id: str) -> List[Dict]:
        """Get exploit data from ExploitDB"""
        try:
            # Note: ExploitDB doesn't have a public API, so we'll simulate data
            # In production, you might scrape their search results or use a paid API
            
            exploits = []
            
            # Simulate some exploit data based on CVE patterns
            if any(year in cve_id for year in ['2023', '2024']):
                exploits.append({
                    'id': f"exploitdb_{cve_id}",
                    'title': f"Exploit for {cve_id}",
                    'type': 'remote',
                    'platform': 'linux',
                    'date_published': '2024-01-15',
                    'verified': True,
                    'maturity': 'functional',
                    'url': f"https://www.exploit-db.com/exploits/example"
                })
            
            return exploits
            
        except Exception as e:
            logger.error(f"Error fetching ExploitDB data for {cve_id}: {e}")
            return []
    
    async def _get_rapid7_data(self, cve_id: str) -> Optional[Dict]:
        """Get vulnerability data from Rapid7's vulnerability database"""
        try:
            # Note: Using simulated data as Rapid7's API requires authentication
            # In production, you would use their actual API with proper credentials
            
            rapid7_data = {
                'vuln_id': cve_id,
                'risk_score': self._calculate_risk_score(cve_id),
                'exploit_available': cve_id.endswith(('1', '3', '5', '7', '9')),  # Simulate
                'metasploit_modules': [],
                'attack_patterns': self._get_attack_patterns(cve_id),
                'remediation': {
                    'patch_available': True,
                    'workaround_available': False,
                    'vendor_advisory': f"https://vendor.com/advisory/{cve_id}"
                }
            }
            
            return rapid7_data
            
        except Exception as e:
            logger.error(f"Error fetching Rapid7 data for {cve_id}: {e}")
            return None
    
    def _parse_nvd_data(self, nvd_cve_data: Dict) -> Dict:
        """Parse and extract relevant information from NVD data"""
        try:
            parsed_data = {
                'id': nvd_cve_data.get('id'),
                'published_date': nvd_cve_data.get('published'),
                'modified_date': nvd_cve_data.get('lastModified'),
                'description': '',
                'cvss_v3': {},
                'cvss_v2': {},
                'cpe_data': [],
                'weakness_data': [],
                'references': []
            }
            
            # Extract description
            descriptions = nvd_cve_data.get('descriptions', [])
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    parsed_data['description'] = desc.get('value', '')
                    break
            
            # Extract CVSS data
            metrics = nvd_cve_data.get('metrics', {})
            
            # CVSS v3.x
            cvss_v3_data = metrics.get('cvssMetricV31') or metrics.get('cvssMetricV30')
            if cvss_v3_data:
                cvss_v3 = cvss_v3_data[0]['cvssData']
                parsed_data['cvss_v3'] = {
                    'base_score': cvss_v3.get('baseScore'),
                    'base_severity': cvss_v3.get('baseSeverity'),
                    'vector_string': cvss_v3.get('vectorString'),
                    'attack_vector': cvss_v3.get('attackVector'),
                    'attack_complexity': cvss_v3.get('attackComplexity'),
                    'privileges_required': cvss_v3.get('privilegesRequired'),
                    'user_interaction': cvss_v3.get('userInteraction'),
                    'confidentiality_impact': cvss_v3.get('confidentialityImpact'),
                    'integrity_impact': cvss_v3.get('integrityImpact'),
                    'availability_impact': cvss_v3.get('availabilityImpact')
                }
            
            # CVSS v2
            cvss_v2_data = metrics.get('cvssMetricV2')
            if cvss_v2_data:
                cvss_v2 = cvss_v2_data[0]['cvssData']
                parsed_data['cvss_v2'] = {
                    'base_score': cvss_v2.get('baseScore'),
                    'vector_string': cvss_v2.get('vectorString'),
                    'access_vector': cvss_v2.get('accessVector'),
                    'access_complexity': cvss_v2.get('accessComplexity'),
                    'authentication': cvss_v2.get('authentication'),
                    'confidentiality_impact': cvss_v2.get('confidentialityImpact'),
                    'integrity_impact': cvss_v2.get('integrityImpact'),
                    'availability_impact': cvss_v2.get('availabilityImpact')
                }
            
            # Extract CPE data
            configurations = nvd_cve_data.get('configurations', [])
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        if cpe_match.get('vulnerable'):
                            parsed_data['cpe_data'].append({
                                'cpe23Uri': cpe_match.get('criteria'),
                                'version_start_including': cpe_match.get('versionStartIncluding'),
                                'version_end_excluding': cpe_match.get('versionEndExcluding'),
                                'version_start_excluding': cpe_match.get('versionStartExcluding'),
                                'version_end_including': cpe_match.get('versionEndIncluding')
                            })
            
            # Extract weakness data (CWE)
            weaknesses = nvd_cve_data.get('weaknesses', [])
            for weakness in weaknesses:
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        parsed_data['weakness_data'].append({
                            'cwe_id': desc.get('value'),
                            'description': desc.get('value')
                        })
            
            # Extract references
            references = nvd_cve_data.get('references', [])
            for ref in references:
                parsed_data['references'].append({
                    'url': ref.get('url'),
                    'source': ref.get('source'),
                    'tags': ref.get('tags', [])
                })
            
            return parsed_data
            
        except Exception as e:
            logger.error(f"Error parsing NVD data: {e}")
            return {}
    
    def _analyze_threat_data(self, cve_id: str, nvd_data: Dict, exploitdb_data: List[Dict], 
                           rapid7_data: Dict) -> ThreatIntelResult:
        """Analyze and correlate threat intelligence data"""
        
        # Determine exploit availability and maturity
        exploit_available = False
        exploit_maturity = "unknown"
        
        if exploitdb_data:
            exploit_available = True
            # Determine maturity based on exploit characteristics
            if any(e.get('verified') for e in exploitdb_data):
                exploit_maturity = "functional"
            else:
                exploit_maturity = "proof-of-concept"
        elif rapid7_data and rapid7_data.get('exploit_available'):
            exploit_available = True
            exploit_maturity = "functional"
        
        # Extract threat actors (simulated for demo)
        threat_actors = []
        if nvd_data and nvd_data.get('cvss_v3', {}).get('base_score', 0) >= 9.0:
            threat_actors = ["APT groups", "Ransomware operators"]
        
        # Extract attack patterns based on CVSS vector
        attack_patterns = []
        if nvd_data:
            cvss_v3 = nvd_data.get('cvss_v3', {})
            if cvss_v3.get('attack_vector') == 'NETWORK':
                attack_patterns.append("Remote Code Execution")
            if cvss_v3.get('privileges_required') == 'NONE':
                attack_patterns.append("Unauthenticated Attack")
            if cvss_v3.get('user_interaction') == 'NONE':
                attack_patterns.append("Automated Exploitation")
        
        # Compile remediation information
        remediation_info = {
            'patch_available': False,
            'workaround_available': False,
            'vendor_advisories': [],
            'mitigation_steps': []
        }
        
        if nvd_data and nvd_data.get('references'):
            for ref in nvd_data['references']:
                if any(tag in ref.get('tags', []) for tag in ['Patch', 'Vendor Advisory']):
                    remediation_info['patch_available'] = True
                    remediation_info['vendor_advisories'].append(ref['url'])
        
        return ThreatIntelResult(
            cve_id=cve_id,
            nvd_data=nvd_data,
            exploitdb_data=exploitdb_data,
            rapid7_data=rapid7_data,
            exploit_available=exploit_available,
            exploit_maturity=exploit_maturity,
            threat_actors=threat_actors,
            attack_patterns=attack_patterns,
            remediation_info=remediation_info,
            last_updated=datetime.now()
        )
    
    def _empty_result(self, cve_id: str) -> ThreatIntelResult:
        """Return empty result for invalid or failed lookups"""
        return ThreatIntelResult(
            cve_id=cve_id,
            nvd_data=None,
            exploitdb_data=[],
            rapid7_data=None,
            exploit_available=False,
            exploit_maturity="unknown",
            threat_actors=[],
            attack_patterns=[],
            remediation_info={},
            last_updated=datetime.now()
        )
    
    def _calculate_risk_score(self, cve_id: str) -> float:
        """Calculate a risk score based on CVE characteristics (simulated)"""
        # Simple simulation based on CVE year and number
        year = int(cve_id.split('-')[1]) if '-' in cve_id else 2020
        number = int(cve_id.split('-')[2]) if '-' in cve_id else 0
        
        base_score = 5.0
        if year >= 2023:
            base_score += 1.0
        if number % 10 in [1, 3, 7, 9]:  # Simulate higher risk for certain patterns
            base_score += 2.0
            
        return min(base_score, 10.0)
    
    def _get_attack_patterns(self, cve_id: str) -> List[str]:
        """Get MITRE ATT&CK patterns for a CVE (simulated)"""
        patterns = []
        
        # Simulate patterns based on CVE characteristics
        if 'remote' in cve_id.lower() or any(x in cve_id for x in ['network', 'rce']):
            patterns.extend(['T1190', 'T1203'])  # Exploit Public-Facing Application, Exploitation for Client Execution
            
        if 'privilege' in cve_id.lower() or 'escalation' in cve_id.lower():
            patterns.append('T1068')  # Exploitation for Privilege Escalation
            
        if 'buffer' in cve_id.lower() or 'overflow' in cve_id.lower():
            patterns.append('T1203')  # Exploitation for Client Execution
            
        return patterns

# Singleton instance
threat_intelligence_service = ThreatIntelligenceService()