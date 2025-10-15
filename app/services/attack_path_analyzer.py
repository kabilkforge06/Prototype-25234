"""
Attack Path Analysis Service
Generates possible attack paths for simple and chain vulnerabilities
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import json
import networkx as nx
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

@dataclass
class AttackStep:
    """Individual step in an attack path"""
    step_id: str
    title: str
    description: str
    vulnerability_ids: List[str]
    mitre_technique: str
    prerequisites: List[str]
    tools_required: List[str]
    difficulty: str  # Easy, Medium, Hard
    detection_difficulty: str  # Easy, Medium, Hard
    impact_level: str  # Low, Medium, High, Critical

@dataclass
class AttackPath:
    """Complete attack path from entry to objective"""
    path_id: str
    name: str
    description: str
    attack_type: str  # simple, chain, lateral_movement, privilege_escalation
    steps: List[AttackStep]
    entry_points: List[str]
    target_assets: List[str]
    total_risk_score: float
    likelihood: str
    impact: str
    mitigation_strategies: List[str]
    detection_methods: List[str]

class AttackPathAnalyzer:
    """Service for analyzing and generating attack paths"""
    
    def __init__(self):
        self.attack_graph = nx.DiGraph()
        self.vulnerability_relationships = {}
        self.mitre_attack_mapping = self._load_mitre_mappings()
        
    def analyze_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]], 
                              network_topology: Dict = None) -> List[AttackPath]:
        """Analyze vulnerabilities and generate possible attack paths"""
        logger.info(f"Analyzing {len(vulnerabilities)} vulnerabilities for attack paths")
        
        # Build attack graph
        self._build_attack_graph(vulnerabilities, network_topology)
        
        # Generate different types of attack paths
        attack_paths = []
        
        # Simple attack paths (single vulnerability exploitation)
        simple_paths = self._generate_simple_attack_paths(vulnerabilities)
        attack_paths.extend(simple_paths)
        
        # Chain attack paths (multiple vulnerabilities in sequence)
        chain_paths = self._generate_chain_attack_paths(vulnerabilities)
        attack_paths.extend(chain_paths)
        
        # Lateral movement paths
        lateral_paths = self._generate_lateral_movement_paths(vulnerabilities)
        attack_paths.extend(lateral_paths)
        
        # Privilege escalation paths
        privilege_paths = self._generate_privilege_escalation_paths(vulnerabilities)
        attack_paths.extend(privilege_paths)
        
        # Sort by risk score
        attack_paths.sort(key=lambda x: x.total_risk_score, reverse=True)
        
        logger.info(f"Generated {len(attack_paths)} attack paths")
        return attack_paths[:10]  # Return top 10 most critical paths
    
    def _build_attack_graph(self, vulnerabilities: List[Dict[str, Any]], 
                           network_topology: Dict = None):
        """Build a graph representing possible attack relationships"""
        self.attack_graph.clear()
        
        # Add vulnerabilities as nodes
        for vuln in vulnerabilities:
            self.attack_graph.add_node(
                vuln['id'],
                vuln_data=vuln,
                host=vuln.get('target_host'),
                service=vuln.get('service_name'),
                severity=vuln.get('severity'),
                cvss_score=vuln.get('cvss_v3_score', 0)
            )
        
        # Add edges based on attack relationships
        self._add_attack_relationships(vulnerabilities)
        
        # Add network topology if provided
        if network_topology:
            self._incorporate_network_topology(network_topology)
    
    def _add_attack_relationships(self, vulnerabilities: List[Dict[str, Any]]):
        """Add edges between vulnerabilities that can be chained"""
        for i, vuln1 in enumerate(vulnerabilities):
            for j, vuln2 in enumerate(vulnerabilities):
                if i != j:
                    relationship_weight = self._calculate_relationship_weight(vuln1, vuln2)
                    if relationship_weight > 0:
                        self.attack_graph.add_edge(
                            vuln1['id'], 
                            vuln2['id'], 
                            weight=relationship_weight,
                            relationship_type=self._get_relationship_type(vuln1, vuln2)
                        )
    
    def _calculate_relationship_weight(self, vuln1: Dict, vuln2: Dict) -> float:
        """Calculate the weight of relationship between two vulnerabilities"""
        weight = 0.0
        
        # Same host - higher relationship
        if vuln1.get('target_host') == vuln2.get('target_host'):
            weight += 0.5
        
        # Network proximity (simulated)
        if self._are_network_adjacent(vuln1.get('target_host'), vuln2.get('target_host')):
            weight += 0.3
        
        # Attack vector compatibility
        if self._are_attack_vectors_compatible(vuln1, vuln2):
            weight += 0.4
        
        # Privilege escalation potential
        if self._enables_privilege_escalation(vuln1, vuln2):
            weight += 0.6
        
        # Service dependencies
        if self._have_service_dependencies(vuln1, vuln2):
            weight += 0.3
        
        return min(weight, 1.0)
    
    def _get_relationship_type(self, vuln1: Dict, vuln2: Dict) -> str:
        """Determine the type of relationship between vulnerabilities"""
        if vuln1.get('target_host') == vuln2.get('target_host'):
            if self._enables_privilege_escalation(vuln1, vuln2):
                return "privilege_escalation"
            else:
                return "local_exploitation"
        else:
            return "lateral_movement"
    
    def _generate_simple_attack_paths(self, vulnerabilities: List[Dict[str, Any]]) -> List[AttackPath]:
        """Generate single-vulnerability attack paths"""
        paths = []
        
        for vuln in vulnerabilities:
            # Only create simple paths for high-impact vulnerabilities
            if vuln.get('cvss_v3_score', 0) >= 7.0:
                path = self._create_simple_attack_path(vuln)
                if path:
                    paths.append(path)
        
        return paths
    
    def _create_simple_attack_path(self, vuln: Dict[str, Any]) -> Optional[AttackPath]:
        """Create a simple attack path for a single vulnerability"""
        try:
            # Create attack step
            step = AttackStep(
                step_id=f"step_{vuln['id']}_1",
                title=f"Exploit {vuln.get('title', 'Unknown Vulnerability')}",
                description=f"Direct exploitation of {vuln.get('description', 'vulnerability')}",
                vulnerability_ids=[vuln['id']],
                mitre_technique=self._get_mitre_technique(vuln),
                prerequisites=self._get_prerequisites(vuln),
                tools_required=self._get_required_tools(vuln),
                difficulty=self._assess_exploit_difficulty(vuln),
                detection_difficulty=self._assess_detection_difficulty(vuln),
                impact_level=vuln.get('severity', 'Medium')
            )
            
            # Calculate risk score
            risk_score = self._calculate_path_risk_score([step])
            
            path = AttackPath(
                path_id=f"simple_path_{vuln['id']}",
                name=f"Direct Exploitation - {vuln.get('title', 'Unknown')}",
                description=f"Direct exploitation of {vuln.get('title')} on {vuln.get('target_host')}",
                attack_type="simple",
                steps=[step],
                entry_points=[f"{vuln.get('target_host')}:{vuln.get('target_port', 'N/A')}"],
                target_assets=[vuln.get('target_host', 'Unknown')],
                total_risk_score=risk_score,
                likelihood=self._calculate_likelihood([step]),
                impact=self._calculate_impact([step]),
                mitigation_strategies=self._get_mitigation_strategies([vuln]),
                detection_methods=self._get_detection_methods([vuln])
            )
            
            return path
            
        except Exception as e:
            logger.error(f"Error creating simple attack path for {vuln.get('id')}: {e}")
            return None
    
    def _generate_chain_attack_paths(self, vulnerabilities: List[Dict[str, Any]]) -> List[AttackPath]:
        """Generate multi-step attack paths using vulnerability chains"""
        paths = []
        
        # Find paths in the attack graph
        try:
            # Generate paths between different hosts
            hosts = set(v.get('target_host') for v in vulnerabilities if v.get('target_host'))
            
            for source_host in hosts:
                for target_host in hosts:
                    if source_host != target_host:
                        chain_paths = self._find_attack_chains(source_host, target_host, vulnerabilities)
                        paths.extend(chain_paths)
            
        except Exception as e:
            logger.error(f"Error generating chain attack paths: {e}")
        
        return paths
    
    def _find_attack_chains(self, source_host: str, target_host: str, 
                           vulnerabilities: List[Dict[str, Any]]) -> List[AttackPath]:
        """Find attack chains between two hosts"""
        chains = []
        
        # Get vulnerabilities on source and target hosts
        source_vulns = [v for v in vulnerabilities if v.get('target_host') == source_host]
        target_vulns = [v for v in vulnerabilities if v.get('target_host') == target_host]
        
        for source_vuln in source_vulns:
            for target_vuln in target_vulns:
                # Check if we can create a viable chain
                if self._can_chain_vulnerabilities(source_vuln, target_vuln):
                    chain_path = self._create_chain_attack_path(source_vuln, target_vuln)
                    if chain_path:
                        chains.append(chain_path)
        
        return chains
    
    def _create_chain_attack_path(self, source_vuln: Dict, target_vuln: Dict) -> Optional[AttackPath]:
        """Create a chain attack path between two vulnerabilities"""
        try:
            # Step 1: Initial compromise
            step1 = AttackStep(
                step_id=f"chain_step_{source_vuln['id']}_1",
                title=f"Initial Compromise - {source_vuln.get('title', 'Unknown')}",
                description=f"Exploit {source_vuln.get('title')} to gain initial foothold",
                vulnerability_ids=[source_vuln['id']],
                mitre_technique=self._get_mitre_technique(source_vuln),
                prerequisites=["External network access"],
                tools_required=self._get_required_tools(source_vuln),
                difficulty=self._assess_exploit_difficulty(source_vuln),
                detection_difficulty=self._assess_detection_difficulty(source_vuln),
                impact_level="Medium"
            )
            
            # Step 2: Lateral movement / Privilege escalation
            step2 = AttackStep(
                step_id=f"chain_step_{target_vuln['id']}_2",
                title=f"Lateral Movement - {target_vuln.get('title', 'Unknown')}",
                description=f"Use compromised system to exploit {target_vuln.get('title')}",
                vulnerability_ids=[target_vuln['id']],
                mitre_technique=self._get_mitre_technique(target_vuln),
                prerequisites=[f"Compromise of {source_vuln.get('target_host')}"],
                tools_required=self._get_required_tools(target_vuln),
                difficulty=self._assess_exploit_difficulty(target_vuln),
                detection_difficulty=self._assess_detection_difficulty(target_vuln),
                impact_level=target_vuln.get('severity', 'High')
            )
            
            steps = [step1, step2]
            risk_score = self._calculate_path_risk_score(steps)
            
            path = AttackPath(
                path_id=f"chain_path_{source_vuln['id']}_{target_vuln['id']}",
                name=f"Chain Attack: {source_vuln.get('target_host')} → {target_vuln.get('target_host')}",
                description=f"Multi-step attack from {source_vuln.get('target_host')} to {target_vuln.get('target_host')}",
                attack_type="chain",
                steps=steps,
                entry_points=[f"{source_vuln.get('target_host')}:{source_vuln.get('target_port', 'N/A')}"],
                target_assets=[target_vuln.get('target_host', 'Unknown')],
                total_risk_score=risk_score,
                likelihood=self._calculate_likelihood(steps),
                impact=self._calculate_impact(steps),
                mitigation_strategies=self._get_mitigation_strategies([source_vuln, target_vuln]),
                detection_methods=self._get_detection_methods([source_vuln, target_vuln])
            )
            
            return path
            
        except Exception as e:
            logger.error(f"Error creating chain attack path: {e}")
            return None
    
    def _generate_lateral_movement_paths(self, vulnerabilities: List[Dict[str, Any]]) -> List[AttackPath]:
        """Generate lateral movement attack paths"""
        paths = []
        
        # Group vulnerabilities by host
        host_vulns = defaultdict(list)
        for vuln in vulnerabilities:
            host = vuln.get('target_host')
            if host:
                host_vulns[host].append(vuln)
        
        # Generate lateral movement paths between hosts
        hosts = list(host_vulns.keys())
        for i, source_host in enumerate(hosts):
            for target_host in hosts[i+1:]:
                lateral_path = self._create_lateral_movement_path(
                    source_host, target_host, host_vulns[source_host], host_vulns[target_host]
                )
                if lateral_path:
                    paths.append(lateral_path)
        
        return paths
    
    def _create_lateral_movement_path(self, source_host: str, target_host: str,
                                    source_vulns: List[Dict], target_vulns: List[Dict]) -> Optional[AttackPath]:
        """Create a lateral movement attack path"""
        try:
            # Select best vulnerabilities for lateral movement
            source_vuln = self._select_best_entry_point(source_vulns)
            target_vuln = self._select_best_lateral_target(target_vulns)
            
            if not source_vuln or not target_vuln:
                return None
            
            # Create steps for lateral movement
            steps = [
                AttackStep(
                    step_id=f"lateral_entry_{source_vuln['id']}",
                    title=f"Initial Compromise - {source_host}",
                    description=f"Gain access to {source_host} via {source_vuln.get('title')}",
                    vulnerability_ids=[source_vuln['id']],
                    mitre_technique="T1190",  # Exploit Public-Facing Application
                    prerequisites=["Network access to target"],
                    tools_required=["Exploitation framework"],
                    difficulty="Medium",
                    detection_difficulty="Medium",
                    impact_level="Medium"
                ),
                AttackStep(
                    step_id=f"lateral_recon_{source_host}",
                    title="Network Reconnaissance",
                    description="Discover internal network and identify targets",
                    vulnerability_ids=[],
                    mitre_technique="T1018",  # Remote System Discovery
                    prerequisites=[f"Access to {source_host}"],
                    tools_required=["Network scanning tools"],
                    difficulty="Easy",
                    detection_difficulty="Hard",
                    impact_level="Low"
                ),
                AttackStep(
                    step_id=f"lateral_move_{target_vuln['id']}",
                    title=f"Lateral Movement to {target_host}",
                    description=f"Exploit {target_vuln.get('title')} on {target_host}",
                    vulnerability_ids=[target_vuln['id']],
                    mitre_technique="T1021",  # Remote Services
                    prerequisites=["Internal network access", "Target discovery"],
                    tools_required=["Lateral movement tools"],
                    difficulty="Medium",
                    detection_difficulty="Medium",
                    impact_level="High"
                )
            ]
            
            risk_score = self._calculate_path_risk_score(steps)
            
            path = AttackPath(
                path_id=f"lateral_{source_host}_{target_host}",
                name=f"Lateral Movement: {source_host} → {target_host}",
                description=f"Lateral movement attack from {source_host} to {target_host}",
                attack_type="lateral_movement",
                steps=steps,
                entry_points=[source_host],
                target_assets=[target_host],
                total_risk_score=risk_score,
                likelihood=self._calculate_likelihood(steps),
                impact=self._calculate_impact(steps),
                mitigation_strategies=[
                    "Network segmentation",
                    "Least privilege access",
                    "Monitor lateral movement indicators"
                ],
                detection_methods=[
                    "Network traffic analysis",
                    "Host-based monitoring",
                    "Behavioral analytics"
                ]
            )
            
            return path
            
        except Exception as e:
            logger.error(f"Error creating lateral movement path: {e}")
            return None
    
    def _generate_privilege_escalation_paths(self, vulnerabilities: List[Dict[str, Any]]) -> List[AttackPath]:
        """Generate privilege escalation attack paths"""
        paths = []
        
        # Find vulnerabilities that enable privilege escalation
        for vuln in vulnerabilities:
            if self._enables_privilege_escalation_single(vuln):
                escalation_path = self._create_privilege_escalation_path(vuln)
                if escalation_path:
                    paths.append(escalation_path)
        
        return paths
    
    def _create_privilege_escalation_path(self, vuln: Dict[str, Any]) -> Optional[AttackPath]:
        """Create a privilege escalation attack path"""
        try:
            steps = [
                AttackStep(
                    step_id=f"privesc_initial_{vuln['id']}",
                    title="Initial Low-Privilege Access",
                    description="Obtain initial low-privilege access to the system",
                    vulnerability_ids=[],
                    mitre_technique="T1078",  # Valid Accounts
                    prerequisites=["Valid user credentials or access"],
                    tools_required=["Authentication bypass"],
                    difficulty="Medium",
                    detection_difficulty="Hard",
                    impact_level="Low"
                ),
                AttackStep(
                    step_id=f"privesc_exploit_{vuln['id']}",
                    title=f"Privilege Escalation - {vuln.get('title')}",
                    description=f"Exploit {vuln.get('title')} to gain elevated privileges",
                    vulnerability_ids=[vuln['id']],
                    mitre_technique="T1068",  # Exploitation for Privilege Escalation
                    prerequisites=["Low-privilege system access"],
                    tools_required=["Privilege escalation exploits"],
                    difficulty=self._assess_exploit_difficulty(vuln),
                    detection_difficulty=self._assess_detection_difficulty(vuln),
                    impact_level="Critical"
                )
            ]
            
            risk_score = self._calculate_path_risk_score(steps)
            
            path = AttackPath(
                path_id=f"privesc_{vuln['id']}",
                name=f"Privilege Escalation - {vuln.get('target_host')}",
                description=f"Escalate privileges on {vuln.get('target_host')} using {vuln.get('title')}",
                attack_type="privilege_escalation",
                steps=steps,
                entry_points=[vuln.get('target_host')],
                target_assets=[vuln.get('target_host')],
                total_risk_score=risk_score,
                likelihood=self._calculate_likelihood(steps),
                impact=self._calculate_impact(steps),
                mitigation_strategies=[
                    "Implement least privilege principle",
                    "Regular security updates",
                    "Application whitelisting"
                ],
                detection_methods=[
                    "Privilege escalation monitoring",
                    "System call monitoring",
                    "File integrity monitoring"
                ]
            )
            
            return path
            
        except Exception as e:
            logger.error(f"Error creating privilege escalation path: {e}")
            return None
    
    # Helper methods
    def _are_network_adjacent(self, host1: str, host2: str) -> bool:
        """Check if two hosts are network adjacent (simplified)"""
        if not host1 or not host2:
            return False
        
        # Simple subnet check (same /24 network)
        try:
            ip1_parts = host1.split('.')
            ip2_parts = host2.split('.')
            
            if len(ip1_parts) == 4 and len(ip2_parts) == 4:
                return ip1_parts[:3] == ip2_parts[:3]
        except:
            pass
        
        return False
    
    def _are_attack_vectors_compatible(self, vuln1: Dict, vuln2: Dict) -> bool:
        """Check if attack vectors are compatible for chaining"""
        # Simplified compatibility check
        vector1 = vuln1.get('attack_vector', '').upper()
        vector2 = vuln2.get('attack_vector', '').upper()
        
        # Network -> Local is a common progression
        if vector1 == 'NETWORK' and vector2 in ['LOCAL', 'ADJACENT_NETWORK']:
            return True
        
        return False
    
    def _enables_privilege_escalation(self, vuln1: Dict, vuln2: Dict) -> bool:
        """Check if vuln1 enables exploitation of vuln2 for privilege escalation"""
        # Check if vuln2 requires higher privileges than vuln1 provides
        priv1 = vuln1.get('privileges_required', '').upper()
        priv2 = vuln2.get('privileges_required', '').upper()
        
        return priv1 in ['NONE', 'LOW'] and priv2 in ['LOW', 'HIGH']
    
    def _enables_privilege_escalation_single(self, vuln: Dict) -> bool:
        """Check if a single vulnerability enables privilege escalation"""
        title = vuln.get('title', '').lower()
        description = vuln.get('description', '').lower()
        
        escalation_keywords = ['privilege escalation', 'elevation of privilege', 'local privilege', 'root access']
        return any(keyword in title or keyword in description for keyword in escalation_keywords)
    
    def _have_service_dependencies(self, vuln1: Dict, vuln2: Dict) -> bool:
        """Check if services have dependencies"""
        service1 = vuln1.get('service_name', '').lower()
        service2 = vuln2.get('service_name', '').lower()
        
        # Common service dependencies
        dependencies = {
            'web': ['database', 'ldap', 'smtp'],
            'database': ['web', 'application'],
            'smtp': ['web', 'ldap'],
            'ftp': ['web', 'database']
        }
        
        return service2 in dependencies.get(service1, [])
    
    def _can_chain_vulnerabilities(self, vuln1: Dict, vuln2: Dict) -> bool:
        """Check if two vulnerabilities can be chained together"""
        # Different hosts (for lateral movement)
        if vuln1.get('target_host') != vuln2.get('target_host'):
            return True
        
        # Same host but different privileges (for escalation)
        if self._enables_privilege_escalation(vuln1, vuln2):
            return True
        
        return False
    
    def _select_best_entry_point(self, vulnerabilities: List[Dict]) -> Optional[Dict]:
        """Select the best vulnerability for initial entry"""
        if not vulnerabilities:
            return None
        
        # Prefer network-accessible, high-impact vulnerabilities
        scored_vulns = []
        for vuln in vulnerabilities:
            score = 0
            if vuln.get('attack_vector', '').upper() == 'NETWORK':
                score += 3
            if vuln.get('privileges_required', '').upper() == 'NONE':
                score += 2
            if vuln.get('user_interaction', '').upper() == 'NONE':
                score += 1
            score += vuln.get('cvss_v3_score', 0) / 2
            
            scored_vulns.append((score, vuln))
        
        scored_vulns.sort(reverse=True)
        return scored_vulns[0][1] if scored_vulns else None
    
    def _select_best_lateral_target(self, vulnerabilities: List[Dict]) -> Optional[Dict]:
        """Select the best vulnerability for lateral movement target"""
        return self._select_best_entry_point(vulnerabilities)  # Same logic for now
    
    def _get_mitre_technique(self, vuln: Dict) -> str:
        """Get MITRE ATT&CK technique for vulnerability"""
        # Simplified mapping based on vulnerability characteristics
        attack_vector = vuln.get('attack_vector', '').upper()
        title = vuln.get('title', '').lower()
        
        if 'remote code execution' in title or 'rce' in title:
            return 'T1203'  # Exploitation for Client Execution
        elif attack_vector == 'NETWORK':
            return 'T1190'  # Exploit Public-Facing Application
        elif 'privilege escalation' in title:
            return 'T1068'  # Exploitation for Privilege Escalation
        elif 'sql injection' in title:
            return 'T1190'  # Exploit Public-Facing Application
        else:
            return 'T1203'  # Default to Exploitation for Client Execution
    
    def _get_prerequisites(self, vuln: Dict) -> List[str]:
        """Get prerequisites for exploiting vulnerability"""
        prerequisites = []
        
        attack_vector = vuln.get('attack_vector', '').upper()
        if attack_vector == 'NETWORK':
            prerequisites.append("Network access to target")
        elif attack_vector == 'LOCAL':
            prerequisites.append("Local system access")
        elif attack_vector == 'ADJACENT_NETWORK':
            prerequisites.append("Adjacent network access")
        
        if vuln.get('user_interaction', '').upper() == 'REQUIRED':
            prerequisites.append("User interaction")
        
        priv_req = vuln.get('privileges_required', '').upper()
        if priv_req == 'LOW':
            prerequisites.append("Low-privilege access")
        elif priv_req == 'HIGH':
            prerequisites.append("High-privilege access")
        
        return prerequisites
    
    def _get_required_tools(self, vuln: Dict) -> List[str]:
        """Get tools required for exploitation"""
        tools = ["Vulnerability scanner"]
        
        title = vuln.get('title', '').lower()
        if 'web' in title or 'http' in title:
            tools.append("Web application testing tools")
        if 'sql' in title:
            tools.append("SQL injection tools")
        if 'buffer overflow' in title:
            tools.append("Exploit development framework")
        if 'remote' in title:
            tools.append("Remote exploitation framework")
        
        return tools
    
    def _assess_exploit_difficulty(self, vuln: Dict) -> str:
        """Assess the difficulty of exploiting the vulnerability"""
        complexity = vuln.get('attack_complexity', '').upper()
        cvss_score = vuln.get('cvss_v3_score', 0)
        
        if complexity == 'LOW' and cvss_score >= 9.0:
            return "Easy"
        elif complexity == 'LOW' and cvss_score >= 7.0:
            return "Medium"
        else:
            return "Hard"
    
    def _assess_detection_difficulty(self, vuln: Dict) -> str:
        """Assess how difficult it is to detect exploitation"""
        # Simplified assessment
        attack_vector = vuln.get('attack_vector', '').upper()
        
        if attack_vector == 'NETWORK':
            return "Medium"  # Network traffic can be monitored
        elif attack_vector == 'LOCAL':
            return "Hard"  # Local exploitation harder to detect
        else:
            return "Medium"
    
    def _calculate_path_risk_score(self, steps: List[AttackStep]) -> float:
        """Calculate total risk score for attack path"""
        base_score = 0.0
        
        for step in steps:
            # Add score based on step impact
            impact_scores = {"Low": 2, "Medium": 4, "High": 7, "Critical": 10}
            base_score += impact_scores.get(step.impact_level, 4)
            
            # Adjust for difficulty
            difficulty_multipliers = {"Easy": 1.2, "Medium": 1.0, "Hard": 0.7}
            multiplier = difficulty_multipliers.get(step.difficulty, 1.0)
            base_score *= multiplier
        
        # Path length penalty (longer paths are less likely)
        path_length_penalty = 1.0 - (len(steps) - 1) * 0.1
        base_score *= max(path_length_penalty, 0.3)
        
        return min(base_score, 10.0)
    
    def _calculate_likelihood(self, steps: List[AttackStep]) -> str:
        """Calculate likelihood of attack path success"""
        total_difficulty = sum(
            {"Easy": 1, "Medium": 2, "Hard": 3}.get(step.difficulty, 2) for step in steps
        )
        avg_difficulty = total_difficulty / len(steps) if steps else 2
        
        if avg_difficulty <= 1.5:
            return "High"
        elif avg_difficulty <= 2.5:
            return "Medium"
        else:
            return "Low"
    
    def _calculate_impact(self, steps: List[AttackStep]) -> str:
        """Calculate overall impact of attack path"""
        max_impact = "Low"
        impact_levels = ["Low", "Medium", "High", "Critical"]
        
        for step in steps:
            if step.impact_level in impact_levels:
                current_index = impact_levels.index(step.impact_level)
                max_index = impact_levels.index(max_impact)
                if current_index > max_index:
                    max_impact = step.impact_level
        
        return max_impact
    
    def _get_mitigation_strategies(self, vulnerabilities: List[Dict]) -> List[str]:
        """Get mitigation strategies for vulnerabilities"""
        strategies = set()
        
        for vuln in vulnerabilities:
            # Add general strategies based on vulnerability type
            attack_vector = vuln.get('attack_vector', '').upper()
            if attack_vector == 'NETWORK':
                strategies.add("Network firewalls and access controls")
                strategies.add("Web application firewall (WAF)")
            
            if vuln.get('privileges_required', '').upper() == 'NONE':
                strategies.add("Authentication and authorization controls")
            
            # Add specific strategies based on vulnerability title
            title = vuln.get('title', '').lower()
            if 'sql injection' in title:
                strategies.add("Input validation and parameterized queries")
            if 'xss' in title or 'cross-site scripting' in title:
                strategies.add("Output encoding and Content Security Policy")
            if 'buffer overflow' in title:
                strategies.add("Address Space Layout Randomization (ASLR)")
            
            strategies.add("Regular security updates and patches")
        
        return list(strategies)
    
    def _get_detection_methods(self, vulnerabilities: List[Dict]) -> List[str]:
        """Get detection methods for vulnerabilities"""
        methods = set()
        
        for vuln in vulnerabilities:
            attack_vector = vuln.get('attack_vector', '').upper()
            
            if attack_vector == 'NETWORK':
                methods.add("Network intrusion detection system (IDS)")
                methods.add("Web application security monitoring")
            
            methods.add("Host-based intrusion detection")
            methods.add("Security information and event management (SIEM)")
            methods.add("Vulnerability scanning")
            
            # Add specific detection based on vulnerability type
            title = vuln.get('title', '').lower()
            if 'sql injection' in title:
                methods.add("Database activity monitoring")
            if 'privilege escalation' in title:
                methods.add("Privilege escalation monitoring")
        
        return list(methods)
    
    def _load_mitre_mappings(self) -> Dict[str, str]:
        """Load MITRE ATT&CK technique mappings"""
        # Simplified mapping - in production, load from comprehensive database
        return {
            "network_exploitation": "T1190",
            "client_exploitation": "T1203",
            "privilege_escalation": "T1068",
            "lateral_movement": "T1021",
            "discovery": "T1018",
            "credential_access": "T1110"
        }

# Singleton instance
attack_path_analyzer = AttackPathAnalyzer()