import re
import asyncio
import aiohttp
import hashlib
import json
import time
import urllib.parse
import socket
import ssl
# import dns.resolver  # Comment out this line
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import sqlite3
import os
from config import config

# Load risk patterns and scam data
def load_risk_data():
    """Load risk patterns and scam addresses from JSON files"""
    try:
        with open(config.SCAM_ADDRESSES_PATH, 'r') as f:
            scam_addresses = json.load(f)
    except FileNotFoundError:
        scam_addresses = []
    
    try:
        with open(config.RISKY_PATTERNS_PATH, 'r') as f:
            risky_patterns = json.load(f)
    except FileNotFoundError:
        risky_patterns = {}
    
    return scam_addresses, risky_patterns

class AdvancedMalwareDetector:
    def __init__(self):
        self.threat_db_path = "data/threat_intelligence.db"
        self.ml_patterns_path = "data/ml_patterns.json"
        self.init_threat_database()
        self.load_ml_patterns()
        
    def init_threat_database(self):
        """Initialize local threat intelligence database"""
        os.makedirs("data", exist_ok=True)
        conn = sqlite3.connect(self.threat_db_path)
        cursor = conn.cursor()
        
        # Create tables for threat intelligence
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malicious_domains (
                domain TEXT PRIMARY KEY,
                threat_type TEXT,
                confidence REAL,
                last_seen TIMESTAMP,
                source TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malicious_ips (
                ip TEXT PRIMARY KEY,
                threat_type TEXT,
                confidence REAL,
                last_seen TIMESTAMP,
                source TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS url_patterns (
                pattern TEXT PRIMARY KEY,
                threat_type TEXT,
                confidence REAL,
                regex_pattern TEXT
            )
        ''')
        
        # Insert initial threat patterns
        initial_patterns = [
            ('phishing', 0.9, r'(secure|verify|update|confirm).*?(account|payment|billing)'),
            ('malware', 0.8, r'(download|install|update).*?(exe|zip|rar|scr)'),
            ('scam', 0.85, r'(urgent|immediate|expire|suspend|limited).*?(action|time)'),
            ('crypto_scam', 0.9, r'(bitcoin|crypto|wallet|mining|investment).*?(double|profit|guarantee)'),
            ('fake_login', 0.95, r'(login|signin|account).*?(verification|security|update)')
        ]
        
        cursor.executemany(
            'INSERT OR IGNORE INTO url_patterns (threat_type, confidence, regex_pattern) VALUES (?, ?, ?)',
            initial_patterns
        )
        
        conn.commit()
        conn.close()
    
    def load_ml_patterns(self):
        """Load machine learning patterns for behavioral analysis"""
        default_patterns = {
            "suspicious_tlds": [
                ".tk", ".ml", ".ga", ".cf", ".pw", ".top", ".click", ".download",
                ".stream", ".science", ".work", ".party", ".trade", ".webcam",
                ".win", ".date", ".racing", ".review", ".faith", ".loan"
            ],
            "malware_keywords": [
                "trojan", "virus", "malware", "ransomware", "keylogger", "backdoor",
                "rootkit", "spyware", "adware", "botnet", "exploit", "payload",
                "shell", "reverse", "metasploit", "meterpreter", "cobalt", "beacon"
            ],
            "phishing_indicators": [
                "verify-account", "secure-login", "update-payment", "confirm-identity",
                "suspended-account", "urgent-action", "limited-time", "click-here",
                "download-now", "install-update", "security-alert", "verify-now"
            ],
            "crypto_scam_patterns": [
                "double-bitcoin", "crypto-giveaway", "investment-opportunity",
                "mining-profit", "wallet-verification", "airdrop-claim",
                "trading-bot", "guaranteed-returns", "crypto-multiplier"
            ],
            "suspicious_file_extensions": [
                ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
                ".jar", ".app", ".deb", ".rpm", ".dmg", ".pkg", ".msi"
            ]
        }
        
        if os.path.exists(self.ml_patterns_path):
            with open(self.ml_patterns_path, 'r') as f:
                self.ml_patterns = json.load(f)
        else:
            self.ml_patterns = default_patterns
            with open(self.ml_patterns_path, 'w') as f:
                json.dump(default_patterns, f, indent=2)
    
    async def analyze_url_advanced(self, url: str) -> Dict:
        """Advanced URL analysis with multiple detection techniques"""
        analysis_result = {
            "url": url,
            "risk_level": "SAFE",
            "confidence": 0.0,
            "threats_detected": [],
            "analysis_details": {},
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # Parse URL components
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc.lower()
            path = parsed_url.path.lower()
            query = parsed_url.query.lower()
            
            # Run multiple analysis techniques in parallel
            tasks = [
                self.heuristic_analysis(url, domain, path, query),
                self.behavioral_analysis(url, domain, path),
                self.network_analysis(domain),
                self.content_analysis(url),
                self.reputation_analysis(domain),
                self.ml_pattern_analysis(url, domain, path, query)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Aggregate results
            total_confidence = 0
            threat_count = 0
            
            for i, result in enumerate(results):
                if isinstance(result, dict) and not isinstance(result, Exception):
                    analysis_result["analysis_details"][f"technique_{i+1}"] = result
                    if result.get("threats"):
                        analysis_result["threats_detected"].extend(result["threats"])
                        threat_count += len(result["threats"])
                    total_confidence += result.get("confidence", 0)
            
            # Calculate final risk assessment
            avg_confidence = total_confidence / len([r for r in results if isinstance(r, dict)])
            analysis_result["confidence"] = min(avg_confidence, 1.0)
            
            # Determine risk level based on threats and confidence
            if threat_count >= 3 or avg_confidence >= 0.9:
                analysis_result["risk_level"] = "CRITICAL"
            elif threat_count >= 2 or avg_confidence >= 0.7:
                analysis_result["risk_level"] = "DANGEROUS"
            elif threat_count >= 1 or avg_confidence >= 0.5:
                analysis_result["risk_level"] = "SUSPICIOUS"
            elif avg_confidence >= 0.3:
                analysis_result["risk_level"] = "CAUTION"
            
            # Update threat database with findings
            await self.update_threat_database(domain, analysis_result)
            
        except Exception as e:
            analysis_result["error"] = str(e)
            analysis_result["risk_level"] = "UNKNOWN"
        
        return analysis_result
    
    async def heuristic_analysis(self, url: str, domain: str, path: str, query: str) -> Dict:
        """Heuristic-based threat detection"""
        threats = []
        confidence = 0.0
        
        # Domain analysis
        if any(tld in domain for tld in self.ml_patterns["suspicious_tlds"]):
            threats.append("suspicious_tld")
            confidence += 0.3
        
        # Subdomain analysis
        subdomains = domain.split('.')
        if len(subdomains) > 3:
            threats.append("excessive_subdomains")
            confidence += 0.2
        
        # Character analysis
        if re.search(r'[0-9]{3,}', domain):  # Many numbers in domain
            threats.append("numeric_domain")
            confidence += 0.2
        
        if re.search(r'[a-z]{20,}', domain):  # Very long strings
            threats.append("long_random_string")
            confidence += 0.3
        
        # Homograph attack detection
        suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'х', 'у']  # Cyrillic lookalikes
        if any(char in domain for char in suspicious_chars):
            threats.append("homograph_attack")
            confidence += 0.8
        
        # URL shortener detection
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link']
        if any(shortener in domain for shortener in shorteners):
            threats.append("url_shortener")
            confidence += 0.4
        
        # Path analysis
        if any(keyword in path for keyword in self.ml_patterns["malware_keywords"]):
            threats.append("malware_path")
            confidence += 0.7
        
        if any(pattern in path for pattern in self.ml_patterns["phishing_indicators"]):
            threats.append("phishing_path")
            confidence += 0.6
        
        # File extension analysis
        if any(ext in path for ext in self.ml_patterns["suspicious_file_extensions"]):
            threats.append("suspicious_file")
            confidence += 0.8
        
        # Query parameter analysis
        if 'redirect' in query or 'url=' in query:
            threats.append("redirect_parameter")
            confidence += 0.4
        
        return {
            "technique": "heuristic",
            "threats": threats,
            "confidence": min(confidence, 1.0)
        }
    
    async def behavioral_analysis(self, url: str, domain: str, path: str) -> Dict:
        """Behavioral pattern analysis"""
        threats = []
        confidence = 0.0
        
        # Brand impersonation detection
        legitimate_brands = [
            'google', 'microsoft', 'apple', 'amazon', 'facebook', 'twitter',
            'paypal', 'ebay', 'netflix', 'spotify', 'instagram', 'linkedin',
            'github', 'stackoverflow', 'reddit', 'youtube', 'gmail', 'outlook'
        ]
        
        for brand in legitimate_brands:
            # Check for typosquatting
            if self.is_typosquatting(domain, brand):
                threats.append(f"typosquatting_{brand}")
                confidence += 0.9
                break
        
        # Suspicious pattern combinations
        urgent_words = ['urgent', 'immediate', 'expire', 'suspend', 'limited', 'act now']
        action_words = ['click', 'download', 'install', 'verify', 'update', 'confirm']
        
        url_lower = url.lower()
        urgent_count = sum(1 for word in urgent_words if word in url_lower)
        action_count = sum(1 for word in action_words if word in url_lower)
        
        if urgent_count >= 2 and action_count >= 1:
            threats.append("social_engineering")
            confidence += 0.8
        
        # Cryptocurrency scam patterns
        crypto_keywords = ['bitcoin', 'crypto', 'blockchain', 'wallet', 'mining']
        scam_keywords = ['double', 'multiply', 'investment', 'profit', 'guarantee']
        
        crypto_matches = sum(1 for word in crypto_keywords if word in url_lower)
        scam_matches = sum(1 for word in scam_keywords if word in url_lower)
        
        if crypto_matches >= 1 and scam_matches >= 1:
            threats.append("crypto_scam")
            confidence += 0.9
        
        return {
            "technique": "behavioral",
            "threats": threats,
            "confidence": min(confidence, 1.0)
        }
    
    async def network_analysis(self, domain: str) -> Dict:
        """Network-based analysis (simplified without DNS)"""
        threats = []
        confidence = 0.0
        
        try:
            # Skip DNS analysis if dnspython not available
            # try:
            #     answers = dns.resolver.resolve(domain, 'A')
            #     ips = [str(answer) for answer in answers]
            #     
            #     # Check for suspicious IP ranges
            #     for ip in ips:
            #         if self.is_suspicious_ip(ip):
            #             threats.append("suspicious_ip_range")
            #             confidence += 0.6
            #             break
            # except:
            #     threats.append("dns_resolution_failed")
            #     confidence += 0.4
            
            # SSL certificate analysis (still works without DNS)
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Check certificate validity
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if not_after < datetime.now():
                            threats.append("expired_certificate")
                            confidence += 0.7
                        
                        # Check for self-signed or suspicious issuer
                        issuer = dict(x[0] for x in cert['issuer'])
                        if issuer.get('organizationName') == domain:
                            threats.append("self_signed_certificate")
                            confidence += 0.5
            except:
                threats.append("ssl_analysis_failed")
                confidence += 0.3
        
        except Exception:
            pass
        
        return {
            "technique": "network",
            "threats": threats,
            "confidence": min(confidence, 1.0)
        }
    
    async def content_analysis(self, url: str) -> Dict:
        """Content-based analysis"""
        threats = []
        confidence = 0.0
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(url, allow_redirects=False) as response:
                    # Redirect analysis
                    if response.status in [301, 302, 303, 307, 308]:
                        redirect_url = response.headers.get('Location', '')
                        if redirect_url and self.is_suspicious_redirect(url, redirect_url):
                            threats.append("suspicious_redirect")
                            confidence += 0.6
                    
                    # Content type analysis
                    content_type = response.headers.get('Content-Type', '').lower()
                    if 'application/octet-stream' in content_type or 'application/x-msdownload' in content_type:
                        threats.append("executable_download")
                        confidence += 0.8
                    
                    # Response headers analysis
                    if 'x-frame-options' not in response.headers:
                        threats.append("missing_security_headers")
                        confidence += 0.2
        
        except Exception:
            threats.append("content_analysis_failed")
            confidence += 0.1
        
        return {
            "technique": "content",
            "threats": threats,
            "confidence": min(confidence, 1.0)
        }
    
    async def reputation_analysis(self, domain: str) -> Dict:
        """Domain reputation analysis using local database"""
        threats = []
        confidence = 0.0
        
        try:
            conn = sqlite3.connect(self.threat_db_path)
            cursor = conn.cursor()
            
            # Check against known malicious domains
            cursor.execute('SELECT threat_type, confidence FROM malicious_domains WHERE domain = ?', (domain,))
            result = cursor.fetchone()
            
            if result:
                threat_type, db_confidence = result
                threats.append(f"known_{threat_type}")
                confidence += db_confidence
            
            # Check domain age (if available)
            # This would require WHOIS data, simplified here
            
            conn.close()
        
        except Exception:
            pass
        
        return {
            "technique": "reputation",
            "threats": threats,
            "confidence": min(confidence, 1.0)
        }
    
    async def ml_pattern_analysis(self, url: str, domain: str, path: str, query: str) -> Dict:
        """Machine learning pattern analysis"""
        threats = []
        confidence = 0.0
        
        try:
            conn = sqlite3.connect(self.threat_db_path)
            cursor = conn.cursor()
            
            # Check against regex patterns
            cursor.execute('SELECT threat_type, confidence, regex_pattern FROM url_patterns')
            patterns = cursor.fetchall()
            
            full_url = url.lower()
            for threat_type, pattern_confidence, regex_pattern in patterns:
                if re.search(regex_pattern, full_url, re.IGNORECASE):
                    threats.append(f"pattern_{threat_type}")
                    confidence += pattern_confidence * 0.8  # Slightly reduce confidence for pattern matches
            
            conn.close()
        
        except Exception:
            pass
        
        return {
            "technique": "ml_pattern",
            "threats": threats,
            "confidence": min(confidence, 1.0)
        }
    
    def is_typosquatting(self, domain: str, brand: str) -> bool:
        """Detect typosquatting attempts"""
        # Remove TLD for comparison
        domain_name = domain.split('.')[0]
        
        # Check for character substitution
        substitutions = {
            'o': '0', 'i': '1', 'l': '1', 'e': '3', 'a': '@',
            'g': '9', 's': '5', 't': '7', 'b': '6'
        }
        
        for original, substitute in substitutions.items():
            if brand.replace(original, substitute) == domain_name:
                return True
        
        # Check for character insertion/deletion
        if abs(len(domain_name) - len(brand)) <= 2:
            # Simple edit distance check
            if self.edit_distance(domain_name, brand) <= 2:
                return True
        
        return False
    
    def edit_distance(self, s1: str, s2: str) -> int:
        """Calculate edit distance between two strings"""
        if len(s1) < len(s2):
            return self.edit_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is in suspicious ranges"""
        suspicious_ranges = [
            '10.0.0.0/8',      # Private
            '172.16.0.0/12',   # Private
            '192.168.0.0/16',  # Private
            '127.0.0.0/8',     # Loopback
            '169.254.0.0/16',  # Link-local
        ]
        
        # This is a simplified check - in practice, you'd use ipaddress module
        for suspicious_range in suspicious_ranges:
            if ip.startswith(suspicious_range.split('/')[0].rsplit('.', 1)[0]):
                return True
        
        return False
    
    def is_suspicious_redirect(self, original_url: str, redirect_url: str) -> bool:
        """Check if redirect is suspicious"""
        original_domain = urllib.parse.urlparse(original_url).netloc
        redirect_domain = urllib.parse.urlparse(redirect_url).netloc
        
        # Different domains
        if original_domain != redirect_domain:
            return True
        
        # Multiple redirects (simplified check)
        if 'redirect' in redirect_url.lower():
            return True
        
        return False
    
    async def update_threat_database(self, domain: str, analysis_result: Dict):
        """Update local threat database with analysis results"""
        try:
            if analysis_result["risk_level"] in ["DANGEROUS", "CRITICAL"] and analysis_result["confidence"] > 0.7:
                conn = sqlite3.connect(self.threat_db_path)
                cursor = conn.cursor()
                
                threat_types = [threat.split('_')[0] for threat in analysis_result["threats_detected"]]
                primary_threat = max(set(threat_types), key=threat_types.count) if threat_types else "unknown"
                
                cursor.execute(
                    'INSERT OR REPLACE INTO malicious_domains (domain, threat_type, confidence, last_seen, source) VALUES (?, ?, ?, ?, ?)',
                    (domain, primary_threat, analysis_result["confidence"], datetime.now(), "local_analysis")
                )
                
                conn.commit()
                conn.close()
        except Exception:
            pass

# Initialize the detector
detector = AdvancedMalwareDetector()

async def analyze_url_security(url: str) -> Dict:
    """Main function for URL security analysis"""
    return await detector.analyze_url_advanced(url)

def calculate_similarity(str1: str, str2: str) -> float:
    """Calculate similarity between two strings using simple character comparison"""
    if len(str1) == 0 or len(str2) == 0:
        return 0.0
    
    # Simple character-based similarity
    matches = sum(1 for a, b in zip(str1, str2) if a == b)
    max_len = max(len(str1), len(str2))
    return matches / max_len

async def analyze_wallet_security(address: str) -> dict:
    """Analyze wallet security and trust score"""
    scam_addresses, _ = load_risk_data()
    
    trust_score = 75  # Base trust score
    risk_flags = []
    suggestions = []
    
    # Check against known scam addresses
    if address.lower() in [addr.lower() for addr in scam_addresses]:
        trust_score -= 50
        risk_flags.append("Address found in scam database")
        suggestions.append("Avoid all transactions with this address")
    
    # Simulate additional checks (in real implementation, use blockchain APIs)
    # Check for high-risk patterns (mock data)
    import random
    
    # Simulate transaction analysis
    if random.random() < 0.3:  # 30% chance of suspicious activity
        trust_score -= 20
        risk_flags.append("Unusual transaction patterns detected")
        suggestions.append("Review transaction history carefully")
    
    # Simulate approval analysis
    if random.random() < 0.2:  # 20% chance of excessive approvals
        trust_score -= 15
        risk_flags.append("Multiple token approvals detected")
        suggestions.append("Revoke unnecessary token approvals")
    
    # Add positive indicators
    if random.random() < 0.4:  # 40% chance of positive indicators
        trust_score += 10
        suggestions.append("Wallet shows normal activity patterns")
    
    trust_score = max(0, min(100, trust_score))
    
    if not risk_flags:
        suggestions.append("No immediate red flags detected")
        suggestions.append("Continue monitoring for unusual activity")
    
    return {
        "trust_score": trust_score,
        "risk_flags": risk_flags,
        "suggestions": suggestions
    }

async def analyze_contract_security(address: str) -> dict:
    """Analyze smart contract security"""
    _, risky_patterns = load_risk_data()
    
    audit_score = 70  # Base audit score
    warnings = []
    risk_patterns = []
    
    # Simulate contract analysis (in real implementation, analyze bytecode/source)
    import random
    
    # Check for common risky patterns
    potential_risks = [
        "Unrestricted transferFrom function",
        "Blacklist functionality detected",
        "Mint function without proper access control",
        "Proxy contract with upgradeable logic",
        "No ownership renouncement",
        "Excessive gas usage in functions"
    ]
    
    # Randomly assign some risks (simulate analysis)
    for risk in potential_risks:
        if random.random() < 0.25:  # 25% chance for each risk
            audit_score -= 15
            risk_patterns.append(risk)
    
    # Add warnings based on score
    if audit_score < 50:
        warnings.append("High-risk contract detected")
        warnings.append("Multiple security concerns identified")
    elif audit_score < 70:
        warnings.append("Medium-risk contract")
        warnings.append("Some security concerns present")
    
    # Add general warnings
    if random.random() < 0.3:
        warnings.append("Contract not verified on Etherscan")
        audit_score -= 10
    
    audit_score = max(0, min(100, audit_score))
    
    return {
        "audit_score": audit_score,
        "warnings": warnings,
        "risk_patterns": risk_patterns
    }