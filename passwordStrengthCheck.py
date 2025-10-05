import re
import hashlib
from urllib.request import urlopen
from urllib.error import URLError
from collections import Counter

class PasswordStrengthAnalyzer:
    """
    Analyzes password strength and checks against known data breaches.
    Demonstrates understanding of authentication security, NIST guidelines, and HIBP API.
    """
    
    def __init__(self):
        self.common_passwords = self._load_common_passwords()
        
    def _load_common_passwords(self):
        """Load list of most common passwords"""
        # Top 100 most common passwords (simplified for demo)
        return {
            'password', '123456', '123456789', 'qwerty', 'abc123', 
            'password1', '12345678', '111111', '123123', 'admin',
            'letmein', 'welcome', 'monkey', 'dragon', 'master',
            'sunshine', 'princess', 'football', 'iloveyou', 'superman'}
        
    
    def analyze_password(self, password):
        """
        Comprehensive password analysis with scoring
        
        Args:
            password (str): Password to analyze
            
        Returns:
            dict: Analysis results with score, strength, and recommendations
        """
        results = {
            'password': '*' * len(password),  # Don't display actual password
            'length': len(password),
            'score': 0,
            'max_score': 100,
            'strength': '',
            'checks': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Check 1: Length (30 points max)
        length_score = self._check_length(password)
        results['score'] += length_score
        results['checks']['length'] = {
            'passed': length_score >= 20,
            'score': length_score,
            'max': 30
        }
        
        # Check 2: Character variety (30 points max)
        variety_score = self._check_variety(password)
        results['score'] += variety_score
        results['checks']['variety'] = {
            'passed': variety_score >= 20,
            'score': variety_score,
            'max': 30
        }
        
        # Check 3: Common password check (20 points)
        is_common = password.lower() in self.common_passwords
        if not is_common:
            results['score'] += 20
        else:
            results['vulnerabilities'].append('Password found in common password list')
        results['checks']['common_password'] = {
            'passed': not is_common,
            'score': 0 if is_common else 20,
            'max': 20
        }
        
        # Check 4: Pattern detection (20 points)
        has_patterns = self._detect_patterns(password)
        if not has_patterns:
            results['score'] += 20
        else:
            results['vulnerabilities'].extend(has_patterns)
        results['checks']['patterns'] = {
            'passed': not has_patterns,
            'score': 0 if has_patterns else 20,
            'max': 20
        }
        
        # Determine overall strength
        results['strength'] = self._calculate_strength(results['score'])
        
        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(results)
        
        return results
    
    def _check_length(self, password):
        """Score based on password length (NIST recommends 8+ characters)"""
        length = len(password)
        if length < 8:
            return 0
        elif length < 12:
            return 15
        elif length < 16:
            return 25
        else:
            return 30
    
    def _check_variety(self, password):
        """Score based on character type variety"""
        score = 0
        
        if re.search(r'[a-z]', password):  # Lowercase
            score += 7
        if re.search(r'[A-Z]', password):  # Uppercase
            score += 7
        if re.search(r'[0-9]', password):  # Numbers
            score += 8
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):  # Special chars
            score += 8
        
        return score
    
    def _detect_patterns(self, password):
        """Detect common weak patterns"""
        vulnerabilities = []
        
        # Sequential characters (abc, 123)
        if re.search(r'(abc|bcd|cde|def|123|234|345|456|567|678|789)', password.lower()):
            vulnerabilities.append('Contains sequential characters')
        
        # Repeated characters (aaa, 111)
        if re.search(r'(.)\1{2,}', password):
            vulnerabilities.append('Contains repeated characters')
        
        # Keyboard patterns (qwerty, asdf)
        keyboard_patterns = ['qwerty', 'asdf', 'zxcv', 'qwertyuiop']
        if any(pattern in password.lower() for pattern in keyboard_patterns):
            vulnerabilities.append('Contains keyboard pattern')
        
        # Common substitutions (@ for a, 3 for e, etc.)
        if re.search(r'p@ssw0rd|p4ssw0rd|passw0rd', password.lower()):
            vulnerabilities.append('Uses predictable character substitutions')
        
        return vulnerabilities
    
    def _calculate_strength(self, score):
        """Convert numeric score to strength rating"""
        if score < 40:
            return 'WEAK'
        elif score < 60:
            return 'FAIR'
        elif score < 80:
            return 'GOOD'
        else:
            return 'STRONG'
    
    def _generate_recommendations(self, results):
        """Generate specific recommendations based on analysis"""
        recommendations = []
        
        if results['length'] < 12:
            recommendations.append('Increase length to at least 12 characters')
        
        if results['checks']['variety']['score'] < 20:
            if not re.search(r'[A-Z]', results['password']):
                recommendations.append('Add uppercase letters')
            if not re.search(r'[0-9]', results['password']):
                recommendations.append('Add numbers')
            if not re.search(r'[!@#$%^&*()]', results['password']):
                recommendations.append('Add special characters')
        
        if results['vulnerabilities']:
            recommendations.append('Avoid common patterns and predictable substitutions')
        
        if results['score'] < 80:
            recommendations.append('Consider using a passphrase (e.g., "Coffee!Morning@2024")')
        
        return recommendations
    
    def check_breach(self, password):
        """
        Check if password appears in known data breaches using HIBP API.
        Uses k-anonymity model - only sends first 5 chars of hash.
        
        Args:
            password (str): Password to check
            
        Returns:
            dict: Breach information
        """
        try:
            # Hash the password using SHA-1
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            
            # k-anonymity: Only send first 5 characters
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Query HIBP API using urllib (built-in, no install needed)
            url = f'https://api.pwnedpasswords.com/range/{prefix}'
            
            with urlopen(url, timeout=5) as response:
                if response.status == 200:
                    # Check if our hash suffix appears in results
                    response_text = response.read().decode('utf-8')
                    hashes = response_text.split('\r\n')
                hashes = response_text.split('\r\n')
                for hash_line in hashes:
                    if ':' in hash_line:
                        hash_suffix, count = hash_line.split(':')
                        if hash_suffix == suffix:
                            return {
                                'breached': True,
                                'count': int(count),
                                'message': f'⚠️  CRITICAL: Password found in {count:,} data breaches!'
                            }
                
                return {
                    'breached': False,
                    'count': 0,
                    'message': '✓ Password not found in known breaches'
                }
                
        except URLError as e:
            return {
                'error': True,
                'message': f'Network error: Unable to reach breach database'
            }
        except Exception as e:
            return {
                'error': True,
                'message': f'Error checking breaches: {str(e)}'
            }
    
    def generate_report(self, password, check_breaches=True):
        """
        Generate comprehensive security report
        
        Args:
            password (str): Password to analyze
            check_breaches (bool): Whether to check against breach database
            
        Returns:
            str: Formatted report
        """
        # Perform analysis
        analysis = self.analyze_password(password)
        
        # Build report
        report = []
        report.append("=" * 70)
        report.append("PASSWORD SECURITY ANALYSIS REPORT")
        report.append("=" * 70)
        report.append("")
        
        # Overall score
        report.append(f"Overall Strength: {analysis['strength']}")
        report.append(f"Security Score: {analysis['score']}/{analysis['max_score']}")
        report.append("")
        
        # Detailed checks
        report.append("Detailed Analysis:")
        report.append("-" * 70)
        report.append(f"Length: {analysis['length']} characters "
                     f"[{'✓' if analysis['checks']['length']['passed'] else '✗'}] "
                     f"({analysis['checks']['length']['score']}/30 points)")
        
        report.append(f"Character Variety: "
                     f"[{'✓' if analysis['checks']['variety']['passed'] else '✗'}] "
                     f"({analysis['checks']['variety']['score']}/30 points)")
        
        report.append(f"Common Password Check: "
                     f"[{'✓' if analysis['checks']['common_password']['passed'] else '✗'}] "
                     f"({analysis['checks']['common_password']['score']}/20 points)")
        
        report.append(f"Pattern Detection: "
                     f"[{'✓' if analysis['checks']['patterns']['passed'] else '✗'}] "
                     f"({analysis['checks']['patterns']['score']}/20 points)")
        report.append("")
        
        # Vulnerabilities
        if analysis['vulnerabilities']:
            report.append("⚠️  Vulnerabilities Detected:")
            for vuln in analysis['vulnerabilities']:
                report.append(f"  • {vuln}")
            report.append("")
        
        # Breach check
        if check_breaches:
            report.append("Data Breach Check:")
            report.append("-" * 70)
            breach_info = self.check_breach(password)
            report.append(breach_info['message'])
            report.append("")
        
        # Recommendations
        if analysis['recommendations']:
            report.append("Recommendations:")
            report.append("-" * 70)
            for i, rec in enumerate(analysis['recommendations'], 1):
                report.append(f"{i}. {rec}")
            report.append("")
        
        report.append("=" * 70)
        report.append("Security Best Practices:")
        report.append("• Use unique passwords for each account")
        report.append("• Enable multi-factor authentication (MFA)")
        report.append("• Use a password manager")
        report.append("• Never share passwords")
        report.append("• Update passwords if a breach is detected")
        report.append("=" * 70)
        
        return '\n'.join(report)


def main():
    """Demo the password analyzer"""
    analyzer = PasswordStrengthAnalyzer()
    
    print("🔒 PASSWORD STRENGTH ANALYZER")
    print("Demonstrates cybersecurity principles for authentication security\n")
    
    # Test passwords (from weak to strong)
    test_passwords = [
        "password",           # Very weak - common password
        "Password1",          # Weak - predictable pattern
        "P@ssw0rd123",       # Fair - has variety but common substitutions
        "MyD0g&M3!",         # Good - variety but short
        "Coffee!Morning@2024" # Strong - long, varied, no patterns
    ]
    
    for password in test_passwords:
        print(analyzer.generate_report(password, check_breaches=True))
        print("\n" + "="*70 + "\n")
    
    # Interactive mode
    print("\nInteractive Mode - Enter your own password to test:")
    user_password = input("Password: ")
    if user_password:
        print("\n" + analyzer.generate_report(user_password, check_breaches=True))


if __name__ == "__main__":
    main()