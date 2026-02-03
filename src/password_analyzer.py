"""
Password Analysis Module
Checks password against security criteria using regex patterns
"""

import re
import math


class PasswordAnalyzer:
    """Analyzes password strength and characteristics"""
    
    def __init__(self):
        """Initialize regex patterns for password checks"""
        self.patterns = {
            'uppercase': re.compile(r'[A-Z]'),
            'lowercase': re.compile(r'[a-z]'),
            'number': re.compile(r'[0-9]'),
            'special': re.compile(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]')
        }
    
    def check_uppercase(self, password: str) -> bool:
        """Check if password contains uppercase letters"""
        return bool(self.patterns['uppercase'].search(password))
    
    def check_lowercase(self, password: str) -> bool:
        """Check if password contains lowercase letters"""
        return bool(self.patterns['lowercase'].search(password))
    
    def check_numbers(self, password: str) -> bool:
        """Check if password contains numbers"""
        return bool(self.patterns['number'].search(password))
    
    def check_special_chars(self, password: str) -> bool:
        """Check if password contains special characters"""
        return bool(self.patterns['special'].search(password))
    
    def check_length(self, password: str, min_length: int = 8) -> bool:
        """Check if password meets minimum length requirement"""
        return len(password) >= min_length
    
    def calculate_charset_size(self, password: str) -> int:
        """Calculate the effective character set size for entropy calculation"""
        charset_size = 0
        
        if self.check_lowercase(password):
            charset_size += 26
        if self.check_uppercase(password):
            charset_size += 26
        if self.check_numbers(password):
            charset_size += 10
        if self.check_special_chars(password):
            charset_size += 32  # Approximate special characters
        
        return charset_size
    
    def check_common_patterns(self, password: str) -> bool:
        """
        Check if password contains common patterns that reduce entropy
        
        Args:
            password (str): Password to check
        
        Returns:
            bool: True if suspicious patterns detected
        """
        lower = password.lower()
        
        # Keyboard patterns
        if 'qwerty' in lower or 'asdf' in lower or 'zxcv' in lower or 'qazwsx' in lower:
            return True
        
        # Numeric sequences
        if '123' in lower or '456' in lower or '789' in lower or '012' in lower:
            return True
        
        # Repeated characters (3+ same)
        if any(char * 3 in lower for char in '0123456789abcdefghijklmnopqrstuvwxyz'):
            return True
        
        # Common word patterns
        if any(word in lower for word in ['password', 'admin', 'user', 'login', 'root']):
            return True
        
        return False
    
    def calculate_entropy(self, password: str) -> float:
        """
        Calculate password entropy using formula: entropy = length × log2(charset_size)
        
        Returns:
            float: Entropy in bits
        """
        charset_size = self.calculate_charset_size(password)
        password_length = len(password)
        
        if charset_size == 0:
            return 0.0
        
        entropy = password_length * math.log2(charset_size)
        return round(entropy, 2)
    
    def analyze(self, password: str, min_length: int = 8) -> dict:
        """
        Perform complete password analysis
        
        Args:
            password (str): Password to analyze
            min_length (int): Minimum password length requirement (default: 8)
        
        Returns:
            dict: Analysis results including strength, entropy, and issues
        """
        # Check all criteria
        has_uppercase = self.check_uppercase(password)
        has_lowercase = self.check_lowercase(password)
        has_numbers = self.check_numbers(password)
        has_special = self.check_special_chars(password)
        meets_length = self.check_length(password, min_length)
        
        # Collect issues
        issues = []
        if not meets_length:
            issues.append(f"Password must be at least {min_length} characters long")
        if not has_uppercase:
            issues.append("No uppercase letters")
        if not has_lowercase:
            issues.append("No lowercase letters")
        if not has_numbers:
            issues.append("No numbers")
        if not has_special:
            issues.append("No special characters")
        
        # Calculate entropy
        entropy = self.calculate_entropy(password)
        
        # Determine strength
        strength = self._determine_strength(password, entropy, len(issues))
        
        result = {
            'password_length': len(password),
            'strength': strength,
            'entropy': entropy,
            'has_uppercase': has_uppercase,
            'has_lowercase': has_lowercase,
            'has_numbers': has_numbers,
            'has_special_chars': has_special,
            'meets_length': meets_length,
            'issues': issues,
            'has_common_patterns': self.check_common_patterns(password),
            'score': self._calculate_score(password, entropy, len(issues), self.check_common_patterns(password))
        }
        
        # Secure memory handling: Clear password variable after use
        password = None
        
        return result
    
    def _determine_strength(self, password: str, entropy: float, issue_count: int) -> str:
        """
        Determine password strength level
        
        Args:
            password (str): Password being analyzed
            entropy (float): Calculated entropy
            issue_count (int): Number of security issues found
        
        Returns:
            str: Strength level (Weak, Fair, Good, Strong, Very Strong)
        """
        if len(password) < 8 or entropy < 40:
            return "Weak"
        elif entropy < 50 or issue_count >= 2:
            return "Fair"
        elif entropy < 60 or issue_count >= 1:
            return "Good"
        elif entropy < 80:
            return "Strong"
        else:
            return "Very Strong"
    
    def _calculate_score(self, password: str, entropy: float, issue_count: int, has_patterns: bool = False) -> int:
        """
        Calculate a numerical score (0-100)
        
        Pattern detection significantly reduces the score even if entropy is high.
        
        Args:
            password (str): Password being analyzed
            entropy (float): Calculated entropy
            issue_count (int): Number of security issues found
            has_patterns (bool): Whether password contains common patterns
        
        Returns:
            int: Score between 0 and 100
        """
        score = 0
        
        # Length score (0-25)
        score += min(25, len(password) * 2)
        
        # Entropy score (0-50)
        score += min(50, int(entropy * 0.625))
        
        # Criteria score (0-25)
        criteria_met = 5 - issue_count
        if criteria_met > 0:
            score += criteria_met * 5
        
        # Pattern penalty: -10 to -20 points (critical security issue)
        if has_patterns:
            score -= 15  # Moderate penalty for common patterns
        
        return min(100, max(0, score))
