"""
Blacklist Checker Module
Checks passwords against common/weak passwords
"""

import os
from typing import Set


class BlacklistChecker:
    """Checks passwords against blacklist of common passwords"""
    
    def __init__(self, blacklist_file: str = None):
        """
        Initialize blacklist checker
        
        Args:
            blacklist_file (str): Path to blacklist file (one password per line)
        """
        self.blacklist: Set[str] = set()
        self.blacklist_loaded = False
        
        if blacklist_file and os.path.exists(blacklist_file):
            self.load_blacklist(blacklist_file)
        else:
            # Load default common passwords
            self._load_default_blacklist()
    
    def load_blacklist(self, filepath: str) -> bool:
        """
        Load blacklist from file
        
        Args:
            filepath (str): Path to blacklist file
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                self.blacklist = set(line.strip().lower() for line in f if line.strip())
            self.blacklist_loaded = True
            return True
        
        except Exception as e:
            print(f"Error loading blacklist: {e}")
            self._load_default_blacklist()
            return False
    
    def _load_default_blacklist(self):
        """Load a basic default blacklist of common weak passwords"""
        # Top 100 most common passwords (simplified)
        self.blacklist = {
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
            'baseball', '111111', 'iloveyou', 'master', 'sunshine',
            'ashley', 'bailey', 'passw0rd', 'shadow', '123123',
            '654321', 'superman', 'qazwsx', 'michael', 'football',
            'hello', 'login', 'welcome', 'admin', 'root',
            'toor', 'pass', '1234', '4321', 'pass123',
            'password123', 'qwerty123', 'admin123', 'root123',
            'test', 'guest', 'user', 'username', 'password1',
            '123456789', 'aaaa', 'abcd1234', 'password!',
            'starwars', 'princess', 'solo', 'luke', 'leia',
            'yoda', 'chewie', 'vader', 'kylo', 'rey'
        }
        self.blacklist_loaded = True
    
    def is_blacklisted(self, password: str) -> bool:
        """
        Check if password is in blacklist
        
        Args:
            password (str): Password to check
        
        Returns:
            bool: True if password is blacklisted
        """
        return password.lower() in self.blacklist
    
    def check_variations(self, password: str) -> dict:
        """
        Check password and common variations
        
        Args:
            password (str): Password to check
        
        Returns:
            dict: Results of blacklist checks
        """
        lower = password.lower()
        reversed_pass = password[::-1].lower()
        
        return {
            'exact_match': lower in self.blacklist,
            'reversed_match': reversed_pass in self.blacklist,
            'base_blacklisted': lower in self.blacklist or reversed_pass in self.blacklist,
            'similar_to_common': self._check_similarity(password)
        }
    
    def _check_similarity(self, password: str) -> bool:
        """
        Check if password is similar to common passwords
        (simple check for obvious patterns)
        
        Args:
            password (str): Password to check
        
        Returns:
            bool: True if password matches obvious patterns
        """
        lower = password.lower()
        
        # Check for sequential patterns
        if 'qwerty' in lower or 'asdf' in lower or 'zxcv' in lower:
            return True
        
        # Check for numeric sequences
        if '123' in lower or '456' in lower or '789' in lower:
            return True
        
        return False


def create_blacklist_file(filepath: str, passwords: list):
    """
    Create a blacklist file from a list of passwords
    
    Args:
        filepath (str): Path where to save blacklist file
        passwords (list): List of passwords to add to blacklist
    """
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            for password in passwords:
                f.write(f"{password}\n")
        return True
    
    except Exception as e:
        print(f"Error creating blacklist file: {e}")
        return False
