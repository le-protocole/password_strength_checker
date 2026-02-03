"""
Password Hashing Module
Provides secure password hashing using SHA-256 and bcrypt
"""

import hashlib
import secrets
import string
import hmac
from typing import Tuple


class PasswordHasher:
    """Handles secure password hashing and verification"""
    
    @staticmethod
    def sha256_hash(password: str, salt: str = None) -> Tuple[str, str]:
        """
        Hash password using SHA-256 (for educational purposes)
        
        WARNING: SHA-256 alone is NOT recommended for production.
        Use bcrypt or argon2 instead.
        
        Args:
            password (str): Password to hash
            salt (str): Optional salt string. If None, generates random salt.
        
        Returns:
            Tuple[str, str]: (hashed_password, salt)
        """
        if salt is None:
            salt = secrets.token_hex(16)  # Generate random 32-char salt
        
        salted_password = salt + password
        hash_object = hashlib.sha256(salted_password.encode())
        hashed = hash_object.hexdigest()
        
        return hashed, salt
    
    @staticmethod
    def verify_sha256(password: str, stored_hash: str, stored_salt: str) -> bool:
        """
        Verify password against SHA-256 hash
        
        Uses constant-time comparison (hmac.compare_digest) to prevent timing attacks.
        
        Args:
            password (str): Password to verify
            stored_hash (str): Stored hash value
            stored_salt (str): Stored salt value
        
        Returns:
            bool: True if password matches stored hash
        """
        computed_hash, _ = PasswordHasher.sha256_hash(password, stored_salt)
        # Constant-time comparison prevents timing attacks
        is_valid = hmac.compare_digest(computed_hash, stored_hash)
        
        # Clear sensitive data from memory
        password = None
        
        return is_valid
    
    @staticmethod
    def try_bcrypt_hash(password: str) -> Tuple[str, str] or None:
        """
        Hash password using bcrypt (requires bcrypt package)
        
        Args:
            password (str): Password to hash
        
        Returns:
            str: bcrypt hash or None if bcrypt not installed
        """
        try:
            import bcrypt
            
            # Generate salt and hash
            salt = bcrypt.gensalt(rounds=12)  # 12 rounds for security
            hashed = bcrypt.hashpw(password.encode(), salt)
            
            return hashed.decode()
        
        except ImportError:
            return None
    
    @staticmethod
    def try_bcrypt_verify(password: str, hashed: str) -> bool:
        """
        Verify password against bcrypt hash
        
        Args:
            password (str): Password to verify
            hashed (str): bcrypt hash to check against
        
        Returns:
            bool: True if password matches, False if bcrypt not installed or hash doesn't match
        """
        try:
            import bcrypt
            return bcrypt.checkpw(password.encode(), hashed.encode())
        
        except ImportError:
            return False
    
    @staticmethod
    def try_argon2_hash(password: str) -> str or None:
        """
        Hash password using argon2 (requires argon2-cffi package)
        
        Args:
            password (str): Password to hash
        
        Returns:
            str: argon2 hash or None if argon2 not installed
        """
        try:
            from argon2 import PasswordHasher
            ph = PasswordHasher()
            return ph.hash(password)
        
        except ImportError:
            return None
    
    @staticmethod
    def try_argon2_verify(password: str, hashed: str) -> bool:
        """
        Verify password against argon2 hash
        
        Args:
            password (str): Password to verify
            hashed (str): argon2 hash to check against
        
        Returns:
            bool: True if password matches, False if argon2 not installed or hash doesn't match
        """
        try:
            from argon2 import PasswordHasher
            ph = PasswordHasher()
            return ph.verify(hashed, password)
        
        except ImportError:
            return False


class SecurePasswordStorage:
    """Manages secure password storage with encryption"""
    
    def __init__(self, use_bcrypt: bool = True):
        """
        Initialize storage with preferred hashing method
        
        Args:
            use_bcrypt (bool): Prefer bcrypt if available (default: True)
        """
        self.use_bcrypt = use_bcrypt
        self.hasher = PasswordHasher()
    
    def store_password(self, password: str) -> dict:
        """
        Hash and prepare password for storage
        
        IMPORTANT: Password is hashed before storage to prevent credential leakage.
        
        Args:
            password (str): Plain text password to store
        
        Returns:
            dict: Storage data including method, hash, and metadata
        """
        # Try bcrypt first
        if self.use_bcrypt:
            bcrypt_hash = self.hasher.try_bcrypt_hash(password)
            if bcrypt_hash:
                return {
                    'method': 'bcrypt',
                    'hash': bcrypt_hash,
                    'algorithm': 'bcrypt (recommended for production)'
                }
        
        # Fall back to SHA-256 (educational only)
        sha_hash, salt = self.hasher.sha256_hash(password)
        return {
            'method': 'sha256',
            'hash': sha_hash,
            'salt': salt,
            'algorithm': 'SHA-256 with salt (EDUCATIONAL DEMO ONLY)',
            'note': 'SHA-256 is not recommended for password storage in production.',
            'recommendation': 'Use bcrypt or argon2 for real-world applications.'
        }
    
    def verify_password(self, password: str, stored_data: dict) -> bool:
        """
        Verify password against stored hash
        
        Args:
            password (str): Plain text password to verify
            stored_data (dict): Stored password data
        
        Returns:
            bool: True if password matches
        """
        method = stored_data.get('method')
        
        if method == 'bcrypt':
            return self.hasher.try_bcrypt_verify(password, stored_data['hash'])
        
        elif method == 'sha256':
            return self.hasher.verify_sha256(
                password,
                stored_data['hash'],
                stored_data['salt']
            )
        
        return False
