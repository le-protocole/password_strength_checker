"""
Unit tests for Password Strength Checker
Run with: python -m pytest tests/test_password_analyzer.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.password_analyzer import PasswordAnalyzer
from src.password_hasher import PasswordHasher
from src.blacklist_checker import BlacklistChecker


def test_uppercase_detection():
    """Test uppercase letter detection"""
    analyzer = PasswordAnalyzer()
    assert analyzer.check_uppercase("Password123") == True
    assert analyzer.check_uppercase("password123") == False
    print("✓ Uppercase detection test passed")


def test_lowercase_detection():
    """Test lowercase letter detection"""
    analyzer = PasswordAnalyzer()
    assert analyzer.check_lowercase("PASSWORD123") == False
    assert analyzer.check_lowercase("PassWord123") == True
    print("✓ Lowercase detection test passed")


def test_number_detection():
    """Test number detection"""
    analyzer = PasswordAnalyzer()
    assert analyzer.check_numbers("Password") == False
    assert analyzer.check_numbers("Password123") == True
    print("✓ Number detection test passed")


def test_special_char_detection():
    """Test special character detection"""
    analyzer = PasswordAnalyzer()
    assert analyzer.check_special_chars("Password123") == False
    assert analyzer.check_special_chars("Password123!") == True
    print("✓ Special character detection test passed")


def test_length_check():
    """Test password length validation"""
    analyzer = PasswordAnalyzer()
    assert analyzer.check_length("short", 8) == False
    assert analyzer.check_length("LongPassword123", 8) == True
    print("✓ Length check test passed")


def test_entropy_calculation():
    """Test entropy calculation"""
    analyzer = PasswordAnalyzer()
    entropy = analyzer.calculate_entropy("Password123!")
    assert entropy > 0
    assert isinstance(entropy, float)
    print(f"✓ Entropy calculation test passed (entropy: {entropy} bits)")


def test_complete_analysis():
    """Test complete password analysis"""
    analyzer = PasswordAnalyzer()
    
    # Test weak password
    weak = analyzer.analyze("weak")
    assert weak['strength'] in ['Weak', 'Fair']
    assert len(weak['issues']) > 0
    
    # Test strong password
    strong = analyzer.analyze("MySecure@Pass123")
    assert strong['strength'] in ['Good', 'Strong', 'Very Strong']
    assert strong['score'] > 50
    
    print("✓ Complete analysis test passed")


def test_sha256_hashing():
    """Test SHA-256 hashing"""
    hasher = PasswordHasher()
    password = "TestPassword123"
    
    hash1, salt1 = hasher.sha256_hash(password)
    hash2, salt2 = hasher.sha256_hash(password)
    
    # Same password with different salt should produce different hashes
    assert hash1 != hash2
    assert salt1 != salt2
    
    # Verification should work
    assert hasher.verify_sha256(password, hash1, salt1) == True
    assert hasher.verify_sha256("WrongPassword", hash1, salt1) == False
    
    print("✓ SHA-256 hashing test passed")


def test_blacklist_checking():
    """Test blacklist functionality"""
    blacklist = BlacklistChecker()
    
    assert blacklist.is_blacklisted("password") == True
    assert blacklist.is_blacklisted("123456") == True
    assert blacklist.is_blacklisted("MyUnique@Pass123") == False
    
    print("✓ Blacklist checking test passed")


def test_password_variations():
    """Test blacklist checking of variations"""
    blacklist = BlacklistChecker()
    
    result = blacklist.check_variations("qwerty")
    assert result['exact_match'] == True
    
    result = blacklist.check_variations("MySecurePass")
    assert result['exact_match'] == False
    
    print("✓ Password variations test passed")


if __name__ == "__main__":
    print("\n" + "="*50)
    print("🧪 Running Password Strength Checker Tests")
    print("="*50 + "\n")
    
    try:
        test_uppercase_detection()
        test_lowercase_detection()
        test_number_detection()
        test_special_char_detection()
        test_length_check()
        test_entropy_calculation()
        test_complete_analysis()
        test_sha256_hashing()
        test_blacklist_checking()
        test_password_variations()
        
        print("\n" + "="*50)
        print("✅ All tests passed!")
        print("="*50 + "\n")
    
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}\n")
        sys.exit(1)
