#!/usr/bin/env python3
"""
Password Strength Checker - Main Application
Comprehensive password analysis and security tool
"""

import sys
import os
from src.password_analyzer import PasswordAnalyzer
from src.password_hasher import SecurePasswordStorage
from src.blacklist_checker import BlacklistChecker


def print_header():
    """Print application header"""
    print("\n" + "="*60)
    print(" PASSWORD STRENGTH CHECKER")
    print("="*60 + "\n")


def print_results(analysis: dict, blacklist_result: dict):
    """Print formatted analysis results"""
    print(f" ANALYSIS RESULTS:")
    print(f"  Length: {analysis['password_length']} characters")
    print(f"  Strength: {analysis['strength']} (Score: {analysis['score']}/100)")
    print(f"  Entropy: {analysis['entropy']} bits")
    
    print(f"\n CRITERIA MET:")
    print(f"  ✓ Uppercase: {'Yes' if analysis['has_uppercase'] else 'No'}")
    print(f"  ✓ Lowercase: {'Yes' if analysis['has_lowercase'] else 'No'}")
    print(f"  ✓ Numbers: {'Yes' if analysis['has_numbers'] else 'No'}")
    print(f"  ✓ Special Chars: {'Yes' if analysis['has_special_chars'] else 'No'}")
    print(f"  ✓ Min Length (8): {'Yes' if analysis['meets_length'] else 'No'}")
    
    if analysis['issues']:
        print(f"\n  ISSUES FOUND ({len(analysis['issues'])}):")
        for issue in analysis['issues']:
            print(f"  ✗ {issue}")
    else:
        print(f"\n NO ISSUES FOUND!")
    
    if blacklist_result['exact_match']:
        print(f"\n SECURITY ALERT: Password is on blacklist of common passwords!")
    elif blacklist_result['reversed_match']:
        print(f"\n SECURITY ALERT: Reversed password matches common password!")
    elif blacklist_result['similar_to_common']:
        print(f"\n  WARNING: Password matches common patterns (sequential keys, numbers)")


def test_password(password: str, show_hashing: bool = False):
    """
    Analyze a single password
    
    Args:
        password (str): Password to analyze
        show_hashing (bool): Whether to show hashing examples
    """
    print(f"\n Testing password: {'*' * len(password)}")
    print(f"   (Length: {len(password)})")
    
    # Analyze password
    analyzer = PasswordAnalyzer()
    analysis = analyzer.analyze(password)
    
    # Check blacklist
    blacklist = BlacklistChecker()
    blacklist_result = blacklist.check_variations(password)
    
    # Print results
    print_results(analysis, blacklist_result)
    
    # Show hashing example if requested
    if show_hashing:
        print(f"\n HASHING (EDUCATIONAL DEMO):")
        storage = SecurePasswordStorage(use_bcrypt=True)
        stored_data = storage.store_password(password)
        
        if stored_data['method'] == 'sha256':
            print(f"  Algorithm: SHA-256")
            print(f"  Salt: {stored_data['salt'][:16]}...")
            print(f"  Hash: {stored_data['hash'][:32]}...")
        else:
            print(f"  Algorithm: bcrypt")
            print(f"  Hash: {stored_data['hash'][:32]}...")
        
        print(f"\n  NOTE:")
        print(f"  - SHA-256 is shown for educational purposes only")
        print(f"  - Production systems MUST use bcrypt or argon2")


def interactive_mode():
    """Run in interactive mode"""
    print_header()
    print("Enter passwords to analyze (type 'quit' to exit)")
    print("-" * 60)
    
    while True:
        password = input("\n🔑 Enter password to analyze: ")
        
        if password.lower() in ['quit', 'exit', 'q']:
            print("\n Goodbye!")
            break
        
        if not password:
            print(" Please enter a password")
            continue
        
        test_password(password, show_hashing=True)
        print("\n" + "-" * 60)


def demo_mode():
    """Run demonstration with sample passwords"""
    print_header()
    print("Running demonstration with sample passwords...\n")
    
    test_passwords = [
        "weak",
        "Password123",
        "MyS3cur3P@ssw0rd!",
        "qwerty",  # Will be blacklisted
        "MyP@ssw0rd!2024"
    ]
    
    for i, pwd in enumerate(test_passwords, 1):
        print(f"\n{'='*60}")
        print(f"Example {i}/5")
        print('='*60)
        test_password(pwd, show_hashing=True)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "demo":
            demo_mode()
        elif sys.argv[1] == "test":
            if len(sys.argv) > 2:
                password = " ".join(sys.argv[2:])
                test_password(password, show_hashing=True)
            else:
                print("Usage: python main.py test <password>")
        else:
            print("Usage:")
            print("  Interactive mode: python main.py")
            print("  Demo mode: python main.py demo")
            print("  Test single password: python main.py test <password>")
    else:
        interactive_mode()
