"""
Flask Backend API
RESTful API for password strength checking
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sys
import os
import logging

# Add parent directory to path to import src modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.password_analyzer import PasswordAnalyzer
from src.password_hasher import SecurePasswordStorage
from src.blacklist_checker import BlacklistChecker


app = Flask(__name__)
CORS(app)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["10 per minute"],
    storage_uri="memory://"
)

# Configure security logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)s | %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize components
analyzer = PasswordAnalyzer()
storage = SecurePasswordStorage(use_bcrypt=True)
blacklist = BlacklistChecker()


def log_analysis(analysis: dict, endpoint: str):
    """
    Log password analysis metadata (NO sensitive data)
    
    Args:
        analysis (dict): Analysis results
        endpoint (str): API endpoint name
    """
    logger.info(
        f"Password analyzed | endpoint={endpoint} | "
        f"entropy={analysis['entropy']} | score={analysis['score']} | "
        f"strength={analysis['strength']}"
    )


@app.route('/api/check-password', methods=['POST'])
@limiter.limit("10 per minute")
def check_password():
    """
    Check password strength
    
    Request JSON:
    {
        "password": "string"
    }
    
    Response JSON:
    {
        "strength": "string",
        "entropy": float,
        "score": int,
        "has_uppercase": bool,
        "has_lowercase": bool,
        "has_numbers": bool,
        "has_special_chars": bool,
        "meets_length": bool,
        "issues": [string],
        "is_blacklisted": bool
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'password' not in data:
            return jsonify({'error': 'Password field required'}), 400
        
        password = data['password']
        
        if not password or len(password) == 0:
            return jsonify({'error': 'Password cannot be empty'}), 400
        
        # Analyze password
        analysis = analyzer.analyze(password)
        
        # Check blacklist
        blacklist_result = blacklist.check_variations(password)
        
        # Prepare response
        response = {
            'strength': analysis['strength'],
            'entropy': analysis['entropy'],
            'score': analysis['score'],
            'password_length': analysis['password_length'],
            'has_uppercase': analysis['has_uppercase'],
            'has_lowercase': analysis['has_lowercase'],
            'has_numbers': analysis['has_numbers'],
            'has_special_chars': analysis['has_special_chars'],
            'meets_length': analysis['meets_length'],
            'issues': analysis['issues'],
            'is_blacklisted': blacklist_result['exact_match'],
            'is_similar_to_common': blacklist_result['similar_to_common']
        }
        
        # Log analysis (metadata only, no sensitive data)
        log_analysis(analysis, 'check-password')
        
        return jsonify(response), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/hash-password', methods=['POST'])
@limiter.limit("5 per minute")
def hash_password():
    """
    Hash a password securely
    
    Request JSON:
    {
        "password": "string"
    }
    
    Response JSON:
    {
        "method": "string",
        "hash": "string",
        "algorithm": "string"
    }
    
    WARNING: Never send raw passwords over HTTP. Use HTTPS only.
    """
    try:
        data = request.get_json()
        
        if not data or 'password' not in data:
            return jsonify({'error': 'Password field required'}), 400
        
        password = data['password']
        
        if not password:
            return jsonify({'error': 'Password cannot be empty'}), 400
        
        # Hash password
        stored_data = storage.store_password(password)
        
        response = {
            'method': stored_data['method'],
            'algorithm': stored_data['algorithm'],
            'hash_preview': stored_data['hash'][:32] + '...',
            'warning': 'This is for demonstration. Never send raw passwords over HTTP!'
        }
        
        # Add production recommendation
        if stored_data['method'] == 'sha256':
            response['note'] = 'SHA-256 is educational demo only. Use bcrypt or argon2 in production.'
            response['recommended_methods'] = ['bcrypt (12+ rounds)', 'argon2 (memory-hard)']
        
        # Log hashing operation (no sensitive data)
        logger.info(f"Password hashed | endpoint=hash-password | method={stored_data['method']}")
        
        return jsonify(response), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'running',
        'version': '1.0.0',
        'endpoints': [
            '/api/check-password (POST)',
            '/api/hash-password (POST)',
            '/api/health (GET)'
        ]29)
def ratelimit_handler(e):
    """Handle rate limit exceeded"""
    logger.warning(f"Rate limit exceeded from {get_remote_address()}")
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Maximum 10 per minute.',
        'retry_after': 60
    }), 429


@app.errorhandler(4
    }), 200

" + "="*60)
    print(" Password Strength Checker API")
    print("="*60)
    print("Starting Flask server...")
    print("📍 API running at http://localhost:5000")
    print("\n🛡 Security Features Enabled:")
    print("  ✓ Rate limiting (10 req/min)")
    print("  ✓ CORS protection")
    print("  ✓ Secure logging (no sensitive data)")
    print("  ✓ Constant-time hash comparison")
    print("  ✓ Memory cleanup for sensitive data")
    print("\nAvailable endpoints:")
    print("  POST /api/check-password - Check password strength")
    print("  POST /api/hash-password - Hash a password")
    print("  GET  /api/health - Health check")
    print("\n  WARNING: Use HTTPS in production!")
    print("="*605 errors"""
    return jsonify({'error': 'Method not allowed'}), 405


if __name__ == '__main__':
    print("\n Password Strength Checker API")
    print("="*50)
    print("Starting Flask server...")
    print(" API running at http://localhost:5000")
    print("\nAvailable endpoints:")
    print("  POST /api/check-password - Check password strength")
    print("  POST /api/hash-password - Hash a password")
    print("  GET  /api/health - Health check")
    print("\n  WARNING: Use HTTPS in production!")
    print("="*50 + "\n")
    
    app.run(debug=True, host='localhost', port=5000)
