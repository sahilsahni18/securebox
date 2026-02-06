from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import redis
import os
import logging
import secrets
import hashlib
from datetime import datetime, timedelta
import jwt
from io import BytesIO
# ============================================
# SECTION 1: Configuration & Setup
# ============================================
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_FILE_SIZE_MB', 100)) * 1024 * 1024
# ============================================
# SECTION 2: CORS Setup
# ============================================
# Why CORS? Frontend and backend might be on different domains
# Without this, browsers block the requests for security
CORS(app, resources={
    r"/*": {
        "origins": os.getenv('CORS_ORIGINS', '*').split(','),
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})
# ============================================
# SECTION 3: Rate Limiting
# ============================================
# Why? Prevent abuse - one user can't upload 1000 files/minute
REDIS_URL = os.getenv('REDIS_URL')
if REDIS_URL:
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
else:
    redis_client = redis.Redis(
        host=os.getenv('REDIS_HOST', 'localhost'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        decode_responses=True
    )
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=REDIS_URL or f"redis://{os.getenv('REDIS_HOST', 'localhost')}:6379",
    default_limits=["200 per day", "50 per hour"]
)
# ============================================
# SECTION 4: Service URLs
# ============================================
# How to reach other microservices
ENCRYPTION_SERVICE_URL = os.getenv('ENCRYPTION_SERVICE_URL', 'http://localhost:8001')
STORAGE_SERVICE_URL = os.getenv('STORAGE_SERVICE_URL', 'http://localhost:8002')
# JWT configuration (for optional authentication)
SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-dev-secret-change-in-production')
# Default expiry settings
DEFAULT_EXPIRY_HOURS = int(os.getenv('DEFAULT_EXPIRY_HOURS', 24))
MAX_EXPIRY_HOURS = int(os.getenv('MAX_EXPIRY_HOURS', 168))  # 7 days
# ============================================
# SECTION 5: Helper Functions
# ============================================
def generate_file_id() -> str:
    """Generate unique file ID"""
    return secrets.token_hex(16)  # 32 character hex string
def generate_download_token() -> str:
    """Generate secure download token"""
    return secrets.token_urlsafe(32)  # URL-safe random token
def generate_jwt_token(user_id: str) -> str:
    """Generate JWT for authenticated users"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')
# ============================================
# SECTION 6: API Endpoints
# ============================================
@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint
    
    Why important? 
    - Docker uses this to know if container is ready
    - Load balancers check this before routing traffic
    - Monitoring systems alert if this fails
    """
    try:
        # Check connectivity to dependencies
        encryption_health = requests.get(f"{ENCRYPTION_SERVICE_URL}/health", timeout=5)
        storage_health = requests.get(f"{STORAGE_SERVICE_URL}/health", timeout=5)
        redis_client.ping()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'api-gateway',
            'dependencies': {
                'encryption_service': 'healthy' if encryption_health.status_code == 200 else 'unhealthy',
                'storage_service': 'healthy' if storage_health.status_code == 200 else 'unhealthy',
                'redis': 'healthy'
            }
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 503
@app.route('/upload', methods=['POST'])
@limiter.limit("10 per minute")  # Max 10 uploads per minute per IP
def upload_file():
    """
    Handle file upload
    
    Process:
    1. Validate file upload
    2. Generate file_id and token
    3. Read file content
    4. Send to Encryption Service → get encrypted content
    5. Send encrypted content to Storage Service
    6. Cache token→file_id mapping
    7. Return download URL to user
    """
    try:
        logger.info("Processing file upload")
        
        # Step 1: Validate
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Get optional parameters
        expiry_hours = int(request.form.get('expiry_hours', DEFAULT_EXPIRY_HOURS))
        password = request.form.get('password')  # Optional password protection
        
        # Validate expiry
        if expiry_hours > MAX_EXPIRY_HOURS:
            return jsonify({'error': f'Maximum expiry is {MAX_EXPIRY_HOURS} hours'}), 400
        
        if expiry_hours < 1:
            return jsonify({'error': 'Minimum expiry is 1 hour'}), 400
        
        # Step 2: Generate IDs
        file_id = generate_file_id()
        download_token = generate_download_token()
        
        logger.info(f"Generated file_id: {file_id}")
        
        # Step 3: Read file
        file_content = file.read()
        file_size = len(file_content)
        
        logger.info(f"File size: {file_size} bytes")
        
        # Step 4: Encrypt
        encryption_request = {
            'file_id': file_id,
            'content': file_content.hex(),  # Convert bytes to hex string
            'password': password
        }
        
        logger.info(f"Sending to Encryption Service: {ENCRYPTION_SERVICE_URL}/encrypt")
        
        encryption_response = requests.post(
            f"{ENCRYPTION_SERVICE_URL}/encrypt",
            json=encryption_request,
            timeout=30
        )
        
        if encryption_response.status_code != 200:
            logger.error(f"Encryption failed: {encryption_response.text}")
            return jsonify({'error': 'Encryption failed'}), 500
        
        encryption_data = encryption_response.json()
        encrypted_content = encryption_data['encrypted_content']
        encryption_key = encryption_data['encryption_key']
        
        logger.info("File encrypted successfully")
        
        # Step 5: Store
        storage_request = {
            'file_id': file_id,
            'filename': file.filename,
            'encrypted_content': encrypted_content,
            'encryption_key': encryption_key,
            'file_size': file_size,
            'download_token': download_token,
            'expiry_hours': expiry_hours,
            'content_type': file.content_type or 'application/octet-stream'
        }
        
        logger.info(f"Sending to Storage Service: {STORAGE_SERVICE_URL}/store")
        
        storage_response = requests.post(
            f"{STORAGE_SERVICE_URL}/store",
            json=storage_request,
            timeout=30
        )
        
        if storage_response.status_code != 200:
            logger.error(f"Storage failed: {storage_response.text}")
            return jsonify({'error': 'Storage failed'}), 500
        
        storage_data = storage_response.json()
        
        logger.info("File stored successfully")
        
        # Step 6: Cache token mapping
        redis_client.setex(
            f"token:{download_token}",
            expiry_hours * 3600,  # TTL in seconds
            file_id
        )
        
        # Step 7: Return success response
        download_url = f"/download/{download_token}"
        
        response_data = {
            'success': True,
            'file_id': file_id,
            'download_token': download_token,
            'download_url': download_url,
            'filename': file.filename,
            'file_size': file_size,
            'expires_at': storage_data['expires_at'],
            'expiry_hours': expiry_hours
        }
        
        logger.info(f"Upload successful: {file_id}")
        
        return jsonify(response_data), 200
        
    except requests.RequestException as e:
        logger.error(f"Service communication error: {str(e)}")
        return jsonify({'error': 'Service temporarily unavailable'}), 503
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({'error': 'Upload failed'}), 500
@app.route('/download/<token>', methods=['GET'])
@limiter.limit("20 per minute")  # Same user can download more frequently
def download_file(token):
    """
    Handle file download
    
    Process:
    1. Validate token
    2. Get file_id from cache
    3. Retrieve encrypted file from Storage Service
    4. Decrypt using Encryption Service
    5. Mark file as downloaded
    6. Send file to user
    7. Cleanup token
    """
    try:
        logger.info(f"Processing download for token: {token[:10]}...")
        
        # Step 1 & 2: Validate token and get file_id
        file_id = redis_client.get(f"token:{token}")
        
        if not file_id:
            logger.warning(f"Invalid or expired token: {token[:10]}")
            return jsonify({'error': 'Invalid or expired download link'}), 404
        
        # Step 3: Retrieve from storage
        logger.info(f"Retrieving file: {file_id}")
        
        storage_response = requests.get(
            f"{STORAGE_SERVICE_URL}/retrieve/{file_id}",
            params={'token': token},
            timeout=30
        )
        
        if storage_response.status_code == 410:
            # File expired or already downloaded
            redis_client.delete(f"token:{token}")
            return jsonify({'error': 'File has expired or already been downloaded'}), 410
        
        if storage_response.status_code != 200:
            logger.error(f"Storage retrieval failed: {storage_response.text}")
            return jsonify({'error': 'File not found'}), 404
        
        storage_data = storage_response.json()
        
        # Step 4: Decrypt
        password = request.args.get('password')  # If file was password-protected
        
        decryption_request = {
            'file_id': file_id,
            'encrypted_content': storage_data['encrypted_content'],
            'encryption_key': storage_data['encryption_key'],
            'password': password
        }
        
        logger.info("Decrypting file")
        
        decryption_response = requests.post(
            f"{ENCRYPTION_SERVICE_URL}/decrypt",
            json=decryption_request,
            timeout=30
        )
        
        if decryption_response.status_code == 401:
            return jsonify({'error': 'Invalid password'}), 401
        
        if decryption_response.status_code != 200:
            logger.error(f"Decryption failed: {decryption_response.text}")
            return jsonify({'error': 'Decryption failed'}), 500
        
        decryption_data = decryption_response.json()
        
        # Step 5: Mark as downloaded
        mark_response = requests.post(
            f"{STORAGE_SERVICE_URL}/mark_downloaded/{file_id}",
            json={'token': token},
            timeout=10
        )
        
        if mark_response.status_code != 200:
            logger.warning(f"Failed to mark as downloaded: {mark_response.text}")
        
        # Step 6: Send file
        file_content = bytes.fromhex(decryption_data['content'])
        
        logger.info(f"Sending file to user: {storage_data['filename']}")
        
        # Step 7: Cleanup
        redis_client.delete(f"token:{token}")
        
        return send_file(
            BytesIO(file_content),
            mimetype=storage_data['content_type'],
            as_attachment=True,
            download_name=storage_data['filename']
        )
        
    except requests.RequestException as e:
        logger.error(f"Service communication error: {str(e)}")
        return jsonify({'error': 'Service temporarily unavailable'}), 503
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        return jsonify({'error': 'Download failed'}), 500
@app.route('/status/<token>', methods=['GET'])
@limiter.limit("30 per minute")
def check_file_status(token):
    """
    Check file status without downloading
    
    Returns:
    - File metadata
    - Status (available, expired, downloaded)
    - Time until expiry
    """
    try:
        # Get file_id from token
        file_id = redis_client.get(f"token:{token}")
        
        if not file_id:
            return jsonify({
                'status': 'invalid',
                'message': 'Invalid or expired token'
            }), 404
        
        # Get status from storage
        storage_response = requests.get(
            f"{STORAGE_SERVICE_URL}/retrieve/{file_id}",
            params={'token': token},
            timeout=10
        )
        
        if storage_response.status_code == 410:
            return jsonify({
                'status': 'unavailable',
                'message': 'File has expired or been downloaded'
            }), 410
        
        if storage_response.status_code != 200:
            return jsonify({
                'status': 'error',
                'message': 'Unable to retrieve file status'
            }), 500
        
        storage_data = storage_response.json()
        
        # Calculate time remaining
        from dateutil import parser
        expires_at = parser.parse(storage_data['expires_at'])
        time_remaining = expires_at - datetime.utcnow()
        
        return jsonify({
            'status': 'available',
            'file_id': file_id,
            'filename': storage_data['filename'],
            'file_size': storage_data['file_size'],
            'content_type': storage_data['content_type'],
            'created_at': storage_data['created_at'],
            'expires_at': storage_data['expires_at'],
            'time_remaining_seconds': max(0, int(time_remaining.total_seconds())),
            'is_password_protected': 'password' in request.args  # Hint
        }), 200
        
    except Exception as e:
        logger.error(f"Status check error: {str(e)}")
        return jsonify({'error': 'Status check failed'}), 500
@app.route('/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    """
    Optional: JWT authentication endpoint
    
    For future expansion - user accounts, file history, etc.
    """
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        # TODO: Implement actual user authentication
        # This is a placeholder
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        # Generate JWT token
        token = generate_jwt_token(username)
        
        return jsonify({
            'token': token,
            'user_id': username,
            'expires_in': 86400  # 24 hours
        }), 200
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500
@app.route('/metrics', methods=['GET'])
def metrics():
    """
    Prometheus metrics endpoint
    
    Exports metrics for monitoring:
    - Request counts
    - Response times
    - Error rates
    """
    from prometheus_client import Counter, Histogram, generate_latest
    
    # Define metrics (in production, define these globally)
    request_counter = Counter('securebox_requests_total', 'Total requests', ['method', 'endpoint'])
    
    # Generate Prometheus format
    return generate_latest()
if __name__ == '__main__':
    port = int(os.getenv('API_GATEWAY_PORT', 5000))
    host = os.getenv('API_GATEWAY_HOST', '0.0.0.0')
    
    logger.info(f"Starting API Gateway on {host}:{port}")
    app.run(host=host, port=port, debug=False)