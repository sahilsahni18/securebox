from flask import Flask, request, jsonify
import psycopg2
from psycopg2.extras import RealDictCursor
import redis
from minio import Minio
from minio.error import S3Error
import os
import logging
from datetime import datetime, timedelta
import json
import secrets
# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
app = Flask(__name__)
# ============================================
# SECTION 1: Database Configuration
# ============================================
# Why environment variables? Different credentials for dev/prod
DB_CONFIG = {
    'host': os.getenv('POSTGRES_HOST', 'localhost'),
    'port': int(os.getenv('POSTGRES_PORT', 5432)),
    'database': os.getenv('POSTGRES_DB', 'securebox'),
    'user': os.getenv('POSTGRES_USER', 'securebox_user'),
    'password': os.getenv('POSTGRES_PASSWORD', 'secure_password')
}
# ============================================
# SECTION 2: MinIO Configuration  
# ============================================
MINIO_ENDPOINT = os.getenv('MINIO_ENDPOINT', 'localhost:9000')
MINIO_ACCESS_KEY = os.getenv('MINIO_ACCESS_KEY', 'minioadmin')
MINIO_SECRET_KEY = os.getenv('MINIO_SECRET_KEY', 'minioadmin')
MINIO_BUCKET = os.getenv('MINIO_BUCKET_NAME', 'securebox-files')
MINIO_SECURE = os.getenv('MINIO_SECURE', 'false').lower() == 'true'
# ============================================
# SECTION 3: Redis Setup
# ============================================
REDIS_URL = os.getenv('REDIS_URL')
if REDIS_URL:
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
else:
    redis_client = redis.Redis(
        host=os.getenv('REDIS_HOST', 'localhost'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        password=os.getenv('REDIS_PASSWORD'),
        ssl=os.getenv('REDIS_SSL', 'false').lower() == 'true',
        decode_responses=True
    )
# ============================================
# SECTION 4: MinIO Client
# ============================================
minio_client = Minio(
    MINIO_ENDPOINT,
    access_key=MINIO_ACCESS_KEY,
    secret_key=MINIO_SECRET_KEY,
    secure=MINIO_SECURE
)
# ============================================
# SECTION 5: Helper Functions
# ============================================
def get_db_connection():
    """Get database connection"""
    try:
        return psycopg2.connect(**DB_CONFIG)
    except Exception as e:
        logger.error(f"Database connection failed: {str(e)}")
        raise
def init_minio():
    """Initialize MinIO bucket"""
    # Why? Bucket must exist before we can store files
    try:
        if not minio_client.bucket_exists(MINIO_BUCKET):
            minio_client.make_bucket(MINIO_BUCKET)
            logger.info(f"Created MinIO bucket: {MINIO_BUCKET}")
        else:
            logger.info(f"MinIO bucket exists: {MINIO_BUCKET}")
    except Exception as e:
        logger.error(f"MinIO initialization failed: {str(e)}")
        raise
# Initialize on startup
try:
    init_minio()
except Exception as e:
    logger.critical(f"Service initialization failed: {str(e)}")
    exit(1)
# ============================================
# SECTION 6: API Endpoints
# ============================================
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Test all connections
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        
        minio_client.bucket_exists(MINIO_BUCKET)
        redis_client.ping()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'services': {
                'database': 'healthy',
                'minio': 'healthy',
                'redis': 'healthy'
            }
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 503
@app.route('/store', methods=['POST'])
def store_file():
    """
    Store encrypted file and metadata
    
    Process:
    1. Validate request data
    2. Store encrypted file in MinIO
    3. Store metadata in PostgreSQL
    4. Cache metadata in Redis
    5. Return confirmation
    """
    try:
        data = request.get_json()
        
        # Step 1: Validate
        required_fields = ['file_id', 'filename', 'encrypted_content', 'encryption_key', 
                          'file_size', 'download_token', 'expiry_hours', 'content_type']
        
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        file_id = data['file_id']
        filename = data['filename']
        encrypted_content = data['encrypted_content']
        encryption_key = data['encryption_key']
        file_size = data['file_size']
        download_token = data['download_token']
        expiry_hours = data['expiry_hours']
        content_type = data['content_type']
        
        # Calculate expiration time
        expires_at = datetime.utcnow() + timedelta(hours=expiry_hours)
        
        # Generate unique object name in MinIO
        minio_object_name = f"{file_id}/{secrets.token_hex(8)}"
        
        logger.info(f"Storing file: {file_id}, size: {file_size} bytes")
        
        # Step 2: Store in MinIO
        import base64
        from io import BytesIO
        
        encrypted_bytes = base64.b64decode(encrypted_content)
        minio_client.put_object(
            MINIO_BUCKET,
            minio_object_name,
            BytesIO(encrypted_bytes),
            len(encrypted_bytes),
            content_type='application/octet-stream'
        )
        
        # Step 3: Store metadata in PostgreSQL
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO files (file_id, filename, file_size, content_type, download_token, 
                             encryption_key, expires_at, minio_object_name)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (file_id, filename, file_size, content_type, download_token, 
              encryption_key, expires_at, minio_object_name))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        # Step 4: Cache metadata
        file_metadata = {
            'file_id': file_id,
            'filename': filename,
            'file_size': file_size,
            'content_type': content_type,
            'expires_at': expires_at.isoformat(),
            'minio_object_name': minio_object_name
        }
        
        redis_client.setex(
            f"file_meta:{file_id}",
            expiry_hours * 3600,
            json.dumps(file_metadata)
        )
        
        logger.info(f"File stored successfully: {file_id}")
        
        # Step 5: Return confirmation
        return jsonify({
            'file_id': file_id,
            'status': 'stored',
            'expires_at': expires_at.isoformat(),
            'minio_object': minio_object_name
        }), 200
        
    except S3Error as e:
        logger.error(f"MinIO storage error: {str(e)}")
        return jsonify({'error': 'Storage service error'}), 500
    except Exception as e:
        logger.error(f"Storage error: {str(e)}")
        return jsonify({'error': 'Storage failed'}), 500
@app.route('/retrieve/<file_id>', methods=['GET'])
def retrieve_file(file_id):
    """
    Retrieve encrypted file and metadata
    
    Security checks:
    1. Valid token required
    2. File not expired
    3. Not already downloaded
    """
    try:
        token = request.args.get('token')
        if not token:
            return jsonify({'error': 'Download token required'}), 400
        
        # Get file metadata from database
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT * FROM files 
            WHERE file_id = %s AND download_token = %s
        """, (file_id, token))
        
        file_record = cursor.fetchone()
        
        if not file_record:
            cursor.close()
            conn.close()
            return jsonify({'error': 'File not found or invalid token'}), 404
        
        # Security check 1: Expired?
        if datetime.utcnow() > file_record['expires_at']:
            cursor.close()
            conn.close()
            return jsonify({'error': 'File has expired'}), 410
        
        # Security check 2: Already downloaded?
        if file_record['is_downloaded']:
            cursor.close()
            conn.close()
            return jsonify({'error': 'File has already been downloaded'}), 410
        
        cursor.close()
        conn.close()
        
        # Retrieve from MinIO
        try:
            response = minio_client.get_object(MINIO_BUCKET, file_record['minio_object_name'])
            encrypted_content = response.read()
            response.close()
            
            import base64
            encrypted_content_b64 = base64.b64encode(encrypted_content).decode('utf-8')
            
        except S3Error as e:
            logger.error(f"MinIO retrieval error: {str(e)}")
            return jsonify({'error': 'File not found in storage'}), 404
        
        logger.info(f"File retrieved successfully: {file_id}")
        
        return jsonify({
            'file_id': file_id,
            'filename': file_record['filename'],
            'file_size': file_record['file_size'],
            'content_type': file_record['content_type'],
            'encrypted_content': encrypted_content_b64,
            'encryption_key': file_record['encryption_key'],
            'created_at': file_record['created_at'].isoformat(),
            'expires_at': file_record['expires_at'].isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Retrieval error: {str(e)}")
        return jsonify({'error': 'Retrieval failed'}), 500
@app.route('/mark_downloaded/<file_id>', methods=['POST'])
def mark_file_downloaded(file_id):
    """Mark file as downloaded (enforces one-time download)"""
    try:
        data = request.get_json()
        token = data.get('token')
        
        if not token:
            return jsonify({'error': 'Download token required'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE files 
            SET is_downloaded = TRUE, downloaded_at = CURRENT_TIMESTAMP, 
                download_count = download_count + 1
            WHERE file_id = %s AND download_token = %s
        """, (file_id, token))
        
        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            return jsonify({'error': 'File not found or invalid token'}), 404
        
        conn.commit()
        cursor.close()
        conn.close()
        
        # Remove from cache
        redis_client.delete(f"file_meta:{file_id}")
        
        logger.info(f"File marked as downloaded: {file_id}")
        
        return jsonify({
            'file_id': file_id,
            'status': 'downloaded',
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Mark downloaded error: {str(e)}")
        return jsonify({'error': 'Operation failed'}), 500
@app.route('/stats', methods=['GET'])
def get_storage_stats():
    """Get storage service statistics"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total_files,
                COUNT(CASE WHEN is_downloaded THEN 1 END) as downloaded_files,
                COUNT(CASE WHEN expires_at < CURRENT_TIMESTAMP THEN 1 END) as expired_files,
                COUNT(CASE WHEN expires_at >= CURRENT_TIMESTAMP AND NOT is_downloaded THEN 1 END) as active_files,
                SUM(file_size) as total_size_bytes,
                AVG(file_size) as avg_file_size_bytes
            FROM files
        """)
        
        stats = cursor.fetchone()
        cursor.close()
        conn.close()
        
        return jsonify({
            'service': 'storage-service',
            'database': {
                'total_files': stats[0] or 0,
                'downloaded_files': stats[1] or 0,
                'expired_files': stats[2] or 0,
                'active_files': stats[3] or 0,
                'total_size_bytes': stats[4] or 0,
                'avg_file_size_bytes': float(stats[5] or 0)
            },
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Stats error: {str(e)}")
        return jsonify({'error': 'Stats unavailable'}), 500
if __name__ == '__main__':
    port = int(os.getenv('STORAGE_SERVICE_PORT', 8002))
    host = os.getenv('STORAGE_SERVICE_HOST', '0.0.0.0')
    
    logger.info(f"Starting Storage Service on {host}:{port}")
    app.run(host=host, port=port, debug=False)