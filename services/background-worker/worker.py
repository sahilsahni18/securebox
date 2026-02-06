from celery import Celery
from celery.schedules import crontab
import psycopg2
from minio import Minio
from minio.error import S3Error
import redis
import os
import logging
from datetime import datetime
# ============================================
# SECTION 1: Configuration
# ============================================
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
# ============================================
# SECTION 2: Celery Setup
# ============================================
# Celery needs a "broker" to queue tasks - we use Redis
celery_app = Celery('securebox_worker')
celery_app.conf.update(
    broker_url=os.getenv('REDIS_URL', 'redis://localhost:6379/0'),
    result_backend=os.getenv('REDIS_URL', 'redis://localhost:6379/0'),
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    timezone='UTC',
    enable_utc=True,
)
# ============================================
# SECTION 3: Database & Storage Config
# ============================================
DB_CONFIG = {
    'host': os.getenv('POSTGRES_HOST', 'localhost'),
    'port': int(os.getenv('POSTGRES_PORT', 5432)),
    'database': os.getenv('POSTGRES_DB', 'securebox'),
    'user': os.getenv('POSTGRES_USER', 'securebox_user'),
    'password': os.getenv('POSTGRES_PASSWORD', 'secure_password')
}
MINIO_ENDPOINT = os.getenv('MINIO_ENDPOINT', 'localhost:9000')
MINIO_ACCESS_KEY = os.getenv('MINIO_ACCESS_KEY', 'minioadmin')
MINIO_SECRET_KEY = os.getenv('MINIO_SECRET_KEY', 'minioadmin')
MINIO_BUCKET = os.getenv('MINIO_BUCKET_NAME', 'securebox-files')
MINIO_SECURE = os.getenv('MINIO_SECURE', 'false').lower() == 'true'
minio_client = Minio(
    MINIO_ENDPOINT,
    access_key=MINIO_ACCESS_KEY,
    secret_key=MINIO_SECRET_KEY,
    secure=MINIO_SECURE
)
# ============================================
# SECTION 4: Helper Functions
# ============================================
def get_db_connection():
    """Get PostgreSQL connection"""
    return psycopg2.connect(**DB_CONFIG)
# ============================================
# SECTION 5: Celery Tasks
# ============================================
@celery_app.task(name='cleanup_expired_files')
def cleanup_expired_files():
    """
    Delete expired files from database and MinIO
    
    Runs: Every 5 minutes (configured in beat_schedule below)
    
    Process:
    1. Find all expired files in database
    2. Delete from MinIO object storage
    3. Delete from PostgreSQL database
    4. Log results
    """
    try:
        logger.info("Starting expired files cleanup")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get all expired files
        cursor.execute("""
            SELECT file_id, filename, minio_object_name 
            FROM files 
            WHERE expires_at < CURRENT_TIMESTAMP
        """)
        
        expired_files = cursor.fetchall()
        deleted_count = 0
        
        for file_id, filename, minio_object_name in expired_files:
            try:
                # Delete from MinIO
                minio_client.remove_object(MINIO_BUCKET, minio_object_name)
                logger.info(f"Deleted from MinIO: {minio_object_name}")
                
                # Delete from database
                cursor.execute("DELETE FROM files WHERE file_id = %s", (file_id,))
                
                deleted_count += 1
                
            except S3Error as e:
                logger.error(f"MinIO deletion failed for {file_id}: {str(e)}")
            except Exception as e:
                logger.error(f"Cleanup error for {file_id}: {str(e)}")
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info(f"Cleanup completed: {deleted_count} files deleted")
        
        return {
            'status': 'success',
            'deleted_count': deleted_count,
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Cleanup task failed: {str(e)}")
        return{'status': 'error', 'error': str(e)}
@celery_app.task(name='cleanup_downloaded_files')
def cleanup_downloaded_files():
    """
    Delete files that have been downloaded
    
    Runs: Every hour
    
    Why wait an hour?
    - Give time for download to complete
    - Allow brief window for re-download if network fails
    """
    try:
        logger.info("Starting downloaded files cleanup")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Delete files downloaded more than 1 hour ago
        cursor.execute("""
            SELECT file_id, filename, minio_object_name 
            FROM files 
            WHERE is_downloaded = TRUE 
            AND downloaded_at < (CURRENT_TIMESTAMP - INTERVAL '1 hour')
        """)
        
        downloaded_files = cursor.fetchall()
        deleted_count = 0
        
        for file_id, filename, minio_object_name in downloaded_files:
            try:
                minio_client.remove_object(MINIO_BUCKET, minio_object_name)
                cursor.execute("DELETE FROM files WHERE file_id = %s", (file_id,))
                deleted_count += 1
                
            except Exception as e:
                logger.error(f"Downloaded file cleanup error: {str(e)}")
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info(f"Downloaded files cleanup: {deleted_count} files deleted")
        
        return {
            'status': 'success',
            'deleted_count': deleted_count
        }
        
    except Exception as e:
        logger.error(f"Downloaded files cleanup failed: {str(e)}")
        return {'status': 'error', 'error': str(e)}
@celery_app.task(name='generate_statistics')
def generate_statistics():
    """
    Generate and cache usage statistics
    
    Runs: Every 30 minutes
    
    Stats include:
    - Total files uploaded
    - Active files
    - Total storage used
    - Average file size
    """
    try:
        logger.info("Generating statistics")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total_files,
                COUNT(CASE WHEN is_downloaded THEN 1 END) as downloaded_files,
                COUNT(CASE WHEN expires_at >= CURRENT_TIMESTAMP AND NOT is_downloaded THEN 1 END) as active_files,
                SUM(file_size) as total_size,
                AVG(file_size) as avg_size
            FROM files
        """)
        
        stats = cursor.fetchone()
        cursor.close()
        conn.close()
        
        statistics = {
            'total_files': stats[0] or 0,
            'downloaded_files': stats[1] or 0,
            'active_files': stats[2] or 0,
            'total_size_bytes': stats[3] or 0,
            'avg_file_size_bytes': float(stats[4] or 0),
            'generated_at': datetime.utcnow().isoformat()
        }
        
        # Cache in Redis for 30 minutes
        redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
        redis_client.setex('system:stats', 1800, str(statistics))
        
        logger.info(f"Statistics generated: {statistics}")
        
        return statistics
        
    except Exception as e:
        logger.error(f"Statistics generation failed: {str(e)}")
        return {'status': 'error', 'error': str(e)}
# ============================================
# SECTION 6: Celery Beat Schedule
# ============================================
# Define when each task runs
celery_app.conf.beat_schedule = {
    'cleanup-expired-every-5-minutes': {
        'task': 'cleanup_expired_files',
        'schedule': 300.0,  # 300 seconds = 5 minutes
    },
    'cleanup-downloaded-every-hour': {
        'task': 'cleanup_downloaded_files',
        'schedule': 3600.0,  # 3600 seconds = 1 hour
    },
    'generate-stats-every-30-minutes': {
        'task': 'generate_statistics',
        'schedule': 1800.0,  # 1800 seconds = 30 minutes
    },
}
if __name__ == '__main__':
    logger.info("Starting Celery worker")
    celery_app.start()