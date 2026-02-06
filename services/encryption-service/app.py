from fastapi import FastAPI, HTTPException, status, Depends
from pydantic import BaseModel
import os
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import base64
import redis
from typing import Optional, Tuple
import hashlib

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SecureBox Encryption Service",
    description="Handles file encryption and decryption using AES and RSA",
    version="1.0.0"
)

# Redis setup for key caching
REDIS_URL = os.getenv('REDIS_URL')
if REDIS_URL:
    redis_client = redis.from_url(REDIS_URL, decode_responses=False)
else:
    redis_client = redis.Redis(
        host=os.getenv('REDIS_HOST', 'localhost'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        password=os.getenv('REDIS_PASSWORD'),
        ssl=os.getenv('REDIS_SSL', 'false').lower() == 'true',
        decode_responses=False  # We need bytes for encryption keys
    )

# Models
class EncryptionRequest(BaseModel):
    file_id: str
    content: str  # Hex encoded content
    password: Optional[str] = None

class DecryptionRequest(BaseModel):
    file_id: str
    encrypted_content: str  # Base64 encoded
    encryption_key: str  # Base64 encoded key (encrypted if password used)
    password: Optional[str] = None

class EncryptionResponse(BaseModel):
    file_id: str
    encrypted_content: str  # Base64 encoded
    encryption_key: str  # Base64 encoded key

class DecryptionResponse(BaseModel):
    file_id: str
    content: str  # Hex encoded decrypted content

class KeyGenerationRequest(BaseModel):
    password: Optional[str] = None

class KeyGenerationResponse(BaseModel):
    encryption_key: str
    salt: Optional[str] = None

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    service: str

def generate_symmetric_key() -> bytes:
    """Generate a new AES key"""
    return Fernet.generate_key()

def generate_key_from_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """Generate AES key from password using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_content(content: bytes, key: bytes) -> bytes:
    """Encrypt content using AES"""
    fernet = Fernet(key)
    return fernet.encrypt(content)

def decrypt_content(encrypted_content: bytes, key: bytes) -> bytes:
    """Decrypt content using AES"""
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_content)

def generate_rsa_keypair() -> Tuple[bytes, bytes]:
    """Generate RSA key pair for hybrid encryption"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=int(os.getenv('RSA_KEY_SIZE', 2048))
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

def encrypt_key_with_rsa(aes_key: bytes, public_key_pem: bytes) -> bytes:
    """Encrypt AES key with RSA public key"""
    public_key = serialization.load_pem_public_key(public_key_pem)
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def decrypt_key_with_rsa(encrypted_key: bytes, private_key_pem: bytes) -> bytes:
    """Decrypt AES key with RSA private key"""
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    try:
        # Test Redis connection
        redis_client.ping()
        
        from datetime import datetime
        return HealthResponse(
            status="healthy",
            timestamp=datetime.utcnow().isoformat(),
            service="encryption-service"
        )
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Service unhealthy: {str(e)}"
        )

@app.post("/encrypt", response_model=EncryptionResponse)
async def encrypt_file(request: EncryptionRequest):
    """Encrypt file content"""
    try:
        logger.info(f"Encrypting file: {request.file_id}")
        
        # Convert hex content back to bytes
        try:
            content = bytes.fromhex(request.content)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid content format"
            )
        
        # Generate or derive encryption key
        if request.password:
            # Use password-based key derivation
            key, salt = generate_key_from_password(request.password)
            
            # Store salt for later decryption
            redis_client.setex(
                f"salt:{request.file_id}",
                24 * 3600,  # 24 hours
                salt
            )
        else:
            # Generate random key
            key = generate_symmetric_key()
        
        # Encrypt the content
        encrypted_content = encrypt_content(content, key)
        
        # Prepare response
        response = EncryptionResponse(
            file_id=request.file_id,
            encrypted_content=base64.b64encode(encrypted_content).decode('utf-8'),
            encryption_key=base64.b64encode(key).decode('utf-8')
        )
        
        # Cache the key temporarily for potential re-encryption
        redis_client.setex(
            f"key:{request.file_id}",
            3600,  # 1 hour
            key
        )
        
        logger.info(f"File encrypted successfully: {request.file_id}")
        return response
        
    except Exception as e:
        logger.error(f"Encryption failed for {request.file_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Encryption failed: {str(e)}"
        )

@app.post("/decrypt", response_model=DecryptionResponse)
async def decrypt_file(request: DecryptionRequest):
    """Decrypt file content"""
    try:
        logger.info(f"Decrypting file: {request.file_id}")
        
        # Decode base64 encrypted content
        try:
            encrypted_content = base64.b64decode(request.encrypted_content)
            encryption_key = base64.b64decode(request.encryption_key)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid encrypted content format"
            )
        
        # If password was used, derive key from password
        if request.password:
            salt = redis_client.get(f"salt:{request.file_id}")
            if not salt:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Salt not found for password-based decryption"
                )
            
            # Derive key from password and salt
            derived_key, _ = generate_key_from_password(request.password, salt)
            
            # Verify the derived key matches the stored key
            if derived_key != encryption_key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid password"
                )
            
            key = derived_key
        else:
            key = encryption_key
        
        # Decrypt the content
        try:
            decrypted_content = decrypt_content(encrypted_content, key)
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to decrypt content - invalid key or corrupted data"
            )
        
        # Clean up cached data
        redis_client.delete(f"key:{request.file_id}")
        redis_client.delete(f"salt:{request.file_id}")
        
        response = DecryptionResponse(
            file_id=request.file_id,
            content=decrypted_content.hex()
        )
        
        logger.info(f"File decrypted successfully: {request.file_id}")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Decryption failed for {request.file_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Decryption failed: {str(e)}"
        )

@app.post("/generate-key", response_model=KeyGenerationResponse)
async def generate_key(request: KeyGenerationRequest):
    """Generate a new encryption key"""
    try:
        if request.password:
            key, salt = generate_key_from_password(request.password)
            return KeyGenerationResponse(
                encryption_key=base64.b64encode(key).decode('utf-8'),
                salt=base64.b64encode(salt).decode('utf-8')
            )
        else:
            key = generate_symmetric_key()
            return KeyGenerationResponse(
                encryption_key=base64.b64encode(key).decode('utf-8')
            )
    except Exception as e:
        logger.error(f"Key generation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Key generation failed: {str(e)}"
        )

@app.get("/stats")
async def get_encryption_stats():
    """Get encryption service statistics"""
    try:
        # Get Redis info
        redis_info = redis_client.info()
        
        # Count active keys
        active_keys = len(redis_client.keys("key:*"))
        active_salts = len(redis_client.keys("salt:*"))
        
        return {
            "service": "encryption-service",
            "status": "operational",
            "active_keys": active_keys,
            "active_salts": active_salts,
            "redis_connected_clients": redis_info.get('connected_clients', 0),
            "memory_usage_mb": round(redis_info.get('used_memory', 0) / 1024 / 1024, 2)
        }
    except Exception as e:
        logger.error(f"Stats retrieval failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Stats unavailable"
        )

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv('ENCRYPTION_SERVICE_PORT', 8001))
    host = os.getenv('ENCRYPTION_SERVICE_HOST', '0.0.0.0')
    
    logger.info(f"Starting Encryption Service on {host}:{port}")
    uvicorn.run(app, host=host, port=port)
