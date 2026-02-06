-- Initialize SecureBox Database
-- This script runs automatically when PostgreSQL container starts
-- Create files table
CREATE TABLE IF NOT EXISTS files (
    id SERIAL PRIMARY KEY,                    -- Auto-incrementing ID
    file_id VARCHAR(32) UNIQUE NOT NULL,      -- Our custom file ID
    filename VARCHAR(255) NOT NULL,           -- Original filename
    file_size BIGINT NOT NULL,                -- Size in bytes
    content_type VARCHAR(100),                -- MIME type (image/png, etc.)
    download_token VARCHAR(64) UNIQUE NOT NULL, -- One-time download token
    encryption_key TEXT NOT NULL,             -- Encrypted file's key
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- When uploaded
    expires_at TIMESTAMP NOT NULL,            -- When it expires
    downloaded_at TIMESTAMP,                  -- When downloaded (null if not)
    is_downloaded BOOLEAN DEFAULT FALSE,      -- One-time download flag
    download_count INTEGER DEFAULT 0,         -- How many times accessed
    minio_object_name VARCHAR(255) NOT NULL   -- Where file is in MinIO
);
-- Create indexes for faster queries
-- Why? Searching by file_id is common, index makes it O(log n) instead of O(n)
CREATE INDEX IF NOT EXISTS idx_files_file_id ON files(file_id);
CREATE INDEX IF NOT EXISTS idx_files_download_token ON files(download_token);
CREATE INDEX IF NOT EXISTS idx_files_expires_at ON files(expires_at);
CREATE INDEX IF NOT EXISTS idx_files_is_downloaded ON files(is_downloaded);
-- Audit log table (track all operations)
CREATE TABLE IF NOT EXISTS file_audit_log (
    id SERIAL PRIMARY KEY,
    file_id VARCHAR(32) NOT NULL,
    operation VARCHAR(50) NOT NULL,           -- 'upload', 'download', 'expire', etc.
    ip_address INET,                          -- Who did it
    user_agent TEXT,                          -- Browser info
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB                            -- Extra data as JSON
);
-- Indexes for audit log
CREATE INDEX IF NOT EXISTS idx_audit_file_id ON file_audit_log(file_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON file_audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_operation ON file_audit_log(operation);
-- Create view for active files (convenient query)
CREATE OR REPLACE VIEW active_files AS
SELECT 
    file_id,
    filename,
    file_size,
    content_type,
    created_at,
    expires_at,
    download_count,
    EXTRACT(EPOCH FROM (expires_at - NOW())) AS seconds_until_expiry
FROM files
WHERE expires_at > NOW() AND is_downloaded = FALSE;
-- Function to cleanup expired files
CREATE OR REPLACE FUNCTION cleanup_expired_files()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER := 0;
BEGIN
    -- Log which files we're deleting
    INSERT INTO file_audit_log (file_id, operation, metadata)
    SELECT 
        file_id, 
        'expire',
        json_build_object(
            'filename', filename,
            'expired_at', expires_at,
            'was_downloaded', is_downloaded
        )
    FROM files 
    WHERE expires_at < NOW();
    
    -- Delete expired files
    DELETE FROM files WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;
