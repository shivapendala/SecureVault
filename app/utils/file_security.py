import os
import hashlib
import uuid
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from app.utils.crypto import get_fernet_instance

ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'svg',
    'json', 'yaml', 'yml', 'xml', 'csv', 'log',
    'key', 'crt', 'pem', 'pub', 'conf', 'cfg', 'ini',
    'zip', 'gz', 'tar', 'sql', 'md', 'env', 'example',
    'doc', 'docx', 'xls', 'xlsx', 'pfx', 'cer'
}

DANGEROUS_EXTENSIONS = {
    'exe', 'bat', 'cmd', 'sh', 'vbs', 'msi', 'com', 'scr',
    'pif', 'ps1', 'dll', 'sys', 'iso', 'jar', 'apk', 'vbe',
    'wsf', 'wsh', 'hta', 'reg'
}

MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024 # 25 MB

def get_file_extension(filename: str) -> str:
    """Extract lowercase file extension without leading dot."""
    if '.' in filename:
        return filename.rsplit('.', 1)[1].lower()
    return ''

def validate_file_upload(file_storage) -> tuple[bool, str]:
    """Validate uploaded file against security policies."""
    if not file_storage or not file_storage.filename or file_storage.filename.strip() == '':
        return False, "No file was selected for upload."

    orig_name = file_storage.filename.strip()
    ext = get_file_extension(orig_name)

    # 1. Dangerous extension check
    if ext in DANGEROUS_EXTENSIONS:
        return False, f"Upload rejected: Executable or script extension (.{ext}) is blocked by Zero-Trust policy."

    # 2. Allowed extension check
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Upload rejected: File extension (.{ext}) is not in the authorized cybersecurity whitelist."

    # 3. Path traversal sanitize check
    safe_name = secure_filename(orig_name)
    if not safe_name:
        return False, "Invalid filename provided."

    return True, ""

def calculate_bytes_hashes(data: bytes) -> tuple[str, str]:
    """Calculate SHA-256 and MD5 hashes of raw bytes."""
    sha256_hash = hashlib.sha256(data).hexdigest()
    md5_hash = hashlib.md5(data).hexdigest()
    return sha256_hash, md5_hash

def calculate_stream_sha256(stream) -> tuple[str, int]:
    """Calculate SHA-256 hash and size from a file stream."""
    hasher = hashlib.sha256()
    size = 0
    stream.seek(0)
    while True:
        chunk = stream.read(65536)
        if not chunk:
            break
        hasher.update(chunk)
        size += len(chunk)
    stream.seek(0)
    return hasher.hexdigest(), size

def encrypt_file_data(data: bytes) -> bytes:
    """Encrypt raw file bytes using Fernet / AES-256."""
    f = get_fernet_instance()
    return f.encrypt(data)

def decrypt_file_data(encrypted_data: bytes) -> bytes:
    """Decrypt encrypted file bytes using Fernet / AES-256."""
    f = get_fernet_instance()
    return f.decrypt(encrypted_data)
