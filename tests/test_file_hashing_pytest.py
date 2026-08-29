import io
import pytest
from app.models.file import FileVault
from app.utils.file_security import calculate_bytes_hashes, encrypt_file_data, decrypt_file_data

def test_file_sha256_computation_and_encryption(app):
    """Test cryptographic SHA-256 hashing and AES-256 Fernet encryption/decryption."""
    with app.app_context():
        test_data = b"CONFIDENTIAL SOC INCIDENT RESPONSE AUDIT LOG 2026"
        
        sha256_hash, md5_hash = calculate_bytes_hashes(test_data)
        assert len(sha256_hash) == 64
        assert len(md5_hash) == 32
        
        encrypted_blob = encrypt_file_data(test_data)
        assert encrypted_blob != test_data
        
        decrypted_data = decrypt_file_data(encrypted_blob)
        assert decrypted_data == test_data

def test_file_upload_and_tamper_verification(client, admin_user, db_session):
    """Test uploading file to vault, calculating baseline hash, and verifying integrity."""
    # Login as admin
    client.post('/login', data={
        'identifier': 'admin',
        'password': 'Admin@SecureVault2026!'
    }, follow_redirects=True)

    file_content = b"CRITICAL SECURITY COMPLIANCE REPORT EVIDENCE"
    data = {
        'file': (io.BytesIO(file_content), 'compliance_evidence.txt'),
        'description': 'SOC Compliance Document'
    }

    upload_resp = client.post('/file-security/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert upload_resp.status_code == 200
    assert b"cryptographic sha-256 baseline" in upload_resp.data.lower() or b"uploaded" in upload_resp.data.lower()

    file_record = FileVault.query.filter_by(original_filename='compliance_evidence.txt').first()
    assert file_record is not None
    assert file_record.checksum_sha256 == calculate_bytes_hashes(file_content)[0]
    assert file_record.integrity_status == 'VERIFIED'

    # Verify endpoint
    verify_resp = client.post(f'/file-security/{file_record.id}/verify', follow_redirects=True)
    assert verify_resp.status_code == 200
    assert b"Integrity Verified" in verify_resp.data

    # Clean up
    db_session.delete(file_record)
    db_session.commit()
