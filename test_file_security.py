import unittest
import io
import os
import hashlib
from app import create_app, db
from app.models.user import User
from app.models.file import FileVault
from app.utils.file_security import (
    validate_file_upload,
    calculate_bytes_hashes,
    encrypt_file_data,
    decrypt_file_data
)

class MockFileStorage:
    def __init__(self, filename, data=b""):
        self.filename = filename
        self.stream = io.BytesIO(data)

    def read(self):
        return self.stream.getvalue()

class TestFileSecurityModule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.app_context = cls.app.app_context()
        cls.app_context.push()

    @classmethod
    def tearDownClass(cls):
        cls.app_context.pop()

    def setUp(self):
        self.client = self.app.test_client()

    def test_01_safe_file_validation(self):
        """Test dangerous extension rejection and safe whitelist approval."""
        # Dangerous extensions
        bad_exe = MockFileStorage("malware.exe", b"fake binary")
        is_val, msg = validate_file_upload(bad_exe)
        self.assertFalse(is_val)
        self.assertIn("Executable or script extension", msg)

        bad_sh = MockFileStorage("script.sh", b"#!/bin/bash\necho 1")
        is_val2, msg2 = validate_file_upload(bad_sh)
        self.assertFalse(is_val2)

        # Safe extensions
        good_pdf = MockFileStorage("audit_report.pdf", b"%PDF-1.4...")
        is_val3, msg3 = validate_file_upload(good_pdf)
        self.assertTrue(is_val3)

        good_crt = MockFileStorage("server.crt", b"-----BEGIN CERTIFICATE-----")
        is_val4, msg4 = validate_file_upload(good_crt)
        self.assertTrue(is_val4)

    def test_02_cryptographic_hash_and_encryption_roundtrip(self):
        """Test SHA-256 calculation and AES-256 encrypt/decrypt roundtrip."""
        test_payload = b"SecureVault High-Assurance Defense Matrix Payload 2026"
        expected_sha256 = hashlib.sha256(test_payload).hexdigest()
        
        calc_sha256, _ = calculate_bytes_hashes(test_payload)
        self.assertEqual(calc_sha256, expected_sha256)

        # Encrypt & Decrypt
        encrypted = encrypt_file_data(test_payload)
        self.assertNotEqual(encrypted, test_payload)
        decrypted = decrypt_file_data(encrypted)
        self.assertEqual(decrypted, test_payload)

    def test_03_file_upload_and_tamper_detection(self):
        """Test file upload, baseline hash storage, integrity check, and tampering detection."""
        # Login
        self.client.post('/login', data={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        }, follow_redirects=True)

        # 1. Upload valid file
        test_content = b"Integrity Check Baseline Confidential Data 2026"
        expected_hash = hashlib.sha256(test_content).hexdigest()
        
        upload_resp = self.client.post('/file-security/upload', data={
            'file': (io.BytesIO(test_content), 'soc_baseline.txt'),
            'description': 'Baseline SOC Config',
            'encrypt': 'true'
        }, content_type='multipart/form-data', follow_redirects=True)
        self.assertEqual(upload_resp.status_code, 200)
        self.assertIn(b'uploaded and cryptographic SHA-256 baseline computed', upload_resp.data)

        # Find record in database
        file_rec = FileVault.query.filter_by(original_filename='soc_baseline.txt').order_by(FileVault.uploaded_at.desc()).first()
        self.assertIsNotNone(file_rec)
        self.assertEqual(file_rec.checksum_sha256, expected_hash)
        self.assertEqual(file_rec.integrity_status, 'VERIFIED')

        # 2. Verify untampered file
        verify_resp = self.client.post(f'/file-security/{file_rec.id}/verify', follow_redirects=True)
        self.assertIn(b'Integrity Verified', verify_resp.data)

        # 3. Simulate physical disk tampering
        upload_dir = os.path.join(self.app.root_path, '..', 'uploads')
        disk_path = os.path.join(upload_dir, file_rec.filename)
        self.assertTrue(os.path.exists(disk_path))

        # Tamper the stored bytes
        with open(disk_path, 'wb') as f:
            f.write(encrypt_file_data(b"TAMPERED CORRUPTED PAYLOAD"))

        # Re-run verification: MUST detect tamper violation!
        tamper_verify_resp = self.client.post(f'/file-security/{file_rec.id}/verify', follow_redirects=True)
        self.assertIn(b'Integrity violation detected', tamper_verify_resp.data)
        
        db.session.refresh(file_rec)
        self.assertEqual(file_rec.integrity_status, 'MODIFIED_WARNING')

        # 4. Clean up
        self.client.post(f'/file-security/{file_rec.id}/delete', follow_redirects=True)

if __name__ == '__main__':
    unittest.main()
