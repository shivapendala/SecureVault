import pytest
import json
from app.models.crypto_kms import AsymmetricKeyPair, KeyRotationLog, SecretShareRecord
from app.services.crypto_kms.asymmetric_kms import AsymmetricKmsService
from app.services.crypto_kms.shamir_secret_sharing import ShamirSecretSharingService
from app.services.crypto_kms.digital_signature import DigitalSignatureService
from app.services.crypto_kms.key_rotator import KeyRotatorService

def test_asymmetric_key_generation_and_storage(app, db_session):
    """Test generating RSA-2048 and ECC-SECP256R1 keypairs with AES-256 encrypted storage."""
    with app.app_context():
        rsa_key = AsymmetricKmsService.generate_key_pair('Test-RSA-Enclave-Key', algorithm='RSA-2048')
        assert rsa_key.id is not None
        assert 'BEGIN PUBLIC KEY' in rsa_key.public_key_pem
        assert len(rsa_key.key_fingerprint) == 64
        assert rsa_key.state == 'ACTIVE'

        ecc_key = AsymmetricKmsService.generate_key_pair('Test-ECC-Enclave-Key', algorithm='ECC-SECP256R1')
        assert ecc_key.id is not None
        assert 'BEGIN PUBLIC KEY' in ecc_key.public_key_pem

        # Test private key retrieval & decryption
        priv_pem = AsymmetricKmsService.get_decrypted_private_key_pem(rsa_key.id)
        assert b'BEGIN PRIVATE KEY' in priv_pem

def test_shamir_secret_sharing_roundtrip(app, db_session):
    """Test Shamir's (k, n) polynomial threshold splitting and reconstruction."""
    with app.app_context():
        original_secret = "MasterEnclave$Password2026!SuperSecure"
        
        # Split into 5 shares (Threshold 3)
        split_data = ShamirSecretSharingService.split_secret(original_secret, k=3, n=5, label='Recovery Vault')
        assert len(split_data['shares']) == 5
        assert split_data['threshold_k'] == 3

        # Reconstruct with 3 shares (any 3)
        subset_shares = [split_data['shares'][0], split_data['shares'][2], split_data['shares'][4]]
        recovered = ShamirSecretSharingService.reconstruct_secret(subset_shares)
        assert recovered == original_secret

        # Reconstruct with 4 shares
        subset_4 = split_data['shares'][:4]
        assert ShamirSecretSharingService.reconstruct_secret(subset_4) == original_secret

def test_digital_signature_and_verification(app, db_session):
    """Test generating digital signatures and verifying with public key."""
    with app.app_context():
        key = AsymmetricKmsService.generate_key_pair('Signer-Key', algorithm='RSA-2048')
        message = "CONFIDENTIAL SOC COMPLIANCE ATTESTATION 2026"

        sig_data = DigitalSignatureService.sign_payload(key.id, message)
        assert 'signature_base64' in sig_data
        assert sig_data['algorithm'] == 'RSA-PSS-SHA256'

        # Verify valid signature
        is_valid = DigitalSignatureService.verify_signature(
            public_key_pem=key.public_key_pem,
            message_str=message,
            signature_b64=sig_data['signature_base64']
        )
        assert is_valid is True

        # Verify tampered message fails
        tampered_valid = DigitalSignatureService.verify_signature(
            public_key_pem=key.public_key_pem,
            message_str="TAMPERED MESSAGE PAYLOAD",
            signature_b64=sig_data['signature_base64']
        )
        assert tampered_valid is False

def test_key_rotation_lifecycle(app, db_session):
    """Test rotating an asymmetric key and archiving historical records."""
    with app.app_context():
        initial_key = AsymmetricKmsService.generate_key_pair('Rotation-Test-Key', algorithm='RSA-2048')
        old_id = initial_key.id

        rot_res = KeyRotatorService.rotate_asymmetric_key(old_id, rotated_by_name='Test Operator')
        assert rot_res['success'] is True

        db_session.refresh(initial_key)
        assert initial_key.state == 'ROTATED'

        # Check rotation log
        log = KeyRotationLog.query.filter_by(key_alias='Rotation-Test-Key').first()
        assert log is not None
        assert log.rotated_by == 'Test Operator'

def test_crypto_kms_web_routes_and_api(client, admin_user):
    """Test KMS UI dashboards and REST API endpoints."""
    # Login admin
    client.post('/login', data={'identifier': 'admin', 'password': 'Admin@SecureVault2026!'}, follow_redirects=True)

    # 1. Main Hub
    hub_res = client.get('/kms/', follow_redirects=True)
    assert hub_res.status_code == 200
    assert b"Cryptographic KMS & Asymmetric Suite" in hub_res.data

    # 2. REST API Generate Key
    api_gen = client.post('/kms/api/generate-key', json={'key_alias': 'API-RSA-Key', 'algorithm': 'RSA-2048'})
    assert api_gen.status_code == 201
    gen_json = json.loads(api_gen.data)
    assert gen_json['success'] is True
    assert 'key' in gen_json

    # 3. REST API Shamir Split and Combine
    api_split = client.post('/kms/api/shamir-split', json={'secret': 'ZeroTrustPayload99', 'k': 2, 'n': 3})
    assert api_split.status_code == 200
    split_json = json.loads(api_split.data)
    shares = split_json['split']['shares']

    api_comb = client.post('/kms/api/shamir-combine', json={'shares': shares[:2]})
    assert api_comb.status_code == 200
    comb_json = json.loads(api_comb.data)
    assert comb_json['reconstructed_secret'] == 'ZeroTrustPayload99'
