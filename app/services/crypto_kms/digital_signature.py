import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.primitives import serialization
from app.services.crypto_kms.asymmetric_kms import AsymmetricKmsService

class DigitalSignatureService:
    """Signs payloads and verifies digital signatures using managed asymmetric keys."""

    @classmethod
    def sign_payload(cls, key_id: int, message_str: str) -> dict:
        """Sign message string using managed private key."""
        priv_pem = AsymmetricKmsService.get_decrypted_private_key_pem(key_id)
        private_key = serialization.load_pem_private_key(priv_pem, password=None)

        msg_bytes = message_str.encode('utf-8')

        if isinstance(private_key, rsa.RSAPrivateKey):
            sig_bytes = private_key.sign(
                msg_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            algo = 'RSA-PSS-SHA256'
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            sig_bytes = private_key.sign(msg_bytes, ec.ECDSA(hashes.SHA256()))
            algo = 'ECDSA-SHA256'
        else:
            raise ValueError("Unsupported key algorithm for signing")

        sig_b64 = base64.b64encode(sig_bytes).decode('utf-8')
        return {
            'algorithm': algo,
            'signature_base64': sig_b64,
            'message_length': len(msg_bytes)
        }

    @classmethod
    def verify_signature(cls, public_key_pem: str, message_str: str, signature_b64: str) -> bool:
        """Verify digital signature against public key."""
        try:
            pub_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
            msg_bytes = message_str.encode('utf-8')
            sig_bytes = base64.b64decode(signature_b64.encode('utf-8'))

            if isinstance(pub_key, rsa.RSAPublicKey):
                pub_key.verify(
                    sig_bytes,
                    msg_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return True
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                pub_key.verify(sig_bytes, msg_bytes, ec.ECDSA(hashes.SHA256()))
                return True
            return False
        except Exception:
            return False
