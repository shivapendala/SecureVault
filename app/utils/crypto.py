import base64
import os
import secrets
import string
import math
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import current_app

def get_fernet_instance():
    """Retrieve Fernet instance initialized with MASTER_ENCRYPTION_KEY or derived key."""
    key = current_app.config.get('MASTER_ENCRYPTION_KEY')
    if not key:
        key = Fernet.generate_key().decode()
    if isinstance(key, str):
        key = key.encode()
    # Ensure key is valid Fernet 32-byte urlsafe base64
    try:
        return Fernet(key)
    except Exception:
        # If the provided key wasn't properly base64-encoded 32 bytes, derive one using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"securevault_static_salt_2026",
            iterations=100000,
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(key))
        return Fernet(derived_key)

def encrypt_secret(plain_text: str) -> str:
    """Encrypt plain text string and return url-safe base64 ciphertext string."""
    if not plain_text:
        return ""
    f = get_fernet_instance()
    encrypted_bytes = f.encrypt(plain_text.encode('utf-8'))
    return encrypted_bytes.decode('utf-8')

def decrypt_secret(cipher_text: str) -> str:
    """Decrypt ciphertext string and return plain text string."""
    if not cipher_text:
        return ""
    f = get_fernet_instance()
    try:
        decrypted_bytes = f.decrypt(cipher_text.encode('utf-8'))
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        return f"[Decryption Error: {str(e)}]"

def mask_secret(secret_str: str) -> str:
    """Return a masked representation of a secret (e.g. sec_••••••••3b9a)."""
    if not secret_str:
        return "••••••••"
    if len(secret_str) <= 6:
        return "••••••••"
    return f"{secret_str[:4]}••••••••{secret_str[-4:]}"

def generate_secure_password(length: int = 18, use_symbols: bool = True, use_numbers: bool = True, use_uppercase: bool = True) -> str:
    """Generate a cryptographically secure random password."""
    chars = string.ascii_lowercase
    if use_uppercase:
        chars += string.ascii_uppercase
    if use_numbers:
        chars += string.digits
    if use_symbols:
        chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase) if use_uppercase else secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits) if use_numbers else secrets.choice(string.ascii_lowercase),
        secrets.choice("!@#$%^&*()-_=+") if use_symbols else secrets.choice(string.ascii_lowercase)
    ]
    for _ in range(length - len(password)):
        password.append(secrets.choice(chars))
    
    # Shuffle cryptographically
    shuffled = list(password)
    secrets.SystemRandom().shuffle(shuffled)
    return "".join(shuffled)

def calculate_password_entropy(password: str) -> dict:
    """Calculate Shannon entropy and NIST password strength assessment."""
    if not password:
        return {"entropy": 0, "strength": "Empty", "score": 0, "feedback": ["Password cannot be blank."]}
    
    pool_size = 0
    has_lower = bool(any(c.islower() for c in password))
    has_upper = bool(any(c.isupper() for c in password))
    has_digit = bool(any(c.isdigit() for c in password))
    has_symbol = bool(any(c in string.punctuation for c in password))
    
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_symbol: pool_size += 32
    
    if pool_size == 0:
        pool_size = 1
        
    entropy = len(password) * math.log2(pool_size)
    
    feedback = []
    if len(password) < 12:
        feedback.append("Increase length to at least 12-16 characters for enterprise resistance.")
    if not has_upper:
        feedback.append("Include uppercase characters (A-Z).")
    if not has_digit:
        feedback.append("Include numbers (0-9).")
    if not has_symbol:
        feedback.append("Include special symbols (!@#$%^&*).")
        
    if entropy < 40:
        strength = "Critical / Very Weak"
        score = 1
    elif entropy < 60:
        strength = "Moderate / Weak"
        score = 2
    elif entropy < 80:
        strength = "Good / Strong"
        score = 3
    else:
        strength = "Enterprise / Very Strong"
        score = 4
        
    if not feedback:
        feedback.append("Password meets all enterprise security complexity and entropy standards.")
        
    return {
        "entropy": round(entropy, 2),
        "strength": strength,
        "score": score,
        "length": len(password),
        "feedback": feedback,
        "pool_size": pool_size
    }
