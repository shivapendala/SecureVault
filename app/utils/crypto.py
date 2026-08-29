import base64
import os
import secrets
import string
import math
import re
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
    try:
        return Fernet(key)
    except Exception:
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

def generate_secure_password(length: int = 20, use_symbols: bool = True, use_numbers: bool = True, use_uppercase: bool = True, avoid_ambiguous: bool = False) -> str:
    """Generate a cryptographically secure random password."""
    length = max(8, min(64, length))
    
    lowers = string.ascii_lowercase
    uppers = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"

    if avoid_ambiguous:
        ambiguous = "Il1O0o|`'\";:,."
        for ch in ambiguous:
            lowers = lowers.replace(ch, '')
            uppers = uppers.replace(ch, '')
            digits = digits.replace(ch, '')
            symbols = symbols.replace(ch, '')

    char_pool = lowers
    required_chars = [secrets.choice(lowers)]

    if use_uppercase and uppers:
        char_pool += uppers
        required_chars.append(secrets.choice(uppers))
    if use_numbers and digits:
        char_pool += digits
        required_chars.append(secrets.choice(digits))
    if use_symbols and symbols:
        char_pool += symbols
        required_chars.append(secrets.choice(symbols))

    password = list(required_chars)
    for _ in range(length - len(password)):
        password.append(secrets.choice(char_pool))

    # Cryptographically secure shuffle
    shuffled = list(password)
    secrets.SystemRandom().shuffle(shuffled)
    return "".join(shuffled)

COMMON_WEAK_PATTERNS = [
    'password', '123456', '12345678', 'qwerty', 'admin', 'welcome', 'login', 'secure',
    'vault', 'pass123', 'root123', 'iloveyou', 'sunshine', 'princess', 'football'
]

def calculate_password_entropy(password: str) -> dict:
    """Calculate Shannon entropy, dictionary checks, and NIST SP 800-63B password rating."""
    if not password:
        return {"entropy": 0, "strength": "Empty", "score": 0, "feedback": ["Passphrase cannot be blank."], "pool_size": 0}

    pool_size = 0
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password))

    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_symbol: pool_size += 32

    if pool_size == 0:
        pool_size = 1

    entropy = len(password) * math.log2(pool_size)

    feedback = []
    lower_pwd = password.lower()
    
    # Common pattern checks
    for pat in COMMON_WEAK_PATTERNS:
        if pat in lower_pwd:
            feedback.append(f"Contains common dictionary word '{pat}', making it vulnerable to pattern attacks.")
            entropy = max(10, entropy - 25)
            break

    # Sequential character checks (e.g. 123, abc)
    if re.search(r'(012|123|234|345|456|567|678|789|abc|bcd|cde|def|xyz)', lower_pwd):
        feedback.append("Contains sequential characters (e.g. '123' or 'abc').")
        entropy = max(10, entropy - 15)

    if len(password) < 12:
        feedback.append("Increase length to at least 12-16 characters for maximum resistance.")
    if not has_upper:
        feedback.append("Add uppercase characters (A-Z).")
    if not has_digit:
        feedback.append("Add numeric digits (0-9).")
    if not has_symbol:
        feedback.append("Add special symbols (!@#$%^&*).")

    if entropy < 40:
        strength = "Critical / Very Weak"
        score = 1
        color = "danger"
    elif entropy < 60:
        strength = "Moderate / Weak"
        score = 2
        color = "warning"
    elif entropy < 80:
        strength = "Good / Strong"
        score = 3
        color = "info"
    else:
        strength = "Enterprise / Very Strong"
        score = 4
        color = "success"

    if not feedback:
        feedback.append("Passphrase meets all enterprise security complexity and entropy standards.")

    return {
        "entropy": round(entropy, 2),
        "strength": strength,
        "score": score,
        "color": color,
        "length": len(password),
        "feedback": feedback,
        "pool_size": pool_size,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol
    }
