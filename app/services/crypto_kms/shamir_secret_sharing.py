import secrets
import hashlib
from app import db
from app.models.crypto_kms import SecretShareRecord

# 4096-bit safe prime for arbitrary length secrets
PRIME = (1 << 4096) - 105

def _eval_poly(coeffs: list[int], x: int) -> int:
    """Evaluate polynomial at x using Horner's method modulo PRIME."""
    result = 0
    for coeff in reversed(coeffs):
        result = (result * x + coeff) % PRIME
    return result

def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm for modular inverse."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = _extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def _mod_inverse(k: int, p: int) -> int:
    """Compute modular inverse of k modulo p."""
    k = k % p
    gcd, x, _ = _extended_gcd(k, p)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % p + p) % p

class ShamirSecretSharingService:
    """Implements Shamir's (k, n) Threshold Secret Sharing Scheme."""

    @classmethod
    def split_secret(cls, secret_str: str, k: int = 3, n: int = 5, label: str = 'Master Key') -> dict:
        """Split a secret string into n shares such that any k shares can reconstruct it."""
        if k > n:
            raise ValueError("Threshold k cannot exceed total shares n.")
        if k < 2:
            raise ValueError("Threshold k must be at least 2.")

        secret_bytes = secret_str.encode('utf-8')
        secret_int = int.from_bytes(secret_bytes, byteorder='big')

        if secret_int >= PRIME:
            raise ValueError("Secret is too large for field prime.")

        # Generate random polynomial coefficients
        coeffs = [secret_int] + [secrets.randbelow(PRIME) for _ in range(k - 1)]

        # Generate n shares (x, f(x))
        shares = []
        for x in range(1, n + 1):
            y = _eval_poly(coeffs, x)
            shares.append(f"{x}-{hex(y)[2:]}")

        sha256_hash = hashlib.sha256(secret_bytes).hexdigest()

        rec = SecretShareRecord(
            secret_label=label,
            threshold_k=k,
            total_shares_n=n,
            secret_sha256_checksum=sha256_hash
        )
        db.session.add(rec)
        db.session.commit()

        return {
            'label': label,
            'threshold_k': k,
            'total_shares_n': n,
            'checksum_sha256': sha256_hash,
            'shares': shares
        }

    @classmethod
    def reconstruct_secret(cls, share_strings: list[str]) -> str:
        """Reconstruct secret from at least k valid share strings using Lagrange polynomial interpolation."""
        points = []
        for s in share_strings:
            clean = s.strip()
            if '-' in clean:
                x_str, y_str = clean.split('-', 1)
                x = int(x_str)
                y = int(y_str, 16)
                points.append((x, y))

        if len(points) < 2:
            raise ValueError("At least 2 shares are required to reconstruct secret.")

        # Lagrange interpolation at x = 0
        secret_int = 0
        k = len(points)

        for i in range(k):
            xi, yi = points[i]
            numerator = 1
            denominator = 1
            for j in range(k):
                if i != j:
                    xj, _ = points[j]
                    numerator = (numerator * (-xj)) % PRIME
                    denominator = (denominator * (xi - xj)) % PRIME

            lagrange_l_i = (numerator * _mod_inverse(denominator, PRIME)) % PRIME
            secret_int = (secret_int + yi * lagrange_l_i) % PRIME

        secret_int = (secret_int % PRIME + PRIME) % PRIME

        # Convert back to string
        try:
            byte_len = (secret_int.bit_length() + 7) // 8
            secret_bytes = secret_int.to_bytes(byte_len, byteorder='big')
            return secret_bytes.decode('utf-8')
        except Exception:
            return hex(secret_int)
