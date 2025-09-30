import secrets
import math
from typing import Tuple, List

# --- Miller-Rabin Primality Test ---

def is_probable_prime(n: int, k: int = 8) -> bool:
    """Miller-Rabin primality test (probabilistic)."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Write n - 1 as d * 2^s
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # a ∈ [2, n-2]
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# --- Prime Generation ---

def generate_prime(bits: int) -> int:
    """Generate a prime number of specified bit length."""
    if bits < 2:
        raise ValueError("bits must be >= 2")
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1  # Ensure high bit and odd
        if is_probable_prime(p):
            return p

# --- Extended Euclidean Algorithm (iterative) ---

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended GCD (iterative): returns (g, x, y) such that ax + by = g = gcd(a, b)."""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

def modinv(a: int, m: int) -> int:
    """Modular inverse of a mod m."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m

# --- RSA Key Generation ---

class RSAKeyPair:
    def __init__(self, n: int, e: int, d: int, p: int = None, q: int = None):
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q

def generate_rsa(bits_per_prime: int = 512, e: int = 65537) -> RSAKeyPair:
    """Generate RSA key pair."""
    while True:
        p = generate_prime(bits_per_prime)
        q = generate_prime(bits_per_prime)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            break

    n = p * q
    d = modinv(e, phi)
    return RSAKeyPair(n=n, e=e, d=d, p=p, q=q)

# --- Block Encoding ---

def _max_block_bytes(n: int) -> int:
    return (n.bit_length() - 1) // 8

def text_to_blocks(msg: str, n: int) -> List[int]:
    """Convert UTF-8 text to list of integer blocks < n."""
    data = msg.encode('utf-8')
    max_len = _max_block_bytes(n)
    return [int.from_bytes(data[i:i + max_len], 'big') for i in range(0, len(data), max_len)]

def blocks_to_text(blocks: List[int], n: int) -> str:
    """Convert integer blocks back to text (UTF-8)."""
    max_len = _max_block_bytes(n)
    data = bytearray()
    for block in blocks:
        chunk = block.to_bytes(max_len, 'big').lstrip(b'\x00')
        data.extend(chunk)
    return data.decode('utf-8', errors='ignore')

# --- RSA Operations ---

def encrypt_int(m: int, pub: RSAKeyPair) -> int:
    if m >= pub.n:
        raise ValueError("message integer >= modulus")
    return pow(m, pub.e, pub.n)

def decrypt_int(c: int, priv: RSAKeyPair) -> int:
    return pow(c, priv.d, priv.n)

def encrypt_text(msg: str, pub: RSAKeyPair) -> List[int]:
    return [encrypt_int(b, pub) for b in text_to_blocks(msg, pub.n)]

def decrypt_text(cipher_blocks: List[int], priv: RSAKeyPair) -> str:
    return blocks_to_text([decrypt_int(c, priv) for c in cipher_blocks], priv.n)

# --- Demo ---

if __name__ == "__main__":
    import time

    bits = 256  # Change for stronger keys
    print(f"Generating RSA keypair with {bits}-bit primes...")
    start = time.time()
    keypair = generate_rsa(bits_per_prime=bits)
    end = time.time()
    print(f"Key generation completed in {end - start:.2f} seconds")
    print("Public Key (n, e):", keypair.n, keypair.e)
    print("Private Key (d):", str(keypair.d)[:80] + "...")

    # Integer encryption/decryption
    m = 12345678901234567890
    c = encrypt_int(m, keypair)
    m2 = decrypt_int(c, keypair)
    print("\nInteger Encryption Demo:")
    print("Original:", m)
    print("Encrypted:", c)
    print("Decrypted:", m2)

    # Text encryption/decryption
    msg = "MYSELF TATA CHETANA SREE. Testing RSA Algorithm"
    cipher = encrypt_text(msg, keypair)
    recovered = decrypt_text(cipher, keypair)
    print("\nText Encryption Demo:")
    print("Original:", msg)
    print("Encrypted (first blocks):", cipher[:6], "..." if len(cipher) > 6 else "")
    print("Decrypted:", recovered)
