import secrets

class EllipticCurve:
    def __init__(self, p, a, b, Gx, Gy, n):
        self.p = p  # Prime modulus
        self.a = a  # Curve parameter
        self.b = b  # Curve parameter
        self.G = (Gx, Gy)  # Base point
        self.n = n  # Order of G
        self.inf = None  # Point at infinity

    def mod_inverse(self, a, m):
        # Modular inverse using extended Euclidean algorithm
        m0, y, x = m, 0, 1
        if m == 1:
            return 0
        while a > 1:
            q = a // m
            m, a = a % m, m
            y, x = x - q * y, y
        if x < 0:
            x += m0
        return x

    def point_add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        if P[0] == Q[0] and P[1] != Q[1]:
            return None  # Vertical line, point at infinity
        if P == Q:
            return self.point_double(P)
        
        # Slope m = (Q.y - P.y) * inv(Q.x - P.x) mod p
        dx = (Q[0] - P[0]) % self.p
        dy = (Q[1] - P[1]) % self.p
        m = (dy * self.mod_inverse(dx, self.p)) % self.p
        
        # New point
        x3 = (m**2 - P[0] - Q[0]) % self.p
        y3 = (m * (P[0] - x3) - P[1]) % self.p
        return (x3, y3)

    def point_double(self, P):
        if P is None or P[1] == 0:
            return None
        
        # Slope m = (3*P.x^2 + a) * inv(2*P.y) mod p
        numerator = (3 * P[0]**2 + self.a) % self.p
        denominator = (2 * P[1]) % self.p
        m = (numerator * self.mod_inverse(denominator, self.p)) % self.p
        
        x3 = (m**2 - 2 * P[0]) % self.p
        y3 = (m * (P[0] - x3) - P[1]) % self.p
        return (x3, y3)

    def scalar_multiply(self, k, P):
        result = None
        while k > 0:
            if k % 2 == 1:
                result = self.point_add(result, P)
            P = self.point_double(P)
            k //= 2
        return result

    def is_on_curve(self, P):
        if P is None:
            return True
        x, y = P
        return (y**2 - x**3 - self.a * x - self.b) % self.p == 0

# secp256k1 parameters
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0
b = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

curve = EllipticCurve(p, a, b, Gx, Gy, n)

# Example: ECDH Key Exchange
def generate_keypair():
    private_key = secrets.randbelow(curve.n)  # Random private key
    public_key = curve.scalar_multiply(private_key, curve.G)
    return private_key, public_key

def compute_shared_secret(private_key, other_public_key):
    return curve.scalar_multiply(private_key, other_public_key)

# Usage
alice_priv, alice_pub = generate_keypair()
bob_priv, bob_pub = generate_keypair()

alice_shared = compute_shared_secret(alice_priv, bob_pub)
bob_shared = compute_shared_secret(bob_priv, alice_pub)

print("Alice's public key:", hex(alice_pub[0]), hex(alice_pub[1]))
print("Bob's public key:", hex(bob_pub[0]), hex(bob_pub[1]))
print("Shared secrets match:", alice_shared == bob_shared)
