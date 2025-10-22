# Diffie-Hellman Key Exchange Algorithm

# Step 1: Publicly shared prime number and primitive root
p = 23  # Prime number
g = 5   # Primitive root

# Step 2: Each party chooses a private key (kept secret)
a = 6   # Alice's private key
b = 15  # Bob's private key

# Step 3: Generate public keys
A = pow(g, a, p)   # Alice's public key = g^a mod p
B = pow(g, b, p)   # Bob's public key = g^b mod p

print("Publicly Shared Values:")
print(f"Prime (p): {p}")
print(f"Primitive Root (g): {g}\n")

print("Public Keys:")
print(f"Alice's Public Key (A): {A}")
print(f"Bob's Public Key (B): {B}\n")

# Step 4: Generate shared secret key
secret_key_alice = pow(B, a, p)  # (B^a) mod p
secret_key_bob = pow(A, b, p)    # (A^b) mod p

print("Shared Secret Keys:")
print(f"Alice's Computed Secret Key: {secret_key_alice}")
print(f"Bob's Computed Secret Key:   {secret_key_bob}")

# Check if both keys are same
if secret_key_alice == secret_key_bob:
    print(f"\n✅ Key Exchange Successful! Shared Secret Key: {secret_key_alice}")
else:
    print("\n❌ Key Exchange Failed. Keys do not match.")
