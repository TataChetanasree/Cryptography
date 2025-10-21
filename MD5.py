import hmac
import hashlib

# Sender side - Generate the signature
def generate_signature(secret_key, message):

    # Create an HMAC-MD5 signature from the secret key and message
 return hmac.new(secret_key, message, hashlib.md5).hexdigest()

# Receiver side - Validate the received signature
def authenticate_signature(secret_key, message, received_signature):
    
# Recalculate the signature using the same key and message
    expected_signature = hmac.new(secret_key, message, hashlib.md5).hexdigest()

    # Compare both signatures securely
    if hmac.compare_digest(expected_signature, received_signature):
        print("Signature is valid! The message is authentic and unaltered.")
    else:
        print("Signature is invalid or the message was tampered with.")

# Example usage
secret_key = b"my_secret_key"
message = b"Hello, I am TCS , This must be secret"

# Sender generates signature
signature = generate_signature(secret_key, message)
print("Generated Signature:", signature)

# Receiver verifies signature
authenticate_signature(secret_key, message, signature)
