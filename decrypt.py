from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

# Load student's private key
with open("student_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# Load encrypted seed
with open("encrypted_seed.txt", "rb") as f:
    encrypted_b64 = f.read().strip()

# Decode from Base64
encrypted_bytes = base64.b64decode(encrypted_b64)

# Decrypt using RSA-OAEP-SHA256
seed_bytes = private_key.decrypt(
    encrypted_bytes,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Seed MUST be 32 bytes => 64 hex chars
hex_seed = seed_bytes.hex().upper()

with open("seed.txt", "w") as f:
    f.write(hex_seed)

print("Decrypted SEED saved as seed.txt")
print("HEX SEED:", hex_seed)
print("Length:", len(hex_seed))
