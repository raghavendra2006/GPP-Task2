import hmac, hashlib, time, struct

def generate_totp(hex_seed):
    key = bytes.fromhex(hex_seed)

    timestep = int(time.time()) // 30
    timestep_bytes = struct.pack(">Q", timestep)

    hmac_hash = hmac.new(key, timestep_bytes, hashlib.sha1).digest()

    offset = hmac_hash[-1] & 0x0F

    truncated_hash = (
        (hmac_hash[offset] & 0x7F) << 24 |
        (hmac_hash[offset+1] & 0xFF) << 16 |
        (hmac_hash[offset+2] & 0xFF) << 8 |
        (hmac_hash[offset+3] & 0xFF)
    )

    otp = truncated_hash % 1000000
    return f"{otp:06d}"

if __name__ == "__main__":
    with open("seed.txt") as f:
        seed = f.read().strip()

    print("Current OTP:", generate_totp(seed))
