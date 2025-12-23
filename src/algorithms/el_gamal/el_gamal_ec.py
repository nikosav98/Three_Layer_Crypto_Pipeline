import os
import sys
from pathlib import Path

# Add parent directories to Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.utils import ec_scalar_mult, ec_point_add, ec_point_double, ec_mod_inverse

# --- Constants (secp256k1) ---
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def ensure_32_bytes(data: bytes) -> bytes:
    """Ensure the byte array is exactly 32 bytes, padding with leading zeros if necessary."""
    if len(data) < 32:
        return b'\x00' * (32 - len(data)) + data
    elif len(data) > 32:
        return data[:32]
    return data

def encode_plaintext_as_point(plaintext):
    """Map plaintext bytes to elliptic curve point using Koblitz padding."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
        
    if len(plaintext) > 31:
        plaintext = plaintext[:31]
    
    m_int = int.from_bytes(plaintext, byteorder='big')
    K = 256
    x_base = m_int * K
    
    for i in range(K):
        x = (x_base + i) % P
        y_square = (pow(x, 3, P) + (A * x) + B) % P
        y = pow(y_square, (P + 1) // 4, P)
        
        if (y * y) % P == y_square:
            return (x, y)
            
    raise ValueError("Failed to map message to point")

def decode_point_as_plaintext(point):
    """Extract plaintext bytes from elliptic curve point."""
    x, _ = point
    m_int = x // 256
    return m_int.to_bytes((m_int.bit_length() + 7) // 8, byteorder='big')

def generate_keys():
    """Generate ElGamal key pair (private_key, public_key)."""
    private_key = 1 + os.urandom(31)[0]  # Use os.urandom instead of secrets.randbelow
    public_key = ec_scalar_mult(private_key, G, P)
    return private_key, public_key

def encrypt(public_key, message_text):
    """Encrypt message using ElGamal encryption. Returns (C1, C2)."""
    M = encode_plaintext_as_point(message_text)
    k = 1 + os.urandom(31)[0]
    
    C1 = ec_scalar_mult(k, G, P)
    S = ec_scalar_mult(k, public_key, P)
    C2 = ec_point_add(M, S, P)

    return (C1, C2)

def decrypt(private_key, ciphertext):
    """Decrypt ElGamal ciphertext. Returns original message bytes."""
    C1, C2 = ciphertext
    
    S = ec_scalar_mult(private_key, C1, P)
    neg_S = (S[0], (P - S[1]) % P)
    M = ec_point_add(C2, neg_S, P)
    
    return decode_point_as_plaintext(M)
#El gamal Example

def main():
    # --- 1. Key Generation ---
    print("\n--- Key Generation ---")
    private_key, public_key = generate_keys()
    
    print(f"Private Key: {hex(private_key)}")
    print(f"Public Key:  {public_key}")

    # --- 2. Encryption ---
    print("\n--- Encryption ---")
    message = "Hello, ElGamal!"
    print(f"Original Message: {message}")

    ciphertext = encrypt(public_key, message)
    
    C1, C2 = ciphertext
    print(f"Ciphertext C1: {C1}")
    print(f"Ciphertext C2: {C2}")

    # --- 3. Decryption ---
    print("\n--- Decryption ---")
    decrypted_message = decrypt(private_key, ciphertext)
    
    print(f"Decrypted Message: {decrypted_message.decode('utf-8')}")

if __name__ == "__main__":
    main()


