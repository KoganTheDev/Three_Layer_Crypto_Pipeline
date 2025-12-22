
from utils import utils
import secrets

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
    private_key = 1 + secrets.randbelow(N - 1)
    public_key = utils.ec_scalar_mult(private_key, G, A, P)
    return private_key, public_key

def encrypt(public_key, message_text):
    """Encrypt message using ElGamal encryption. Returns (C1, C2)."""
    M = encode_plaintext_as_point(message_text)
    k = 1 + secrets.randbelow(N - 1)
    
    C1 = utils.ec_scalar_mult(k, G, A, P)
    S = utils.ec_scalar_mult(k, public_key, A, P)
    C2 = utils.ec_point_add(M, S, A, P)

    return (C1, C2)

def decrypt(private_key, ciphertext):
    """Decrypt ElGamal ciphertext. Returns original message bytes."""
    C1, C2 = ciphertext
    
    S = utils.ec_scalar_mult(private_key, C1, A, P)
    neg_S = (S[0], (P - S[1]) % P)
    M = utils.ec_point_add(C2, neg_S, A, P)
    
    return decode_point_as_plaintext(M)
#El gamal Example

def main():
    # Key Generation
    private_key, public_key = generate_keys()
    print("Private Key:", private_key)
    print("Public Key:", public_key)

    # Message to encrypt
    message = "Hello, ElGamal!"
    print("Original Message:", message)

    # Encryption
    ciphertext = encrypt(public_key, message)
    print("Ciphertext (C1, C2):", ciphertext)

    # Decryption
    decrypted_message = decrypt(private_key, ciphertext)
    print("Decrypted Message:", decrypted_message.decode('utf-8'))
