from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

class ElGamal:
    def __init__(self):
        # We use the base point G indirectly through the SECP256K1 curve
        self.curve = ec.SECP256K1() 

    def encrypt_key(self, session_key: bytes, public_key: ec.EllipticCurvePublicKey) -> bytes:
        """Step 4: Key Wrapping"""
        # 1. Generate ephemeral 'r'
        ephemeral_key = ec.generate_private_key(self.curve)
        
        # 2. Calculate shared secret (r * recipient_pub_key)
        shared_secret = ephemeral_key.exchange(ec.ECDH(), public_key)
        
        # 3. C1: The Ephemeral Public Key (r * G)
        # FIX: Use UncompressedPoint instead of Uncompressed
        c1 = ephemeral_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        # 4. C2: XOR the session_key with the shared secret
        c2 = bytes(a ^ b for a, b in zip(session_key, shared_secret[:32]))
        
        # Return EK (Encrypted Key) as a combined byte array
        return c1 + c2

    def decrypt_key(self, ek: bytes, private_key: ec.EllipticCurvePrivateKey) -> bytes:
        """Step 6: Key Unwrapping"""
        # 1. Split EK back into C1 and C2
        # For SECP256K1, an uncompressed point is 65 bytes (1 byte prefix + 64 bytes data)
        c1_bytes = ek[:65]
        c2 = ek[65:]
        
        # 2. Reconstruct C1 as a Public Key object from X962 bytes
        c1_obj = ec.EllipticCurvePublicKey.from_encoded_point(self.curve, c1_bytes)
        
        # 3. Calculate the same shared secret (private_key * C1)
        shared_secret = private_key.exchange(ec.ECDH(), c1_obj)
        
        # 4. Recover the session_key
        session_key = bytes(a ^ b for a, b in zip(c2, shared_secret[:32]))
        
        return session_key