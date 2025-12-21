from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


class SchnorrSigner:
    def __init__(self):
        self._hash_function = hashes.SHA256() #

    def generate_signature(self, data: bytes, private_key: ec.EllipticCurvePrivateKey):
        # The library handles the internal r and s generation securely
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        return signature # This returns a byte[] containing the encoded r and s

    def verify_signature(self, data: bytes, signature: bytes, public_key: ec.EllipticCurvePublicKey):
        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True #
        except Exception:
            return False # Identity Verification failed