from cryptography.hazmat.primitives.asymmetric import ec

class KeyPair:
    @staticmethod
    def generate():
        # Generates a private key on the SECP256K1 curve
        private_key = ec.generate_private_key(ec.SECP256K1())
        # Extracts the public key from the private key
        public_key = private_key.public_key()
        return private_key, public_key