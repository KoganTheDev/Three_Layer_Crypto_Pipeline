import base64

class SignatureObject:
    def __init__(self, r: bytes, s: bytes):
        # Fields are private (-) as per the class diagram
        self.__r = r  # The commitment/random part of the signature
        self.__s = s  # The proof part of the signature

    # Getters for the verification process
    def get_r(self) -> bytes:
        return self.__r

    def get_s(self) -> bytes:
        return self.__s

    def to_bytes(self) -> bytes:
        """
        Concatenates r and s into a single byte array.
        Useful for Step 3: Main Encryption.
        """
        # Assuming r and s are both 32 bytes for a 256-bit curve
        return self.__r + self.__s

    @classmethod
    def from_bytes(cls, data: bytes):
        """
        Splits a byte array back into r and s components.
        Used after Step 7: Main Decryption.
        """
        if len(data) != 64:
            raise ValueError("Invalid signature length. Expected 64 bytes.")
        
        r = data[:32]
        s = data[32:]
        return cls(r, s)

    def to_base64(self) -> str:
        """Helper for easy debugging or text-based logs."""
        return base64.b64encode(self.to_bytes()).decode('utf-8')