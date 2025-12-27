# rc6_gcm_mode.py
# Glue code: RC6 block cipher + GCM mode = AEAD (encrypt + authenticate)

import os

from rc6 import expand_key, encrypt_block
from gcm import gcm_encrypt, gcm_decrypt


def rc6_block_encryptor(key: bytes):
    """
    Creates and returns a function E(block16) using RC6 with the expanded key.
    This is what GCM needs (ONLY block encryption).
    """
    S = expand_key(key)

    def block_encrypt(block16: bytes) -> bytes:
        return encrypt_block(block16, S)

    return block_encrypt


def rc6_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"", nonce: bytes = None):
    """
    Encrypt + authenticate.
    Returns: (nonce, ciphertext, tag)

    - nonce must be 12 bytes.
    - If nonce is None, we generate a random one.
    """
    if nonce is None:
        nonce = os.urandom(12)

    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes (GCM standard)")

    block_encrypt = rc6_block_encryptor(key)

    ciphertext, tag = gcm_encrypt(block_encrypt, nonce, plaintext, aad)
    return nonce, ciphertext, tag


def rc6_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b""):
    """
    Verify + decrypt.
    Returns plaintext if tag is valid, otherwise raises ValueError.
    """
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes (GCM standard)")

    block_encrypt = rc6_block_encryptor(key)

    plaintext = gcm_decrypt(block_encrypt, nonce, ciphertext, aad, tag)
    return plaintext
