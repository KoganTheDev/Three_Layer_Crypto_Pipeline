import os
from constants import R
# RC6 in GCM mode
#1) CTR-mode encryption  (XOR plaintext with encrypted counters)
#2) Authentication tag using GHASH (finite field math)
#
# We assume nonce is 12 bytes (the standard easy case)

# -------------------------------------------
# Before you proceed to read this or make any changes,
# never reuse a nonce with the same key!!!
# nonce reuse in GCM is like reusing a one-time pad - catastrophic
# -------------------------------------------

poly_const = R  # GCM polynomial constant for 128 bit blocks

def xor_bytes(a: bytes, b: bytes) -> bytes:
    #XOR two byte strings (up to the shortest length)
    out = bytearray()
    n = min(len(a), len(b))
    for i in range(n):
        out.append(a[i] ^ b[i])
    return bytes(out)

def split_blocks_16(data: bytes) -> list:
    #Split data into chunks of 16 bytes (last chunk may be smaller)
    blocks = []
    i = 0
    while i < len(data):
        blocks.append(data[i:i+16])
        i += 16
    return blocks

def pad_to_16(data: bytes) -> bytes:
    #Pad with zero bytes so length becomes multiple of 16
    if len(data) % 16 == 0:
        return data
    need = 16 - (len(data) % 16)
    return data + (b"\x00" * need)

def inc32(counter_block: bytes) -> bytes:

    # Increment the last 32 bits of a 16-byte counter block (big endian)
    # Counter block layout is [12 bytes prefix][4 bytes counter] 
    if len(counter_block) != 16:
        raise ValueError("counter_block must be 16 bytes")

    prefix = counter_block[:12]
    ctr_bytes = counter_block[12:]
    ctr = int.from_bytes(ctr_bytes, "big")
    ctr = (ctr + 1) & 0xFFFFFFFF
    return prefix + ctr.to_bytes(4, "big")

def gf_mul(x: int, y: int) -> int:
    # Galoais Field multiplication
    #Multiply x*y in GF(2^128)
    #x,y are 128-bit integers
    #this is the main math behind GHASH

    z = 0
    v = x

    # we read bits of y from MSB -> LSB
    for i in range(128):
        bit = (y >> (127 - i)) & 1
        if bit == 1:
            z ^= v

        # Shift v right by 1.
        # If the bit that fell off was 1, XOR with R (reduction)
        if (v & 1) == 0:
            v >>= 1
        else:
            v = (v >> 1) ^ poly_const

    return z

def ghash(H: bytes, data_aligned_16: bytes) -> bytes:
    #GHASH(H, X) where X is multiple of 16 bytes.
    #H is 16 bytes: H = E(K, 0^128)

    if len(H) != 16:
        raise ValueError("H must be 16 bytes")
    if len(data_aligned_16) % 16 != 0:
        raise ValueError("data must be aligned to 16 bytes")

    h = int.from_bytes(H, "big")
    y = 0
    blocks = split_blocks_16(data_aligned_16)
    for blk in blocks:
        x = int.from_bytes(blk, "big")
        y = gf_mul(y ^ x, h)

    return y.to_bytes(16, "big")

def build_len_block(aad_len_bytes: int, ct_len_bytes: int) -> bytes:

    #GCM appends lengths in BITS (not bytes):
    #[len(AAD) in bits as 64-bit big-endian] || [len(CT) in bits as 64-bit big-endian]

    a_bits = aad_len_bytes * 8
    c_bits = ct_len_bytes * 8
    return a_bits.to_bytes(8, "big") + c_bits.to_bytes(8, "big")


def derive_J0(nonce: bytes) -> bytes:
    #We enforce nonce length 12 to keep implementation simple
    if len(nonce) != 12:
        raise ValueError("nonce must be exactly 12 bytes for this simplified GCM")
    return nonce + b"\x00\x00\x00\x01"

def constant_time_eq(a: bytes, b: bytes) -> bool:
    #Compare bytes in constant-time style (avoid early exit)
    if len(a) != len(b):
        return False
    diff = 0
    for i in range(len(a)):
        diff |= (a[i] ^ b[i])
    return diff == 0

def gcm_encrypt(block_encrypt_func, nonce: bytes, plaintext: bytes, aad: bytes):
   
    #block_encrypt_func: function that takes 16 bytes and returns 16 bytes (E_K(block))
    #Returns: (ciphertext, tag)
    
    #H = E(K, 0^128)
    H = block_encrypt_func(b"\x00" * 16)

    #J0 (initial counter base)
    J0 = derive_J0(nonce)

    #CTR encryption
    counter = J0
    ct_parts = []
    pt_blocks = split_blocks_16(plaintext)

    for blk in pt_blocks:
        counter = inc32(counter)
        stream = block_encrypt_func(counter)# 16 bytes
        ct_parts.append(xor_bytes(blk, stream[:len(blk)]))

    ciphertext = b"".join(ct_parts)

    #Authentication (GHASH)
    # GHASH input = pad(AAD) || pad(CT) || len_block
    g_in = pad_to_16(aad) + pad_to_16(ciphertext) + build_len_block(len(aad), len(ciphertext))
    S = ghash(H, g_in)

    #Tag = E(K, J0) XOR S
    tag = xor_bytes(block_encrypt_func(J0), S)
    return ciphertext, tag

def gcm_decrypt(block_encrypt_func, nonce: bytes, ciphertext: bytes, aad: bytes, tag: bytes):
    """
    Verify tag, then decrypt.
    Returns plaintext or raises error if authentication fails.
    """
    if len(tag) != 16:
        raise ValueError("tag must be 16 bytes")

    H = block_encrypt_func(b"\x00" * 16)
    J0 = derive_J0(nonce)

    # Recompute expected tag
    g_in = pad_to_16(aad) + pad_to_16(ciphertext) + build_len_block(len(aad), len(ciphertext))
    S = ghash(H, g_in)
    expected_tag = xor_bytes(block_encrypt_func(J0), S)

    if not constant_time_eq(expected_tag, tag):
        raise ValueError("AUTH FAIL: tag mismatch")

    # CTR decrypt (same as encrypt)
    counter = J0
    pt_parts = []
    ct_blocks = split_blocks_16(ciphertext)

    for blk in ct_blocks:
        counter = inc32(counter)
        stream = block_encrypt_func(counter)
        pt_parts.append(xor_bytes(blk, stream[:len(blk)]))

    return b"".join(pt_parts)