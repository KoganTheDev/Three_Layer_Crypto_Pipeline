import os
import pytest

import rc6
import gcm
import constants as const


# -------------------------
# Fixtures
# -------------------------

@pytest.fixture
def rc6_key_schedule():
    # 16-byte key for RC6
    key = b"this is 16 bytes"  # exactly 16 bytes
    S = rc6.expand_key(key, rounds=const.ROUNDS_DEFAULT)
    return key, S


@pytest.fixture
def rc6_block_encrypt(rc6_key_schedule):
    _, S = rc6_key_schedule

    def _enc(block16: bytes) -> bytes:
        assert len(block16) == 16
        return rc6.encrypt_block(block16, S)

    return _enc


@pytest.fixture
def nonce():
    # exactly 12 bytes for this simplified GCM
    return b"unique_nonce"  # len == 12


# -------------------------
# RC6 helper tests
# -------------------------

def test_u32_masks_to_32_bits():
    x = 0x123456789ABCDEF
    y = rc6.u32(x)
    assert 0 <= y <= const.WORD_MASK
    assert y == (x & const.WORD_MASK)


def test_rotl_rotr_inverse():
    x = 0xDEADBEEF
    for s in range(0, 40):  # beyond 32 to test masking
        r = rc6.rotl32(x, s)
        back = rc6.rotr32(r, s)
        assert back == rc6.u32(x)


def test_pack_unpack_roundtrip():
    A, B, C, D = 0x12345678, 0x9ABCDEF0, 0x13579BDF, 0x2468ACE0
    block = rc6.pack_block_little_endian(A, B, C, D)
    assert len(block) == 16
    a2, b2, c2, d2 = rc6.unpack_block_little_endian(block)
    assert (A, B, C, D) == (a2, b2, c2, d2)


def test_bytes_to_words_little_endian_padding_and_empty():
    # empty -> [0] (per your implementation)
    assert rc6.bytes_to_words_little_endian(b"") == [0]

    # exact multiple of 4
    data = b"\x01\x02\x03\x04\xAA\xBB\xCC\xDD"
    words = rc6.bytes_to_words_little_endian(data)
    assert len(words) == 2
    assert words[0] == int.from_bytes(data[0:4], "little")
    assert words[1] == int.from_bytes(data[4:8], "little")

    # not multiple of 4 -> padded
    data2 = b"\x01\x02\x03"
    words2 = rc6.bytes_to_words_little_endian(data2)
    assert len(words2) == 1
    assert words2[0] == int.from_bytes(data2 + b"\x00", "little")


def test_expand_key_output_length_and_mask():
    key = b"this is 16 bytes"
    S = rc6.expand_key(key, rounds=const.ROUNDS_DEFAULT)
    assert len(S) == 2 * const.ROUNDS_DEFAULT + 4
    assert all(0 <= w <= const.WORD_MASK for w in S)


# -------------------------
# RC6 block cipher tests
# -------------------------

def test_encrypt_decrypt_block_roundtrip(rc6_key_schedule):
    _, S = rc6_key_schedule
    pt = bytes(range(16))

    ct = rc6.encrypt_block(pt, S)
    assert len(ct) == 16
    assert ct != pt

    dt = rc6.decrypt_block(ct, S)
    assert dt == pt


def test_encrypt_decrypt_random_blocks(rc6_key_schedule):
    _, S = rc6_key_schedule
    for _ in range(10):
        pt = os.urandom(16)
        ct = rc6.encrypt_block(pt, S)
        dt = rc6.decrypt_block(ct, S)
        assert dt == pt


# -------------------------
# GCM helper tests
# -------------------------

def test_xor_bytes_basic():
    a = b"\x00\xFF\x55"
    b_ = b"\xFF\x00\x55"
    out = gcm.xor_bytes(a, b_)
    assert out == b"\xFF\xFF\x00"


def test_split_blocks_16():
    data = bytes(range(40))  # 2 full blocks + 1 partial (8)
    blocks = gcm.split_blocks_16(data)
    assert len(blocks) == 3
    assert blocks[0] == data[0:16]
    assert blocks[1] == data[16:32]
    assert blocks[2] == data[32:40]


def test_pad_to_16():
    d1 = b"A" * 16
    assert gcm.pad_to_16(d1) == d1

    d2 = b""
    assert gcm.pad_to_16(d2) == b""

    d3 = b"12345"
    padded = gcm.pad_to_16(d3)
    assert len(padded) % 16 == 0
    assert padded.startswith(d3)
    assert padded[len(d3):] == b"\x00" * (len(padded) - len(d3))


def test_inc32_increments_last_32_bits_and_wraps():
    blk = b"A" * 12 + b"\x00\x00\x00\x01"
    out = gcm.inc32(blk)
    assert out[:12] == b"A" * 12
    assert out[12:] == b"\x00\x00\x00\x02"

    blk_wrap = b"B" * 12 + b"\xFF\xFF\xFF\xFF"
    out_wrap = gcm.inc32(blk_wrap)
    assert out_wrap[:12] == b"B" * 12
    assert out_wrap[12:] == b"\x00\x00\x00\x00"


def test_constant_time_eq():
    a = b"abcdef"
    b_ = b"abcdef"
    c = b"abcdeg"
    d = b"abc"
    assert gcm.constant_time_eq(a, b_)
    assert not gcm.constant_time_eq(a, c)
    assert not gcm.constant_time_eq(a, d)


def test_gf_mul_zero_identities():
    x = int.from_bytes(os.urandom(16), "big")
    assert gcm.gf_mul(x, 0) == 0
    assert gcm.gf_mul(0, x) == 0


def test_gf_mul_commutative_random():
    for _ in range(10):
        x = int.from_bytes(os.urandom(16), "big")
        y = int.from_bytes(os.urandom(16), "big")
        xy = gcm.gf_mul(x, y)
        yx = gcm.gf_mul(y, x)
        assert xy == yx


def test_ghash_zero_data_zero_H():
    H = b"\x00" * 16
    data = b""
    tag = gcm.ghash(H, data)
    assert tag == b"\x00" * 16


def test_ghash_zero_data_nonzero_H():
    H = b"\x01" * 16
    data = b""
    tag = gcm.ghash(H, data)
    assert tag == b"\x00" * 16


def test_build_len_block_bits():
    aad_len = 13
    ct_len = 31
    lb = gcm.build_len_block(aad_len, ct_len)
    assert len(lb) == 16
    aad_bits = int.from_bytes(lb[:8], "big")
    ct_bits = int.from_bytes(lb[8:], "big")
    assert aad_bits == aad_len * 8
    assert ct_bits == ct_len * 8


def test_derive_J0_and_nonce_length():
    n = b"123456789012"  # 12 bytes
    j0 = gcm.derive_J0(n)
    assert len(j0) == 16
    assert j0[:12] == n
    assert j0[12:] == b"\x00\x00\x00\x01"

    with pytest.raises(ValueError):
        gcm.derive_J0(b"short")


# -------------------------
# GCM + RC6 integration tests
# -------------------------

def test_gcm_roundtrip_with_rc6_single_block(rc6_block_encrypt, nonce):
    plaintext = b"Hello RC6-GCM!!"  # 16 bytes
    aad = b"header"

    ct, tag = gcm.gcm_encrypt(rc6_block_encrypt, nonce, plaintext, aad)
    assert ct != plaintext
    assert len(tag) == 16

    decrypted = gcm.gcm_decrypt(rc6_block_encrypt, nonce, ct, aad, tag)
    assert decrypted == plaintext


def test_gcm_roundtrip_with_rc6_multi_block(rc6_block_encrypt, nonce):
    plaintext = b"RC6-GCM test that is longer than one block!!"
    aad = b"authenticated-but-not-encrypted"

    ct, tag = gcm.gcm_encrypt(rc6_block_encrypt, nonce, plaintext, aad)
    decrypted = gcm.gcm_decrypt(rc6_block_encrypt, nonce, ct, aad, tag)
    assert decrypted == plaintext


def test_gcm_tag_mismatch_raises(rc6_block_encrypt, nonce):
    plaintext = b"attack at dawn"
    aad = b"hdr"

    ct, tag = gcm.gcm_encrypt(rc6_block_encrypt, nonce, plaintext, aad)
    bad_tag = bytearray(tag)
    bad_tag[0] ^= 0x01
    bad_tag = bytes(bad_tag)

    with pytest.raises(ValueError, match="AUTH FAIL"):
        gcm.gcm_decrypt(rc6_block_encrypt, nonce, ct, aad, bad_tag)


def test_gcm_ciphertext_tamper_raises(rc6_block_encrypt, nonce):
    plaintext = b"very secret message"
    aad = b"hdr"

    ct, tag = gcm.gcm_encrypt(rc6_block_encrypt, nonce, plaintext, aad)
    bad_ct = bytearray(ct)
    bad_ct[0] ^= 0x01
    bad_ct = bytes(bad_ct)

    with pytest.raises(ValueError, match="AUTH FAIL"):
        gcm.gcm_decrypt(rc6_block_encrypt, nonce, bad_ct, aad, tag)


def test_gcm_invalid_tag_length_raises(rc6_block_encrypt, nonce):
    plaintext = b"msg"
    aad = b"hdr"
    ct, tag = gcm.gcm_encrypt(rc6_block_encrypt, nonce, plaintext, aad)
    too_short_tag = tag[:-1]

    with pytest.raises(ValueError):
        gcm.gcm_decrypt(rc6_block_encrypt, nonce, ct, aad, too_short_tag)
