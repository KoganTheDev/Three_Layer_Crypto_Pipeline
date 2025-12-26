import os
from src.rc6.rc6 import expand_key, encrypt_block, decrypt_block, rotl32

def _hex(b: bytes) -> str:
    return b.hex().upper()

def _hamming_bits(a: bytes, b: bytes) -> int:
    """Count differing bits between two equal-length byte strings."""
    if len(a) != len(b):
        raise ValueError("Lengths differ")
    x = int.from_bytes(a, "big") ^ int.from_bytes(b, "big")
    return x.bit_count()

def run_rc6_print_tests():
    print("\n==============================")
    print(" RC6 PRINT TEST HARNESS")
    print("==============================\n")

    # ------------------------------------------------------------
    # 0) Quick sanity on rotl32 correctness (masking + precedence)
    # ------------------------------------------------------------
    print("[0] rotl32 sanity checks:")
    x = rotl32(0x80000000, 1)
    print(f"rotl32(0x80000000, 1) = 0x{x:08X}  (expected 0x00000001)")
    if x != 0x00000001:
        print("!! WARNING: rotl32 looks wrong (likely missing parentheses/mask).")
        print("   Correct form should be: return (((x<<s) | (x>>(32-s))) & WORD_MASK)\n")
    else:
        print("OK\n")

    # ------------------------------------------------------------
    # 1) Known Answer Test (RC6-32/20/16)
    # Key: 000102...0F
    # PT : 000102...0F
    # CT : 3A96F9C7F6755CFE46F00E3DCD5D2A3C
    # ------------------------------------------------------------
    print("[1] Known Answer Test (RC6-32/20/16):")
    key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    pt  = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    expected_ct = bytes.fromhex("3A96F9C7F6755CFE46F00E3DCD5D2A3C")

    S = expand_key(key, rounds=20)
    ct = encrypt_block(pt, S, rounds=20)

    print("Key        :", _hex(key))
    print("Plaintext  :", _hex(pt))
    print("Ciphertext :", _hex(ct))
    print("Expected   :", _hex(expected_ct))
    print("S words    :", len(S), "(expected 44 for r=20)")

    if ct == expected_ct:
        print("KAT Encrypt : PASS ✅")
    else:
        print("KAT Encrypt : FAIL ❌")
        print("If this fails, the top suspects are:")
        print(" - rotl32 masking/parentheses")
        print(" - endianness in pack/unpack")
        print(" - multiplication not u32-masked at the right spots")
    print()

    # Decrypt check for the KAT
    dec = decrypt_block(ct, S, rounds=20)
    print("Decrypted  :", _hex(dec))
    print("Matches PT :", "YES ✅" if dec == pt else "NO ❌")
    if dec != pt:
        print("If decrypt fails but encrypt matches, likely your decrypt uses rotl32")
        print("where RC6 requires rotr32 in the inverse step.\n")
    else:
        print()

    # ------------------------------------------------------------
    # 2) Edge-pattern roundtrip tests (fast, catches endian/whitening bugs)
    # ------------------------------------------------------------
    print("[2] Edge-pattern roundtrip tests:")
    patterns = [
        bytes(16),                                 # all 00
        b"\xFF" * 16,                               # all FF
        bytes(range(16)),                           # 00..0F
        bytes([0xAA] * 16),                         # 1010...
        bytes([0x55] * 16),                         # 0101...
        b"\x00" * 15 + b"\x01",                     # only last byte set
        b"\x80" + b"\x00" * 15,                     # first byte high bit set
    ]
    key2 = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    S2 = expand_key(key2, rounds=20)
    ok = True
    for idx, p in enumerate(patterns, 1):
        c = encrypt_block(p, S2, rounds=20)
        d = decrypt_block(c, S2, rounds=20)
        status = "PASS ✅" if d == p else "FAIL ❌"
        print(f"  Pattern {idx}: {status}  PT={_hex(p)}  CT={_hex(c)}")
        if d != p:
            print(f"           DEC={_hex(d)}")
            ok = False
            break
    print("Edge-pattern summary:", "ALL PASS ✅\n" if ok else "FAILED ❌\n")

    # ------------------------------------------------------------
    # 3) Randomized roundtrip tests (best overall “does it invert?” check)
    # ------------------------------------------------------------
    print("[3] Random roundtrip tests:")
    trials = 50
    for i in range(1, trials + 1):
        rk = os.urandom(16)
        rp = os.urandom(16)
        rS = expand_key(rk, rounds=20)
        rc = encrypt_block(rp, rS, rounds=20)
        rd = decrypt_block(rc, rS, rounds=20)
        if rd != rp:
            print(f"  Trial {i}: FAIL ❌")
            print("  Key:", _hex(rk))
            print("  PT :", _hex(rp))
            print("  CT :", _hex(rc))
            print("  DEC:", _hex(rd))
            break
        if i in (1, 2, 3, 10, trials):
            print(f"  Trial {i}: PASS ✅")
    else:
        print(f"All {trials} random trials: PASS ✅")
    print()

    # ------------------------------------------------------------
    # 4) Avalanche sanity check (flip 1 bit → lots of output bits change)
    # ------------------------------------------------------------
    print("[4] Avalanche sanity check (not a proof, just a smell test):")
    key3 = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    S3 = expand_key(key3, rounds=20)
    ptA = bytes(16)
    ptB = bytes([ptA[0] ^ 0x01]) + ptA[1:]  # flip 1 bit in the first byte
    ctA = encrypt_block(ptA, S3, rounds=20)
    ctB = encrypt_block(ptB, S3, rounds=20)
    diff = _hamming_bits(ctA, ctB)
    print("PT A:", _hex(ptA))
    print("PT B:", _hex(ptB))
    print("CT A:", _hex(ctA))
    print("CT B:", _hex(ctB))
    print(f"Bit differences in CT: {diff} / 128 (typical is ~64-ish)")
    print("\nDone.\n")


# If you want it to run automatically when you run the file:
if __name__ == "__main__":
    run_rc6_print_tests()
