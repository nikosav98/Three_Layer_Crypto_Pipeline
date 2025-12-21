"""
pytest test suite that checks:
u32 truncation
rotl32/rotr32 correctness
pack/unpack roundtrip + byte order
bytes_to_words_little_endian
key expansion determinism + length
encrypt/decrypt roundtrip on many random vectors
error handling on wrong block length
"""

# test_rc6_single_file.py
# Single file: implementation + pytest tests
# Run: pytest -q

from __future__ import annotations
import os
import pytest

# =========================
# "common.constants" stand-in
# =========================
class const:
    WORD_MASK = 0xFFFFFFFF
    ROUNDS_DEFAULT = 20
    P32 = 0xB7E15163
    Q32 = 0x9E3779B9


# =========================
# RC6 helpers + implementation
# =========================

ROUNDS = const.ROUNDS_DEFAULT  # number of rounds


def u32(x: int) -> int:
    """Force every operation into 32-bit math (mod 2^32)."""
    return x & const.WORD_MASK


def rotl32(x: int, s: int) -> int:
    """Circular rotate-left on 32-bit word."""
    s &= 31
    x &= const.WORD_MASK
    return u32((x << s) | (x >> (32 - s)))


def rotr32(x: int, s: int) -> int:
    """Circular rotate-right on 32-bit word."""
    s &= 31
    x &= const.WORD_MASK
    return u32((x >> s) | (x << (32 - s)))


def unpack_block_little_endian(block16: bytes) -> tuple[int, int, int, int]:
    """Unpack a 16-byte block into four little-endian 32-bit words."""
    if len(block16) != 16:
        raise ValueError("Block must be exactly 16 bytes")

    w0 = int.from_bytes(block16[0:4], "little")
    w1 = int.from_bytes(block16[4:8], "little")
    w2 = int.from_bytes(block16[8:12], "little")
    w3 = int.from_bytes(block16[12:16], "little")
    return (w0, w1, w2, w3)


def pack_block_little_endian(A: int, B: int, C: int, D: int) -> bytes:
    """Pack four 32-bit words into a 16-byte block (little-endian per word)."""
    return (
        u32(A).to_bytes(4, "little")
        + u32(B).to_bytes(4, "little")
        + u32(C).to_bytes(4, "little")
        + u32(D).to_bytes(4, "little")
    )


def bytes_to_words_little_endian(data: bytes) -> list[int]:
    """Convert bytes into a list of 32-bit words (little-endian). Pads with zeros to multiple of 4."""
    if len(data) == 0:
        return [0]

    if len(data) % 4 != 0:
        padding_length = 4 - (len(data) % 4)
        data += b"\x00" * padding_length

    words: list[int] = []
    for i in range(0, len(data), 4):
        word = int.from_bytes(data[i : i + 4], "little")
        words.append(word)
    return words


def expand_key(user_key: bytes, rounds: int = const.ROUNDS_DEFAULT) -> list[int]:
    """
    RC6 key expansion:
    user_key: bytes
    rounds: int
    returns S: list[int] of length t = 2*rounds + 4
    """
    r = rounds
    b = len(user_key)
    c = (b + 3) // 4  # ceil(b/4), number of words in key
    if c == 0:
        c = 1

    P32 = const.P32
    Q32 = const.Q32

    L = bytes_to_words_little_endian(user_key)
    # Ensure L has length c
    if len(L) < c:
        L += [0] * (c - len(L))

    t = 2 * r + 4
    S = [0] * t

    S[0] = P32
    for i in range(1, t):
        S[i] = u32(S[i - 1] + Q32)

    A = B = 0
    i = j = 0
    v = 3 * max(c, t)

    for _ in range(v):
        A = S[i] = rotl32(u32(S[i] + A + B), 3)
        B = L[j] = rotl32(u32(L[j] + A + B), u32(A + B))
        i = (i + 1) % t
        j = (j + 1) % c

    return S


def encrypt_block(block16: bytes, S: list[int], rounds: int = const.ROUNDS_DEFAULT) -> bytes:
    """RC6 encryption of a single 16-byte block."""
    A, B, C, D = unpack_block_little_endian(block16)

    B = u32(B + S[0])
    D = u32(D + S[1])

    for i in range(1, rounds + 1):
        t = rotl32(u32(B * u32(2 * B + 1)), 5)
        u = rotl32(u32(D * u32(2 * D + 1)), 5)

        A = u32(rotl32(u32(A ^ t), u) + S[2 * i])
        C = u32(rotl32(u32(C ^ u), t) + S[2 * i + 1])

        A, B, C, D = B, C, D, A  # rotate words

    A = u32(A + S[2 * rounds + 2])
    C = u32(C + S[2 * rounds + 3])

    return pack_block_little_endian(A, B, C, D)


def decrypt_block(block16: bytes, S: list[int], rounds: int = const.ROUNDS_DEFAULT) -> bytes:
    """RC6 decryption of a single 16-byte block."""
    A, B, C, D = unpack_block_little_endian(block16)

    C = u32(C - S[2 * rounds + 3])
    A = u32(A - S[2 * rounds + 2])

    for i in range(rounds, 0, -1):
        A, B, C, D = D, A, B, C  # undo rotate

        t = rotl32(u32(B * u32(2 * B + 1)), 5)
        u = rotl32(u32(D * u32(2 * D + 1)), 5)

        C = u32(rotr32(u32(C - S[2 * i + 1]), t) ^ u)
        A = u32(rotr32(u32(A - S[2 * i]), u) ^ t)

    B = u32(B - S[0])
    D = u32(D - S[1])

    return pack_block_little_endian(A, B, C, D)


# =========================
# Pytest test suite
# =========================

def test_u32_truncation():
    assert u32(0xFFFFFFFF) == 0xFFFFFFFF
    assert u32(0x100000000) == 0  # wraps mod 2^32
    assert u32(-1) == 0xFFFFFFFF  # two's complement masking behavior


def _rotl32_ref(x: int, s: int) -> int:
    s &= 31
    x &= 0xFFFFFFFF
    return ((x << s) | (x >> (32 - s))) & 0xFFFFFFFF


def _rotr32_ref(x: int, s: int) -> int:
    s &= 31
    x &= 0xFFFFFFFF
    return ((x >> s) | (x << (32 - s))) & 0xFFFFFFFF


def test_rotations_match_reference():
    for _ in range(200):
        x = int.from_bytes(os.urandom(4), "little")
        s = int.from_bytes(os.urandom(2), "little")  # any size, we mod 32
        assert rotl32(x, s) == _rotl32_ref(x, s)
        assert rotr32(x, s) == _rotr32_ref(x, s)


def test_pack_unpack_roundtrip_and_endianness():
    A = 0x12345678
    B = 0x9ABCDEF0
    C = 0x13579BDF
    D = 0x2468ACE0

    block = pack_block_little_endian(A, B, C, D)

    # Little-endian per word check:
    assert block[0:4] == bytes.fromhex("78 56 34 12".replace(" ", ""))

    out = unpack_block_little_endian(block)
    assert out == (A, B, C, D)

    # Roundtrip invariant for random words
    for _ in range(200):
        A = int.from_bytes(os.urandom(4), "little")
        B = int.from_bytes(os.urandom(4), "little")
        C = int.from_bytes(os.urandom(4), "little")
        D = int.from_bytes(os.urandom(4), "little")
        blk = pack_block_little_endian(A, B, C, D)
        assert unpack_block_little_endian(blk) == (A, B, C, D)


def test_unpack_rejects_wrong_length():
    with pytest.raises(ValueError):
        unpack_block_little_endian(b"\x00" * 15)
    with pytest.raises(ValueError):
        unpack_block_little_endian(b"\x00" * 17)


def test_bytes_to_words_padding():
    # 3 bytes -> pads to 4
    data = b"\x01\x02\x03"
    words = bytes_to_words_little_endian(data)
    assert len(words) == 1
    # little-endian: 0x00030201
    assert words[0] == 0x00030201

    # 5 bytes -> pads to 8 -> 2 words
    data = b"\x01\x02\x03\x04\x05"
    words = bytes_to_words_little_endian(data)
    assert len(words) == 2
    assert words[0] == 0x04030201
    assert words[1] == 0x00000005


def test_expand_key_length_and_determinism():
    key = b"secret-key-123"
    S1 = expand_key(key, rounds=20)
    S2 = expand_key(key, rounds=20)
    assert S1 == S2
    assert len(S1) == (2 * 20 + 4)

    # Different key should (almost certainly) differ
    key2 = b"secret-key-124"
    S3 = expand_key(key2, rounds=20)
    assert S1 != S3


def test_encrypt_decrypt_roundtrip_random():
    # This is the core property test for RC6: D(E(P)) == P
    for _ in range(200):
        key = os.urandom(16)  # choose your key size; RC6 supports variable lengths
        S = expand_key(key, rounds=ROUNDS)

        pt = os.urandom(16)
        ct = encrypt_block(pt, S, rounds=ROUNDS)
        out = decrypt_block(ct, S, rounds=ROUNDS)

        assert out == pt


def test_encrypt_rejects_wrong_block_size():
    key = os.urandom(16)
    S = expand_key(key, rounds=ROUNDS)
    with pytest.raises(ValueError):
        encrypt_block(b"\x00" * 15, S, rounds=ROUNDS)
    with pytest.raises(ValueError):
        decrypt_block(b"\x00" * 17, S, rounds=ROUNDS)